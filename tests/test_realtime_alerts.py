"""Focused tests for real-time file security alerts and SMTP behavior.

All notification transports are faked here: these tests never contact SMTP,
webhooks, WMI, or a physical USB device.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import alert_system
import file_auditor
from alert_system import AlertSystem
from file_auditor import FileAuditHandler, TransferSession
from yara_scanner import YaraScanResult


def _wait_for(predicate, timeout: float = 2.5) -> None:
    """Keep asynchronous tests bounded while allowing the stability worker to run."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "timed out waiting for asynchronous result"


class RecordingDb:
    """Small in-memory stand-in for the database notification seam."""

    def __init__(self):
        self.events = []
        self.file_events = []
        self.violations = []
        self.devices = []

    def log_event(self, *args, **kwargs):
        self.events.append((args, kwargs))

    def log_file_event(self, *args, **kwargs):
        self.file_events.append((args, kwargs))

    def log_violation(self, *args, **kwargs):
        self.violations.append((args, kwargs))

    def log_device(self, *args, **kwargs):
        self.devices.append((args, kwargs))


class RecordingAlerts:
    def __init__(self):
        self.yara = []
        self.large_transfers = []
        self.usb = []

    def send_yara_alert(self, *args, **kwargs):
        self.yara.append((args, kwargs))
        return True

    def send_large_transfer_alert(self, *args, **kwargs):
        self.large_transfers.append((args, kwargs))
        return True

    def send_spoofing_alert(self, device):
        self.usb.append(("spoofing", device))

    def send_badusb_alert(self, device):
        self.usb.append(("badusb", device))

    def send_violation_alert(self, device, violation_type, threat_score):
        self.usb.append(("violation", device, violation_type, threat_score))


class RecordingNotifier:
    def __init__(self):
        self.yara = []
        self.large_transfers = []
        self.usb = []

    def send_yara_hit(self, *args, **kwargs):
        self.yara.append((args, kwargs))

    def send_large_transfer(self, *args, **kwargs):
        self.large_transfers.append((args, kwargs))

    def send_spoofing(self, device):
        self.usb.append(("spoofing", device))

    def send_badusb(self, device):
        self.usb.append(("badusb", device))

    def send_violation(self, device, violation_type, threat_score):
        self.usb.append(("violation", device, violation_type, threat_score))


class Scanner:
    """Configurable fake scanner that records exactly what the worker scanned."""

    def __init__(self, make_result):
        self.make_result = make_result
        self.paths = []

    def scan(self, path):
        self.paths.append(path)
        return self.make_result(path)


def _matched_result(path: str) -> YaraScanResult:
    return YaraScanResult(
        file_path=path,
        matched=True,
        rule_names=["AutoRun_Infection"],
        severity="CRITICAL",
        descriptions=["Autorun infection vector"],
        categories=["autorun"],
    )


@pytest.fixture
def fast_stability(monkeypatch):
    """Keep real stability behavior while making tests quick and deterministic."""
    monkeypatch.setattr(config, "YARA_DEBOUNCE_SECONDS", 0.01)
    monkeypatch.setattr(config, "YARA_STABILITY_SECONDS", 0.02)
    monkeypatch.setattr(config, "YARA_STABILITY_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(config, "YARA_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(config, "YARA_MAX_RETRIES", 1)


def _handler(tmp_path, monkeypatch, scanner, alerts=None, notifier=None):
    db = RecordingDb()
    monkeypatch.setattr(file_auditor, "get_db", lambda: db)
    session = TransferSession("E:\\", alert_system=alerts, notifier=notifier)
    session.device_fp = "VID_1234&PID_5678&SER_TEST123456"
    session.vid = "1234"
    session.pid = "5678"
    session.serial = "TEST123456"
    session.description = "Test USB Drive"
    return (FileAuditHandler(session, alert_system=alerts, notifier=notifier,
                             yara_scanner=scanner), db)


def _event(path: Path):
    return SimpleNamespace(src_path=str(path), is_directory=False)


class TestAlertSystemSmtp:
    def _configure_live_smtp(self, monkeypatch):
        monkeypatch.setattr(config, "ALERT_DEMO_MODE", False)
        monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.test")
        monkeypatch.setattr(config, "SMTP_PORT", 587)
        monkeypatch.setattr(config, "SMTP_USE_TLS", True)
        monkeypatch.setattr(config, "SMTP_USER", "sender@example.test")
        monkeypatch.setattr(config, "SMTP_PASS", "app-password")
        monkeypatch.setattr(config, "SMTP_FROM", "sender@example.test")
        monkeypatch.setattr(config, "SMTP_TO", "security@example.test")

    def test_live_smtp_uses_tls_login_and_message(self, monkeypatch):
        self._configure_live_smtp(monkeypatch)
        calls = []

        class FakeSmtp:
            def __init__(self, host, port, timeout):
                calls.append(("connect", host, port, timeout))

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def ehlo(self):
                calls.append(("ehlo",))

            def starttls(self):
                calls.append(("starttls",))

            def login(self, user, password):
                calls.append(("login", user, password))

            def send_message(self, message):
                calls.append(("send", message))

        monkeypatch.setattr(alert_system.smtplib, "SMTP", FakeSmtp)
        alerts = AlertSystem()

        assert alerts._send_smtp("YARA THREAT", "rule: AutoRun_Infection") is True
        assert calls[0] == ("connect", "smtp.example.test", 587, 10)
        assert ("starttls",) in calls
        assert ("login", "sender@example.test", "app-password") in calls
        sent = next(value for value in calls if value[0] == "send")[1]
        assert sent["Subject"] == "[USB-SECURITY] YARA THREAT"
        assert "AutoRun_Infection" in sent.get_payload()[0].get_payload()

    def test_missing_live_smtp_configuration_never_connects(self, monkeypatch):
        self._configure_live_smtp(monkeypatch)
        monkeypatch.setattr(config, "SMTP_TO", "")
        monkeypatch.setattr(
            alert_system.smtplib, "SMTP",
            lambda *args, **kwargs: pytest.fail("SMTP must not be opened"),
        )

        assert AlertSystem()._send_smtp("subject", "body") is False

    def test_smtp_failure_returns_false_and_redacts_password(self, monkeypatch):
        self._configure_live_smtp(monkeypatch)
        captured_errors = []

        class Logger:
            def error(self, message, *args):
                captured_errors.append(message % args if args else message)

        class BrokenSmtp:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                raise RuntimeError("delivery failed for app-password")

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(alert_system, "audit_logger", Logger())
        monkeypatch.setattr(alert_system.smtplib, "SMTP", BrokenSmtp)
        assert AlertSystem()._send_smtp("subject", "body") is False
        assert captured_errors
        assert "app-password" not in "\n".join(captured_errors)

    def test_demo_queue_is_not_counted_as_smtp_delivery(self, monkeypatch):
        monkeypatch.setattr(config, "ALERT_DEMO_MODE", True)
        monkeypatch.setattr(config, "ALERT_DEDUP_SECONDS", 0)
        alerts = AlertSystem()
        smtp_calls = []
        monkeypatch.setattr(
            alerts, "_send_smtp",
            lambda *args, **kwargs: smtp_calls.append(args) or True,
        )
        alerts.start()
        try:
            assert alerts._enqueue("CRITICAL", "demo event", "body") is True
            _wait_for(lambda: alerts._demo_count == 1)
            assert alerts._sent_count == 0
            assert smtp_calls == []
        finally:
            alerts.stop()


class TestRealtimeYaraAlerts:
    def test_stable_yara_match_records_database_webhook_and_email(
            self, tmp_path, monkeypatch, fast_stability):
        path = tmp_path / "yara_test.txt"
        path.write_text("[AutoRun]\nopen=harmless.exe\n", encoding="utf-8")
        alerts = RecordingAlerts()
        notifier = RecordingNotifier()
        scanner = Scanner(_matched_result)
        handler, db = _handler(tmp_path, monkeypatch, scanner, alerts, notifier)

        try:
            handler.on_created(_event(path))
            _wait_for(lambda: len(alerts.yara) == 1)
            assert scanner.paths == [str(path)]
            args, kwargs = alerts.yara[0]
            assert args[:3] == (str(path), ["AutoRun_Infection"], "CRITICAL")
            assert kwargs["drive_letter"] == "E:\\"
            assert kwargs["device_fp"].startswith("VID_1234")
            assert kwargs["serial"] == "TEST123456"
            assert len(notifier.yara) == 1
            assert any(event[0][0] == "YARA_THREAT_DETECTED" for event in db.events)
            assert len(db.violations) == 1
        finally:
            handler.stop()

    def test_clean_file_does_not_produce_threat_email(
            self, tmp_path, monkeypatch, fast_stability):
        path = tmp_path / "ordinary.txt"
        path.write_text("ordinary harmless notes", encoding="utf-8")
        alerts = RecordingAlerts()
        notifier = RecordingNotifier()
        scanner = Scanner(lambda candidate: YaraScanResult(file_path=candidate))
        handler, db = _handler(tmp_path, monkeypatch, scanner, alerts, notifier)

        try:
            handler.on_created(_event(path))
            _wait_for(lambda: len(scanner.paths) == 1)
            assert alerts.yara == []
            assert notifier.yara == []
            assert not any(event[0][0] == "YARA_THREAT_DETECTED" for event in db.events)
        finally:
            handler.stop()

    def test_modified_file_is_rescanned_after_stability(
            self, tmp_path, monkeypatch, fast_stability):
        path = tmp_path / "changed.txt"
        path.write_text("ordinary content", encoding="utf-8")

        def based_on_contents(candidate):
            payload = Path(candidate).read_text(encoding="utf-8")
            if "[AutoRun]" in payload and "open=" in payload:
                return _matched_result(candidate)
            return YaraScanResult(file_path=candidate)

        alerts = RecordingAlerts()
        scanner = Scanner(based_on_contents)
        handler, _ = _handler(tmp_path, monkeypatch, scanner, alerts, RecordingNotifier())

        try:
            handler.on_created(_event(path))
            _wait_for(lambda: len(scanner.paths) == 1)
            assert alerts.yara == []

            # This is deliberately a separate watchdog MODIFIED event, which
            # must result in a second stable scan rather than merely a log row.
            path.write_text("[AutoRun]\nopen=harmless.exe\n", encoding="utf-8")
            handler.on_modified(_event(path))
            _wait_for(lambda: len(scanner.paths) >= 2)
            _wait_for(lambda: len(alerts.yara) == 1)
            assert len(alerts.yara) == 1
        finally:
            handler.stop()

    def test_duplicate_created_events_do_not_repeat_yara_email(
            self, tmp_path, monkeypatch, fast_stability):
        path = tmp_path / "duplicate.txt"
        path.write_text("[AutoRun]\nopen=harmless.exe\n", encoding="utf-8")
        alerts = RecordingAlerts()
        scanner = Scanner(_matched_result)
        handler, _ = _handler(tmp_path, monkeypatch, scanner, alerts, RecordingNotifier())

        try:
            handler.on_created(_event(path))
            handler.on_created(_event(path))  # Windows-style duplicate notification
            _wait_for(lambda: len(alerts.yara) == 1)
            # Allow enough time for any accidental second scheduled scan.
            time.sleep(0.12)
            assert len(scanner.paths) == 1
            assert len(alerts.yara) == 1
        finally:
            handler.stop()

    def test_large_transfer_routes_through_existing_alert_system(self, monkeypatch):
        db = RecordingDb()
        alerts = RecordingAlerts()
        notifier = RecordingNotifier()
        monkeypatch.setattr(file_auditor, "get_db", lambda: db)
        monkeypatch.setattr(config, "LARGE_TRANSFER_THRESHOLD", 2)
        session = TransferSession("E:\\", alert_system=alerts, notifier=notifier)
        session.device_fp = "test-fingerprint"
        session.description = "Test USB"
        session.record("FILE_CREATED", "E:\\one.txt", 128)
        session.record("FILE_MODIFIED", "E:\\one.txt", 128)

        assert len(alerts.large_transfers) == 1
        assert len(notifier.large_transfers) == 1
        assert sum(event[0][0] == "LARGE_TRANSFER_ALERT" for event in db.events) == 1


class _UsbDevice:
    vendor_id = "1234"
    product_id = "5678"
    serial = "SERIAL123456"
    description = "USB test device"
    drive_letter = "E:"
    instance_id = "USBSTOR\\DISK&VEN_TEST\\SERIAL123456&0"
    disk_id = r"\\.\PHYSICALDRIVE1"
    hid_storage_combo = None

    @property
    def fingerprint(self):
        return "VID_1234&PID_5678&SER_SERIAL123456"


class TestUsbAlertRouting:
    @pytest.mark.parametrize(
        ("spoofed", "badusb", "expected"),
        [
            (False, False, {"violation"}),
            (True, False, {"spoofing", "violation"}),
            (False, True, {"badusb"}),
        ],
    )
    def test_security_usb_events_use_alert_system(
            self, monkeypatch, spoofed, badusb, expected):
        import usb_monitor

        alerts = RecordingAlerts()
        notifier = RecordingNotifier()
        db = RecordingDb()
        device = _UsbDevice()
        monitor = usb_monitor.USBMonitor.__new__(usb_monitor.USBMonitor)
        monitor._connected = {}
        monitor.db = db
        monitor.alert_system = alerts
        monitor.notifier = notifier
        monitor.scorer = SimpleNamespace(
            score_device=lambda candidate: SimpleNamespace(
                score=90 if badusb else 50,
                level="CRITICAL" if badusb else "MEDIUM",
                factors=["test factor"],
                recommendations=["test recommendation"],
            )
        )
        monitor.device_manager = SimpleNamespace(
            is_spoofed_serial=lambda candidate: spoofed,
            is_hid_storage_combo=lambda *args: badusb,
            is_authorized=lambda candidate: False,
        )
        monitor._enumerate_usb_storage = lambda client: [device]
        monkeypatch.setattr(usb_monitor.time, "sleep", lambda seconds: None)
        monkeypatch.setattr(usb_monitor, "block_device", lambda candidate: True)

        monitor._handle_connect(object())

        delivered_types = {entry[0] for entry in alerts.usb}
        assert delivered_types == expected