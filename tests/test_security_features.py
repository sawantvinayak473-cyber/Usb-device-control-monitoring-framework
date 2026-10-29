"""Focused tests for BadUSB detection, optional YARA, and webhooks."""

from types import SimpleNamespace
from urllib.error import URLError

import pytest

import config
from device_manager import DeviceManager
from threat_engine import ThreatScorer
from webhook_notifier import WebhookNotifier
from yara_scanner import YARA_AVAILABLE, YaraScanner


class Entity:
    def __init__(self, device_id, class_guid="", container=""):
        self.DeviceID = device_id
        self.ClassGuid = class_guid
        self.PNPClass = ""
        self.ContainerId = container


class Wmi:
    def __init__(self, entities):
        self.entities = entities

    def Win32_PnPEntity(self):
        return self.entities


class TestBadUsbDetection:
    storage_id = "USBSTOR\\DISK&VEN_TEST\\SERIAL123456&0"
    hid_guid = "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}"

    def test_linked_hid_and_storage_is_detected(self):
        entities = [
            Entity(self.storage_id, container="container-1"),
            Entity("HID\\VID_1234&PID_5678&MI_00\\7&1", self.hid_guid,
                   "container-1"),
        ]
        assert DeviceManager().is_hid_storage_combo(
            self.storage_id, "1234", "5678", Wmi(entities)) is True

    def test_normal_storage_is_not_detected(self):
        assert DeviceManager().is_hid_storage_combo(
            self.storage_id, "1234", "5678", Wmi([Entity(self.storage_id)])) is False

    def test_vid_pid_alone_is_not_enough(self):
        entities = [
            Entity(self.storage_id, container="container-1"),
            Entity("HID\\VID_1234&PID_5678\\7&2", self.hid_guid, "container-2"),
        ]
        assert DeviceManager().is_hid_storage_combo(
            self.storage_id, "1234", "5678", Wmi(entities)) is False

    def test_malformed_instance_is_safe(self):
        assert DeviceManager().is_hid_storage_combo("bad", "", "", Wmi([])) is False

    def test_wmi_failure_is_safe(self):
        class BrokenWmi:
            def Win32_PnPEntity(self):
                raise RuntimeError("unavailable")

        assert DeviceManager().is_hid_storage_combo(
            self.storage_id, "1234", "5678", BrokenWmi()) is False

    def test_verified_combo_scores_critical(self, monkeypatch):
        import threat_engine

        class Manager:
            blocklist = {}
            allowlist = {}

            @staticmethod
            def is_spoofed_serial(device):
                return False

        monkeypatch.setattr(threat_engine, "_device_manager", Manager())
        device = SimpleNamespace(
            fingerprint="test", vendor_id="1234", product_id="5678",
            serial="goodserial", instance_id=self.storage_id,
            hid_storage_combo=True,
        )
        score = ThreatScorer().score_device(device)
        assert (score.score, score.level) == (100, "CRITICAL")


class TestYaraScanner:
    def test_disabled_scanner_is_clean(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "YARA_ENABLED", False)
        scanner = YaraScanner()
        sample = tmp_path / "sample.txt"
        sample.write_text("harmless")
        assert scanner.scan(str(sample)).matched is False

    def test_large_file_is_skipped(self, monkeypatch, tmp_path):
        class Rules:
            called = False

            def match(self, path, timeout):
                self.called = True
                return []

        sample = tmp_path / "large.bin"
        sample.write_bytes(b"x")
        monkeypatch.setattr(config, "YARA_MAX_FILE_SIZE_MB", 0)
        scanner = YaraScanner.__new__(YaraScanner)
        scanner._enabled, scanner._rules = True, Rules()
        assert scanner.scan(str(sample)).matched is False
        assert scanner._rules.called is False

    def test_scan_error_is_contained(self, tmp_path):
        class Rules:
            def match(self, path, timeout):
                raise RuntimeError("scanner error")

        sample = tmp_path / "sample.txt"
        sample.write_text("content")
        scanner = YaraScanner.__new__(YaraScanner)
        scanner._enabled, scanner._rules = True, Rules()
        assert scanner.scan(str(sample)).matched is False

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is optional")
    def test_missing_and_invalid_rules_disable_scanner(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "YARA_ENABLED", True)
        monkeypatch.setattr(config, "YARA_RULES_FILE", str(tmp_path / "missing.yar"))
        assert YaraScanner().is_enabled is False
        invalid = tmp_path / "invalid.yar"
        invalid.write_text("rule malformed { condition: }")
        monkeypatch.setattr(config, "YARA_RULES_FILE", str(invalid))
        assert YaraScanner().is_enabled is False

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python is optional")
    @pytest.mark.parametrize("filename, content, expected_rule", [
        ("sample.exe", b"MZ" + b"x" * 32 + b"PE\x00\x00", "PE_Executable"),
        ("autorun.inf", b"[AutoRun]\nopen=evil.exe", "AutoRun_Infection"),
        ("drop.ps1", b"IEX (New-Object WebClient).DownloadString('x')", "PowerShell_Download_Cradle"),
        ("shell.ps1", b"TCPClient NetworkStream StreamReader", "Reverse_Shell_Indicators"),
        ("encoded.ps1", b"[Convert]::FromBase64String('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB')", "Encoded_Payload"),
    ])
    def test_bundled_rules_detect_threats(self, monkeypatch, tmp_path,
                                           filename, content, expected_rule):
        monkeypatch.setattr(config, "YARA_ENABLED", True)
        scanner = YaraScanner()
        sample = tmp_path / filename
        sample.write_bytes(content)
        assert expected_rule in scanner.scan(str(sample)).rule_names


class TestWebhooks:
    @staticmethod
    def configure(monkeypatch, slack="", token="", chat=""):
        monkeypatch.setattr(config, "WEBHOOK_ENABLED", True)
        monkeypatch.setattr(config, "SLACK_WEBHOOK_URL", slack)
        monkeypatch.setattr(config, "TELEGRAM_BOT_TOKEN", token)
        monkeypatch.setattr(config, "TELEGRAM_CHAT_ID", chat)

    def test_disabled_notifier_does_not_enqueue(self, monkeypatch):
        monkeypatch.setattr(config, "WEBHOOK_ENABLED", False)
        notifier = WebhookNotifier()
        notifier.send_service_started()
        assert notifier._queue.empty()

    def test_slack_and_telegram_delivery(self, monkeypatch):
        self.configure(monkeypatch, "https://slack.invalid/hook", "secret", "42")
        calls = []

        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False

        def fake_open(request_obj, timeout):
            calls.append((request_obj.full_url, timeout))
            return Response()

        import webhook_notifier
        monkeypatch.setattr(webhook_notifier.request, "urlopen", fake_open)
        WebhookNotifier()._deliver("test", "HIGH")
        assert len(calls) == 2
        assert any("slack.invalid" in url for url, _ in calls)
        assert any("api.telegram.org" in url for url, _ in calls)

    def test_missing_credentials_do_not_send(self, monkeypatch):
        self.configure(monkeypatch)
        import webhook_notifier
        monkeypatch.setattr(webhook_notifier.request, "urlopen",
                            lambda *args, **kwargs: pytest.fail("unexpected network call"))
        WebhookNotifier()._deliver("test", "HIGH")

    def test_network_failure_is_contained(self, monkeypatch):
        self.configure(monkeypatch, "https://slack.invalid/hook")
        import webhook_notifier
        def offline(*args, **kwargs):
            raise URLError("offline")
        monkeypatch.setattr(webhook_notifier.request, "urlopen", offline)
        WebhookNotifier()._deliver("test", "HIGH")

    def test_http_failure_is_contained(self, monkeypatch):
        self.configure(monkeypatch, "https://slack.invalid/hook")

        class Response:
            status = 500
            def __enter__(self): return self
            def __exit__(self, *args): return False

        import webhook_notifier
        monkeypatch.setattr(webhook_notifier.request, "urlopen",
                            lambda *args, **kwargs: Response())
        WebhookNotifier()._deliver("test", "HIGH")
