"""
=========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: alert_system.py — asynchronous email and console alert engine
=========================================================================

Security producers enqueue alerts here rather than speaking SMTP directly.
That keeps USB/WMI and watchdog callbacks independent of network latency and
gives every channel one place for duplicate suppression and delivery logging.

DEMO MODE prints an alert only.  It is deliberately tracked separately from
successful SMTP delivery so a demo can never be mistaken for a sent email.
"""

import os
import queue
import smtplib
import threading
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable, Optional

import config
from logger_setup import audit_logger, print_alert, print_info


class AlertSystem:
    """Bounded, de-duplicated alert queue with a single SMTP worker."""

    def __init__(self):
        self._queue: queue.Queue = queue.Queue(maxsize=100)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._recent: dict[str, float] = {}

        # _sent_count is retained for compatibility, but now means successful
        # SMTP deliveries only.
        self._sent_count = 0
        self._demo_count = 0
        self._failed_count = 0
        self._dropped_count = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the worker once; calling start repeatedly is harmless."""
        with self._lock:
            if self._running:
                return
            if self._thread and self._thread.is_alive():
                # A just-stopped worker may still be draining its queue.  Do
                # not create a second SMTP sender for the same queue.
                self._running = True
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._worker, name="Alert-Sender", daemon=True)
            self._thread.start()

        mode = ("DEMO MODE (console only)" if config.ALERT_DEMO_MODE else
                f"LIVE MODE (SMTP {config.SMTP_HOST}:{config.SMTP_PORT})")
        print_info(f"Alert system started — {mode}")

    def stop(self, timeout: float = 12.0) -> None:
        """Stop accepting work and give the worker time to drain safely."""
        with self._lock:
            was_running = self._running
            self._running = False
            thread = self._thread

        if thread and thread is not threading.current_thread():
            # The worker exits once the bounded queue is empty.  A single SMTP
            # attempt has a ten-second timeout, hence the modest grace period.
            thread.join(timeout=timeout)

        with self._lock:
            if self._thread and not self._thread.is_alive():
                self._thread = None

        if was_running:
            print_info(
                "Alert system stopped. SMTP deliveries: "
                f"{self._sent_count}; demo alerts: {self._demo_count}; "
                f"failed: {self._failed_count}; dropped: {self._dropped_count}"
            )

    # ------------------------------------------------------------------
    # Public alert methods — used by USBMonitor and FileAuditor
    # ------------------------------------------------------------------

    def send_violation_alert(self, device, violation_type: str, threat_score) -> bool:
        """Queue an unauthorized-device or blocklist violation alert."""
        subject = f"USB VIOLATION | {violation_type} | {device.description}"
        body = self._violation_body(device, violation_type, threat_score)
        return self._enqueue(
            "CRITICAL", subject, body,
            dedup_key=f"violation:{device.fingerprint}:{violation_type}",
        )

    def send_large_transfer_alert(self, drive_letter: str, file_count: int,
                                  total_kb: int, device=None) -> bool:
        """Queue the one-per-session bulk-transfer security alert."""
        subject = (f"USB LARGE TRANSFER | Drive {drive_letter} | "
                   f"{file_count} files (~{total_kb} KB)")
        device_name = getattr(device, "description", "Monitored USB device")
        vendor_id = getattr(device, "vid", getattr(device, "vendor_id", ""))
        product_id = getattr(device, "pid", getattr(device, "product_id", ""))
        serial = getattr(device, "serial", "")
        device_fp = getattr(device, "device_fp", getattr(device, "fingerprint", ""))
        body = (
            "Large Transfer Alert\n"
            f"{'=' * 40}\n"
            f"Severity    : WARNING\n"
            f"Drive       : {drive_letter}\n"
            f"Files       : {file_count}\n"
            f"Size        : ~{total_kb} KB\n"
            f"Device      : {device_name}\n"
            f"VID / PID   : {vendor_id or 'N/A'} / {product_id or 'N/A'}\n"
            f"Serial      : {serial or 'N/A'}\n"
            f"Fingerprint : {device_fp or 'N/A'}\n"
            f"Timestamp   : {self._timestamp()}\n"
            f"User        : {os.environ.get('USERNAME', '?')}\n\n"
            f"This alert fires when file operations reach "
            f"{config.LARGE_TRANSFER_THRESHOLD} on a monitored drive.\n"
            "Action: Review usb_audit.log and the database for the full file list."
        )
        return self._enqueue(
            "WARNING", subject, body,
            dedup_key=f"large-transfer:{device_fp}:{drive_letter}",
        )

    def send_spoofing_alert(self, device) -> bool:
        """Queue an alert for suspicious USB serial-number heuristics."""
        subject = (f"SPOOFING DETECTED | {device.description} | "
                   f"Serial: '{device.serial}'")
        body = (
            "Device Spoofing Alert\n"
            f"{'=' * 40}\n"
            "Severity    : CRITICAL\n"
            f"Device      : {device.description}\n"
            f"Vendor ID   : {device.vendor_id}\n"
            f"Product ID  : {device.product_id}\n"
            f"Serial      : {device.serial}  <- SUSPICIOUS\n"
            f"Timestamp   : {self._timestamp()}\n\n"
            "Legitimate USB manufacturers assign unique, meaningful serials.\n"
            "All-zero / repeated / very short serials can indicate BadUSB or cloning.\n\n"
            "Action: Remove the device and inspect it physically."
        )
        return self._enqueue(
            "CRITICAL", subject, body,
            dedup_key=f"spoofing:{device.fingerprint}",
        )

    def send_badusb_alert(self, device) -> bool:
        """Queue an alert for a verified storage + HID BadUSB-style device."""
        subject = (f"BADUSB DETECTED | {device.description} | "
                   f"VID:{device.vendor_id} PID:{device.product_id}")
        body = (
            "BadUSB / HID + Storage Alert\n"
            f"{'=' * 40}\n"
            "Severity    : CRITICAL\n"
            f"Device      : {device.description}\n"
            f"Vendor ID   : {device.vendor_id}\n"
            f"Product ID  : {device.product_id}\n"
            f"Serial      : {device.serial}\n"
            f"Timestamp   : {self._timestamp()}\n\n"
            "Windows reported linked storage and HID interfaces for this device. "
            "It has been blocked as a possible keystroke-injection device. "
            "Remove it and review the endpoint immediately."
        )
        return self._enqueue(
            "CRITICAL", subject, body,
            dedup_key=f"badusb:{device.fingerprint}",
        )

    def send_yara_alert(self, file_path: str, rule_names: Iterable[str],
                        severity: str, *, drive_letter: str = "",
                        device_fp: str = "", device_description: str = "",
                        vendor_id: str = "", product_id: str = "",
                        serial: str = "", descriptions: Optional[Iterable[str]] = None,
                        categories: Optional[Iterable[str]] = None,
                        detection_key: str = "") -> bool:
        """Queue a detailed YARA threat email from a stable file scan."""
        rules = [str(rule) for rule in rule_names]
        details = [str(detail) for detail in (descriptions or [])]
        kinds = [str(category) for category in (categories or [])]
        sev = (severity or "HIGH").upper()
        basename = os.path.basename(file_path) or file_path
        subject = f"YARA THREAT | {sev} | {basename}"
        body_lines = [
            "YARA File Threat Detected",
            "=" * 40,
            f"Severity    : {sev}",
            f"Timestamp   : {self._timestamp()}",
            f"File        : {file_path}",
            f"Rules       : {', '.join(rules) or 'Unknown'}",
            f"Categories  : {', '.join(kinds) or 'N/A'}",
            f"Details     : {'; '.join(details) or 'N/A'}",
            f"Drive       : {drive_letter or 'N/A'}",
            f"Device      : {device_description or 'Monitored USB device'}",
            f"VID / PID   : {vendor_id or 'N/A'} / {product_id or 'N/A'}",
            f"Serial      : {serial or 'N/A'}",
            f"Fingerprint : {device_fp or 'N/A'}",
            "",
            "Action: Isolate the USB drive and review the file before opening it.",
        ]
        stable_identity = detection_key or (
            f"{os.path.normcase(os.path.abspath(file_path))}:{','.join(rules)}:{sev}"
        )
        return self._enqueue(
            sev, subject, "\n".join(body_lines),
            dedup_key=f"yara:{device_fp}:{stable_identity}",
        )

    # Alias kept readable for integrations that use the longer event name.
    send_yara_threat_alert = send_yara_alert

    def send_service_started_alert(self) -> bool:
        """Queue a service-start confirmation alert."""
        subject = "USB Monitor Service Started"
        body = ("USB Device Control & Monitoring Framework v2.0\n"
                f"Service started at: {self._timestamp()}\n"
                f"Monitoring host   : {os.environ.get('COMPUTERNAME', '?')}\n"
                f"Enforcement mode  : {config.ENFORCEMENT_MODE}")
        return self._enqueue("INFO", subject, body, dedup_key="service-start")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enqueue(self, level: str, subject: str, body: str,
                 dedup_key: Optional[str] = None) -> bool:
        """Add an alert without ever blocking a security-event producer."""
        key = dedup_key or f"{level}:{subject}"
        now = time.monotonic()
        with self._lock:
            if not self._running:
                self._dropped_count += 1
                audit_logger.warning("Alert dropped because the alert system is stopped: %s", subject)
                return False

            cooldown = config.ALERT_DEDUP_SECONDS
            previous = self._recent.get(key)
            if cooldown and previous is not None and now - previous < cooldown:
                audit_logger.debug("Duplicate alert suppressed: %s", subject)
                return False

            try:
                self._queue.put_nowait((level, subject, body))
            except queue.Full:
                self._dropped_count += 1
                audit_logger.warning("Alert queue full — alert dropped: %s", subject)
                return False

            self._recent[key] = now
            if len(self._recent) > 2000:
                cutoff = now - max(cooldown, 60)
                self._recent = {recent_key: when for recent_key, when in self._recent.items()
                                if when >= cutoff}
        return True

    def _worker(self) -> None:
        """Deliver queued alerts until shutdown has drained the queue."""
        while self._running or not self._queue.empty():
            try:
                level, subject, body = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                if config.ALERT_DEMO_MODE:
                    self._demo_print(level, subject)
                    self._demo_count += 1
                    audit_logger.info("[ALERT-DEMO-%s] %s", level, subject)
                elif self._send_smtp(subject, body):
                    self._sent_count += 1
                    audit_logger.info("[ALERT-DELIVERED-%s] %s", level, subject)
                else:
                    self._failed_count += 1
                    audit_logger.error("[ALERT-FAILED-%s] %s", level, subject)
            except Exception as exc:
                # Queue processing must remain alive even if a console/logger
                # integration has a fault.  SMTP errors are handled below.
                self._failed_count += 1
                audit_logger.error("Alert worker error: %s", self._redact_error(exc))
            finally:
                self._queue.task_done()

    @staticmethod
    def _demo_print(level: str, subject: str) -> None:
        icons = {"CRITICAL": "[CRITICAL]", "WARNING": "[WARNING]", "INFO": "[INFO]"}
        print_alert(f"{icons.get(level, '[INFO]')} DEMO ALERT (not emailed): {subject}")

    def _send_smtp(self, subject: str, body: str) -> bool:
        """Send one email, returning False with a safe actionable log on failure."""
        missing = self._missing_smtp_settings()
        if missing:
            audit_logger.error(
                "SMTP delivery skipped: configure %s before enabling live alerts.",
                ", ".join(missing),
            )
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = config.SMTP_FROM
            msg["To"] = config.SMTP_TO
            msg["Subject"] = f"[USB-SECURITY] {subject}"
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as smtp:
                smtp.ehlo()
                if config.SMTP_USE_TLS:
                    smtp.starttls()
                    smtp.ehlo()
                if config.SMTP_USER:
                    smtp.login(config.SMTP_USER, config.SMTP_PASS)
                smtp.send_message(msg)
            return True
        except Exception as exc:
            audit_logger.error(
                "SMTP delivery failed for %s:%s: %s",
                config.SMTP_HOST, config.SMTP_PORT, self._redact_error(exc),
            )
            return False

    @staticmethod
    def _missing_smtp_settings() -> list[str]:
        missing = []
        if not str(config.SMTP_HOST or "").strip():
            missing.append("USB_SMTP_HOST")
        if not str(config.SMTP_FROM or "").strip():
            missing.append("USB_SMTP_FROM")
        if not str(config.SMTP_TO or "").strip():
            missing.append("USB_SMTP_TO")

        # Gmail's SMTP endpoint requires authenticated app-password login.
        # For another SMTP relay, blank credentials remain valid when that
        # relay is intentionally configured for unauthenticated delivery.
        if str(config.SMTP_HOST or "").strip().lower() == "smtp.gmail.com":
            if not str(config.SMTP_USER or "").strip():
                missing.append("USB_SMTP_USER")
            if not str(config.SMTP_PASS or "").strip():
                missing.append("USB_SMTP_PASS")
        elif config.SMTP_USER and not config.SMTP_PASS:
            missing.append("USB_SMTP_PASS")
        return missing

    @staticmethod
    def _redact_error(exc: Exception) -> str:
        """Never let a password from an exceptional transport leak to logs."""
        message = str(exc)
        for secret in (str(config.SMTP_PASS or ""),):
            if secret:
                message = message.replace(secret, "***")
        return message

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _violation_body(device, violation_type: str, ts) -> str:
        factors = "\n  ".join(f"- {factor}" for factor in ts.factors) or "None"
        recommendations = "\n  ".join(f"- {item}" for item in ts.recommendations) or "None"
        return (
            "USB Security Violation\n"
            f"{'=' * 40}\n"
            f"Type        : {violation_type}\n"
            f"Threat Level: {ts.level} (Score {ts.score}/100)\n"
            f"Timestamp   : {AlertSystem._timestamp()}\n\n"
            "Device:\n"
            f"  Name      : {device.description}\n"
            f"  VID / PID : {device.vendor_id} / {device.product_id}\n"
            f"  Serial    : {device.serial}\n"
            f"  Drive     : {device.drive_letter or 'N/A'}\n\n"
            f"Risk Factors:\n  {factors}\n\n"
            f"Recommended Actions:\n  {recommendations}\n"
        )
