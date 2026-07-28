"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: alert_system.py — Email & Console Alert Engine
===========================================================================
  Non-blocking alert system using a background thread + queue.
  USB monitoring is never slowed down by network/SMTP latency.

  DEMO MODE  (config.ALERT_DEMO_MODE = True)
    All alerts are printed to the terminal with color formatting.
    No email account or internet connection needed.
    Perfect for demos and college submission.

  LIVE MODE  (config.ALERT_DEMO_MODE = False)
    Alerts are emailed via SMTP. Works with Gmail (app password),
    Outlook, or any corporate mail relay.
===========================================================================
"""

import os
import smtplib
import threading
import queue
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

import config
from logger_setup import audit_logger, print_warn, print_info, print_alert


class AlertSystem:
    """
    Queues alert messages and sends them asynchronously in a daemon thread.
    This design ensures USB event processing is never blocked by SMTP delays.
    """

    def __init__(self):
        self._queue:  queue.Queue = queue.Queue(maxsize=100)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._sent_count = 0

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._thread  = threading.Thread(
            target=self._worker, name="Alert-Sender", daemon=True)
        self._thread.start()
        mode = "DEMO MODE (console only)" if config.ALERT_DEMO_MODE else \
               f"LIVE MODE (SMTP {config.SMTP_HOST}:{config.SMTP_PORT})"
        print_info(f"Alert system started — {mode}")

    def stop(self):
        self._running = False
        print_info(f"Alert system stopped. Total alerts sent: {self._sent_count}")

    # ──────────────────────────────────────────────────────────────────────
    # Public alert methods — call these from usb_monitor / file_auditor
    # ──────────────────────────────────────────────────────────────────────

    def send_violation_alert(self, device, violation_type: str, threat_score):
        """Alert for unauthorized USB access / blocklist hit."""
        subject = f"USB VIOLATION | {violation_type} | {device.description}"
        body    = self._violation_body(device, violation_type, threat_score)
        self._enqueue("CRITICAL", subject, body)

    def send_large_transfer_alert(self, drive_letter: str,
                                   file_count: int, total_kb: int):
        """Alert when bulk file transfer detected (possible data exfiltration)."""
        subject = (f"USB LARGE TRANSFER | Drive {drive_letter} | "
                   f"{file_count} files (~{total_kb} KB)")
        body = (
            f"Large Transfer Alert\n"
            f"{'='*40}\n"
            f"Drive       : {drive_letter}\n"
            f"Files       : {file_count}\n"
            f"Size        : ~{total_kb} KB\n"
            f"Timestamp   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"User        : {os.environ.get('USERNAME','?')}\n\n"
            f"This alert fires when file operations exceed "
            f"{config.LARGE_TRANSFER_THRESHOLD} files on a single drive.\n"
            f"Action: Review usb_audit.log and the database for full file list."
        )
        self._enqueue("WARNING", subject, body)

    def send_spoofing_alert(self, device):
        """Alert when serial number heuristics detect possible BadUSB."""
        subject = (f"SPOOFING DETECTED | {device.description} | "
                   f"Serial: '{device.serial}'")
        body = (
            f"Device Spoofing Alert\n"
            f"{'='*40}\n"
            f"Device      : {device.description}\n"
            f"Vendor ID   : {device.vendor_id}\n"
            f"Product ID  : {device.product_id}\n"
            f"Serial      : {device.serial}  ← SUSPICIOUS\n"
            f"Timestamp   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"Legitimate USB manufacturers assign unique, meaningful serials.\n"
            f"All-zero / repeated / very short serials indicate BadUSB or cloning.\n\n"
            f"Action: Remove device immediately and inspect it physically."
        )
        self._enqueue("CRITICAL", subject, body)

    def send_service_started_alert(self):
        """Confirmation alert sent when the Windows Service starts."""
        subject = "USB Monitor Service Started"
        body    = (f"USB Device Control & Monitoring Framework v2.0\n"
                   f"Service started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                   f"Monitoring host   : {os.environ.get('COMPUTERNAME','?')}\n"
                   f"Enforcement mode  : {config.ENFORCEMENT_MODE}")
        self._enqueue("INFO", subject, body)

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    def _enqueue(self, level: str, subject: str, body: str):
        """Add alert to queue (drops if queue is full to avoid memory pressure)."""
        try:
            self._queue.put_nowait((level, subject, body))
        except queue.Full:
            audit_logger.warning("Alert queue full — alert dropped")

    def _worker(self):
        """Background thread: dequeues and sends alerts one by one."""
        while self._running:
            try:
                level, subject, body = self._queue.get(timeout=2)
                if config.ALERT_DEMO_MODE:
                    self._demo_print(level, subject)
                else:
                    self._send_smtp(subject, body)
                audit_logger.info(f"[ALERT-{level}] {subject}")
                self._sent_count += 1
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                audit_logger.error(f"Alert worker error: {e}")

    def _demo_print(self, level: str, subject: str):
        icons = {"CRITICAL": "🚨", "WARNING": "⚠️ ", "INFO": "📧"}
        icon  = icons.get(level, "📧")
        print_alert(f"{icon} ALERT [{level}]: {subject}")

    def _send_smtp(self, subject: str, body: str) -> bool:
        try:
            msg             = MIMEMultipart()
            msg["From"]     = config.SMTP_FROM
            msg["To"]       = config.SMTP_TO
            msg["Subject"]  = f"[USB-SECURITY] {subject}"
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
                s.ehlo()
                if config.SMTP_USE_TLS:
                    s.starttls()
                if config.SMTP_USER:
                    s.login(config.SMTP_USER, config.SMTP_PASS)
                s.send_message(msg)
            return True
        except Exception as e:
            audit_logger.error(f"SMTP failed: {e}")
            return False

    @staticmethod
    def _violation_body(device, violation_type: str, ts) -> str:
        factors = "\n  ".join(f"• {f}" for f in ts.factors) or "None"
        recs    = "\n  ".join(f"• {r}" for r in ts.recommendations) or "None"
        return (
            f"USB Security Violation\n"
            f"{'='*40}\n"
            f"Type        : {violation_type}\n"
            f"Threat Level: {ts.level} (Score {ts.score}/100)\n"
            f"Timestamp   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"Device:\n"
            f"  Name      : {device.description}\n"
            f"  VID / PID : {device.vendor_id} / {device.product_id}\n"
            f"  Serial    : {device.serial}\n"
            f"  Drive     : {device.drive_letter or 'N/A'}\n\n"
            f"Risk Factors:\n  {factors}\n\n"
            f"Recommended Actions:\n  {recs}\n"
        )
