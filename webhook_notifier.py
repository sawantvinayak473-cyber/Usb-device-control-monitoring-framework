"""Non-blocking Slack and Telegram delivery for USB security events."""

import json
import queue
import threading
import time
from datetime import datetime
from typing import Optional
from urllib import error, request

import config
from logger_setup import audit_logger


class WebhookNotifier:
    """Queue-based optional webhook channel; it never blocks USB handling."""

    def __init__(self):
        self._queue: queue.Queue = queue.Queue(maxsize=100)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        if not config.WEBHOOK_ENABLED or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker,
                                        name="Webhook-Notifier", daemon=True)
        self._thread.start()
        audit_logger.info("Webhook notifier started.")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None

    def send_service_started(self) -> None:
        self._enqueue("service-start", "USB monitoring started", "INFO")

    def send_violation(self, device, violation_type: str, threat_score) -> None:
        message = self._device_message(
            f"USB violation: {violation_type}", device,
            f"Severity: {threat_score.level} ({threat_score.score}/100)\n"
            "Action: Device blocked by enforcement engine.")
        self._enqueue(f"violation:{device.fingerprint}:{violation_type}", message, "CRITICAL")

    def send_badusb(self, device) -> None:
        message = self._device_message(
            "BADUSB HID + Storage detected", device,
            "Severity: CRITICAL\nDetection: linked HID and storage interfaces\n"
            "Action: Device blocked; inspect endpoint for keystroke injection.")
        self._enqueue(f"badusb:{device.fingerprint}", message, "CRITICAL")

    def send_spoofing(self, device) -> None:
        message = self._device_message(
            "USB serial spoofing indicator", device,
            "Severity: CRITICAL\nAction: Device requires investigation.")
        self._enqueue(f"spoofing:{device.fingerprint}", message, "CRITICAL")

    def send_yara_hit(self, file_path: str, rule_names: list[str], severity: str,
                      device_fp: str = "") -> None:
        message = (f"YARA detection\nSeverity: {severity}\nFile: {file_path}\n"
                   f"Rules: {', '.join(rule_names)}\nDevice: {device_fp or 'unknown'}\n"
                   f"Timestamp: {self._timestamp()}")
        self._enqueue(f"yara:{device_fp}:{file_path}:{','.join(rule_names)}", message, severity)

    def send_large_transfer(self, drive_letter: str, file_count: int, total_bytes: int,
                            device_fp: str = "") -> None:
        message = (f"Large USB transfer\nDrive: {drive_letter}\nFiles: {file_count}\n"
                   f"Size: ~{total_bytes // 1024} KB\nDevice: {device_fp or 'unknown'}\n"
                   f"Timestamp: {self._timestamp()}")
        self._enqueue(f"large-transfer:{device_fp}:{drive_letter}", message, "WARNING")

    def _enqueue(self, key: str, message: str, severity: str) -> None:
        if not config.WEBHOOK_ENABLED:
            return
        self.start()
        now = time.monotonic()
        with self._lock:
            previous = self._recent.get(key, 0.0)
            if now - previous < config.WEBHOOK_DEDUP_SECONDS:
                return
            self._recent[key] = now
            if len(self._recent) > 1000:
                cutoff = now - config.WEBHOOK_DEDUP_SECONDS
                self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        try:
            self._queue.put_nowait((message, severity))
        except queue.Full:
            audit_logger.warning("Webhook queue full; notification dropped.")

    def _worker(self) -> None:
        while self._running:
            try:
                message, severity = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._deliver(message, severity)
            except Exception as exc:
                audit_logger.warning(f"Webhook delivery failed: {exc}")
            finally:
                self._queue.task_done()

    def _deliver(self, message: str, severity: str) -> None:
        # URLs/tokens are intentionally never included in logs or messages.
        if config.SLACK_WEBHOOK_URL:
            self._post_json(config.SLACK_WEBHOOK_URL, {
                "text": f"[{severity}] USB Security Framework\n{message}"
            }, "Slack")
        if config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID:
            url = ("https://api.telegram.org/bot" + config.TELEGRAM_BOT_TOKEN +
                   "/sendMessage")
            self._post_json(url, {
                "chat_id": config.TELEGRAM_CHAT_ID,
                "text": f"[{severity}] USB Security Framework\n{message}",
            }, "Telegram")

    @staticmethod
    def _post_json(url: str, payload: dict, channel: str) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data,
                              headers={"Content-Type": "application/json"},
                              method="POST")
        try:
            with request.urlopen(req, timeout=config.WEBHOOK_TIMEOUT_SECONDS) as response:
                if not 200 <= response.status < 300:
                    audit_logger.warning(f"{channel} webhook returned HTTP {response.status}")
        except error.HTTPError as exc:
            audit_logger.warning(f"{channel} webhook returned HTTP {exc.code}")
        except error.URLError as exc:
            audit_logger.warning(f"{channel} webhook network error: {exc.reason}")
        except Exception as exc:
            # Malformed responses and unexpected transport errors are not
            # allowed to escape the optional notification channel.
            audit_logger.warning(f"{channel} webhook delivery error: {exc}")

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _device_message(self, title: str, device, detail: str) -> str:
        return (f"{title}\nDevice: {device.description}\n"
                f"VID/PID: {device.vendor_id}/{device.product_id}\n"
                f"Serial: {device.serial}\n{detail}\nTimestamp: {self._timestamp()}")


_notifier: Optional[WebhookNotifier] = None
_notifier_lock = threading.Lock()


def get_notifier() -> WebhookNotifier:
    global _notifier
    with _notifier_lock:
        if _notifier is None:
            _notifier = WebhookNotifier()
        return _notifier
