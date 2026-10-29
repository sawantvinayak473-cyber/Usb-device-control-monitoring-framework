"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: config.py — Central Configuration
===========================================================================
  This file holds ALL settings for the framework in one place.
  As a beginner, this is the FIRST file you should edit to customize
  the tool for your environment.
===========================================================================
"""

import os


def _env_int(name: str, default: int) -> int:
    """Read an integer environment setting without making startup fragile."""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    """Read a floating-point environment setting without making startup fragile."""
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

# ---------------------------------------------------------------------------
# PATHS — where logs, reports, and the allowlist/blocklist are stored
# ---------------------------------------------------------------------------

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
LOG_DIR         = os.path.join(BASE_DIR, "logs")
REPORT_DIR      = os.path.join(BASE_DIR, "reports")
ALLOWLIST_FILE  = os.path.join(BASE_DIR, "allowlist.json")
BLOCKLIST_FILE  = os.path.join(BASE_DIR, "blocklist.json")
YARA_RULES_FILE = os.path.join(BASE_DIR, "yara_rules", "usb_threats.yar")
AUDIT_LOG_FILE  = os.path.join(LOG_DIR,  "usb_audit.log")
EVENT_LOG_FILE  = os.path.join(LOG_DIR,  "usb_events.log")

# ---------------------------------------------------------------------------
# MONITORING SETTINGS
# ---------------------------------------------------------------------------

# How often (seconds) the USB poller checks for new devices
POLL_INTERVAL_SECONDS = 2

# Maximum file size (MB) to hash during auditing. Files larger than this
# are still logged, but won't be hashed (saves CPU time).
MAX_HASH_SIZE_MB = 100

# If a single file transfer copies more than this many files, raise alert
LARGE_TRANSFER_THRESHOLD = 20

# Optional YARA scanning for files created or modified on monitored USB
# volumes. The framework remains operational when yara-python is not installed.
YARA_ENABLED = os.getenv("USB_YARA_ENABLED", "true").strip().lower() not in {
    "0", "false", "no", "off"
}
YARA_MAX_FILE_SIZE_MB = _env_int("USB_YARA_MAX_FILE_SIZE_MB", 50)

# Real-time file events often arrive before a copy operation has finished.
# The file auditor coalesces those events and samples size/mtime until the
# file remains unchanged for this interval before passing it to YARA.  The
# worker is separate from watchdog, so these waits never block USB event
# handling.
YARA_DEBOUNCE_SECONDS = max(0.0, _env_float("USB_YARA_DEBOUNCE_SECONDS", 0.75))
YARA_STABILITY_SECONDS = max(0.0, _env_float("USB_YARA_STABILITY_SECONDS", 0.75))
YARA_STABILITY_TIMEOUT_SECONDS = max(
    YARA_STABILITY_SECONDS,
    _env_float("USB_YARA_STABILITY_TIMEOUT_SECONDS", 30.0),
)
YARA_RETRY_SECONDS = max(0.1, _env_float("USB_YARA_RETRY_SECONDS", 1.0))
YARA_MAX_RETRIES = max(0, _env_int("USB_YARA_MAX_RETRIES", 2))

# ---------------------------------------------------------------------------
# BLOCKING SETTINGS
# ---------------------------------------------------------------------------

# Set to True to ACTUALLY block devices. Set False to run in "monitor only"
# mode (logs everything but never blocks — good for testing).
ENFORCEMENT_MODE = True

# When True, the framework will disable the entire USB Storage service
# (USBSTOR) for unauthorized devices instead of per-device blocking.
# WARNING: This blocks ALL USB drives, not just the unauthorized one.
BLOCK_VIA_USBSTOR_SERVICE = False

# ---------------------------------------------------------------------------
# ALERT SETTINGS
# ---------------------------------------------------------------------------

# Print colored alerts to the terminal
CONSOLE_ALERTS = True

# Write every event to the log file
FILE_LOGGING = True

# ---------------------------------------------------------------------------
# REPORT SETTINGS
# ---------------------------------------------------------------------------

REPORT_TITLE    = "USB Security Audit Report"
ORGANIZATION    = "Your Organization Name"   # <-- CHANGE THIS

# ---------------------------------------------------------------------------
# SEVERITY LEVELS  (used in logs and reports)
# ---------------------------------------------------------------------------

SEV_INFO    = "INFO"
SEV_WARNING = "WARNING"
SEV_ALERT   = "ALERT"
SEV_BLOCKED = "BLOCKED"

# ------------------------------------------------------------
# DASHBOARD SETTINGS
# ------------------------------------------------------------

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = True
# ==========================================================================
#  v2.0 SETTINGS  (added to complete integration)
# ==========================================================================


# Alert / Email system
ALERT_DEMO_MODE = os.getenv(
    "USB_ALERT_DEMO_MODE", "true"
).strip().lower() in {"1", "true", "yes", "on"}

SMTP_HOST = os.getenv("USB_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = _env_int("USB_SMTP_PORT", 587)
SMTP_USE_TLS = True

SMTP_USER = os.getenv("USB_SMTP_USER", "")
SMTP_PASS = os.getenv("USB_SMTP_PASS", "")
SMTP_FROM = os.getenv("USB_SMTP_FROM", SMTP_USER)
SMTP_TO = os.getenv("USB_SMTP_TO", "")

# Queue-level protection in addition to source-specific de-duplication.  It
# prevents a transient duplicate USB / filesystem event from becoming a burst
# of identical email while allowing a genuinely changed file to raise a new
# detection.
ALERT_DEDUP_SECONDS = max(0, _env_int("USB_ALERT_DEDUP_SECONDS", 300))

# ── Optional Slack / Telegram webhooks ────────────────────────────────────
# Keep credentials out of source control by supplying them as environment
# variables.  Each configured channel is independent of the other.
WEBHOOK_ENABLED = os.getenv("USB_WEBHOOK_ENABLED", "false").strip().lower() in {
    "1", "true", "yes", "on"
}
SLACK_WEBHOOK_URL  = os.getenv("USB_SLACK_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("USB_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("USB_TELEGRAM_CHAT_ID", "")
WEBHOOK_TIMEOUT_SECONDS = _env_float("USB_WEBHOOK_TIMEOUT_SECONDS", 8.0)
WEBHOOK_DEDUP_SECONDS   = _env_int("USB_WEBHOOK_DEDUP_SECONDS", 60)

# ── Threat scoring thresholds ──────────────────────────────────────────────
THREAT_LOW_MAX    = 29   # 0–29   = LOW
THREAT_MEDIUM_MAX = 59   # 30–59  = MEDIUM
THREAT_HIGH_MAX   = 79   # 60–79  = HIGH
                          # 80–100 = CRITICAL

# ── Database ───────────────────────────────────────────────────────────────
DATABASE_FILE = None      # None = auto (BASE_DIR/usb_security.db)

# ── Windows Service ────────────────────────────────────────────────────────
SERVICE_NAME        = "USBSecurityMonitor"
SERVICE_DISPLAY     = "USB Device Control & Monitoring Framework"
SERVICE_DESCRIPTION = "Real-time USB device detection, blocking, and file auditing."
