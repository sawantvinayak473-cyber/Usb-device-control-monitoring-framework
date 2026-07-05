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

# ---------------------------------------------------------------------------
# PATHS — where logs, reports, and the allowlist/blocklist are stored
# ---------------------------------------------------------------------------

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
LOG_DIR         = os.path.join(BASE_DIR, "logs")
REPORT_DIR      = os.path.join(BASE_DIR, "reports")
ALLOWLIST_FILE  = os.path.join(BASE_DIR, "allowlist.json")
BLOCKLIST_FILE  = os.path.join(BASE_DIR, "blocklist.json")
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
