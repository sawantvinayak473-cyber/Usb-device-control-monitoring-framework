"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: reporter.py — Audit Report Generator
===========================================================================
  Reads the log files and generates a formatted text report that can be
  saved as .txt or printed to the terminal.

  Report sections:
    1. Executive Summary     — counts and severity
    2. Device Events         — every USB connect/disconnect
    3. Violations            — unauthorized access attempts
    4. File Transfer Audit   — per-drive file activity
    5. Recommendations       — auto-generated based on findings
===========================================================================
"""

import os
import re
from datetime import datetime
from typing import List, Dict
from collections import defaultdict

import config
from logger_setup import print_info


# ---------------------------------------------------------------------------
# Helper — parse a log file into structured records
# ---------------------------------------------------------------------------

def _parse_log(filepath: str) -> List[Dict]:
    """
    Reads a log file and returns a list of dicts:
    { timestamp, level, message }
    """
    records = []
    if not os.path.exists(filepath):
        return records

    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\s*\]\s+(.+)$"
    )
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pattern.match(line.strip())
                if m:
                    records.append({
                        "timestamp": m.group(1),
                        "level":     m.group(2),
                        "message":   m.group(3)
                    })
    except IOError:
        pass
    return records


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates a full USB audit report from the log files.
    """

    def __init__(self):
        self.event_records = _parse_log(config.EVENT_LOG_FILE)
        self.audit_records = _parse_log(config.AUDIT_LOG_FILE)
        self.generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_path: str = None) -> str:
        """
        Builds the full report string.
        If output_path is given, also saves to that file.
        Returns the report text.
        """
        lines = []
        sep = "=" * 70

        # -------------------------------------------------------------------
        # Header
        # -------------------------------------------------------------------
        lines += [
            sep,
            f"  {config.REPORT_TITLE}",
            f"  Organization : {config.ORGANIZATION}",
            f"  Generated    : {self.generated_at}",
            f"  Framework    : USB Device Control & Monitoring Framework v1.0",
            sep, ""
        ]

        # -------------------------------------------------------------------
        # Section 1: Executive Summary
        # -------------------------------------------------------------------
        connects    = sum(1 for r in self.event_records if "USB CONNECTED"    in r["message"])
        disconnects = sum(1 for r in self.event_records if "USB DISCONNECTED" in r["message"])
        blocked     = sum(1 for r in self.audit_records if "BLOCKLIST HIT"    in r["message"]
                                                        or "UNAUTHORIZED USB" in r["message"])
        allowed     = sum(1 for r in self.audit_records if "ALLOWLIST HIT"    in r["message"])
        spoofed     = sum(1 for r in self.audit_records if "SPOOFING ALERT"   in r["message"])
        large_xfer  = sum(1 for r in self.audit_records if "LARGE TRANSFER"   in r["message"])
        files_made  = sum(1 for r in self.audit_records if "FILE CREATED"     in r["message"])
        files_del   = sum(1 for r in self.audit_records if "FILE DELETED"     in r["message"])

        lines += [
            "SECTION 1 — EXECUTIVE SUMMARY",
            "-" * 40,
            f"  USB Connect Events     : {connects}",
            f"  USB Disconnect Events  : {disconnects}",
            f"  Authorized Devices     : {allowed}",
            f"  Blocked Devices        : {blocked}",
            f"  Spoofing Alerts        : {spoofed}",
            f"  Large Transfer Alerts  : {large_xfer}",
            f"  Files Created on USB   : {files_made}",
            f"  Files Deleted from USB : {files_del}",
            ""
        ]

        # Risk level
        if blocked > 0 or spoofed > 0:
            risk = "HIGH — Unauthorized access or spoofing detected."
        elif large_xfer > 0:
            risk = "MEDIUM — Large file transfers recorded."
        else:
            risk = "LOW — No significant violations detected."
        lines += [f"  Risk Assessment        : {risk}", "", ""]

        # -------------------------------------------------------------------
        # Section 2: USB Device Events
        # -------------------------------------------------------------------
        lines += [
            "SECTION 2 — USB DEVICE EVENTS",
            "-" * 40
        ]
        device_events = [r for r in self.event_records
                         if "USB CONNECTED" in r["message"]
                         or "USB DISCONNECTED" in r["message"]]
        if device_events:
            for r in device_events:
                lines.append(f"  [{r['timestamp']}] {r['message']}")
        else:
            lines.append("  No device events recorded.")
        lines += ["", ""]

        # -------------------------------------------------------------------
        # Section 3: Security Violations
        # -------------------------------------------------------------------
        lines += [
            "SECTION 3 — SECURITY VIOLATIONS",
            "-" * 40
        ]
        violations = [
            r for r in self.audit_records
            if any(kw in r["message"] for kw in
                   ["UNAUTHORIZED", "BLOCKLIST HIT", "SPOOFING", "BLOCKED"])
        ]
        if violations:
            for r in violations:
                lines.append(f"  [{r['timestamp']}] *** {r['message']}")
        else:
            lines.append("  No violations detected.")
        lines += ["", ""]

        # -------------------------------------------------------------------
        # Section 4: File Transfer Audit
        # -------------------------------------------------------------------
        lines += [
            "SECTION 4 — FILE TRANSFER AUDIT",
            "-" * 40
        ]
        file_events = [
            r for r in self.audit_records
            if any(kw in r["message"] for kw in
                   ["FILE CREATED", "FILE DELETED", "FILE MODIFIED",
                    "FILE MOVED", "LARGE TRANSFER", "SESSION SUMMARY"])
        ]
        if file_events:
            for r in file_events:
                tag = "***" if "LARGE" in r["message"] else "   "
                lines.append(f"  [{r['timestamp']}] {tag} {r['message']}")
        else:
            lines.append("  No file transfer events recorded.")
        lines += ["", ""]

        # -------------------------------------------------------------------
        # Section 5: Recommendations
        # -------------------------------------------------------------------
        lines += [
            "SECTION 5 — RECOMMENDATIONS",
            "-" * 40
        ]
        recs = self._generate_recommendations(blocked, spoofed, large_xfer)
        for i, rec in enumerate(recs, 1):
            lines.append(f"  {i}. {rec}")
        lines += ["", sep]
        lines.append("  END OF REPORT")
        lines.append(sep)

        report_text = "\n".join(lines)

        # Save to file
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            print_info(f"Report saved to: {output_path}")

        return report_text

    @staticmethod
    def _generate_recommendations(blocked: int, spoofed: int, large_xfer: int) -> List[str]:
        recs = [
            "Enforce Group Policy to disable USB storage on all non-authorized endpoints.",
            "Deploy this framework as a Windows Service for 24/7 monitoring.",
            "Regularly review and audit the allowlist — remove stale entries.",
            "Store audit logs in a centralized SIEM (e.g. Splunk, Elastic).",
            "Train employees on USB security risks and acceptable use policies.",
        ]
        if blocked > 0:
            recs.insert(0, f"URGENT: {blocked} unauthorized USB device(s) detected. "
                           "Investigate the users/machines involved immediately.")
        if spoofed > 0:
            recs.insert(0, f"CRITICAL: {spoofed} device(s) with suspicious serials detected. "
                           "These may be BadUSB or spoofed hardware — escalate to SOC.")
        if large_xfer > 0:
            recs.insert(0, f"WARNING: {large_xfer} large transfer event(s) detected. "
                           "Review the file lists in Section 4 for data exfiltration signs.")
        return recs
