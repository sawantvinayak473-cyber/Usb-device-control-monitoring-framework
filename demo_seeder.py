"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: demo_seeder.py — Realistic Demo Data Generator
===========================================================================
  Populates usb_security.db with realistic sample data so the dashboard
  and PDF report look fully operational during a demo or submission.

  Generates:
    • 14 USB device records  (8 allowed, 3 blocked, 2 suspicious, 1 unknown)
    • 180 event records      (spread across last 24 hours realistically)
    • 95 file event records  (realistic filenames, sizes, SHA-256s)
    • 12 violation records   (unauthorized access, spoofing, large transfers)
    • Threat scores for all devices

  Run this ONCE before opening the dashboard:
    python demo_seeder.py

  Run with --reset to wipe existing data first:
    python demo_seeder.py --reset
===========================================================================
"""

import sys
import os
import random
import hashlib
import sqlite3
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from database import get_db


# ── Sample device definitions ─────────────────────────────────────────────

DEVICES = [
    # (vendor_id, product_id, serial, description, status, threat_score, threat_level)
    ("0781", "5567", "4C530001200624116282", "SanDisk Cruzer Blade 32GB",   "ALLOWED",    8,  "LOW"),
    ("0951", "1666", "001CC07C121A9261D498", "Kingston DataTraveler 64GB",   "ALLOWED",   12,  "LOW"),
    ("04E8", "61F5", "0000000000000FE21A88", "Samsung BAR Plus 128GB",       "ALLOWED",   15,  "LOW"),
    ("0BC2", "AB24", "NA8BR04A",             "Seagate Backup Plus Slim",     "ALLOWED",   10,  "LOW"),
    ("0781", "5581", "4C530012600601124130", "SanDisk Ultra USB 3.0 64GB",   "ALLOWED",    5,  "LOW"),
    ("059F", "10C8", "575843413933383138",   "LaCie Rugged USB-C 1TB",       "ALLOWED",   18,  "LOW"),
    ("0930", "6544", "000000000000000001A2", "Toshiba TransMemory 16GB",     "ALLOWED",   20,  "LOW"),
    ("1908", "0226", "AA00000000000001",     "Verbatim Store N Go 32GB",     "ALLOWED",   22,  "LOW"),
    ("1234", "5678", "0000000000000000",     "Generic USB Mass Storage",     "BLOCKED",  100, "CRITICAL"),
    ("ABCD", "EF01", "0000000000000000",     "Unidentified USB Device",      "BLOCKED",   95, "CRITICAL"),
    ("1A2B", "3C4D", "00000001",             "BadUSB HID Emulator",          "BLOCKED",  100, "CRITICAL"),
    ("058F", "6387", "0",                    "Alcor Micro USB Hub (Spoofed)","SUSPICIOUS",72,  "HIGH"),
    ("0BDA", "0129", "00000000",             "Realtek USB Card Reader",      "SUSPICIOUS",55,  "MEDIUM"),
    ("FFFF", "FFFF", "",                     "Unknown USB Device #14",       "UNKNOWN",   40,  "MEDIUM"),
]

VIOLATIONS = [
    ("UNAUTHORIZED_ACCESS",  "BLOCKED",   "Disable-PnpDevice executed",     9),
    ("UNAUTHORIZED_ACCESS",  "BLOCKED",   "Disable-PnpDevice executed",    10),
    ("UNAUTHORIZED_ACCESS",  "BLOCKED",   "Drive ejected — no admin rights",11),
    ("DEVICE_SPOOFING",      "CRITICAL",  "Device blocked — spoofed serial", 8),
    ("DEVICE_SPOOFING",      "CRITICAL",  "Device blocked — spoofed serial",11),
    ("LARGE_TRANSFER",       "WARNING",   "Transfer alert logged — 34 files",1),
    ("LARGE_TRANSFER",       "WARNING",   "Transfer alert logged — 28 files",5),
    ("BLOCKLIST_HIT",        "CRITICAL",  "Disable-PnpDevice executed",     9),
    ("BLOCKLIST_HIT",        "CRITICAL",  "Disable-PnpDevice executed",    10),
    ("BLOCKLIST_HIT",        "CRITICAL",  "Disable-PnpDevice executed",    11),
    ("RAPID_RECONNECTIONS",  "WARNING",   "Monitoring escalated",           7),
    ("OFF_HOURS_CONNECTION", "WARNING",   "Event logged — after hours",    23),
]

FILE_NAMES = [
    "Q3_Financial_Report.xlsx", "Employee_Database_2024.csv", "ProjectX_Design.pdf",
    "client_contacts.xlsx",     "salary_structure.docx",      "system_backup.zip",
    "network_topology.pdf",     "source_code_v2.zip",         "HR_Records_Nov.xlsx",
    "budget_forecast.xlsx",     "meeting_notes.docx",         "product_roadmap.pptx",
    "security_audit.pdf",       "api_keys.txt",               "deployment_guide.docx",
    "database_dump.sql",        "marketing_plan.pptx",        "invoice_batch.zip",
    "customer_data.csv",        "server_config.xml",          "README.md",
    "sales_nov_2024.xlsx",      "training_material.pptx",     "compliance_doc.pdf",
]

EVENT_TYPES = [
    "USB_CONNECTED", "USB_CONNECTED", "USB_CONNECTED",   # weighted higher
    "USB_DISCONNECTED", "USB_DISCONNECTED",
    "FILE_AUDIT_STARTED", "FILE_AUDIT_ENDED",
    "MONITOR_STARTED", "LARGE_TRANSFER_ALERT",
]


# ── Helpers ───────────────────────────────────────────────────────────────

def _ts(hours_ago: float, jitter_min: int = 0) -> str:
    """Timestamp N hours ago + random jitter in minutes."""
    base = datetime.now() - timedelta(hours=hours_ago)
    base += timedelta(minutes=random.randint(0, jitter_min))
    return base.isoformat()


def _fake_sha256() -> str:
    return hashlib.sha256(
        random.randbytes(32)
    ).hexdigest()


def _fake_fingerprint(vid: str, pid: str, serial: str) -> str:
    return f"VID_{vid}&PID_{pid}&SER_{serial or 'EMPTY'}"


# ── Main seeder ───────────────────────────────────────────────────────────

def seed(reset: bool = False):
    db_path = os.path.join(config.BASE_DIR, "usb_security.db")

    if reset and os.path.exists(db_path):
        os.remove(db_path)
        print("  [RESET] Existing database removed.")

    db = get_db()
    print("  Seeding database with realistic demo data...")

    # ── 1. Devices ─────────────────────────────────────────────────────
    print(f"  → Inserting {len(DEVICES)} device records...")

    class _FakeDevice:
        def __init__(self, vid, pid, serial, desc):
            self.vendor_id    = vid
            self.product_id   = pid
            self.serial       = serial
            self.description  = desc
            self.fingerprint  = _fake_fingerprint(vid, pid, serial)
            self.drive_letter = None

    device_fps = []
    for vid, pid, serial, desc, status, score, level in DEVICES:
        d = _FakeDevice(vid, pid, serial, desc)
        db.log_device(d, status, threat_score=score, threat_level=level)
        device_fps.append((d.fingerprint, status, score))

    # ── 2. Events ──────────────────────────────────────────────────────
    print("  → Inserting 180 event records...")

    severities = {"USB_CONNECTED": "INFO", "USB_DISCONNECTED": "INFO",
                  "FILE_AUDIT_STARTED": "INFO", "FILE_AUDIT_ENDED": "INFO",
                  "MONITOR_STARTED": "INFO", "LARGE_TRANSFER_ALERT": "WARNING"}

    conn = sqlite3.connect(db.db_path)
    conn.execute("PRAGMA journal_mode=WAL")

    # Distribute events realistically — more during business hours
    for i in range(180):
        # Business hours (9-18) get 60% of events
        if random.random() < 0.6:
            hours_ago = random.uniform(0, 9)     # last 9 hours (business day)
        else:
            hours_ago = random.uniform(9, 24)    # older events

        etype = random.choice(EVENT_TYPES)
        fp, status, _ = random.choice(device_fps)
        sev = severities.get(etype, "INFO")
        if status == "BLOCKED":
            sev = "ALERT"
        elif status == "SUSPICIOUS" and random.random() < 0.4:
            sev = "WARNING"

        drives = ["E:", "F:", "G:"]
        conn.execute("""
            INSERT INTO events
                (timestamp, event_type, device_fingerprint,
                 drive_letter, username, details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (_ts(hours_ago, 30), etype, fp,
              random.choice(drives),
              random.choice(["jdoe", "asmith", "mwilson", "System", "hradmin"]),
              f"{etype} on device {fp[:30]}",
              sev))
    conn.commit()

    # ── 3. File events ─────────────────────────────────────────────────
    print("  → Inserting 95 file event records...")

    ops = ["CREATED", "CREATED", "CREATED", "MODIFIED", "DELETED", "MOVED"]
    for i in range(95):
        hours_ago = random.uniform(0, 16)
        fname     = random.choice(FILE_NAMES)
        op        = random.choice(ops)
        size      = random.randint(4096, 52_428_800)   # 4 KB – 50 MB
        fp, _, _  = random.choice(device_fps[:8])       # only allowed devices get files

        conn.execute("""
            INSERT INTO file_events
                (timestamp, operation, file_path, file_name, file_size,
                 sha256, drive_letter, username, device_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (_ts(hours_ago, 20),
              op,
              f"E:\\{random.choice(['Documents','Projects','Backup','Data'])}\\{fname}",
              fname,
              size,
              _fake_sha256(),
              random.choice(["E:", "F:"]),
              random.choice(["jdoe", "asmith", "mwilson"]),
              fp))
    conn.commit()

    # ── 4. Violations ──────────────────────────────────────────────────
    print(f"  → Inserting {len(VIOLATIONS)} violation records...")

    blocked_fps = [fp for fp, st, _ in device_fps if st in ("BLOCKED","SUSPICIOUS","CRITICAL")]

    for vtype, sev, action, hours_ago in VIOLATIONS:
        fp = random.choice(blocked_fps) if blocked_fps else device_fps[-1][0]
        desc = next((d[3] for d in DEVICES
                     if _fake_fingerprint(d[0],d[1],d[2]) == fp), "Unknown Device")
        conn.execute("""
            INSERT INTO violations
                (timestamp, violation_type, device_fingerprint,
                 device_description, severity, action_taken, details, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (_ts(hours_ago, 15), vtype, fp, desc, sev, action,
              f"Automatic detection: {vtype.replace('_',' ').title()}",
              random.choice([0, 0, 1])))
    conn.commit()

    # ── 5. Threat scores history ────────────────────────────────────────
    print("  → Inserting threat score history...")

    for vid, pid, serial, desc, status, score, level in DEVICES:
        fp = _fake_fingerprint(vid, pid, serial)
        factors = []
        if score >= 80:
            factors = ["Device on blocklist", "Spoofed serial detected",
                       "Multiple prior violations"]
        elif score >= 60:
            factors = ["Device not in allowlist", "Suspicious serial number",
                       "Off-hours connection detected"]
        elif score >= 30:
            factors = ["Device not in allowlist", "Unknown vendor ID"]
        else:
            factors = ["Device registered in allowlist",
                       "Recognized reputable vendor"]

        conn.execute("""
            INSERT INTO threat_scores
                (timestamp, device_fingerprint, score, level, factors, recommendations)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (_ts(random.uniform(0, 12)), fp, score, level,
              str(factors),
              '["Review device logs", "Update allowlist if legitimate"]'))
    conn.commit()
    conn.close()

    # Summary
    final_db = get_db()
    stats = final_db.get_stats()
    print("\n  ✓ Demo database seeded successfully!")
    print(f"    Devices    : {stats['total_devices']}")
    print(f"    Events     : {stats['total_events']}")
    print(f"    File Ops   : {stats['total_files']}")
    print(f"    Violations : {stats['total_violations']}")
    print(f"    Blocked    : {stats['blocked_devices']}")
    print(f"    Critical   : {stats['critical_threats']}")
    print(f"\n  Database: {final_db.db_path}")
    print("  Open dashboard: python dashboard/app.py")


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    reset = "--reset" in sys.argv
    seed(reset=reset)
