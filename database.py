"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: database.py — SQLite Database Engine
===========================================================================
  Replaces plain text logs with a structured SQLite database.

  WHY SQLite?
    • Zero-install, single-file database (usb_security.db)
    • WAL mode = safe concurrent reads (dashboard) + writes (monitor)
    • SQL queries give the dashboard exactly the data it needs instantly
    • Used in production by Firefox, Android, WhatsApp, and many EDR tools

  TABLES:
    devices        → registry of all detected USB devices + current score
    events         → every connect / disconnect / monitor event
    file_events    → every file-level operation on a USB drive
    violations     → security incidents (unauthorized, spoofed, large xfer)
    threat_scores  → historical threat score log per device
===========================================================================
"""

import sqlite3
import os
import json
from datetime import datetime
from contextlib import contextmanager
from typing import List, Dict, Optional

import config


class DatabaseManager:
    """
    Central database access object. One shared instance runs the whole app.
    Get it anywhere by calling: from database import get_db; db = get_db()
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(config.BASE_DIR, "usb_security.db")
        self._init_schema()

    # ──────────────────────────────────────────────────────────────────────
    # Connection context manager
    # ──────────────────────────────────────────────────────────────────────

    @contextmanager
    def _conn(self):
        """Opens a connection, commits on success, rolls back on error."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # concurrent-safe
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ──────────────────────────────────────────────────────────────────────
    # Schema
    # ──────────────────────────────────────────────────────────────────────

    def _init_schema(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint       TEXT    UNIQUE NOT NULL,
                    vendor_id         TEXT    NOT NULL DEFAULT '0000',
                    product_id        TEXT    NOT NULL DEFAULT '0000',
                    serial            TEXT    DEFAULT '',
                    description       TEXT    DEFAULT 'Unknown Device',
                    status            TEXT    DEFAULT 'UNKNOWN',
                    threat_score      INTEGER DEFAULT 0,
                    threat_level      TEXT    DEFAULT 'LOW',
                    first_seen        TEXT,
                    last_seen         TEXT,
                    total_connections INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS events (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT    NOT NULL,
                    event_type        TEXT    NOT NULL,
                    device_fingerprint TEXT,
                    drive_letter      TEXT,
                    username          TEXT    DEFAULT 'System',
                    details           TEXT,
                    severity          TEXT    DEFAULT 'INFO'
                );

                CREATE TABLE IF NOT EXISTS file_events (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT    NOT NULL,
                    operation         TEXT    NOT NULL,
                    file_path         TEXT,
                    file_name         TEXT,
                    file_size         INTEGER DEFAULT 0,
                    sha256            TEXT    DEFAULT '',
                    drive_letter      TEXT,
                    username          TEXT    DEFAULT 'System',
                    device_fingerprint TEXT
                );

                CREATE TABLE IF NOT EXISTS violations (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT    NOT NULL,
                    violation_type    TEXT    NOT NULL,
                    device_fingerprint TEXT,
                    device_description TEXT,
                    severity          TEXT    NOT NULL DEFAULT 'WARNING',
                    action_taken      TEXT,
                    details           TEXT,
                    resolved          INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS threat_scores (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp         TEXT    NOT NULL,
                    device_fingerprint TEXT   NOT NULL,
                    score             INTEGER NOT NULL,
                    level             TEXT    NOT NULL,
                    factors           TEXT,
                    recommendations   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_violations_ts   ON violations(timestamp);
                CREATE INDEX IF NOT EXISTS idx_files_drive     ON file_events(drive_letter);
                CREATE INDEX IF NOT EXISTS idx_devices_fp      ON devices(fingerprint);
            """)

    # ──────────────────────────────────────────────────────────────────────
    # WRITE methods
    # ──────────────────────────────────────────────────────────────────────

    def log_device(self, device, status: str,
                   threat_score: int = 0, threat_level: str = "LOW"):
        """Insert a new device or update its last-seen / status if it exists."""
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO devices
                    (fingerprint, vendor_id, product_id, serial, description,
                     status, threat_score, threat_level, first_seen, last_seen,
                     total_connections)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    status            = excluded.status,
                    threat_score      = excluded.threat_score,
                    threat_level      = excluded.threat_level,
                    last_seen         = excluded.last_seen,
                    total_connections = total_connections + 1
            """, (device.fingerprint, device.vendor_id, device.product_id,
                  device.serial, device.description, status,
                  threat_score, threat_level, now, now))

    def log_event(self, event_type: str, device_fingerprint: str = None,
                  drive_letter: str = None, details: str = None,
                  severity: str = "INFO"):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO events
                    (timestamp, event_type, device_fingerprint, drive_letter,
                     username, details, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), event_type, device_fingerprint,
                  drive_letter, os.environ.get("USERNAME", "System"),
                  details, severity))

    def log_file_event(self, operation: str, file_path: str, size: int,
                       sha256: str, drive_letter: str, device_fp: str = None):
        import ntpath; fname = ntpath.basename(file_path) if file_path else ""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO file_events
                    (timestamp, operation, file_path, file_name, file_size,
                     sha256, drive_letter, username, device_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), operation, file_path, fname,
                  size, sha256, drive_letter,
                  os.environ.get("USERNAME", "System"), device_fp))

    def log_violation(self, violation_type: str, device, severity: str,
                      action_taken: str, details: str = None):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO violations
                    (timestamp, violation_type, device_fingerprint,
                     device_description, severity, action_taken, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), violation_type,
                  device.fingerprint if device else None,
                  device.description if device else "Unknown",
                  severity, action_taken, details))

    def log_threat_score(self, device_fp: str, score: int, level: str,
                         factors: list, recommendations: list):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO threat_scores
                    (timestamp, device_fingerprint, score, level,
                     factors, recommendations)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), device_fp, score, level,
                  json.dumps(factors), json.dumps(recommendations)))
            conn.execute("""
                UPDATE devices SET threat_score=?, threat_level=?
                WHERE fingerprint=?
            """, (score, level, device_fp))

    # ──────────────────────────────────────────────────────────────────────
    # READ methods  (used by dashboard + reporter)
    # ──────────────────────────────────────────────────────────────────────

    def get_recent_events(self, limit: int = 50) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_all_devices(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
            return [dict(r) for r in rows]

    def get_violations(self, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM violations ORDER BY timestamp DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_file_events(self, drive_letter: str = None, limit: int = 200) -> List[Dict]:
        with self._conn() as conn:
            if drive_letter:
                rows = conn.execute(
                    "SELECT * FROM file_events WHERE drive_letter=? "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (drive_letter, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?",
                    (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with self._conn() as conn:
            def n(sql, *a): return conn.execute(sql, a).fetchone()[0]
            return {
                "total_events":       n("SELECT COUNT(*) FROM events"),
                "total_violations":   n("SELECT COUNT(*) FROM violations"),
                "total_files":        n("SELECT COUNT(*) FROM file_events"),
                "blocked_devices":    n("SELECT COUNT(*) FROM devices WHERE status='BLOCKED'"),
                "allowed_devices":    n("SELECT COUNT(*) FROM devices WHERE status='ALLOWED'"),
                "suspicious_devices": n("SELECT COUNT(*) FROM devices WHERE status='SUSPICIOUS'"),
                "unknown_devices":    n("SELECT COUNT(*) FROM devices WHERE status='UNKNOWN'"),
                "critical_threats":   n("SELECT COUNT(*) FROM devices WHERE threat_score>=80"),
                "high_threats":       n("SELECT COUNT(*) FROM devices WHERE threat_score BETWEEN 60 AND 79"),
                "total_devices":      n("SELECT COUNT(*) FROM devices"),
            }

    def get_hourly_timeline(self, hours: int = 24) -> Dict:
        """Hourly event counts for the last N hours — drives the line chart."""
        with self._conn() as conn:
            ev = {r["hr"]: r["cnt"] for r in conn.execute("""
                SELECT strftime('%H', timestamp) hr, COUNT(*) cnt
                FROM events WHERE timestamp >= datetime('now',?)
                GROUP BY hr
            """, (f"-{hours} hours",)).fetchall()}
            vi = {r["hr"]: r["cnt"] for r in conn.execute("""
                SELECT strftime('%H', timestamp) hr, COUNT(*) cnt
                FROM violations WHERE timestamp >= datetime('now',?)
                GROUP BY hr
            """, (f"-{hours} hours",)).fetchall()}
            labels     = [f"{h:02d}:00" for h in range(24)]
            events_arr = [ev.get(f"{h:02d}", 0) for h in range(24)]
            viols_arr  = [vi.get(f"{h:02d}", 0) for h in range(24)]
            return {"labels": labels, "events": events_arr, "violations": viols_arr}

    def get_device_events_count(self, device_fp: str, hours: int = 1) -> int:
        """How many times has this device connected in the last N hours?"""
        with self._conn() as conn:
            return conn.execute("""
                SELECT COUNT(*) FROM events
                WHERE device_fingerprint=? AND event_type='USB_CONNECTED'
                  AND timestamp >= datetime('now',?)
            """, (device_fp, f"-{hours} hours")).fetchone()[0]

    def get_device_violation_count(self, device_fp: str) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM violations WHERE device_fingerprint=?",
                (device_fp,)).fetchone()[0]

    def get_top_threats(self, limit: int = 5) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT * FROM devices
                WHERE threat_score > 0
                ORDER BY threat_score DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ──────────────────────────────────────────────────────────────────────────

_db: Optional[DatabaseManager] = None

def get_db() -> DatabaseManager:
    """Returns the shared DatabaseManager. Creates it on first call."""
    global _db
    if _db is None:
        _db = DatabaseManager()
    return _db
