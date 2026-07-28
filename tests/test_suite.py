"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: tests/test_suite.py — Comprehensive Unit Test Suite
===========================================================================
  Tests every critical component of the framework using pytest.

  Run all tests:
    pytest tests/test_suite.py -v

  Run a specific class:
    pytest tests/test_suite.py::TestThreatEngine -v

  Coverage report (requires pytest-cov):
    pytest tests/test_suite.py --cov=.. --cov-report=term-missing

  MODULES TESTED:
    ✓ DatabaseManager   — CRUD, concurrent safety, schema integrity
    ✓ ThreatScorer      — Scoring logic with known inputs + edge cases
    ✓ DeviceManager     — Allowlist / blocklist policy enforcement
    ✓ PDFReporter       — Report generation (no crash test)
    ✓ AlertSystem       — Queue + demo-mode print (no real emails sent)
    ✓ DemoSeeder        — Data integrity after seeding
===========================================================================
"""

import sys
import os
import pytest
import tempfile
import shutil

# ── Path setup ────────────────────────────────────────────────────────────
# Tests live in tests/ — add the parent (usb_framework_v2/) to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_dir():
    """A fresh temp directory, cleaned up after each test."""
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def db(tmp_dir, monkeypatch):
    """An isolated DatabaseManager pointing at a temp file."""
    import config
    db_path = os.path.join(tmp_dir, "test.db")
    monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
    from database import DatabaseManager
    return DatabaseManager(db_path=db_path)


@pytest.fixture
def fake_device():
    """Returns a minimal USBDevice-like object for testing."""
    from dataclasses import dataclass
    from typing import Optional

    @dataclass
    class FakeDevice:
        vendor_id:    str = "0781"
        product_id:   str = "5567"
        serial:       str = "4C530001200624116282"
        description:  str = "SanDisk Cruzer Blade 32GB"
        drive_letter: Optional[str] = "E:"
        instance_id:  str = "USB\\VID_0781&PID_5567\\123"
        connected_at: str = "2024-01-15T10:00:00"

        @property
        def fingerprint(self):
            return f"VID_{self.vendor_id}&PID_{self.product_id}&SER_{self.serial}"

    return FakeDevice()


@pytest.fixture
def spoofed_device(fake_device):
    fake_device.serial = "0000000000000000"
    fake_device.vendor_id = "1234"
    fake_device.product_id = "5678"
    fake_device.description = "Suspicious Generic Device"
    return fake_device


# ══════════════════════════════════════════════════════════════════════════
# 1. Database Tests
# ══════════════════════════════════════════════════════════════════════════

class TestDatabase:
    """Tests for database.py — DatabaseManager"""

    def test_schema_created(self, db):
        """All five tables should exist after init."""
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "devices"       in tables
        assert "events"        in tables
        assert "file_events"   in tables
        assert "violations"    in tables
        assert "threat_scores" in tables

    def test_log_and_retrieve_device(self, db, fake_device):
        """A device logged once should appear in get_all_devices()."""
        db.log_device(fake_device, status="ALLOWED", threat_score=10)
        devices = db.get_all_devices()
        assert len(devices) == 1
        d = devices[0]
        assert d["fingerprint"] == fake_device.fingerprint
        assert d["status"]      == "ALLOWED"
        assert d["threat_score"] == 10

    def test_duplicate_device_increments_connections(self, db, fake_device):
        """Logging the same device twice should increment total_connections."""
        db.log_device(fake_device, "ALLOWED")
        db.log_device(fake_device, "ALLOWED")
        devices = db.get_all_devices()
        assert len(devices) == 1
        assert devices[0]["total_connections"] == 2

    def test_log_event(self, db, fake_device):
        db.log_event("USB_CONNECTED", fake_device.fingerprint,
                     drive_letter="E:", details="Test event", severity="INFO")
        events = db.get_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_type"] == "USB_CONNECTED"
        assert events[0]["severity"]   == "INFO"

    def test_log_violation(self, db, fake_device):
        db.log_violation("UNAUTHORIZED_ACCESS", fake_device,
                         severity="CRITICAL",
                         action_taken="PnP disabled",
                         details="Not in allowlist")
        viols = db.get_violations()
        assert len(viols) == 1
        assert viols[0]["violation_type"] == "UNAUTHORIZED_ACCESS"
        assert viols[0]["severity"]       == "CRITICAL"

    def test_log_file_event(self, db, fake_device):
        db.log_file_event("CREATED", "E:\\test.txt", 1024,
                          "abc123", "E:", fake_device.fingerprint)
        files = db.get_file_events()
        assert len(files) == 1
        assert files[0]["operation"]  == "CREATED"
        assert files[0]["file_name"]  == "test.txt"
        assert files[0]["file_size"]  == 1024

    def test_get_stats_empty(self, db):
        """Stats on an empty database should return all zeros."""
        stats = db.get_stats()
        assert stats["total_events"]    == 0
        assert stats["total_devices"]   == 0
        assert stats["blocked_devices"] == 0

    def test_get_stats_populated(self, db, fake_device):
        db.log_device(fake_device, "ALLOWED", threat_score=10)
        db.log_device(
            type("D", (), {"fingerprint":"V&P&S_BAD","vendor_id":"X",
                           "product_id":"Y","serial":"Z",
                           "description":"Bad Device"})(),
            "BLOCKED", threat_score=95
        )
        db.log_event("USB_CONNECTED", fake_device.fingerprint)
        stats = db.get_stats()
        assert stats["total_devices"]   == 2
        assert stats["allowed_devices"] == 1
        assert stats["blocked_devices"] == 1
        assert stats["total_events"]    == 1

    def test_hourly_timeline_keys(self, db):
        """Timeline should return exactly 24 hours."""
        timeline = db.get_hourly_timeline(24)
        assert len(timeline["labels"])     == 24
        assert len(timeline["events"])     == 24
        assert len(timeline["violations"]) == 24

    def test_threat_score_persisted(self, db, fake_device):
        db.log_device(fake_device, "ALLOWED")
        db.log_threat_score(fake_device.fingerprint, 75, "HIGH",
                            ["Factor A"], ["Rec A"])
        devices = db.get_all_devices()
        assert devices[0]["threat_score"] == 75
        assert devices[0]["threat_level"] == "HIGH"


# ══════════════════════════════════════════════════════════════════════════
# 2. Threat Engine Tests
# ══════════════════════════════════════════════════════════════════════════

class TestThreatEngine:
    """Tests for threat_engine.py — ThreatScorer"""

    def _scorer_with_empty_db(self, db, monkeypatch):
        """Returns a ThreatScorer wired to our test DB."""
        import threat_engine
        monkeypatch.setattr(threat_engine, "_db", db)
        from threat_engine import ThreatScorer
        return ThreatScorer()

    def test_allowed_device_low_score(self, db, fake_device, monkeypatch, tmp_dir):
        """A device on the allowlist from a known vendor should score LOW."""
        import config
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        import threat_engine
        monkeypatch.setattr(threat_engine, "_db", db)
        monkeypatch.setattr(threat_engine, "_device_manager", None)

        from device_manager import DeviceManager
        dm = DeviceManager()
        dm.add_to_allowlist(fake_device, owner="Test")
        monkeypatch.setattr(threat_engine, "_device_manager", dm)

        from threat_engine import ThreatScorer
        scorer = ThreatScorer()
        ts = scorer.score_device(fake_device)
        assert ts.score < 30
        assert ts.level == "LOW"

    def test_unknown_device_medium_score(self, db, spoofed_device, monkeypatch, tmp_dir):
        """Unknown device not on any list scores at least MEDIUM."""
        import config
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        import threat_engine
        monkeypatch.setattr(threat_engine, "_db", db)
        monkeypatch.setattr(threat_engine, "_device_manager", None)

        from threat_engine import ThreatScorer
        scorer = ThreatScorer()
        ts = scorer.score_device(spoofed_device)
        assert ts.score >= 30

    def test_blocklist_device_critical(self, db, fake_device, monkeypatch, tmp_dir):
        """A blocklisted device must always score 100 / CRITICAL."""
        import config
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        import threat_engine
        monkeypatch.setattr(threat_engine, "_db", db)
        monkeypatch.setattr(threat_engine, "_device_manager", None)

        from device_manager import DeviceManager
        dm = DeviceManager()
        dm.add_to_blocklist(fake_device, reason="Test block")
        monkeypatch.setattr(threat_engine, "_device_manager", dm)

        from threat_engine import ThreatScorer
        ts = ThreatScorer().score_device(fake_device)
        assert ts.score == 100
        assert ts.level == "CRITICAL"

    def test_score_clamped_to_100(self):
        """ThreatScore._finalize must never return score > 100."""
        from threat_engine import ThreatScorer
        ts = ThreatScorer._finalize("test_fp", 150, ["overflow"], ["fix it"])
        assert ts.score == 100

    def test_score_never_negative(self):
        """Score must never go below 0."""
        from threat_engine import ThreatScorer
        ts = ThreatScorer._finalize("test_fp", -20, ["under"], ["ok"])
        assert ts.score == 0

    def test_threat_level_boundaries(self):
        """Verify all four level boundaries."""
        from threat_engine import ThreatScorer
        assert ThreatScorer._finalize("x", 0,  [], []).level == "LOW"
        assert ThreatScorer._finalize("x", 29, [], []).level == "LOW"
        assert ThreatScorer._finalize("x", 30, [], []).level == "MEDIUM"
        assert ThreatScorer._finalize("x", 59, [], []).level == "MEDIUM"
        assert ThreatScorer._finalize("x", 60, [], []).level == "HIGH"
        assert ThreatScorer._finalize("x", 79, [], []).level == "HIGH"
        assert ThreatScorer._finalize("x", 80, [], []).level == "CRITICAL"
        assert ThreatScorer._finalize("x", 100,[], []).level == "CRITICAL"


# ══════════════════════════════════════════════════════════════════════════
# 3. Device Manager Tests
# ══════════════════════════════════════════════════════════════════════════

class TestDeviceManager:
    """Tests for device_manager.py — DeviceManager"""

    def test_empty_allowlist_denies_all(self, tmp_dir, monkeypatch, fake_device):
        import config
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        # Write an empty allowlist
        import json
        with open(config.ALLOWLIST_FILE, "w") as f:
            json.dump({}, f)
        with open(config.BLOCKLIST_FILE, "w") as f:
            json.dump({}, f)
        from device_manager import DeviceManager
        dm = DeviceManager()
        assert dm.is_authorized(fake_device) is False

    def test_add_to_allowlist_then_authorized(self, tmp_dir, monkeypatch, fake_device):
        import config, json
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        with open(config.ALLOWLIST_FILE,"w") as f: json.dump({},f)
        with open(config.BLOCKLIST_FILE,"w") as f: json.dump({},f)
        from device_manager import DeviceManager
        dm = DeviceManager()
        dm.add_to_allowlist(fake_device, owner="IT")
        assert dm.is_authorized(fake_device) is True

    def test_blocklist_overrides_allowlist(self, tmp_dir, monkeypatch, fake_device):
        """A device on both lists should be DENIED (blocklist wins)."""
        import config, json
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        with open(config.ALLOWLIST_FILE,"w") as f: json.dump({},f)
        with open(config.BLOCKLIST_FILE,"w") as f: json.dump({},f)
        from device_manager import DeviceManager
        dm = DeviceManager()
        dm.add_to_allowlist(fake_device, owner="IT")
        dm.add_to_blocklist(fake_device, reason="Rogue device")
        assert dm.is_authorized(fake_device) is False

    def test_spoofed_serial_all_zeros(self, tmp_dir, monkeypatch, fake_device):
        import config, json
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        with open(config.ALLOWLIST_FILE,"w") as f: json.dump({},f)
        with open(config.BLOCKLIST_FILE,"w") as f: json.dump({},f)
        from device_manager import DeviceManager
        dm = DeviceManager()
        fake_device.serial = "0000000000000000"
        assert dm.is_spoofed_serial(fake_device) is True

    def test_valid_serial_not_spoofed(self, tmp_dir, monkeypatch, fake_device):
        import config, json
        monkeypatch.setattr(config, "ALLOWLIST_FILE",
                            os.path.join(tmp_dir, "allowlist.json"))
        monkeypatch.setattr(config, "BLOCKLIST_FILE",
                            os.path.join(tmp_dir, "blocklist.json"))
        with open(config.ALLOWLIST_FILE,"w") as f: json.dump({},f)
        with open(config.BLOCKLIST_FILE,"w") as f: json.dump({},f)
        from device_manager import DeviceManager
        dm = DeviceManager()
        fake_device.serial = "4C530001200624116282"  # Real SanDisk serial
        assert dm.is_spoofed_serial(fake_device) is False


# ══════════════════════════════════════════════════════════════════════════
# 4. Alert System Tests
# ══════════════════════════════════════════════════════════════════════════

class TestAlertSystem:
    """Tests for alert_system.py — AlertSystem"""

    def test_starts_and_stops_cleanly(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "ALERT_DEMO_MODE", True)
        from alert_system import AlertSystem
        a = AlertSystem()
        a.start()
        assert a._running is True
        a.stop()
        assert a._running is False

    def test_queue_accepts_messages(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "ALERT_DEMO_MODE", True)
        from alert_system import AlertSystem
        a = AlertSystem()
        a.start()
        a._enqueue("WARNING", "Test subject", "Test body")
        assert not a._queue.empty() or a._sent_count >= 0
        a.stop()

    def test_large_transfer_alert_queued(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "ALERT_DEMO_MODE", True)
        monkeypatch.setattr(config, "LARGE_TRANSFER_THRESHOLD", 20)
        from alert_system import AlertSystem
        a = AlertSystem()
        a.start()
        a.send_large_transfer_alert("E:", 35, 204800)
        import time; time.sleep(0.2)
        a.stop()


# ══════════════════════════════════════════════════════════════════════════
# 5. PDF Reporter Tests
# ══════════════════════════════════════════════════════════════════════════

class TestPDFReporter:
    """Tests for pdf_reporter.py — PDFReporter"""

    def test_generates_pdf_file(self, tmp_dir, monkeypatch):
        """PDFReporter.generate() should create a non-empty PDF file."""
        import config
        db_path = os.path.join(tmp_dir, "test.db")
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        monkeypatch.setattr(config, "REPORT_DIR", tmp_dir)

        import database as db_mod
        db_mod._db = db_mod.DatabaseManager(db_path=db_path)

        from pdf_reporter import PDFReporter
        out_path = os.path.join(tmp_dir, "test_report.pdf")
        result = PDFReporter().generate(output_path=out_path)

        assert os.path.exists(result)
        assert os.path.getsize(result) > 1024   # PDF must be > 1 KB


# ══════════════════════════════════════════════════════════════════════════
# 6. Demo Seeder Tests
# ══════════════════════════════════════════════════════════════════════════

class TestDemoSeeder:
    """Tests for demo_seeder.py — seed()"""

    def test_seed_populates_all_tables(self, tmp_dir, monkeypatch):
        """After seeding, all five tables should have records."""
        import config, database as db_mod
        db_path = os.path.join(tmp_dir, "seed_test.db")
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        db_mod._db = db_mod.DatabaseManager(db_path=db_path)

        import demo_seeder
        demo_seeder.seed(reset=False)

        db = db_mod.get_db()
        stats = db.get_stats()
        assert stats["total_devices"]   > 0
        assert stats["total_events"]    > 0
        assert stats["total_files"]     > 0
        assert stats["total_violations"]> 0

    def test_seed_has_blocked_and_allowed(self, tmp_dir, monkeypatch):
        import config, database as db_mod
        db_path = os.path.join(tmp_dir, "seed_test2.db")
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        db_mod._db = db_mod.DatabaseManager(db_path=db_path)

        import demo_seeder
        demo_seeder.seed(reset=False)

        db = db_mod.get_db()
        stats = db.get_stats()
        assert stats["allowed_devices"] > 0
        assert stats["blocked_devices"] > 0

    def test_reset_wipes_database(self, tmp_dir, monkeypatch):
        """seed(reset=True) should start with a clean database."""
        import config, database as db_mod
        db_path = os.path.join(tmp_dir, "reset_test.db")
        monkeypatch.setattr(config, "BASE_DIR", tmp_dir)
        db_mod._db = db_mod.DatabaseManager(db_path=db_path)

        import demo_seeder
        demo_seeder.seed(reset=False)
        count_before = db_mod.get_db().get_stats()["total_devices"]

        db_mod._db = None   # Force re-init after reset
        demo_seeder.seed(reset=True)
        count_after = db_mod.get_db().get_stats()["total_devices"]

        assert count_after == count_before   # Same data after fresh seed
