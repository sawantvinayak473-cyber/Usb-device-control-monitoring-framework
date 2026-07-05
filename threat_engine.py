"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: threat_engine.py — Threat Intelligence & Scoring Engine
===========================================================================
  Assigns every USB device a risk score 0–100 using behavioral signals,
  identity heuristics, and historical database records.

  Score → Level mapping:
     0 – 29   LOW       Clean, registered device
    30 – 59   MEDIUM    Unknown or mildly suspicious
    60 – 79   HIGH      Strong risk indicators present
    80 – 100  CRITICAL  Block immediately, escalate

  This mirrors the risk-scoring logic inside commercial EDR products
  such as CrowdStrike Falcon, SentinelOne, and Microsoft Defender.
===========================================================================
"""

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

import config

# Import lazily to avoid circular-import at startup
_device_manager = None
_db             = None

def _get_dm():
    global _device_manager
    if _device_manager is None:
        from device_manager import DeviceManager
        _device_manager = DeviceManager()
    return _device_manager

def _get_db():
    global _db
    if _db is None:
        from database import get_db
        _db = get_db()
    return _db


# ──────────────────────────────────────────────────────────────────────────
# Output dataclass
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatScore:
    score:           int
    level:           str          # LOW / MEDIUM / HIGH / CRITICAL
    factors:         List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    device_fp:       str = ""

    @property
    def is_high_risk(self) -> bool:
        return self.score >= config.THREAT_HIGH_MAX

    @property
    def color_code(self) -> str:
        return {"LOW": "GREEN", "MEDIUM": "YELLOW",
                "HIGH": "ORANGE", "CRITICAL": "RED"}.get(self.level, "WHITE")

    def summary(self) -> str:
        return (f"Threat Score: {self.score}/100 [{self.level}] | "
                f"Factors: {len(self.factors)} | "
                f"Device: {self.device_fp}")


# ──────────────────────────────────────────────────────────────────────────
# Scoring engine
# ──────────────────────────────────────────────────────────────────────────

class ThreatScorer:
    """
    Multi-factor threat scoring engine.

    Factor weights (each adds to the 0-100 score):
      BLOCKLIST_HIT         → 100  Always critical; skip other checks
      UNKNOWN_DEVICE        →  40  Not in allowlist (default-deny)
      SPOOFED_SERIAL        →  35  BadUSB / cloned hardware indicator
      PREVIOUS_VIOLATIONS   →  15  Per recorded violation (max cap 30)
      RAPID_RECONNECTIONS   →  20  >3 plug-ins in last hour
      OFF_HOURS_CONNECTION  →  10  Connected between 22:00 and 06:00
      KNOWN_SAFE_VENDOR     → -10  Recognized brand reduces suspicion
    """

    _WEIGHTS = {
        "BLOCKLIST_HIT":         100,
        "UNKNOWN_DEVICE":         40,
        "SPOOFED_SERIAL":         35,
        "PREVIOUS_VIOLATIONS":    15,   # multiplied by count, capped at 30
        "RAPID_RECONNECTIONS":    20,
        "OFF_HOURS_CONNECTION":   10,
        "KNOWN_SAFE_VENDOR":     -10,   # negative = reduces score
    }

    # Vendor IDs of well-known, reputable manufacturers
    _SAFE_VIDS = {
        "0781",   # SanDisk
        "0951",   # Kingston Technology
        "0BC2",   # Seagate
        "04E8",   # Samsung Electronics
        "0BDA",   # Realtek Semiconductor
        "046D",   # Logitech
        "05AC",   # Apple Inc.
        "04F2",   # Chicony Electronics
        "058F",   # Alcor Micro (corporate USB hubs)
        "1908",   # IPAS / Verbatim
    }

    def score_device(self, device) -> ThreatScore:
        """
        Main entry point. Pass a USBDevice object, receive a ThreatScore.
        The score is also persisted to the database automatically.
        """
        dm      = _get_dm()
        db      = _get_db()
        score   = 0
        factors = []
        recs    = []

        # ── 1. Blocklist hit (maximum score, skip all other checks) ──
        if device.fingerprint in dm.blocklist:
            return self._finalize(device.fingerprint, 100, [
                "Device is on the permanent blocklist — previously flagged as malicious"
            ], [
                "Immediately remove the device from the endpoint",
                "File an IT security incident report",
                "Interview the user who connected this device",
            ])

        # ── 2. Unknown device — not in allowlist ─────────────────────
        if device.fingerprint not in dm.allowlist:
            w = self._WEIGHTS["UNKNOWN_DEVICE"]
            score += w
            factors.append(
                f"Device not in allowlist — unregistered hardware (+{w})")
            recs.append("Add to allowlist (main menu → Option 4) if legitimate")

        # ── 3. Spoofed / suspicious serial number ────────────────────
        if dm.is_spoofed_serial(device):
            w = self._WEIGHTS["SPOOFED_SERIAL"]
            score += w
            factors.append(
                f"Serial '{device.serial}' is suspicious — all-zero, "
                f"too-short, or repeated characters (BadUSB indicator) (+{w})")
            recs.append("URGENT: Physically inspect device — potential BadUSB attack")

        # ── 4. Prior violations in database ──────────────────────────
        try:
            viols = db.get_device_violation_count(device.fingerprint)
            if viols > 0:
                pts = min(viols * self._WEIGHTS["PREVIOUS_VIOLATIONS"], 30)
                score += pts
                factors.append(
                    f"{viols} prior security violation(s) on record (+{pts})")
                recs.append("Review violation history before allowing access")
        except Exception:
            pass   # DB might not be ready on first run

        # ── 5. Rapid reconnections ────────────────────────────────────
        try:
            reconnects = db.get_device_events_count(device.fingerprint, hours=1)
            if reconnects >= 3:
                w = self._WEIGHTS["RAPID_RECONNECTIONS"]
                score += w
                factors.append(
                    f"Reconnected {reconnects}× in the last hour — "
                    f"abnormal plug/unplug pattern (+{w})")
                recs.append("Investigate repeated plug/unplug behavior")
        except Exception:
            pass

        # ── 6. Off-hours connection ───────────────────────────────────
        hour = datetime.now().hour
        if hour >= 22 or hour < 6:
            w = self._WEIGHTS["OFF_HOURS_CONNECTION"]
            score += w
            factors.append(
                f"Connected outside business hours ({hour:02d}:xx) (+{w})")
            recs.append("Confirm whether after-hours USB access is authorised")

        # ── 7. Known-safe vendor (reduces score) ──────────────────────
        if device.vendor_id.upper() in self._SAFE_VIDS:
            w = self._WEIGHTS["KNOWN_SAFE_VENDOR"]   # negative
            score += w
            factors.append(
                f"Vendor ID {device.vendor_id} belongs to a known "
                f"reputable manufacturer ({w})")

        # ── Clamp, level, persist ─────────────────────────────────────
        score = max(0, min(100, score))
        if not recs:
            recs.append("No immediate action required — continue standard monitoring")

        return self._finalize(device.fingerprint, score, factors, recs)

    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _finalize(fp: str, score: int, factors: list, recs: list) -> ThreatScore:
        level = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 30 else
            "LOW"
        )
        ts = ThreatScore(score=score, level=level,
                         factors=factors, recommendations=recs, device_fp=fp)
        try:
            _get_db().log_threat_score(fp, score, level, factors, recs)
        except Exception:
            pass   # Never let DB errors crash the monitor
        return ts
