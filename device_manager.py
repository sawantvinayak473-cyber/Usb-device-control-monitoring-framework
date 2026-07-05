"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: device_manager.py — Allowlist / Blocklist Engine
===========================================================================
  Manages two JSON files:
    • allowlist.json  — devices that are ALWAYS permitted
    • blocklist.json  — devices that are ALWAYS denied

  A "device fingerprint" combines three fields from Windows WMI:
    vendor_id   (e.g. "0781"  — SanDisk)
    product_id  (e.g. "5567"  — Cruzer Blade)
    serial      (e.g. "4C530001..." — unique per physical device)

  Authorization priority:
    1. If on blocklist  → BLOCKED  (even if also on allowlist)
    2. If on allowlist  → ALLOWED
    3. Otherwise        → BLOCKED (default-deny policy)
===========================================================================
"""

import json
import os
from typing import Optional
from dataclasses import dataclass, asdict
from datetime import datetime

import config
from logger_setup import event_logger, audit_logger, print_ok, print_alert, print_blocked


# ---------------------------------------------------------------------------
# Data class — represents one USB device's identity
# ---------------------------------------------------------------------------

@dataclass
class USBDevice:
    """Holds all identifying information for a connected USB device."""
    vendor_id:   str            # 4-char hex, e.g. "0781"
    product_id:  str            # 4-char hex, e.g. "5567"
    serial:      str            # device serial number (may be empty)
    description: str            # human-readable name from Windows
    drive_letter: Optional[str] # e.g. "E:", None if not a storage device
    instance_id:  str           # Windows PnP Instance ID (used for blocking)
    connected_at: str           # ISO timestamp

    @property
    def fingerprint(self) -> str:
        """Unique identifier string: VID_XXXX&PID_XXXX&SER_XXXXXXXX"""
        return f"VID_{self.vendor_id}&PID_{self.product_id}&SER_{self.serial}"

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# DeviceManager — reads/writes allowlist and blocklist
# ---------------------------------------------------------------------------

class DeviceManager:
    """Loads and queries the allowlist and blocklist JSON files."""

    def __init__(self):
        self.allowlist: dict = self._load_json(config.ALLOWLIST_FILE, self._default_allowlist())
        self.blocklist: dict = self._load_json(config.BLOCKLIST_FILE, {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_authorized(self, device: USBDevice) -> bool:
        """
        Returns True if the device is authorized to be used.
        Priority: blocklist check first, then allowlist.
        """
        fp = device.fingerprint

        # Step 1 — Explicit block?
        if fp in self.blocklist:
            entry = self.blocklist[fp]
            msg = (f"BLOCKLIST HIT | {device.description} | "
                   f"VID:{device.vendor_id} PID:{device.product_id} "
                   f"Serial:{device.serial} | Reason: {entry.get('reason','No reason given')}")
            print_blocked(msg)
            audit_logger.warning(msg)
            return False

        # Step 2 — Explicit allow?
        if fp in self.allowlist:
            entry = self.allowlist[fp]
            msg = (f"ALLOWLIST HIT | {device.description} | "
                   f"VID:{device.vendor_id} PID:{device.product_id} "
                   f"Owner: {entry.get('owner','Unknown')}")
            print_ok(msg)
            event_logger.info(msg)
            return True

        # Step 3 — Unknown device → default deny
        msg = (f"UNKNOWN DEVICE | {device.description} | "
               f"VID:{device.vendor_id} PID:{device.product_id} "
               f"Serial:{device.serial} | Action: BLOCKED (not in allowlist)")
        print_alert(msg)
        audit_logger.warning(msg)
        return False

    def add_to_allowlist(self, device: USBDevice, owner: str = "Unknown"):
        """Permanently add a device to the allowlist and save to disk."""
        self.allowlist[device.fingerprint] = {
            "description": device.description,
            "vendor_id":   device.vendor_id,
            "product_id":  device.product_id,
            "serial":      device.serial,
            "owner":       owner,
            "added_at":    datetime.now().isoformat()
        }
        self._save_json(config.ALLOWLIST_FILE, self.allowlist)
        event_logger.info(f"Added to allowlist: {device.fingerprint} | Owner: {owner}")

    def add_to_blocklist(self, device: USBDevice, reason: str = "Manually blocked"):
        """Permanently add a device to the blocklist and save to disk."""
        self.blocklist[device.fingerprint] = {
            "description": device.description,
            "vendor_id":   device.vendor_id,
            "product_id":  device.product_id,
            "serial":      device.serial,
            "reason":      reason,
            "blocked_at":  datetime.now().isoformat()
        }
        self._save_json(config.BLOCKLIST_FILE, self.blocklist)
        audit_logger.warning(f"Added to blocklist: {device.fingerprint} | Reason: {reason}")

    def is_spoofed_serial(self, device: USBDevice) -> bool:
        """
        Basic spoofing detection: serials that are all zeros, very short,
        or contain only repeated characters are suspicious.
        Real devices have unique manufacturer serials (16+ hex chars).
        """
        s = device.serial.strip()
        # Empty serial is suspicious for storage devices
        if not s:
            return True
        # All same character (e.g. "0000000000000000")
        if len(set(s)) == 1:
            return True
        # Very short serial
        if len(s) < 8:
            return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(path: str, default: dict) -> dict:
        if not os.path.exists(path):
            DeviceManager._save_json(path, default)
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            event_logger.error(f"Could not read {path}: {e} — using default")
            return default

    @staticmethod
    def _save_json(path: str, data: dict):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _default_allowlist() -> dict:
        """
        Returns a starter allowlist with one example entry.
        REPLACE this with your own approved devices!
        """
        return {
            "VID_EXAMPLE&PID_EXAMPLE&SER_EXAMPLE": {
                "description": "Example Corporate USB Drive (REPLACE ME)",
                "vendor_id":   "EXAMPLE",
                "product_id":  "EXAMPLE",
                "serial":      "EXAMPLE",
                "owner":       "IT Department",
                "added_at":    datetime.now().isoformat(),
                "note":        "Delete this entry and add your own real devices"
            }
        }
