"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: device_manager.py — Allowlist / Blocklist Engine
===========================================================================
  CHANGE (this release): USBDevice gains a `disk_id` field (default "")
  that stores Win32_DiskDrive.DeviceID (e.g. "\\\\.\\PHYSICALDRIVE1").
  This value is needed by the drive-letter polling thread in usb_monitor.py
  and has a default so all existing call sites remain valid.
===========================================================================
"""

import json
import os
from typing import Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime

import config
from logger_setup import event_logger, audit_logger, print_ok, print_alert, print_blocked


@dataclass
class USBDevice:
    """Holds all identifying information for a connected USB device."""
    vendor_id:    str
    product_id:   str
    serial:       str
    description:  str
    drive_letter: Optional[str]
    instance_id:  str            # USBSTOR path — used by Disable-PnpDevice
    connected_at: str
    disk_id:      str = ""       # Win32_DiskDrive.DeviceID — used for drive-letter polling

    @property
    def fingerprint(self) -> str:
        """Normalized fingerprint: VID_XXXX&PID_XXXX&SER_XXXX (all uppercase)."""
        vid = (self.vendor_id  or "").strip().upper()
        pid = (self.product_id or "").strip().upper()
        ser = (self.serial     or "").strip().upper()
        return f"VID_{vid}&PID_{pid}&SER_{ser}"

    def to_dict(self) -> dict:
        return asdict(self)


class DeviceManager:
    """Loads and queries the allowlist and blocklist JSON files."""

    def __init__(self):
        self.allowlist: dict = self._load_json(
            config.ALLOWLIST_FILE, self._default_allowlist())
        self.blocklist: dict = self._load_json(config.BLOCKLIST_FILE, {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_authorized(self, device: USBDevice) -> bool:
        """
        Field-by-field normalized comparison — not raw string key lookup.
        Case-insensitive, prefix-tolerant, whitespace-tolerant.
        Priority: blocklist → allowlist → default deny.
        """
        norm_vid    = self._normalize_field(device.vendor_id)
        norm_pid    = self._normalize_field(device.product_id)
        norm_serial = self._normalize_field(device.serial)

        # Step 1 — blocklist
        for key, entry in self.blocklist.items():
            if (self._normalize_field(entry.get("vendor_id",  "")) == norm_vid  and
                self._normalize_field(entry.get("product_id", "")) == norm_pid  and
                self._normalize_field(entry.get("serial",     "")) == norm_serial):
                msg = (f"BLOCKLIST HIT | {device.description} | "
                       f"VID:{device.vendor_id} PID:{device.product_id} "
                       f"Serial:{device.serial} | "
                       f"Reason: {entry.get('reason', 'No reason given')}")
                print_blocked(msg)
                audit_logger.warning(msg)
                return False

        # Step 2 — allowlist
        for key, entry in self.allowlist.items():
            if (self._normalize_field(entry.get("vendor_id",  "")) == norm_vid  and
                self._normalize_field(entry.get("product_id", "")) == norm_pid  and
                self._normalize_field(entry.get("serial",     "")) == norm_serial):
                msg = (f"ALLOWLIST HIT | {device.description} | "
                       f"VID:{device.vendor_id} PID:{device.product_id} "
                       f"Owner: {entry.get('owner', 'Unknown')}")
                print_ok(msg)
                event_logger.info(msg)
                return True

        # Step 3 — default deny
        msg = (f"UNKNOWN DEVICE | {device.description} | "
               f"VID:{device.vendor_id} PID:{device.product_id} "
               f"Serial:{device.serial} | Action: BLOCKED (not in allowlist)")
        print_alert(msg)
        audit_logger.warning(msg)
        return False

    def add_to_allowlist(self, device: USBDevice, owner: str = "Unknown"):
        norm_vid    = self._normalize_field(device.vendor_id)
        norm_pid    = self._normalize_field(device.product_id)
        norm_serial = self._normalize_field(device.serial)
        fp          = f"VID_{norm_vid}&PID_{norm_pid}&SER_{norm_serial}"
        self.allowlist[fp] = {
            "description": device.description,
            "vendor_id":   norm_vid,
            "product_id":  norm_pid,
            "serial":      norm_serial,
            "owner":       owner,
            "added_at":    datetime.now().isoformat()
        }
        self._save_json(config.ALLOWLIST_FILE, self.allowlist)
        event_logger.info(f"Added to allowlist: {fp} | Owner: {owner}")

    def add_to_blocklist(self, device: USBDevice, reason: str = "Manually blocked"):
        norm_vid    = self._normalize_field(device.vendor_id)
        norm_pid    = self._normalize_field(device.product_id)
        norm_serial = self._normalize_field(device.serial)
        fp          = f"VID_{norm_vid}&PID_{norm_pid}&SER_{norm_serial}"
        self.blocklist[fp] = {
            "description": device.description,
            "vendor_id":   norm_vid,
            "product_id":  norm_pid,
            "serial":      norm_serial,
            "reason":      reason,
            "blocked_at":  datetime.now().isoformat()
        }
        self._save_json(config.BLOCKLIST_FILE, self.blocklist)
        audit_logger.warning(f"Added to blocklist: {fp} | Reason: {reason}")

    def is_spoofed_serial(self, device: USBDevice) -> bool:
        s = device.serial.strip()
        if not s:                     return True
        if len(set(s.upper())) == 1:  return True   # all same char
        if len(s) < 8:                return True
        return False

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_field(value: str) -> str:
        """
        Strip whitespace, strip known prefixes (serial: / vid_ / pid_),
        convert to uppercase.  Returns "" for None / empty.
        """
        if not value:
            return ""
        v = str(value).strip()
        lower_v = v.lower()
        for prefix in ("serial:", "vid_", "pid_"):
            if lower_v.startswith(prefix):
                v = v[len(prefix):].strip()
                break
        return v.upper()

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
