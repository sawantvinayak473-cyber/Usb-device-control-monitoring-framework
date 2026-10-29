"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: usb_monitor.py — Real-Time USB Event Detection (Windows/WMI)
===========================================================================
  ROOT CAUSE FIX — Drive: None / file auditor never starts
  ──────────────────────────────────────────────────────────
  PROBLEM 1: _get_drive_letter() used the same WMI connection `c` that
  was opened when the watcher thread started. This stale connection does
  not reflect the new Win32_LogicalDisk entry that Windows creates when
  it mounts the USB filesystem. No retry mechanism existed, so the
  method returned None every time on a real system.

  PROBLEM 2: _handle_connect() guarded file auditor start with
  `if device.drive_letter:` — since drive_letter was always None,
  the FileAuditor was never started and file events never appeared.

  PROBLEM 3: disk.DeviceID (e.g. "\\\\.\\PHYSICALDRIVE1") was used
  inside _enumerate_usb_storage to call _get_drive_letter but was
  never stored in USBDevice, so a background retry thread had no way
  to poll for the drive letter later.

  THE FIX:
  1. Store disk.DeviceID in device.disk_id (new field in USBDevice).
  2. _get_drive_letter() accepts a fresh WMI connection each call.
  3. After authorization succeeds, spawn _start_file_auditing(device)
     as a daemon thread. It polls for the drive letter with fresh WMI
     connections (up to 15 attempts, 1 s apart), updates device.drive_letter,
     then calls file_auditor.start_watching() with full device metadata.
  4. _handle_disconnect() stops the correct FileAuditor instance using
     the now-populated device.drive_letter.
===========================================================================
"""

import threading
import time
import re
from datetime import datetime
from typing import Optional, List, Dict, Tuple

import config
from logger_setup import event_logger, audit_logger, print_info, print_alert, print_warn
from device_manager import USBDevice, DeviceManager
from blocker import block_device
from file_auditor import FileAuditor
from database import get_db
from threat_engine import ThreatScorer
from alert_system import AlertSystem
from webhook_notifier import get_notifier

try:
    import wmi
    import win32api
    import win32file
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False


class USBMonitor:

    def __init__(self, alert_system: Optional[AlertSystem] = None, notifier=None):
        self.device_manager = DeviceManager()
        self.db             = get_db()
        self.scorer         = ThreatScorer()
        # The file auditor receives this exact queue instance so a YARA
        # detection follows the same safe SMTP path as USB policy events.
        self.alert_system   = alert_system or AlertSystem()
        self.notifier       = notifier or get_notifier()
        self.file_auditor   = FileAuditor(
            alert_system=self.alert_system, notifier=self.notifier)
        self._running       = False
        self._threads: List[threading.Thread] = []
        self._connected: dict = {}   # {fingerprint: USBDevice}

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------

    def start(self):
        self.alert_system.start()
        self.notifier.send_service_started()
        if not WMI_AVAILABLE:
            print_warn("WMI not available — running in SIMULATION mode.")
            print_warn("Install pywin32:  pip install pywin32")
            self._simulation_mode()
            return

        self._running = True
        t_connect    = threading.Thread(target=self._watch_connect_events,
                                        name="USB-Connect-Watcher", daemon=True)
        t_disconnect = threading.Thread(target=self._watch_disconnect_events,
                                        name="USB-Disconnect-Watcher", daemon=True)
        self._threads = [t_connect, t_disconnect]
        for t in self._threads:
            t.start()

        print_info("USB monitoring active. Press Ctrl+C to stop.")
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print_info("Stopping USB monitor...")
        self._running = False
        self.file_auditor.stop_all()
        self.alert_system.stop()
        self.notifier.stop()
        event_logger.info("USB Monitor stopped.")

    # ------------------------------------------------------------------
    # WMI event watchers
    # ------------------------------------------------------------------

    def _watch_connect_events(self):
        c = wmi.WMI()
        watcher = c.Win32_USBControllerDevice.watch_for("creation")
        while self._running:
            try:
                event = watcher(timeout_ms=config.POLL_INTERVAL_SECONDS * 1000)
                if event:
                    self._handle_connect(c)
            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                event_logger.error(f"Connect watcher error: {e}")
                time.sleep(2)

    def _watch_disconnect_events(self):
        c = wmi.WMI()
        watcher = c.Win32_USBControllerDevice.watch_for("deletion")
        while self._running:
            try:
                event = watcher(timeout_ms=config.POLL_INTERVAL_SECONDS * 1000)
                if event:
                    self._handle_disconnect()
            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                event_logger.error(f"Disconnect watcher error: {e}")
                time.sleep(2)

    # ------------------------------------------------------------------
    # Connect handler
    # ------------------------------------------------------------------

    def _handle_connect(self, c):
        """Enumerate new USB storage devices and route them through the pipeline."""
        time.sleep(1.5)   # give Windows time to register the device in WMI
        devices = self._enumerate_usb_storage(c)

        for device in devices:
            if device.fingerprint in self._connected:
                continue

            self._connected[device.fingerprint] = device
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            msg = (f"USB CONNECTED | {device.description} | "
                   f"VID:{device.vendor_id} PID:{device.product_id} | "
                   f"Serial:{device.serial} | Drive:{device.drive_letter or 'resolving...'} | "
                   f"Time:{timestamp}")
            event_logger.info(msg)
            print_info(msg)

            self.db.log_event("USB_CONNECTED", device.fingerprint,
                              device.drive_letter, msg, "INFO")

            # Spoofing detection
            if self.device_manager.is_spoofed_serial(device):
                spoof_msg = (f"SPOOFING ALERT | Suspicious serial: "
                             f"'{device.serial}' on {device.description}")
                print_alert(spoof_msg)
                audit_logger.warning(spoof_msg)
                self.db.log_event("SPOOFING_ALERT", device.fingerprint,
                                  device.drive_letter, spoof_msg, "ALERT")
                self.alert_system.send_spoofing_alert(device)
                self.notifier.send_spoofing(device)

            # BadUSB detection needs both a HID interface and a verified PnP
            # relationship to this storage device; a VID/PID match alone is
            # not considered sufficient evidence.
            device.hid_storage_combo = self.device_manager.is_hid_storage_combo(
                device.instance_id, device.vendor_id, device.product_id)

            # Threat scoring
            threat_score = self.scorer.score_device(device)

            if device.hid_storage_combo:
                badusb_msg = (
                    f"BADUSB ALERT | Linked HID (keyboard) + USB Storage interfaces | "
                    f"{device.description} | VID:{device.vendor_id} "
                    f"PID:{device.product_id} | Serial:{device.serial}"
                )
                print_alert(badusb_msg)
                audit_logger.warning(badusb_msg)
                self.db.log_event("BADUSB_HID_COMBO", device.fingerprint,
                                  device.drive_letter, badusb_msg, "CRITICAL")
                self.db.log_device(device, "BLOCKED", threat_score.score,
                                   threat_score.level)
                self.db.log_violation(
                    "BADUSB_HID_COMBO", device, "CRITICAL",
                    "Auto-blocked after verified HID + storage topology match",
                    badusb_msg,
                )
                self.alert_system.send_badusb_alert(device)
                self.notifier.send_badusb(device)
                block_device(device)
                continue

            # Authorization
            authorized = self.device_manager.is_authorized(device)

            if not authorized:
                severity = "CRITICAL" if threat_score.score >= 80 else "WARNING"
                self.db.log_device(device, "BLOCKED",
                                   threat_score.score, threat_score.level)
                self.db.log_violation(
                    "UNAUTHORIZED_ACCESS", device, severity,
                    "Auto-blocked by enforcement engine",
                    f"Score:{threat_score.score} [{threat_score.level}] | "
                    f"Factors: {'; '.join(threat_score.factors[:2])}")
                audit_logger.warning(
                    f"UNAUTHORIZED USB | {device.fingerprint} | "
                    f"Drive:{device.drive_letter} | "
                    f"Score:{threat_score.score} [{threat_score.level}] | "
                    f"At:{timestamp}")
                self.alert_system.send_violation_alert(
                    device, "UNAUTHORIZED_ACCESS", threat_score)
                self.notifier.send_violation(
                    device, "UNAUTHORIZED_ACCESS", threat_score)
                block_device(device)
                continue

            # Authorized path — log device, then spin up file-auditing thread
            self.db.log_device(device, "ALLOWED",
                               threat_score.score, threat_score.level)

            t = threading.Thread(
                target=self._start_file_auditing,
                args=(device,),
                name=f"FileAudit-{device.fingerprint[:20]}",
                daemon=True
            )
            t.start()

    # ------------------------------------------------------------------
    # File-auditing background thread (FIX: drive-letter polling)
    # ------------------------------------------------------------------

    def _start_file_auditing(self, device: USBDevice):
        """
        Background thread per authorized device.

        Polls WMI with a fresh connection each attempt until Windows
        mounts the filesystem and assigns a drive letter (typically
        2-8 seconds after the hardware appears). Then starts the
        FileAuditor for that drive with full device metadata.

        Using a background thread means the monitoring loop is never
        blocked while waiting for Windows to mount the drive.
        """
        MAX_ATTEMPTS = 15   # 15 × 1 s = 15 s maximum wait

        drive = device.drive_letter   # might already be set

        if not drive:
            print_info(f"[FILE AUDITOR] Waiting for drive letter: {device.description} ...")
            for attempt in range(MAX_ATTEMPTS):
                time.sleep(1)
                try:
                    c_fresh = wmi.WMI()   # fresh connection avoids WMI cache
                    drive = self._get_drive_letter(c_fresh, device.disk_id)
                    if drive:
                        # Update the stored device so the disconnect handler
                        # can find and stop the correct FileAuditor instance
                        device.drive_letter = drive
                        if device.fingerprint in self._connected:
                            self._connected[device.fingerprint] = device
                        event_logger.info(
                            f"Drive letter resolved (attempt {attempt + 1}): "
                            f"{drive} for {device.fingerprint}")
                        break
                except Exception as e:
                    event_logger.debug(
                        f"Drive-letter poll attempt {attempt + 1} failed: {e}")

        if not drive:
            event_logger.warning(
                f"[FILE AUDITOR] Drive letter not assigned after {MAX_ATTEMPTS} s "
                f"for {device.fingerprint} — file monitoring disabled for this session.")
            print_warn(
                f"[FILE AUDITOR] No drive letter found for {device.description} "
                f"after {MAX_ATTEMPTS} s. File monitoring skipped.")
            return

        # Start the FileAuditor with full device metadata
        self.file_auditor.start_watching(
            drive,
            device_fp   = device.fingerprint,
            vid         = device.vendor_id,
            pid         = device.product_id,
            serial      = device.serial,
            description = device.description
        )

    # ------------------------------------------------------------------
    # Disconnect handler
    # ------------------------------------------------------------------

    def _handle_disconnect(self):
        """
        Two-pass confirmation prevents false disconnects from non-storage
        USB events (keyboards, hubs, power-management re-enumerations).
        """
        if not self._connected:
            return

        try:
            c1 = wmi.WMI()
            present_1 = {d.fingerprint for d in self._enumerate_usb_storage(c1)}
        except Exception as e:
            event_logger.error(f"Disconnect pass-1 failed: {e}")
            return

        possibly_gone = [fp for fp in self._connected if fp not in present_1]
        if not possibly_gone:
            return

        time.sleep(1.5)   # let the bus settle

        try:
            c2 = wmi.WMI()
            present_2 = {d.fingerprint for d in self._enumerate_usb_storage(c2)}
        except Exception as e:
            event_logger.error(f"Disconnect pass-2 failed: {e}")
            return

        confirmed_gone = [fp for fp in possibly_gone if fp not in present_2]
        if not confirmed_gone:
            event_logger.debug("Transient USB bus event — no disconnect fired.")
            return

        for fp in confirmed_gone:
            device = self._connected.pop(fp, None)
            if not device:
                continue

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = (f"USB DISCONNECTED | {device.description} | "
                   f"{fp} | Time:{timestamp}")
            event_logger.info(msg)
            print_info(msg)

            self.db.log_event("USB_DISCONNECTED", device.fingerprint,
                              device.drive_letter, msg, "INFO")

            if device.drive_letter:
                session = self.file_auditor.stop_watching(device.drive_letter)
                if session:
                    summary = (
                        f"SESSION SUMMARY | Drive:{device.drive_letter} | "
                        f"Created:{session.files_created} | "
                        f"Deleted:{session.files_deleted} | "
                        f"Modified:{session.files_modified} | "
                        f"Moved:{session.files_moved} | "
                        f"Data:~{session.total_bytes // 1024} KB"
                    )
                    audit_logger.info(summary)
                    self.db.log_event("SESSION_ENDED", device.fingerprint,
                                      device.drive_letter, summary, "INFO")

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def _enumerate_usb_storage(self, c) -> List[USBDevice]:
        """
        Enumerate connected USB storage devices with correct VID/PID.
        Stores disk.DeviceID in device.disk_id for drive-letter polling.
        """
        devices    = []
        vid_pid_map = self._build_usb_vid_pid_map(c)

        try:
            for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                disk_pnp  = disk.PNPDeviceID or ""
                disk_dev_id = disk.DeviceID or ""          # e.g. \\.\\PHYSICALDRIVE1
                serial    = (disk.SerialNumber or "").strip().upper()
                desc      = disk.Model or "Unknown USB Disk"

                # Tier 1: PnPEntity map lookup
                key = self._extract_instance_key(disk_pnp, serial)
                vid, pid = "0000", "0000"
                if key and key in vid_pid_map:
                    vid, pid = vid_pid_map[key][:2]

                # Tier 2: direct PNPDeviceID parse
                if vid == "0000":
                    vid, pid = self._parse_vid_pid(disk_pnp)

                # Tier 3: serial string search
                if vid == "0000" and serial:
                    vid, pid = self._search_pnp_by_serial(c, serial)

                if vid == "0000":
                    event_logger.warning(f"Could not resolve VID/PID for: {disk_pnp}")

                # Best-effort drive letter on first attempt (may be None)
                drive_letter = self._get_drive_letter(c, disk_dev_id)

                device = USBDevice(
                    vendor_id    = vid,
                    product_id   = pid,
                    serial       = serial,
                    description  = desc,
                    drive_letter = drive_letter,
                    instance_id  = disk_pnp,      # USBSTOR path for PnP blocking
                    connected_at = datetime.now().isoformat(),
                    disk_id      = disk_dev_id    # stored for drive-letter retry
                )
                devices.append(device)

        except Exception as e:
            event_logger.error(f"WMI enumeration error: {e}")

        return devices

    # ------------------------------------------------------------------
    # VID/PID helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_usb_vid_pid_map(c) -> Dict[str, Tuple[str, str, str]]:
        result: Dict[str, Tuple[str, str, str]] = {}
        try:
            for pnp in c.Win32_PnPEntity():
                raw_did = pnp.DeviceID or ""
                did     = raw_did.upper()
                if not did.startswith("USB\\"):
                    continue
                if "VID_" not in did or "PID_" not in did:
                    continue
                vid_m = re.search(r"VID_([0-9A-Fa-f]{4})", did)
                pid_m = re.search(r"PID_([0-9A-Fa-f]{4})", did)
                if not (vid_m and pid_m):
                    continue
                vid = vid_m.group(1).upper()
                pid = pid_m.group(1).upper()
                segments = did.split("\\")
                if len(segments) >= 3:
                    result[segments[-1]] = (vid, pid, raw_did)
        except Exception as e:
            event_logger.error(f"_build_usb_vid_pid_map error: {e}")
        return result

    @staticmethod
    def _extract_instance_key(usbstor_pnp: str, serial: str) -> str:
        if usbstor_pnp:
            parts = usbstor_pnp.split("\\")
            if len(parts) >= 3:
                raw = parts[-1]
                if "&" in raw:
                    raw = raw.split("&")[0]
                if raw:
                    return raw.upper()
        return (serial or "").strip().upper()

    @staticmethod
    def _search_pnp_by_serial(c, serial: str) -> Tuple[str, str]:
        serial_upper = serial.strip().upper()
        if not serial_upper:
            return "0000", "0000"
        try:
            for pnp in c.Win32_PnPEntity():
                did = (pnp.DeviceID or "").upper()
                if serial_upper not in did:
                    continue
                if "VID_" not in did or "PID_" not in did:
                    continue
                vid_m = re.search(r"VID_([0-9A-Fa-f]{4})", did)
                pid_m = re.search(r"PID_([0-9A-Fa-f]{4})", did)
                if vid_m and pid_m:
                    return vid_m.group(1).upper(), pid_m.group(1).upper()
        except Exception:
            pass
        return "0000", "0000"

    @staticmethod
    def _parse_vid_pid(pnp_id: str) -> Tuple[str, str]:
        vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", pnp_id)
        pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", pnp_id)
        vid = vid_match.group(1).upper() if vid_match else "0000"
        pid = pid_match.group(1).upper() if pid_match else "0000"
        return vid, pid

    @staticmethod
    def _get_drive_letter(c, disk_device_id: str) -> Optional[str]:
        # ROOT CAUSE & FIX
        # -----------------
        # Original code checked:
        #   if disk_device_id not in d2p.Antecedent:  # BUG
        #
        # WMI serialises association references with double-escaped backslashes.
        # disk.DeviceID =  "\\.\\PHYSICALDRIVE1"   (has 4 backslashes)
        # Antecedent   =  "...DeviceID=\"\\\\.\\PHYSICALDRIVE1\""  (has 8)
        # The counts never match -> in-check is always False ->
        # drive letter always returns None -> FileAuditor never starts.
        #
        # METHOD A (primary): WMI DiskIndex + partition.associators()
        #   Extract disk number (integer) from DeviceID with regex,
        #   query Win32_DiskPartition(DiskIndex=N) -- integer compare,
        #   call partition.associators() -- wmi library handles paths.
        #
        # METHOD B (fallback): IOCTL_VOLUME_DISK_EXTENTS via Win32 API
        #   Open each mounted drive letter with CreateFile, send IOCTL,
        #   read VOLUME_DISK_EXTENTS to find which physical disk backs it.
        if not disk_device_id:
            return None

        # Extract disk number: "\\.\\PHYSICALDRIVE1" -> 1
        m = re.search(r'PHYSICALDRIVE(\d+)', disk_device_id, re.IGNORECASE)
        if not m:
            event_logger.debug(
                f"[drive-letter] no PHYSICALDRIVE number in {disk_device_id!r}")
            return None
        disk_num = int(m.group(1))

        # ── Method A: WMI DiskIndex + partition.associators() ────────
        try:
            # DiskIndex is an integer -- no string escaping, no ambiguity.
            for partition in c.Win32_DiskPartition(DiskIndex=disk_num):
                try:
                    # associators() lets the wmi library walk the WMI
                    # association path; we never see raw Antecedent strings.
                    for logical in partition.associators(
                            wmi_association_class=
                            "Win32_LogicalDiskToPartition"):
                        drive_id = logical.DeviceID
                        if drive_id:
                            event_logger.debug(
                                f"[drive-letter WMI] disk {disk_num}"
                                f" -> partition {partition.DeviceID}"
                                f" -> {drive_id}")
                            return drive_id
                except Exception as ae:
                    event_logger.debug(
                        f"[drive-letter WMI] associators error: {ae}")
        except Exception as we:
            event_logger.debug(
                f"[drive-letter WMI] disk {disk_num} failed: {we}")

        # ── Method B: IOCTL_VOLUME_DISK_EXTENTS (pure Win32 fallback) ─
        # Sends IOCTL_VOLUME_DISK_EXTENTS to every mounted drive letter.
        # Windows returns the physical disk number backing each volume.
        # Uses ctypes.Structure so alignment is correct on 32-bit and 64-bit.
        try:
            import ctypes
            import string as _str
            import win32file

            IOCTL_VOLUME_DISK_EXTENTS = 0x00560000

            class _DiskExtent(ctypes.Structure):
                _fields_ = [
                    ("DiskNumber",     ctypes.c_uint32),
                    ("StartingOffset", ctypes.c_int64),
                    ("ExtentLength",   ctypes.c_int64),
                ]

            class _VolumeDiskExtents(ctypes.Structure):
                _fields_ = [
                    ("NumberOfDiskExtents", ctypes.c_uint32),
                    ("Extents",             _DiskExtent * 64),
                ]

            buf_size = ctypes.sizeof(_VolumeDiskExtents)

            for letter in _str.ascii_uppercase:
                unc = "\\\\.\\{}:".format(letter)
                try:
                    h = win32file.CreateFile(
                        unc, 0,
                        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                        None, win32file.OPEN_EXISTING, 0, None)
                    try:
                        raw = win32file.DeviceIoControl(
                            h, IOCTL_VOLUME_DISK_EXTENTS, None, buf_size)
                        if raw and len(raw) >= buf_size:
                            vde = _VolumeDiskExtents.from_buffer_copy(raw)
                            n = min(vde.NumberOfDiskExtents, 64)
                            for i in range(n):
                                if vde.Extents[i].DiskNumber == disk_num:
                                    dl = f"{letter}:"
                                    event_logger.debug(
                                        f"[drive-letter IOCTL]"
                                        f" disk {disk_num} -> {dl}")
                                    return dl
                    finally:
                        win32file.CloseHandle(h)
                except Exception:
                    continue   # drive inaccessible or not yet mounted
        except Exception as ie:
            event_logger.debug(f"[drive-letter IOCTL] failed: {ie}")

        event_logger.debug(f"[drive-letter] not found for disk {disk_num}")
        return None

    # ------------------------------------------------------------------
    # Simulation mode
    # ------------------------------------------------------------------

    def _simulation_mode(self):
        print_warn("=" * 60)
        print_warn("SIMULATION MODE — No real USB monitoring active")
        print_warn("=" * 60)

        fake_devices = [
            USBDevice("0781", "5581", "04014158A56B0F516BC6",
                      "SanDisk Ultra USB 3.0", "E:",
                      "USBSTOR\\DISK&VEN_SANDISK\\04014158A56B0F516BC6&0",
                      datetime.now().isoformat(), disk_id="\\\\.\\PHYSICALDRIVE1"),
            USBDevice("1234", "5678", "0000000000000000",
                      "Suspicious USB Device", "F:",
                      "USBSTOR\\DISK&VEN_GENERIC\\0000000000000000&0",
                      datetime.now().isoformat(), disk_id="\\\\.\\PHYSICALDRIVE2"),
        ]

        for device in fake_devices:
            print_info(f"[SIM] Device connected: {device.description} | "
                       f"VID:{device.vendor_id} PID:{device.product_id} | "
                       f"Serial:{device.serial}")

            self.db.log_event("USB_CONNECTED", device.fingerprint,
                              device.drive_letter,
                              f"[SIM] {device.description}", "INFO")

            if self.device_manager.is_spoofed_serial(device):
                print_alert(f"[SIM] Spoofed serial detected: {device.serial}")

            ts         = self.scorer.score_device(device)
            authorized = self.device_manager.is_authorized(device)

            if not authorized:
                self.db.log_device(device, "BLOCKED", ts.score, ts.level)
                self.db.log_violation("UNAUTHORIZED_ACCESS", device, "WARNING",
                                      "[SIM] Would block", f"Score:{ts.score}")
                print_warn(f"[SIM] BLOCKED: {device.description} "
                           f"(Score:{ts.score} [{ts.level}])")
            else:
                self.db.log_device(device, "ALLOWED", ts.score, ts.level)
                print_info(f"[SIM] ALLOWED: {device.description} "
                           f"(Score:{ts.score} [{ts.level}])")
                if device.drive_letter:
                    self.file_auditor.start_watching(
                        device.drive_letter,
                        device_fp=device.fingerprint,
                        vid=device.vendor_id,
                        pid=device.product_id,
                        serial=device.serial,
                        description=device.description
                    )
            time.sleep(1)

        print_info("[SIM] Simulation complete. Dashboard now shows real data.")
