"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: usb_monitor.py — Real-Time USB Event Detection (Windows/WMI)
===========================================================================
  Uses Windows WMI (Windows Management Instrumentation) to detect USB
  device plug/unplug events in real-time.

  Two WMI queries run as background threads:
    • __InstanceCreationEvent on Win32_USBHub    → device connected
    • __InstanceDeletionEvent on Win32_USBHub    → device disconnected

  For each connect event, we also query:
    • Win32_DiskDrive     → to find storage devices
    • Win32_LogicalDisk   → to find the assigned drive letter

  NOTE: This module only runs on Windows.
        pywin32 (pip install pywin32) is required.
===========================================================================
"""

import threading
import time
import re
from datetime import datetime
from typing import Optional, Callable, List

import config
from logger_setup import event_logger, audit_logger, print_info, print_alert, print_warn
from device_manager import USBDevice, DeviceManager
from blocker import block_device
from file_auditor import FileAuditor

# WMI import is deferred so the module can be imported on non-Windows
# without crashing (useful for testing/development)
try:
    import wmi
    import win32api
    import win32file
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False


# ---------------------------------------------------------------------------
# USB Monitor
# ---------------------------------------------------------------------------

class USBMonitor:
    """
    Main monitoring engine.
    Spawns background threads that watch for WMI USB events.
    Calls device_manager for authorization and blocker if denied.
    """

    def __init__(self):
        self.device_manager = DeviceManager()
        self.file_auditor   = FileAuditor()
        self._running       = False
        self._threads: List[threading.Thread] = []
        # Track currently connected USB devices  {fingerprint: USBDevice}
        self._connected: dict = {}

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------

    def start(self):
        """Start monitoring. Blocks until stop() is called."""
        if not WMI_AVAILABLE:
            print_warn("WMI not available — running in SIMULATION mode.")
            print_warn("Install pywin32:  pip install pywin32")
            self._simulation_mode()
            return

        self._running = True

        # Thread 1: Watch for new USB devices
        t_connect = threading.Thread(
            target=self._watch_connect_events,
            name="USB-Connect-Watcher",
            daemon=True
        )
        # Thread 2: Watch for USB removals
        t_disconnect = threading.Thread(
            target=self._watch_disconnect_events,
            name="USB-Disconnect-Watcher",
            daemon=True
        )

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
        """Gracefully stop all monitoring threads."""
        print_info("Stopping USB monitor...")
        self._running = False
        self.file_auditor.stop_all()
        event_logger.info("USB Monitor stopped.")

    # ------------------------------------------------------------------
    # WMI Event Watchers (private)
    # ------------------------------------------------------------------

    def _watch_connect_events(self):
        """
        Background thread: waits for USB device insertion events.
        WMI sends a notification every time a USB device is plugged in.
        """
        # Each WMI watcher needs its own wmi.WMI() connection
        c = wmi.WMI()
        # Poll for new USB device instances every POLL_INTERVAL seconds
        watcher = c.Win32_USBControllerDevice.watch_for("creation")

        while self._running:
            try:
                # .next() blocks until an event arrives
                event = watcher(timeout_ms=config.POLL_INTERVAL_SECONDS * 1000)
                if event:
                    self._handle_connect(c)
            except wmi.x_wmi_timed_out:
                continue   # No event yet — loop again
            except Exception as e:
                event_logger.error(f"Connect watcher error: {e}")
                time.sleep(2)

    def _watch_disconnect_events(self):
        """
        Background thread: waits for USB device removal events.
        """
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
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_connect(self, c):
        """Called when a new USB device is detected."""
        # Small delay to let Windows assign the drive letter
        time.sleep(1.5)

        # Enumerate all currently connected USB storage devices
        devices = self._enumerate_usb_storage(c)

        for device in devices:
            if device.fingerprint in self._connected:
                continue    # already processed this device

            self._connected[device.fingerprint] = device
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            msg = (f"USB CONNECTED | {device.description} | "
                   f"VID:{device.vendor_id} PID:{device.product_id} | "
                   f"Serial:{device.serial} | Drive:{device.drive_letter} | "
                   f"Time:{timestamp}")
            event_logger.info(msg)
            print_info(msg)

            # --- Spoofing check ---
            if self.device_manager.is_spoofed_serial(device):
                alert_msg = (f"SPOOFING ALERT | Suspicious serial detected: "
                             f"'{device.serial}' on {device.description}")
                print_alert(alert_msg)
                audit_logger.warning(alert_msg)

            # --- Authorization check ---
            authorized = self.device_manager.is_authorized(device)

            if not authorized:
                # Log the violation
                audit_logger.warning(
                    f"UNAUTHORIZED USB | {device.fingerprint} | "
                    f"Drive:{device.drive_letter} | At:{timestamp}"
                )
                # Block the device
                block_device(device)
                return

            # --- Device is authorized: start file auditing ---
            if device.drive_letter:
                self.file_auditor.start_watching(device.drive_letter)

    def _handle_disconnect(self):
        """Called when a USB device is removed."""
        # Re-enumerate to find what's gone
        if WMI_AVAILABLE:
            c = wmi.WMI()
            current = {d.fingerprint for d in self._enumerate_usb_storage(c)}
        else:
            current = set()

        removed = [fp for fp in self._connected if fp not in current]
        for fp in removed:
            device = self._connected.pop(fp)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = (f"USB DISCONNECTED | {device.description} | "
                   f"{fp} | Time:{timestamp}")
            event_logger.info(msg)
            print_info(msg)

            # Stop file auditing for this drive
            if device.drive_letter:
                session = self.file_auditor.stop_watching(device.drive_letter)
                if session:
                    audit_logger.info(
                        f"SESSION SUMMARY | Drive:{device.drive_letter} | "
                        f"Created:{session.files_created} | "
                        f"Deleted:{session.files_deleted} | "
                        f"Modified:{session.files_modified} | "
                        f"Data:~{session.total_bytes//1024}KB"
                    )

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def _enumerate_usb_storage(self, c) -> List[USBDevice]:
        """
        Queries WMI to find all connected USB storage devices and their
        drive letters. Returns a list of USBDevice objects.
        """
        devices = []
        try:
            for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                # Extract VID and PID from the PNP Device ID string
                # Example: USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER&REV_1.27\...
                pnp_id    = disk.PNPDeviceID or ""
                vendor_id, product_id = self._parse_vid_pid(pnp_id)
                serial    = (disk.SerialNumber or "").strip()
                desc      = disk.Model or "Unknown USB Disk"
                instance  = disk.PNPDeviceID or ""

                # Find the drive letter for this physical disk
                drive_letter = self._get_drive_letter(c, disk.DeviceID)

                device = USBDevice(
                    vendor_id    = vendor_id,
                    product_id   = product_id,
                    serial       = serial,
                    description  = desc,
                    drive_letter = drive_letter,
                    instance_id  = instance,
                    connected_at = datetime.now().isoformat()
                )
                devices.append(device)
        except Exception as e:
            event_logger.error(f"WMI enumeration error: {e}")

        return devices

    @staticmethod
    def _parse_vid_pid(pnp_id: str):
        """
        Extracts Vendor ID and Product ID from a Windows PNP Device ID string.
        Example input:  USB\\VID_0781&PID_5567\\...
        Returns: ("0781", "5567")
        """
        vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", pnp_id)
        pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", pnp_id)
        vid = vid_match.group(1).upper() if vid_match else "0000"
        pid = pid_match.group(1).upper() if pid_match else "0000"
        return vid, pid

    @staticmethod
    def _get_drive_letter(c, disk_device_id: str) -> Optional[str]:
        """
        Follows the WMI association chain:
          Win32_DiskDrive → Win32_DiskDriveToDiskPartition
          → Win32_DiskPartition → Win32_LogicalDiskToPartition
          → Win32_LogicalDisk

        Returns the drive letter string (e.g. "E:") or None.
        """
        try:
            for d2p in c.Win32_DiskDriveToDiskPartition():
                if disk_device_id in d2p.Antecedent:
                    for p2l in c.Win32_LogicalDiskToPartition():
                        if d2p.Dependent.split('"')[1] in p2l.Antecedent:
                            logical = p2l.Dependent.split('"')[1]
                            for ld in c.Win32_LogicalDisk(DeviceID=logical):
                                return ld.DeviceID
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Simulation mode (for non-Windows development/testing)
    # ------------------------------------------------------------------

    def _simulation_mode(self):
        """
        Simulates USB events for testing/demo on non-Windows systems.
        Generates fake events every 10 seconds.
        """
        print_warn("=" * 60)
        print_warn("SIMULATION MODE — No real USB monitoring active")
        print_warn("This mode is for testing only (non-Windows or no WMI)")
        print_warn("=" * 60)

        fake_devices = [
            USBDevice("0781", "5567", "4C530001200624116282",
                      "SanDisk Cruzer Blade", "E:", "USB\\VID_0781&PID_5567\\...", datetime.now().isoformat()),
            USBDevice("1234", "5678", "0000000000000000",
                      "Suspicious USB Device", "F:", "USB\\VID_1234&PID_5678\\...", datetime.now().isoformat()),
        ]

        for device in fake_devices:
            print_info(f"[SIM] Device connected: {device.description}")
            if self.device_manager.is_spoofed_serial(device):
                print_alert(f"[SIM] Spoofed serial: {device.serial}")
            authorized = self.device_manager.is_authorized(device)
            if not authorized:
                print_warn(f"[SIM] Would block: {device.description}")
            time.sleep(3)

        print_info("[SIM] Simulation complete.")
