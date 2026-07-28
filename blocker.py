r"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: blocker.py — Device Blocking Engine
===========================================================================
  Three blocking strategies (tried in order):

  Strategy 1 — PowerShell Disable-PnpDevice
    Uses the device's Windows Instance ID to disable it in Device Manager.
    Most precise: only disables the specific unauthorized device.
    Requires: Administrator rights.

  Strategy 2 — Registry USBSTOR Service Stop
    Sets HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start = 4 (disabled)
    This disables ALL USB storage devices system-wide.
    Only used when config.BLOCK_VIA_USBSTOR_SERVICE = True.

  Strategy 3 — Drive Letter Ejection
    Uses PowerShell to safely eject the drive letter.
    Least disruptive but easiest to bypass physically.
===========================================================================
"""

import subprocess
import winreg
import ctypes
import sys
from typing import Optional

import config
from logger_setup import audit_logger, print_blocked, print_warn
from device_manager import USBDevice


# ---------------------------------------------------------------------------
# Admin rights check
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """Returns True if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def block_device(device: USBDevice) -> bool:
    """
    Attempts to block an unauthorized USB device.
    Returns True if blocking succeeded, False otherwise.

    Tries Strategy 1 (PnP disable) first.
    Falls back to Strategy 3 (eject drive) if no admin rights.
    """
    if not config.ENFORCEMENT_MODE:
        print_warn(f"MONITOR MODE — would block: {device.description} | {device.fingerprint}")
        audit_logger.info(f"[MONITOR MODE] Block skipped for: {device.fingerprint}")
        return False

    if not is_admin():
        print_warn("Not running as Administrator — using drive-eject only (limited protection).")
        print_warn("Run the framework as Administrator for full blocking capability.")
        audit_logger.warning("Blocking attempted without admin rights — degraded mode")
        if device.drive_letter:
            return _eject_drive(device.drive_letter)
        return False

    # Strategy 1: Disable via PnP Device Manager (most effective)
    if device.instance_id:
        success = _disable_pnp_device(device.instance_id, device.description)
        if success:
            return True

    # Strategy 2: USBSTOR service disable (nuclear option — all USB storage)
    if config.BLOCK_VIA_USBSTOR_SERVICE:
        return _disable_usbstor_service()

    # Strategy 3: Eject the drive letter
    if device.drive_letter:
        return _eject_drive(device.drive_letter)

    audit_logger.error(f"All blocking strategies failed for: {device.fingerprint}")
    return False


def unblock_device(instance_id: str) -> bool:
    """Re-enables a previously blocked device by its Instance ID."""
    try:
        ps_cmd = (
            f'Enable-PnpDevice -InstanceId "{instance_id}" -Confirm:$false -ErrorAction Stop'
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            audit_logger.info(f"Device re-enabled: {instance_id}")
            return True
        else:
            audit_logger.error(f"Failed to re-enable {instance_id}: {result.stderr.strip()}")
            return False
    except Exception as e:
        audit_logger.error(f"Exception while re-enabling device: {e}")
        return False


def enable_usbstor_service() -> bool:
    """Re-enables the USBSTOR service (reverses _disable_usbstor_service)."""
    return _set_usbstor_start_value(3)   # 3 = demand start (normal)


# ---------------------------------------------------------------------------
# Strategy implementations (private)
# ---------------------------------------------------------------------------

def _disable_pnp_device(instance_id: str, description: str) -> bool:
    """
    Disables the device in Windows Device Manager using PowerShell.
    The device physically disconnects from the OS — the user sees it
    disappear from File Explorer.
    """
    try:
        # Escape any single-quotes in the instance ID
        safe_id = instance_id.replace("'", "''")
        ps_cmd = (
            f"Disable-PnpDevice -InstanceId '{safe_id}' "
            f"-Confirm:$false -ErrorAction Stop"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            msg = f"PnP BLOCKED | {description} | InstanceID: {instance_id}"
            print_blocked(msg)
            audit_logger.warning(msg)
            return True
        else:
            err = result.stderr.strip()
            audit_logger.error(f"PnP block failed for {instance_id}: {err}")
            print_warn(f"PnP disable failed: {err}")
            return False
    except subprocess.TimeoutExpired:
        audit_logger.error(f"PnP block timed out for: {instance_id}")
        return False
    except Exception as e:
        audit_logger.error(f"PnP block exception: {e}")
        return False


def _disable_usbstor_service() -> bool:
    """
    Disables the USBSTOR Windows service via the registry.
    Effect: ALL USB storage devices are blocked system-wide.
    Start value 4 = SERVICE_DISABLED.
    """
    return _set_usbstor_start_value(4)


def _set_usbstor_start_value(value: int) -> bool:
    """Sets HKLM\\...\\USBSTOR\\Start registry key to the given value."""
    reg_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, reg_path,
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        action = "DISABLED" if value == 4 else "ENABLED"
        msg = f"USBSTOR Service {action} (registry Start={value})"
        print_blocked(msg)
        audit_logger.warning(msg)
        return True
    except PermissionError:
        audit_logger.error("Registry write denied — run as Administrator")
        return False
    except Exception as e:
        audit_logger.error(f"Registry edit failed: {e}")
        return False


def _eject_drive(drive_letter: str) -> bool:
    """
    Safely ejects a drive letter using PowerShell.
    Less effective than PnP disable but works without deep system access.
    """
    # Remove trailing colon/backslash if present
    letter = drive_letter.rstrip(":\\")
    try:
        ps_cmd = (
            f"$shell = New-Object -ComObject Shell.Application; "
            f"$folder = $shell.Namespace('{letter}:\\'); "
            f"$folder.Self.InvokeVerb('Eject')"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            msg = f"Drive ejected: {letter}:\\"
            print_blocked(msg)
            audit_logger.info(msg)
            return True
        else:
            audit_logger.error(f"Drive eject failed for {letter}: {result.stderr.strip()}")
            return False
    except Exception as e:
        audit_logger.error(f"Eject exception: {e}")
        return False
