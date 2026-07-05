"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: main.py — Entry Point & CLI Menu
===========================================================================
  HOW TO RUN (Windows, as Administrator):

    python main.py             — starts the monitor (interactive menu)
    python main.py --monitor   — starts monitoring immediately
    python main.py --report    — generates a report from existing logs
    python main.py --add       — adds a device to the allowlist

  REQUIREMENTS:
    pip install wmi pywin32 watchdog colorama

  IMPORTANT: Run as Administrator for full blocking capabilities.
===========================================================================
"""

import sys
import os
import argparse
from datetime import datetime

# Add the framework directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from logger_setup import (print_info, print_ok, print_warn, print_alert,
                           print_banner, event_logger)
from device_manager import DeviceManager, USBDevice
from reporter import ReportGenerator
from usb_monitor import USBMonitor


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="USB Framework",
        description="USB Device Control & Monitoring Framework"
    )
    parser.add_argument("--monitor", action="store_true",
                        help="Start USB monitoring immediately")
    parser.add_argument("--report",  action="store_true",
                        help="Generate audit report from logs")
    parser.add_argument("--add",     action="store_true",
                        help="Add a device to the allowlist manually")
    parser.add_argument("--status",  action="store_true",
                        help="Show current allowlist and blocklist")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Interactive Menu
# ---------------------------------------------------------------------------

def show_menu():
    print(f"""
  ┌─────────────────────────────────────────────┐
  │          MAIN MENU                          │
  ├─────────────────────────────────────────────┤
  │  1. Start USB Monitoring                    │
  │  2. Generate Audit Report                   │
  │  3. View Allowlist & Blocklist              │
  │  4. Add Device to Allowlist Manually        │
  │  5. Add Device to Blocklist Manually        │
  │  6. Show Configuration                      │
  │  7. Exit                                    │
  └─────────────────────────────────────────────┘""")
    return input("  Enter choice [1-7]: ").strip()


def run_monitoring():
    """Starts the USB monitoring engine."""
    event_logger.info("Monitoring session started")
    monitor = USBMonitor()
    monitor.start()   # Blocks until Ctrl+C


def generate_report():
    """Generates and prints the audit report."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(config.REPORT_DIR, f"usb_report_{ts}.txt")
    os.makedirs(config.REPORT_DIR, exist_ok=True)

    gen = ReportGenerator()
    report = gen.generate(output_path=report_path)
    print("\n" + report)
    print_ok(f"\nReport saved: {report_path}")


def view_lists():
    """Prints the current allowlist and blocklist."""
    dm = DeviceManager()
    print("\n  ── ALLOWLIST ──────────────────────────────────")
    if dm.allowlist:
        for fp, info in dm.allowlist.items():
            print(f"  ✓ {fp}")
            print(f"    Device : {info.get('description','?')}")
            print(f"    Owner  : {info.get('owner','?')}")
    else:
        print("  (empty)")

    print("\n  ── BLOCKLIST ──────────────────────────────────")
    if dm.blocklist:
        for fp, info in dm.blocklist.items():
            print(f"  ✗ {fp}")
            print(f"    Device : {info.get('description','?')}")
            print(f"    Reason : {info.get('reason','?')}")
    else:
        print("  (empty)")
    print()


def add_to_allowlist():
    """Interactive prompt to add a device to the allowlist."""
    print("\n  Enter device details (from device label or Device Manager):")
    vid    = input("  Vendor ID  (4 hex chars, e.g. 0781): ").strip().upper()
    pid    = input("  Product ID (4 hex chars, e.g. 5567): ").strip().upper()
    serial = input("  Serial Number (leave blank if unknown): ").strip()
    desc   = input("  Description (e.g. SanDisk Cruzer): ").strip()
    owner  = input("  Owner/User name: ").strip()

    device = USBDevice(
        vendor_id    = vid,
        product_id   = pid,
        serial       = serial or "UNKNOWN",
        description  = desc,
        drive_letter = None,
        instance_id  = "",
        connected_at = datetime.now().isoformat()
    )

    dm = DeviceManager()
    dm.add_to_allowlist(device, owner=owner)
    print_ok(f"Added to allowlist: {device.fingerprint}")


def add_to_blocklist():
    """Interactive prompt to add a device to the blocklist."""
    print("\n  Enter device details to permanently block:")
    vid    = input("  Vendor ID  (4 hex chars): ").strip().upper()
    pid    = input("  Product ID (4 hex chars): ").strip().upper()
    serial = input("  Serial Number (leave blank if unknown): ").strip()
    desc   = input("  Description: ").strip()
    reason = input("  Reason for blocking: ").strip()

    device = USBDevice(
        vendor_id    = vid,
        product_id   = pid,
        serial       = serial or "UNKNOWN",
        description  = desc,
        drive_letter = None,
        instance_id  = "",
        connected_at = datetime.now().isoformat()
    )

    dm = DeviceManager()
    dm.add_to_blocklist(device, reason=reason)
    print_alert(f"Added to blocklist: {device.fingerprint}")


def show_config():
    """Displays current configuration settings."""
    print(f"""
  ── CURRENT CONFIGURATION ───────────────────────────
  Enforcement Mode     : {config.ENFORCEMENT_MODE}
  USBSTOR Block Mode   : {config.BLOCK_VIA_USBSTOR_SERVICE}
  Poll Interval (sec)  : {config.POLL_INTERVAL_SECONDS}
  Large Transfer Limit : {config.LARGE_TRANSFER_THRESHOLD} files
  Max Hash File Size   : {config.MAX_HASH_SIZE_MB} MB
  Log Directory        : {config.LOG_DIR}
  Report Directory     : {config.REPORT_DIR}
  Allowlist File       : {config.ALLOWLIST_FILE}
  Blocklist File       : {config.BLOCKLIST_FILE}
  ────────────────────────────────────────────────────
  To change settings, edit: config.py
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print_banner()
    args = parse_args()

    # Direct CLI mode
    if args.monitor:
        run_monitoring()
        return
    if args.report:
        generate_report()
        return
    if args.add:
        add_to_allowlist()
        return
    if args.status:
        view_lists()
        return

    # Interactive menu
    while True:
        choice = show_menu()
        if   choice == "1": run_monitoring()
        elif choice == "2": generate_report()
        elif choice == "3": view_lists()
        elif choice == "4": add_to_allowlist()
        elif choice == "5": add_to_blocklist()
        elif choice == "6": show_config()
        elif choice == "7":
            print_info("Goodbye.")
            sys.exit(0)
        else:
            print_warn("Invalid choice. Please enter 1-7.")


if __name__ == "__main__":
    main()
