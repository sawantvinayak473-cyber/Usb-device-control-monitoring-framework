"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: main.py — Entry Point & CLI Menu
===========================================================================
  HOW TO RUN (Windows, as Administrator):

    python main.py             — interactive menu
    python main.py --monitor   — start monitoring immediately
    python main.py --report    — generate PDF report from current database
    python main.py --dashboard — launch the web dashboard
    python main.py --demo      — seed database with demo data
    python main.py --add       — add a device to the allowlist

  REQUIREMENTS:
    pip install -r requirements.txt

  Run as Administrator for full blocking capability.

  FIX (this release) — Serial normalization at input time
  ────────────────────────────────────────────────────────
  add_to_allowlist() and add_to_blocklist() now strip the "Serial:" prefix
  that users accidentally copy from the console output, and normalize the
  serial to uppercase before storing it. This ensures the stored value
  always matches what the monitor detects at runtime.

  Before fix: user copies "Serial:04014158a56b0f516bc6" from console,
    stored serial = "Serial:04014158a56b0f516bc6" → never matches detection
  After fix:  any of these inputs produce the same stored value:
    "04014158a56b0f516bc6"        → "04014158A56B0F516BC6"
    "04014158A56B0F516BC6"        → "04014158A56B0F516BC6"
    "Serial:04014158a56b0f516bc6" → "04014158A56B0F516BC6"
    " 04014158a56b0f516bc6 "      → "04014158A56B0F516BC6"
===========================================================================
"""

import sys
import os
import subprocess
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from logger_setup import (print_info, print_ok, print_warn, print_alert,
                           print_banner, event_logger)
from device_manager import DeviceManager, USBDevice


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="USB Framework v2.0",
        description="USB Device Control & Monitoring Framework"
    )
    parser.add_argument("--monitor",   action="store_true",
                        help="Start USB monitoring immediately")
    parser.add_argument("--report",    action="store_true",
                        help="Generate PDF audit report from database")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch the web dashboard at localhost:5000")
    parser.add_argument("--demo",      action="store_true",
                        help="Seed database with realistic demo data")
    parser.add_argument("--add",       action="store_true",
                        help="Add a device to the allowlist")
    parser.add_argument("--status",    action="store_true",
                        help="Show allowlist and blocklist")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_serial(raw: str) -> str:
    """
    Normalize a serial number typed or pasted by the user.

    Handles the common mistake of copying the whole "Serial:xxxx" token
    from the monitor console output instead of just the hex value.

    Transformations (applied in order):
      1. Strip surrounding whitespace
      2. Strip "Serial:" prefix (case-insensitive), then strip again
      3. Convert to uppercase

    Examples:
      "04014158a56b0f516bc6"         → "04014158A56B0F516BC6"
      "Serial:04014158a56b0f516bc6"  → "04014158A56B0F516BC6"
      "serial: 04014158A56B0F516BC6" → "04014158A56B0F516BC6"
      "  04014158A56B0F516BC6  "     → "04014158A56B0F516BC6"
    """
    v = raw.strip()
    if v.lower().startswith("serial:"):
        v = v[7:].strip()   # len("serial:") == 7
    return v.upper()


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def show_menu():
    print("""
  ┌──────────────────────────────────────────────────┐
  │       USB Security Framework  v2.0  — MENU       │
  ├──────────────────────────────────────────────────┤
  │  1.  Start USB Monitoring (as Administrator)     │
  │  2.  Launch Web Dashboard  (localhost:5000)      │
  │  3.  Generate PDF Audit Report                   │
  │  4.  View Allowlist & Blocklist                  │
  │  5.  Add Device to Allowlist                     │
  │  6.  Add Device to Blocklist                     │
  │  7.  Seed Demo Data (populate dashboard)         │
  │  8.  Show Configuration                          │
  │  9.  Exit                                        │
  └──────────────────────────────────────────────────┘""")
    return input("  Enter choice [1–9]: ").strip()


# ---------------------------------------------------------------------------
# Action functions
# ---------------------------------------------------------------------------

def run_monitoring():
    """Start the real-time USB monitoring engine."""
    event_logger.info("Monitoring session started")
    from usb_monitor import USBMonitor
    monitor = USBMonitor()
    monitor.start()


def launch_dashboard():
    """Launch the Flask web dashboard in a background process."""
    dashboard_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "dashboard", "app.py"
    )
    if not os.path.exists(dashboard_path):
        print_warn("dashboard/app.py not found. Check your project folder.")
        return

    print_info("Starting dashboard at http://127.0.0.1:5000 ...")
    print_info("Press Ctrl+C in the dashboard terminal to stop it.")
    try:
        if sys.platform == "win32":
            subprocess.Popen(
                ["python", dashboard_path],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        else:
            subprocess.Popen([sys.executable, dashboard_path])
        print_ok("Dashboard launched. Open http://127.0.0.1:5000 in your browser.")
    except Exception as e:
        print_warn(f"Could not launch dashboard: {e}")
        print_info(f"Start it manually:  python {dashboard_path}")


def generate_pdf_report():
    """Generate a PDF audit report from the current database."""
    try:
        from pdf_reporter import PDFReporter
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(config.REPORT_DIR, f"usb_audit_{ts}.pdf")
        print_info("Generating PDF report from database ...")
        result = PDFReporter().generate(output_path=path)
        print_ok(f"PDF Report saved: {result}")
        if sys.platform == "win32":
            try:
                os.startfile(result)
            except Exception:
                pass
    except Exception as e:
        print_warn(f"PDF generation failed: {e}")
        print_info("Make sure matplotlib and fpdf2 are installed:  "
                   "pip install matplotlib fpdf2")


def view_lists():
    """Print the current allowlist and blocklist."""
    dm = DeviceManager()
    print("\n  ── ALLOWLIST ────────────────────────────────────────")
    if dm.allowlist:
        for fp, info in dm.allowlist.items():
            print(f"  ✓  {fp}")
            print(f"     Device : {info.get('description', '?')}")
            print(f"     Owner  : {info.get('owner', '?')}")
    else:
        print("  (empty — all USB devices will be blocked)")

    print("\n  ── BLOCKLIST ────────────────────────────────────────")
    if dm.blocklist:
        for fp, info in dm.blocklist.items():
            print(f"  ✗  {fp}")
            print(f"     Device : {info.get('description', '?')}")
            print(f"     Reason : {info.get('reason', '?')}")
    else:
        print("  (empty)")
    print()


def add_to_allowlist():
    """
    Interactive prompt to add a device to the allowlist.

    FIX: Serial is now normalized via _clean_serial() before being stored.
    This strips the "Serial:" prefix users often copy from the console,
    removes extra whitespace, and uppercases the value so it always
    matches what the monitor detects at runtime.
    """
    print("\n  Enter device details (from Device Manager → Hardware Ids):")
    print("  Tip: copy just the hex values, not labels like 'VID:' or 'Serial:'")
    print()

    vid_raw = input("  Vendor ID  (4 hex chars, e.g. 0781): ").strip().upper()
    pid_raw = input("  Product ID (4 hex chars, e.g. 5581): ").strip().upper()

    serial_raw = input(
        "  Serial Number (paste from monitor output, leave blank if unknown): "
    ).strip()
    serial = _clean_serial(serial_raw) if serial_raw else "UNKNOWN"

    desc  = input("  Description (e.g. SanDisk Ultra USB 3.0): ").strip()
    owner = input("  Owner / User name: ").strip()

    # Show what will be stored so the user can verify
    print(f"\n  Storing:  VID={vid_raw}  PID={pid_raw}  Serial={serial}")

    device = USBDevice(
        vendor_id    = vid_raw,
        product_id   = pid_raw,
        serial       = serial,
        description  = desc,
        drive_letter = None,
        instance_id  = "",
        connected_at = datetime.now().isoformat()
    )
    dm = DeviceManager()
    dm.add_to_allowlist(device, owner=owner)
    print_ok(f"Added to allowlist: {device.fingerprint}")


def add_to_blocklist():
    """
    Interactive prompt to add a device to the blocklist.

    FIX: Serial is normalized via _clean_serial() before storing.
    """
    print("\n  Enter device details to permanently block:")
    vid_raw = input("  Vendor ID  (4 hex chars): ").strip().upper()
    pid_raw = input("  Product ID (4 hex chars): ").strip().upper()

    serial_raw = input("  Serial Number (paste from monitor, blank if unknown): ").strip()
    serial = _clean_serial(serial_raw) if serial_raw else "UNKNOWN"

    desc   = input("  Description: ").strip()
    reason = input("  Reason for blocking: ").strip()

    print(f"\n  Storing:  VID={vid_raw}  PID={pid_raw}  Serial={serial}")

    device = USBDevice(
        vendor_id    = vid_raw,
        product_id   = pid_raw,
        serial       = serial,
        description  = desc,
        drive_letter = None,
        instance_id  = "",
        connected_at = datetime.now().isoformat()
    )
    dm = DeviceManager()
    dm.add_to_blocklist(device, reason=reason)
    print_alert(f"Added to blocklist: {device.fingerprint}")


def seed_demo_data():
    """Populate the database with realistic demo data."""
    print_info("Seeding database with demo data ...")
    try:
        import demo_seeder
        choice = input("  Reset existing database first? [y/N]: ").strip().lower()
        demo_seeder.seed(reset=(choice == "y"))
        print_ok("Demo data loaded. Open the dashboard to see it.")
    except Exception as e:
        print_warn(f"Demo seeder failed: {e}")


def show_config():
    """Display current configuration."""
    print(f"""
  ── CONFIGURATION ───────────────────────────────────────
  Enforcement Mode      : {config.ENFORCEMENT_MODE}
  USBSTOR Block Mode    : {config.BLOCK_VIA_USBSTOR_SERVICE}
  Poll Interval (sec)   : {config.POLL_INTERVAL_SECONDS}
  Large Transfer Limit  : {config.LARGE_TRANSFER_THRESHOLD} files
  Max Hash File Size    : {config.MAX_HASH_SIZE_MB} MB
  Alert Mode            : {"DEMO (console only)" if getattr(config, "ALERT_DEMO_MODE", True) else "LIVE (SMTP)"}
  Dashboard Port        : {getattr(config, "DASHBOARD_PORT", 5000)}
  Log Directory         : {config.LOG_DIR}
  Report Directory      : {config.REPORT_DIR}
  Allowlist File        : {config.ALLOWLIST_FILE}
  ────────────────────────────────────────────────────────
  To change settings, edit:  config.py
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print_banner()
    args = parse_args()

    if args.monitor:   run_monitoring();      return
    if args.report:    generate_pdf_report(); return
    if args.dashboard: launch_dashboard();    return
    if args.demo:      seed_demo_data();      return
    if args.add:       add_to_allowlist();    return
    if args.status:    view_lists();          return

    while True:
        choice = show_menu()
        if   choice == "1": run_monitoring()
        elif choice == "2": launch_dashboard()
        elif choice == "3": generate_pdf_report()
        elif choice == "4": view_lists()
        elif choice == "5": add_to_allowlist()
        elif choice == "6": add_to_blocklist()
        elif choice == "7": seed_demo_data()
        elif choice == "8": show_config()
        elif choice == "9":
            print_info("Goodbye.")
            sys.exit(0)
        else:
            print_warn("Invalid choice. Enter 1–9.")


if __name__ == "__main__":
    main()
