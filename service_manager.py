"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: service_manager.py — Windows Service Deployment
===========================================================================
  Wraps the USB monitor as a proper Windows NT Service so it runs
  automatically on boot — even when no user is logged in.

  COMMANDS (run as Administrator):
    python service_manager.py install   → Register the service
    python service_manager.py start     → Start it
    python service_manager.py stop      → Stop it
    python service_manager.py remove    → Unregister it
    python service_manager.py status    → Check current state
    python service_manager.py debug     → Run in foreground for testing

  After install + start the service appears in:
    services.msc → "USB Device Control & Monitoring Framework"

  REQUIREMENTS:
    pip install pywin32
    Run: python -m pywin32_postinstall -install  (first time only)
===========================================================================
"""

import sys
import os
import time
import threading

import config

# ── pywin32 service APIs ──────────────────────────────────────────────────
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════
# Windows Service class
# ══════════════════════════════════════════════════════════════════════════

if PYWIN32_AVAILABLE:

    class USBMonitorService(win32serviceutil.ServiceFramework):
        """
        Windows Service shell for the USB monitoring framework.
        The OS calls SvcDoRun() on start and SvcStop() on stop/shutdown.
        """

        _svc_name_         = config.SERVICE_NAME
        _svc_display_name_ = config.SERVICE_DISPLAY
        _svc_description_  = config.SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            # stop_event signals SvcDoRun() to exit
            self._stop_event    = win32event.CreateEvent(None, 0, 0, None)
            self._monitor       = None
            self._alert_system  = None

        # ── Service entry points ──────────────────────────────────────

        def SvcDoRun(self):
            """Called by the SCM when the service starts."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            self._run()

        def SvcStop(self):
            """Called by the SCM when the service is stopped."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._monitor:
                self._monitor.stop()
            if self._alert_system:
                self._alert_system.stop()
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, "")
            )

        # ── Internal run logic ────────────────────────────────────────

        def _run(self):
            """Starts the USB monitor and alert system, then idles."""
            from alert_system import AlertSystem
            from usb_monitor import USBMonitor

            self._alert_system = AlertSystem()
            self._alert_system.start()
            self._alert_system.send_service_started_alert()

            # Start USB monitor in a background thread
            self._monitor = USBMonitor()
            t = threading.Thread(target=self._monitor.start,
                                 name="USBMonitor", daemon=True)
            t.start()

            # Wait for the stop event (set by SvcStop)
            while True:
                rc = win32event.WaitForSingleObject(
                    self._stop_event, 5000   # check every 5 seconds
                )
                if rc == win32event.WAIT_OBJECT_0:
                    break   # Stop event received

            t.join(timeout=10)


# ══════════════════════════════════════════════════════════════════════════
# CLI helpers
# ══════════════════════════════════════════════════════════════════════════

def _check_admin():
    """Warn if not running as Administrator."""
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[WARNING] Not running as Administrator — service commands may fail.")
        print("          Right-click Command Prompt → Run as Administrator\n")


def _status():
    """Print the current Windows Service status."""
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 not installed. Run: pip install pywin32")
        return
    try:
        status_code = win32serviceutil.QueryServiceStatus(config.SERVICE_NAME)[1]
        states = {
            win32service.SERVICE_STOPPED:          "STOPPED",
            win32service.SERVICE_START_PENDING:    "STARTING...",
            win32service.SERVICE_STOP_PENDING:     "STOPPING...",
            win32service.SERVICE_RUNNING:          "RUNNING",
            win32service.SERVICE_PAUSED:           "PAUSED",
        }
        print(f"  Service: {config.SERVICE_DISPLAY}")
        print(f"  Status : {states.get(status_code, 'UNKNOWN')}")
    except Exception as e:
        print(f"  Service '{config.SERVICE_NAME}' not found or inaccessible: {e}")


def _debug_run():
    """Run the framework in foreground (no service install needed)."""
    print(f"\n  Running in DEBUG mode (Ctrl+C to stop)\n")
    from alert_system import AlertSystem
    from usb_monitor  import USBMonitor

    alerts  = AlertSystem()
    alerts.start()
    monitor = USBMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
        alerts.stop()


# ══════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════

def main():
    if not PYWIN32_AVAILABLE:
        print("[ERROR] pywin32 is required for service management.")
        print("        Run:  pip install pywin32")
        print("        Then: python -m pywin32_postinstall -install")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"""
  USB Device Control & Monitoring Framework v2.0 — Service Manager
  ═══════════════════════════════════════════════════════════════

  Usage: python service_manager.py <command>

  Commands:
    install   Register as Windows Service (run at boot, no login needed)
    start     Start the service
    stop      Stop the service
    remove    Unregister / remove the service
    restart   Stop then start
    status    Check if the service is running
    debug     Run in foreground terminal for testing (no install needed)

  All commands except 'debug' require Administrator rights.
""")
        return

    cmd = sys.argv[1].lower()

    if cmd == "debug":
        _debug_run()
        return

    if cmd == "status":
        _status()
        return

    _check_admin()

    # Delegate install/start/stop/remove/restart to pywin32 utility
    try:
        win32serviceutil.HandleCommandLine(USBMonitorService)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
