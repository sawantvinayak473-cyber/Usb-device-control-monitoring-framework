# USB Device Control & Monitoring Framework

A Windows-based blue-team security tool for detecting, auditing, and
blocking unauthorized USB devices in real-time.

---

## Quick Start (5 Steps)

### Step 1 — Install Python 3.10+
Download from https://python.org  
**Check "Add to PATH"** during install.

### Step 2 — Install dependencies
Open **Command Prompt as Administrator** and run:
```
pip install wmi pywin32 watchdog colorama
```

### Step 3 — Configure your allowlist
Edit `allowlist.json` (auto-created on first run) and add your
approved USB devices. You need the Vendor ID and Product ID from
Device Manager.

How to find VID/PID:
1. Plug in your USB device
2. Open Device Manager → Universal Serial Bus controllers
3. Right-click device → Properties → Details
4. Select "Hardware Ids" — look for VID_XXXX&PID_XXXX

### Step 4 — Run as Administrator
```
python main.py
```
Use the menu to start monitoring, view reports, or manage lists.

### Step 5 — Generate a report after monitoring
From the menu, choose option 2 to generate a full audit report.

---

## Project Structure

```
usb_framework/
├── main.py             ← Entry point (START HERE)
├── config.py           ← All settings (edit this to customize)
├── usb_monitor.py      ← WMI-based USB detection engine
├── device_manager.py   ← Allowlist / Blocklist logic
├── blocker.py          ← Device blocking (PowerShell + Registry)
├── file_auditor.py     ← File transfer monitoring (watchdog)
├── reporter.py         ← Audit report generator
├── logger_setup.py     ← Logging and colored console output
├── requirements.txt    ← Python dependencies
├── allowlist.json      ← Your approved devices (auto-created)
├── blocklist.json      ← Permanently blocked devices (auto-created)
├── logs/
│   ├── usb_events.log  ← Connect/disconnect events
│   └── usb_audit.log   ← Violations and file transfers
└── reports/
    └── usb_report_*.txt ← Generated audit reports
```

---

## Security Notes

- Run as **Administrator** for full device blocking capability
- In Monitor-Only mode (`ENFORCEMENT_MODE = False` in config.py),
  all events are logged but no devices are blocked
- The blocklist always takes priority over the allowlist
- Default policy is **deny-all** — only allowlisted devices work

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ImportError: No module named 'wmi'` | Run: `pip install wmi pywin32` |
| "Not running as Administrator" warning | Right-click CMD → Run as Administrator |
| Device not being detected | Check WMI service: `services.msc` → Windows Management Instrumentation → Running |
| Blocking not working | Ensure Administrator rights; check `config.ENFORCEMENT_MODE = True` |
