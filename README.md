# USB Device Control & Monitoring Framework

Windows USB storage monitoring with allow/block lists, WMI device enumeration,
file auditing, a local dashboard, and optional security alerts.

## Security additions

### BadUSB / HID + storage detection

New storage devices are checked for a linked HID interface. A verified
`BADUSB_HID_COMBO` produces a critical event and violation, a 100-point threat
score, email/webhook alerts, and existing device blocking.

VID/PID equality alone is deliberately not sufficient. The detector also needs
a shared Windows PnP Container ID, parent path, location, or stable instance
token. This reduces false positives, but can leave a device unflagged if a
driver does not expose topology data. HID + storage may be legitimate for
specialised composite hardware; investigate alerts in their local context.

### YARA file scanning

Created and modified USB files are scanned without execution once their
size and modification time have remained stable. The watchdog callback only
queues the work; a background worker handles debounce, locks, rescans, and
YARA matching. Repeated filesystem events for the same stable file are
coalesced, while a later real modification is scanned again. Bundled rules
cover PE content, AutoRun patterns, PowerShell download cradles, reverse-shell
indicators, batch persistence, and encoded payloads. PE content using a double
extension such as invoice.pdf.exe is escalated to CRITICAL.

Every YARA match is recorded in SQLite, sent to configured webhooks, and
queued through the same email alert system as USB-policy incidents. Ordinary
file creates and modifications do not generate threat emails. YARA is optional:
missing dependencies, invalid rules, timeouts, locked/deleted files, and
oversized files are logged and normal USB monitoring continues.

### Email security alerts

Unauthorized devices, suspicious serials, verified BadUSB HID/storage
combinations, YARA detections, and configured large-transfer alerts all use
the bounded asynchronous AlertSystem queue. Duplicate alert keys are
suppressed for a configurable window. Demo mode explicitly reports that the
alert was not emailed; only successful live SMTP sends are counted as
deliveries.

### Slack and Telegram alerts

Webhook delivery uses a bounded background queue, so network delays cannot
block monitoring. It supports startup, unauthorized USB, spoofing, BadUSB,
YARA HIGH/CRITICAL, and large-transfer notifications; repeated events are
rate-limited.

## Setup

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest tests\test_suite.py tests\test_security_features.py tests\test_realtime_alerts.py -v
.\.venv\Scripts\python.exe main.py --monitor
```

Run as Administrator for live PnP blocking. Launch the dashboard with
`python main.py --dashboard`.

## Configuration

| Setting | Purpose | Default |
| --- | --- | --- |
| `USB_YARA_ENABLED` | Enable optional file scanning | `true` |
| `USB_YARA_MAX_FILE_SIZE_MB` | Largest file to scan | `50` |
| `USB_YARA_DEBOUNCE_SECONDS` | Delay after the most recent file event | `0.75` |
| `USB_YARA_STABILITY_SECONDS` | Unchanged interval before scanning | `0.75` |
| `USB_ALERT_DEMO_MODE` | Print only; do not email | `true` |
| `USB_ALERT_DEDUP_SECONDS` | Email duplicate-suppression window | `300` |
| `USB_WEBHOOK_ENABLED` | Enable webhook queue | `false` |
| `USB_WEBHOOK_TIMEOUT_SECONDS` | Per-request timeout | `8` |
| `USB_WEBHOOK_DEDUP_SECONDS` | Duplicate suppression window | `60` |

Keep credentials out of source control. Configure them as process environment
variables before startup:

```powershell
$env:USB_WEBHOOK_ENABLED = "true"
$env:USB_SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/..."
# Optional independent Telegram channel
$env:USB_TELEGRAM_BOT_TOKEN = "your-bot-token"
$env:USB_TELEGRAM_CHAT_ID = "your-chat-id"
python main.py --monitor
```

Webhook URLs and tokens are never written to application logs.

### Live Gmail email

The default is demo mode, so live email requires USB_ALERT_DEMO_MODE to be
false. Keep all credentials in the current PowerShell session and use a Gmail
app password rather than the normal account password:

    $env:USB_ALERT_DEMO_MODE = "false"
    $env:USB_SMTP_HOST = "smtp.gmail.com"
    $env:USB_SMTP_PORT = "587"
    $env:USB_SMTP_USER = "your-address@gmail.com"
    $env:USB_SMTP_PASS = "your-gmail-app-password"
    $env:USB_SMTP_FROM = "your-address@gmail.com"
    $env:USB_SMTP_TO = "security-recipient@example.com"
    python main.py --monitor

To verify the real-time path safely, start monitoring an authorised USB drive
and create a file named yara_test.txt on that drive containing the harmless
AutoRun test text below:

    [AutoRun]
    open=harmless.exe

After the file settles, the console should show a CRITICAL AutoRun_Infection
YARA hit. SQLite, configured webhooks, and the email queue receive the same
detection. Remove the harmless test file when finished.
