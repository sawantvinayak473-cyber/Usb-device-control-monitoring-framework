# 🛡️ USB Device Control & Monitoring Framework

::: {align="center"}
# Enterprise-Grade Windows Endpoint Security Solution

**Real-Time USB Device Monitoring • Device Authorization • Threat
Scoring • File Auditing • Live Dashboard • PDF Reports**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?style=for-the-badge&logo=windows)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-000000?style=for-the-badge&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
:::

------------------------------------------------------------------------

## 📖 Overview

The **USB Device Control & Monitoring Framework** is a Windows-based
endpoint security framework that detects USB devices in real time,
authorizes or blocks them, monitors file operations, computes SHA-256
hashes, calculates threat scores, generates PDF audit reports, and
presents live security telemetry through a Flask dashboard.

## ✨ Key Features

-   Real-time USB Detection (WMI)
-   Allowlist & Blocklist Enforcement
-   Automatic USB Blocking
-   File Monitoring
-   SHA-256 Integrity Hashing
-   Threat Scoring Engine
-   SQLite Audit Database
-   Live Flask Dashboard
-   PDF Audit Reports
-   Windows Service Support
-   HTTPS Deployment (Caddy + DuckDNS)
-   AWS Windows EC2 Deployment

## 🏗 Architecture

``` text
USB Device
   │
   ▼
USB Monitor
   │
   ▼
Authorization
   │
   ├── Allowed
   └── Blocked
   │
   ▼
File Auditor
   │
   ▼
Threat Engine
   │
   ▼
SQLite Database
   │
   ├── Dashboard
   └── PDF Reports
```

## 🛠 Tech Stack

-   Python
-   Flask
-   SQLite
-   WMI
-   Watchdog
-   Bootstrap
-   Chart.js
-   AWS Windows EC2
-   DuckDNS
-   Caddy
-   PowerShell

## 🚀 Installation

``` bash
git clone https://github.com/sawantvinayak473-cyber/Usb-device-control-monitoring-framework.git
cd Usb-device-control-monitoring-framework
pip install -r requirements.txt
python main.py
```

Dashboard:

    http://127.0.0.1:5000

## ☁ Deployment

Hosted on AWS Windows EC2 with HTTPS enabled using Caddy and DuckDNS.

## 📂 Project Structure

``` text
dashboard/
logs/
reports/
tests/
main.py
usb_monitor.py
file_auditor.py
database.py
blocker.py
threat_engine.py
```

## 📈 Future Enhancements

-   Microsoft Sentinel Integration
-   Splunk Integration
-   VirusTotal API
-   Machine Learning Detection
-   Active Directory Integration

## 👨‍💻 Author

**Vinayak Sawant**

GitHub: https://github.com/sawantvinayak473-cyber

Repository:
https://github.com/sawantvinayak473-cyber/Usb-device-control-monitoring-framework

## 📜 License

MIT License
