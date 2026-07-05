@echo off
:: ===========================================================================
::  USB Device Control & Monitoring Framework  v2.0
::  install.bat — Automated Windows Setup Script
:: ===========================================================================
::  Run this file as Administrator to set up the full framework.
::  Double-click OR right-click → Run as Administrator
:: ===========================================================================

title USB Security Framework — Installer v2.0
color 0B

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║  USB Device Control and Monitoring Framework  v2.0      ║
echo  ║  Automated Installer                                     ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

:: ── Check for Python ──────────────────────────────────────────────────────
echo  [1/6] Checking Python installation...
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo  [ERROR] Python is not installed or not on PATH.
    echo         Download from: https://python.org
    echo         During install, check "Add Python to PATH"
    pause
    exit /b 1
)
python --version
echo  [OK] Python found.
echo.

:: ── Check for pip ─────────────────────────────────────────────────────────
echo  [2/6] Checking pip...
pip --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo  [ERROR] pip not found. Reinstall Python and check "Add to PATH".
    pause
    exit /b 1
)
echo  [OK] pip found.
echo.

:: ── Install Python dependencies ───────────────────────────────────────────
echo  [3/6] Installing Python libraries...
echo        This may take 1-2 minutes on first run.
echo.
pip install wmi pywin32 watchdog colorama flask fpdf2 matplotlib pytest --quiet
IF ERRORLEVEL 1 (
    echo  [WARNING] Some packages may have failed to install.
    echo           Try running:  pip install -r requirements.txt
)
echo.
echo  [OK] Libraries installed.
echo.

:: ── pywin32 post-install ─────────────────────────────────────────────────
echo  [4/6] Running pywin32 post-install (required for Windows Service)...
python -m pywin32_postinstall -install >nul 2>&1
echo  [OK] pywin32 configured.
echo.

:: ── Create required directories ───────────────────────────────────────────
echo  [5/6] Creating directories...
if not exist "logs"    mkdir logs
if not exist "reports" mkdir reports
echo  [OK] Directories ready.
echo.

:: ── Seed demo data ────────────────────────────────────────────────────────
echo  [6/6] Loading demo data into database...
python demo_seeder.py
IF ERRORLEVEL 1 (
    echo  [WARNING] Demo seeder encountered an issue — see output above.
) ELSE (
    echo  [OK] Demo data loaded.
)
echo.

:: ── Run unit tests ────────────────────────────────────────────────────────
echo  Running unit tests...
pip install pytest --quiet >nul 2>&1
pytest tests\test_suite.py -v --tb=short 2>nul
echo.

:: ── Done ──────────────────────────────────────────────────────────────────
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║  Installation Complete!                                  ║
echo  ╠══════════════════════════════════════════════════════════╣
echo  ║  QUICK START:                                            ║
echo  ║                                                          ║
echo  ║  1. Open web dashboard:                                  ║
echo  ║     python dashboard\app.py                              ║
echo  ║     Then browse: http://127.0.0.1:5000                   ║
echo  ║                                                          ║
echo  ║  2. Start USB monitoring (as Administrator):             ║
echo  ║     python main.py                                       ║
echo  ║                                                          ║
echo  ║  3. Generate PDF report:                                 ║
echo  ║     python main.py --report                              ║
echo  ║                                                          ║
echo  ║  4. Install as Windows Service (as Administrator):       ║
echo  ║     python service_manager.py install                    ║
echo  ║     python service_manager.py start                      ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
pause
