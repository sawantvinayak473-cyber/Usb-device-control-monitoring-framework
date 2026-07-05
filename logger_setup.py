"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: logger_setup.py — Logging & Console Output
===========================================================================
  Sets up two loggers:
    1. event_logger  — records every USB plug/unplug event
    2. audit_logger  — records file transfers and violations
  Also provides colored console printing via colorama.
===========================================================================
"""

import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

import config

# Initialize colorama so ANSI colors work on Windows terminals
init(autoreset=True)

# Create log directories if they don't exist yet
os.makedirs(config.LOG_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Internal helper — builds a standard logger with file + console handlers
# ---------------------------------------------------------------------------

def _build_logger(name: str, log_file: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid adding duplicate handlers if this function is called twice
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File handler — always writes to disk
    if config.FILE_LOGGING:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Public loggers — import these in other modules
# ---------------------------------------------------------------------------

event_logger = _build_logger("usb_events", config.EVENT_LOG_FILE)
audit_logger = _build_logger("usb_audit",  config.AUDIT_LOG_FILE)


# ---------------------------------------------------------------------------
# Colored console printing
# ---------------------------------------------------------------------------

def print_info(msg: str):
    """White — normal informational message."""
    print(f"{Fore.CYAN}[INFO   ]{Style.RESET_ALL}  {msg}")

def print_ok(msg: str):
    """Green — device allowed / action succeeded."""
    print(f"{Fore.GREEN}[ALLOWED]{Style.RESET_ALL}  {msg}")

def print_warn(msg: str):
    """Yellow — something suspicious but not blocked yet."""
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL}  {msg}")

def print_alert(msg: str):
    """Red — unauthorized device or critical violation."""
    print(f"{Fore.RED}[ALERT  ]{Style.RESET_ALL}  {msg}")

def print_blocked(msg: str):
    """Magenta — device has been blocked by the framework."""
    print(f"{Fore.MAGENTA}[BLOCKED]{Style.RESET_ALL}  {msg}")

def print_banner():
    """Prints the startup banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║     USB Device Control & Monitoring Framework  v1.0      ║
║     Blue Team Endpoint Security Tool                      ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
  Started : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  Mode    : {"ENFORCEMENT (Block + Log)" if config.ENFORCEMENT_MODE else "MONITOR ONLY (Log only)"}
  Logs    : {config.LOG_DIR}
"""
    print(banner)
