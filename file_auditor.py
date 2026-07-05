"""
===========================================================================
  USB Device Control & Monitoring Framework
  Module: file_auditor.py — File Transfer Monitoring
===========================================================================
  Uses the 'watchdog' library to watch USB drive letters in real-time.
  Every file create / modify / delete / move on the USB drive is logged.

  Features:
    • Logs the file path, operation type, size, and SHA-256 hash
    • Detects large batch transfers (data exfiltration pattern)
    • Tracks the username doing the transfer (Windows USERPROFILE)
    • Maintains per-session transfer counts

  How it works:
    When a USB drive mounts (e.g. E:\), we create a FileAuditHandler
    and start an Observer on that path. The Observer runs in a background
    thread so it doesn't block the main USB monitor loop.
===========================================================================
"""

import os
import hashlib
import threading
import time
from datetime import datetime
from typing import Dict, Optional

# watchdog provides cross-platform filesystem event monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from logger_setup import audit_logger, print_warn, print_alert, print_info


# ---------------------------------------------------------------------------
# Per-session transfer tracker
# ---------------------------------------------------------------------------

class TransferSession:
    """Tracks statistics for one USB drive's current session."""

    def __init__(self, drive_letter: str):
        self.drive_letter   = drive_letter
        self.start_time     = datetime.now()
        self.files_created  = 0
        self.files_modified = 0
        self.files_deleted  = 0
        self.files_moved    = 0
        self.total_bytes    = 0
        self.file_list: list = []   # list of dicts for the report

    @property
    def total_operations(self) -> int:
        return (self.files_created + self.files_modified +
                self.files_deleted + self.files_moved)

    def record(self, event_type: str, path: str, size_bytes: int = 0):
        """Add one file event to this session's record."""
        self.total_bytes += size_bytes
        self.file_list.append({
            "timestamp":  datetime.now().isoformat(),
            "event_type": event_type,
            "path":       path,
            "size_bytes": size_bytes,
            "user":       os.environ.get("USERNAME", "Unknown")
        })
        if event_type == "CREATED":
            self.files_created += 1
        elif event_type == "MODIFIED":
            self.files_modified += 1
        elif event_type == "DELETED":
            self.files_deleted += 1
        elif event_type in ("MOVED", "RENAMED"):
            self.files_moved += 1

        # Large transfer detection
        if self.total_operations >= config.LARGE_TRANSFER_THRESHOLD:
            msg = (f"LARGE TRANSFER ALERT | Drive {self.drive_letter} | "
                   f"{self.total_operations} file operations detected | "
                   f"~{self.total_bytes // 1024} KB total")
            print_alert(msg)
            audit_logger.warning(msg)


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------

class FileAuditHandler(FileSystemEventHandler):
    """
    Receives filesystem events from watchdog and logs them.
    One instance is created per USB drive letter being monitored.
    """

    def __init__(self, session: TransferSession):
        super().__init__()
        self.session = session

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        size, sha256 = self._stat_file(event.src_path)
        msg = (f"FILE CREATED | Drive {self.session.drive_letter} | "
               f"Path: {event.src_path} | Size: {size} bytes | SHA256: {sha256} | "
               f"User: {os.environ.get('USERNAME','?')}")
        audit_logger.info(msg)
        print_info(f"[AUDIT] Created: {os.path.basename(event.src_path)} ({size} bytes)")
        self.session.record("CREATED", event.src_path, size)

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        msg = (f"FILE DELETED | Drive {self.session.drive_letter} | "
               f"Path: {event.src_path} | "
               f"User: {os.environ.get('USERNAME','?')}")
        audit_logger.warning(msg)
        print_warn(f"[AUDIT] Deleted: {os.path.basename(event.src_path)}")
        self.session.record("DELETED", event.src_path, 0)

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        size, _ = self._stat_file(event.src_path)
        audit_logger.info(
            f"FILE MODIFIED | Drive {self.session.drive_letter} | "
            f"Path: {event.src_path} | Size: {size} bytes"
        )
        self.session.record("MODIFIED", event.src_path, size)

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        msg = (f"FILE MOVED | Drive {self.session.drive_letter} | "
               f"From: {event.src_path} | To: {event.dest_path}")
        audit_logger.info(msg)
        print_warn(f"[AUDIT] Moved: {os.path.basename(event.src_path)}")
        self.session.record("MOVED", event.src_path, 0)

    # ------------------------------------------------------------------

    @staticmethod
    def _stat_file(path: str):
        """Returns (size_in_bytes, sha256_hex) for a file path. Safe — never raises."""
        try:
            size = os.path.getsize(path)
            # Skip hashing very large files to save CPU
            if size > config.MAX_HASH_SIZE_MB * 1024 * 1024:
                return size, "SKIPPED_TOO_LARGE"
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return size, sha.hexdigest()
        except (OSError, PermissionError):
            return 0, "UNREADABLE"


# ---------------------------------------------------------------------------
# FileAuditor — manages observers across multiple drive letters
# ---------------------------------------------------------------------------

class FileAuditor:
    """
    Central controller for all USB file-system watchers.
    Call start_watching(drive_letter) when a USB drive mounts.
    Call stop_watching(drive_letter) when it unmounts.
    """

    def __init__(self):
        # drive_letter -> (Observer, TransferSession)
        self._watchers: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    def start_watching(self, drive_letter: str) -> TransferSession:
        """
        Begin monitoring a drive letter (e.g. "E:").
        Returns the TransferSession for this drive.
        """
        drive = drive_letter.rstrip("\\").rstrip(":") + ":\\"
        with self._lock:
            if drive in self._watchers:
                return self._watchers[drive][1]   # already watching

            session = TransferSession(drive)
            handler = FileAuditHandler(session)
            observer = Observer()
            observer.schedule(handler, path=drive, recursive=True)
            observer.start()
            self._watchers[drive] = (observer, session)

            msg = f"FILE AUDIT STARTED | Watching: {drive}"
            print_info(msg)
            audit_logger.info(msg)
            return session

    def stop_watching(self, drive_letter: str) -> Optional[TransferSession]:
        """
        Stop monitoring a drive and return its completed TransferSession.
        """
        drive = drive_letter.rstrip("\\").rstrip(":") + ":\\"
        with self._lock:
            if drive not in self._watchers:
                return None
            observer, session = self._watchers.pop(drive)
            observer.stop()
            observer.join(timeout=5)

            msg = (f"FILE AUDIT ENDED | Drive {drive} | "
                   f"Total ops: {session.total_operations} | "
                   f"Data: ~{session.total_bytes // 1024} KB")
            audit_logger.info(msg)
            print_info(msg)
            return session

    def stop_all(self):
        """Stop all active file watchers (called on framework shutdown)."""
        letters = list(self._watchers.keys())
        for letter in letters:
            self.stop_watching(letter)
