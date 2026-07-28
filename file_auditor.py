"""
===========================================================================
  USB Device Control & Monitoring Framework  v2.0
  Module: file_auditor.py — Real-Time File Transfer Monitoring
===========================================================================
  Uses the watchdog library to watch a USB drive letter in real-time.

  CHANGES IN THIS RELEASE
  ───────────────────────
  1. start_watching() now accepts device metadata (vid, pid, serial,
     description) so every file event record carries full context.

  2. Each file event is written to BOTH tables:
       file_events — detailed record (size, sha256, dest_path, etc.)
       events      — so the dashboard live feed shows file activity

  3. Deduplication: Windows copy ops fire CREATED then multiple
     MODIFIED events for the same file. A 3-second dedup window per
     (path, event_type) key suppresses the redundant MODIFIED writes.

  4. Renames are detected separately from cross-directory moves.
     on_moved fires for both; we inspect the directories to distinguish.

  5. Terminal output format:
       [FILE AUDITOR] Monitoring started: D:\
       [FILE CREATED]  transfer_test.txt  (1,234 bytes)  D:\
       [FILE MODIFIED] transfer_test.txt  (1,234 bytes)  D:\
       [FILE DELETED]  transfer_test.txt                 D:\
       [FILE MOVED]    docs\\old.txt  ->  archive\\old.txt  D:\
       [FILE RENAMED]  draft.docx   →  final.docx        D:\

  6. Large-transfer alert also fires through AlertSystem when the
     per-session threshold is crossed.
===========================================================================
"""

import os
import time
import hashlib
import threading
from datetime import datetime
from typing import Dict, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from logger_setup import audit_logger, print_warn, print_alert, print_info
from database import get_db


# ---------------------------------------------------------------------------
# Per-session transfer tracker
# ---------------------------------------------------------------------------

class TransferSession:
    """Tracks statistics and metadata for one USB drive's monitoring session."""

    def __init__(self, drive_letter: str):
        self.drive_letter   = drive_letter
        self.start_time     = datetime.now()
        self.files_created  = 0
        self.files_modified = 0
        self.files_deleted  = 0
        self.files_moved    = 0
        self.total_bytes    = 0
        self.file_list: list = []

        # Device metadata (populated by FileAuditor.start_watching)
        self.device_fp:    str = ""
        self.vid:          str = ""
        self.pid:          str = ""
        self.serial:       str = ""
        self.description:  str = ""

    @property
    def total_operations(self) -> int:
        return (self.files_created + self.files_modified +
                self.files_deleted + self.files_moved)

    def record(self, event_type: str, path: str, size_bytes: int = 0):
        self.total_bytes += size_bytes
        self.file_list.append({
            "timestamp":  datetime.now().isoformat(),
            "event_type": event_type,
            "path":       path,
            "size_bytes": size_bytes,
            "user":       os.environ.get("USERNAME", "Unknown")
        })
        if   event_type == "FILE_CREATED":  self.files_created  += 1
        elif event_type == "FILE_MODIFIED": self.files_modified += 1
        elif event_type == "FILE_DELETED":  self.files_deleted  += 1
        elif event_type in ("FILE_MOVED", "FILE_RENAMED"): self.files_moved += 1

        if self.total_operations == config.LARGE_TRANSFER_THRESHOLD:
            msg = (f"LARGE TRANSFER ALERT | Drive {self.drive_letter} | "
                   f"{self.total_operations} file operations detected | "
                   f"~{self.total_bytes // 1024} KB total | "
                   f"VID:{self.vid} PID:{self.pid} Serial:{self.serial}")
            print_alert(msg)
            audit_logger.warning(msg)
            get_db().log_event("LARGE_TRANSFER_ALERT", self.device_fp,
                               self.drive_letter, msg, "WARNING")


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------

class FileAuditHandler(FileSystemEventHandler):
    """
    Receives filesystem events from watchdog and:
      - Prints formatted terminal messages
      - Writes to file_events table (detailed record)
      - Writes to events table (dashboard feed visibility)
      - Suppresses duplicate events from Windows copy operations
    """

    # Dedup window in seconds: suppress same (path, event_type) within this window
    _DEDUP_WINDOW = 3.0

    def __init__(self, session: TransferSession):
        super().__init__()
        self.session = session
        # dedup dict: key = "path::event_type" → last event timestamp (monotonic)
        self._recent: Dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Dedup helper
    # ------------------------------------------------------------------

    def _is_duplicate(self, path: str, event_type: str) -> bool:
        """
        Returns True if the same (path, event_type) was seen within
        _DEDUP_WINDOW seconds. Suppresses the storm of MODIFIED events
        that Windows fires during a file copy operation.
        """
        key = f"{path}::{event_type}"
        now = time.monotonic()
        with self._lock:
            last = self._recent.get(key, 0.0)
            if now - last < self._DEDUP_WINDOW:
                return True
            self._recent[key] = now
            # Prune old entries to prevent memory growth
            if len(self._recent) > 2000:
                cutoff = now - 60
                self._recent = {k: v for k, v in self._recent.items()
                                if v > cutoff}
        return False

    # ------------------------------------------------------------------
    # Stat helper
    # ------------------------------------------------------------------

    @staticmethod
    def _stat(path: str):
        """Returns (size_bytes, sha256_hex). Never raises."""
        try:
            size = os.path.getsize(path)
            if size > config.MAX_HASH_SIZE_MB * 1024 * 1024:
                return size, "SKIPPED_TOO_LARGE"
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return size, sha.hexdigest()
        except (OSError, PermissionError):
            return 0, "UNREADABLE"

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def _log(self, event_type: str, path: str, size: int = 0,
             sha256: str = "", dest_path: str = "", severity: str = "INFO"):
        """Write to file_events and events tables, update session stats."""
        db   = get_db()
        sess = self.session
        fname = os.path.basename(path)
        user  = os.environ.get("USERNAME", "System")

        # ── file_events table (full detail) ───────────────────────────
        db.log_file_event(
            operation        = event_type,
            file_path        = path,
            size             = size,
            sha256           = sha256,
            drive_letter     = sess.drive_letter,
            device_fp        = sess.device_fp,
            dest_path        = dest_path
        )

        # ── events table (dashboard feed) ─────────────────────────────
        if dest_path:
            detail = (f"{fname} | {path} → {dest_path} | "
                      f"VID:{sess.vid} PID:{sess.pid} Serial:{sess.serial}")
        else:
            detail = (f"{fname} | {path}"
                      + (f" | {size:,} bytes" if size else "")
                      + f" | VID:{sess.vid} PID:{sess.pid} Serial:{sess.serial}")

        db.log_event(event_type, sess.device_fp,
                     sess.drive_letter, detail, severity)

        # ── session stats ──────────────────────────────────────────────
        sess.record(event_type, path, size)

    # ------------------------------------------------------------------
    # Watchdog callbacks
    # ------------------------------------------------------------------

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path  = event.src_path
        fname = os.path.basename(path)

        if self._is_duplicate(path, "FILE_CREATED"):
            return

        size, sha256 = self._stat(path)
        print_info(f"[FILE CREATED]   {fname:<40} ({size:,} bytes)  "
                   f"{self.session.drive_letter}")
        self._log("FILE_CREATED", path, size, sha256)

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path  = event.src_path
        fname = os.path.basename(path)

        if self._is_duplicate(path, "FILE_MODIFIED"):
            return

        size, _ = self._stat(path)
        print_info(f"[FILE MODIFIED]  {fname:<40} ({size:,} bytes)  "
                   f"{self.session.drive_letter}")
        self._log("FILE_MODIFIED", path, size)

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path  = event.src_path
        fname = os.path.basename(path)

        if self._is_duplicate(path, "FILE_DELETED"):
            return

        print_warn(f"[FILE DELETED]   {fname:<40}             "
                   f"{self.session.drive_letter}")
        self._log("FILE_DELETED", path, severity="WARNING")

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        src   = event.src_path
        dst   = event.dest_path
        fname = os.path.basename(src)
        dname = os.path.basename(dst)

        if self._is_duplicate(src, "FILE_MOVED"):
            return

        # Distinguish rename (same directory) from move (different directory)
        same_dir    = (os.path.dirname(src) == os.path.dirname(dst))
        event_type  = "FILE_RENAMED" if same_dir else "FILE_MOVED"

        if same_dir:
            print_info(f"[FILE RENAMED]   {fname:<20} → {dname:<20}  "
                       f"{self.session.drive_letter}")
        else:
            rel_src = os.path.relpath(src, self.session.drive_letter)
            rel_dst = os.path.relpath(dst, self.session.drive_letter)
            print_info(f"[FILE MOVED]     {rel_src} → {rel_dst}  "
                       f"{self.session.drive_letter}")

        self._log(event_type, src, dest_path=dst)


# ---------------------------------------------------------------------------
# FileAuditor — manages observers across multiple drive letters
# ---------------------------------------------------------------------------

class FileAuditor:
    """
    Central controller for all USB file-system watchers.

    start_watching(drive_letter, device_fp, vid, pid, serial, description)
      — called by _start_file_auditing() in usb_monitor once the drive
        letter has been confirmed
    stop_watching(drive_letter)
      — called by _handle_disconnect()
    stop_all()
      — called on framework shutdown
    """

    def __init__(self):
        # drive_letter (normalised, e.g. "E:\\") → (Observer, TransferSession)
        self._watchers: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    def start_watching(
            self,
            drive_letter: str,
            device_fp:    str = "",
            vid:          str = "",
            pid:          str = "",
            serial:       str = "",
            description:  str = ""
    ) -> "TransferSession":
        """
        Begin monitoring a USB drive.
        Stores full device metadata in the TransferSession so every file
        event record carries VID, PID, serial, and device fingerprint.
        Returns the TransferSession for this drive.
        """
        drive = drive_letter.rstrip("\\").rstrip(":") + ":\\"

        with self._lock:
            if drive in self._watchers:
                return self._watchers[drive][1]   # already watching

            session             = TransferSession(drive)
            session.device_fp   = device_fp
            session.vid         = vid
            session.pid         = pid
            session.serial      = serial
            session.description = description

            handler  = FileAuditHandler(session)
            observer = Observer()
            observer.schedule(handler, path=drive, recursive=True)
            observer.start()
            self._watchers[drive] = (observer, session)

            msg = (f"[FILE AUDITOR] Monitoring started: {drive} | "
                   f"VID:{vid} PID:{pid} Serial:{serial}")
            print_info(msg)
            audit_logger.info(msg)
            get_db().log_event("FILE_AUDIT_STARTED", device_fp,
                               drive_letter, msg, "INFO")
            return session

    def stop_watching(self, drive_letter: str) -> Optional[TransferSession]:
        """Stop monitoring a drive and return its completed TransferSession."""
        drive = drive_letter.rstrip("\\").rstrip(":") + ":\\"

        with self._lock:
            if drive not in self._watchers:
                return None
            observer, session = self._watchers.pop(drive)
            observer.stop()
            observer.join(timeout=5)

            msg = (f"[FILE AUDITOR] Monitoring stopped: {drive} | "
                   f"Ops:{session.total_operations} | "
                   f"~{session.total_bytes // 1024} KB")
            print_info(msg)
            audit_logger.info(msg)
            get_db().log_event("FILE_AUDIT_ENDED", session.device_fp,
                               drive_letter, msg, "INFO")
            return session

    def stop_all(self):
        """Stop all active watchers (called on framework shutdown)."""
        for letter in list(self._watchers.keys()):
            self.stop_watching(letter)
