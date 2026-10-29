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

  7. Created and modified files are passed to YARA only after a background
     stability/debounce worker confirms their contents stopped changing.
     Confirmed matches retain database and webhook reporting and now queue
     the shared AlertSystem email with device and file context.
===========================================================================
"""

import os
import time
import hashlib
import threading
from datetime import datetime
from typing import Callable, Dict, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config
from logger_setup import audit_logger, print_warn, print_alert, print_info
from database import get_db
from yara_scanner import YaraScanner
from webhook_notifier import get_notifier


# ---------------------------------------------------------------------------
# Per-session transfer tracker
# ---------------------------------------------------------------------------

class TransferSession:
    """Tracks statistics and metadata for one USB drive's monitoring session."""

    def __init__(self, drive_letter: str, alert_system=None, notifier=None):
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
        self.alert_system = alert_system
        self.notifier = notifier
        self._large_transfer_alerted = False

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

        threshold = max(1, config.LARGE_TRANSFER_THRESHOLD)
        if (not self._large_transfer_alerted and
                self.total_operations >= threshold):
            self._large_transfer_alerted = True
            msg = (f"LARGE TRANSFER ALERT | Drive {self.drive_letter} | "
                   f"{self.total_operations} file operations detected | "
                   f"~{self.total_bytes // 1024} KB total | "
                   f"VID:{self.vid} PID:{self.pid} Serial:{self.serial}")
            print_alert(msg)
            audit_logger.warning(msg)
            try:
                get_db().log_event("LARGE_TRANSFER_ALERT", self.device_fp,
                                   self.drive_letter, msg, "WARNING")
            except Exception as exc:
                # Notification channels remain independent so an SQLite fault
                # cannot hide a security signal from the operator.
                audit_logger.warning(f"Large-transfer database logging failed: {exc}")
            try:
                notifier = self.notifier or get_notifier()
                notifier.send_large_transfer(
                    self.drive_letter, self.total_operations, self.total_bytes,
                    self.device_fp)
            except Exception as exc:
                audit_logger.warning(f"Large-transfer webhook notification failed: {exc}")
            try:
                if self.alert_system:
                    self.alert_system.send_large_transfer_alert(
                        self.drive_letter, self.total_operations,
                        self.total_bytes // 1024, device=self)
            except Exception as exc:
                audit_logger.warning(f"Large-transfer email alert queue failed: {exc}")


# ---------------------------------------------------------------------------
# Background YARA scan scheduler
# ---------------------------------------------------------------------------

class _StableYaraScanScheduler:
    """
    Coalesce watchdog events, wait for a stable file, then scan on one
    dedicated background thread.  Watchdog callbacks only enqueue work; they
    never sleep while a copy operation is still writing.
    """

    def __init__(self, scanner: YaraScanner,
                 on_result: Callable[[str, object, str], None]):
        self._scanner = scanner
        self._on_result = on_result
        self._condition = threading.Condition()
        self._pending: Dict[str, dict] = {}
        self._completed: Dict[str, tuple] = {}
        self._running = True
        self._thread = threading.Thread(
            target=self._run, name="YARA-Stability-Worker", daemon=True)
        self._thread.start()

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    @staticmethod
    def _signature(path: str) -> tuple:
        """Return a stable identity that changes when the file is rewritten."""
        info = os.stat(path)
        mtime_ns = getattr(info, "st_mtime_ns",
                           int(info.st_mtime * 1_000_000_000))
        return (
            getattr(info, "st_dev", 0),
            getattr(info, "st_ino", 0),
            info.st_size,
            mtime_ns,
        )

    def schedule(self, path: str) -> None:
        """Reset debounce/stability state for a created or modified file."""
        if not path:
            return
        key = self._key(path)
        now = time.monotonic()
        with self._condition:
            self._pending[key] = {
                "path": path,
                # A fresh filesystem event means a slow copy is still making
                # progress. Restart the stability budget so long transfers are
                # scanned after completion rather than skipped at an arbitrary
                # age; lock/error retries remain bounded separately.
                "first_seen": now,
                "not_before": now + config.YARA_DEBOUNCE_SECONDS,
                "signature": None,
                "stable_since": None,
                "retry_count": 0,
            }
            self._condition.notify()

    def cancel(self, path: str) -> None:
        """Forget a source path that was moved or deleted before scanning."""
        if not path:
            return
        with self._condition:
            self._pending.pop(self._key(path), None)
            self._condition.notify()

    def stop(self, timeout: float = 12.0) -> None:
        """Cancel pending work and join the stability worker cleanly."""
        with self._condition:
            self._running = False
            self._pending.clear()
            self._condition.notify_all()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while True:
            with self._condition:
                while self._running and not self._pending:
                    self._condition.wait()
                if not self._running:
                    return

                now = time.monotonic()
                key, job = min(
                    self._pending.items(),
                    key=lambda entry: entry[1]["not_before"],
                )
                wait = job["not_before"] - now
                if wait > 0:
                    self._condition.wait(timeout=wait)
                    continue

                if now - job["first_seen"] > config.YARA_STABILITY_TIMEOUT_SECONDS:
                    self._pending.pop(key, None)
                    audit_logger.warning(
                        "[YARA] File did not stabilize before timeout; skipped: %s",
                        job["path"],
                    )
                    continue

                path = job["path"]

            # Stat and scanning occur outside the condition.  New watchdog
            # events can coalesce or cancel this job while we are working.
            try:
                signature = self._signature(path)
            except FileNotFoundError:
                with self._condition:
                    if self._pending.get(key) is job:
                        self._pending.pop(key, None)
                audit_logger.debug("[YARA] File vanished before scan: %s", path)
                continue
            except OSError as exc:
                with self._condition:
                    if self._pending.get(key) is job:
                        job["not_before"] = time.monotonic() + config.YARA_RETRY_SECONDS
                        job["retry_count"] += 1
                        if job["retry_count"] > config.YARA_MAX_RETRIES:
                            self._pending.pop(key, None)
                            audit_logger.warning(
                                "[YARA] File remained inaccessible; skipped: %s (%s)",
                                path, exc,
                            )
                        self._condition.notify()
                continue

            with self._condition:
                if not self._running:
                    return
                if self._pending.get(key) is not job:
                    # A newer event replaced this job while os.stat ran.
                    continue

                now = time.monotonic()
                if job["signature"] != signature:
                    job["signature"] = signature
                    job["stable_since"] = now
                    job["not_before"] = now + config.YARA_STABILITY_SECONDS
                    continue

                stable_since = job["stable_since"] or now
                remaining = config.YARA_STABILITY_SECONDS - (now - stable_since)
                if remaining > 0:
                    job["not_before"] = now + remaining
                    continue

                self._pending.pop(key, None)
                previous = self._completed.get(key)
                if previous and previous[0] == signature:
                    audit_logger.debug("[YARA] Duplicate stable file scan skipped: %s", path)
                    continue

            result = self._scanner.scan(path)
            with self._condition:
                # A scan may outlive the observer's stop request.  Never
                # record or notify from it once the monitored drive/session
                # has been torn down.
                if not self._running:
                    return
            if getattr(result, "retryable", False):
                self._retry_after_scan_error(key, job, path, signature, result)
                continue

            # A slow scan can overlap a new write.  Never alert from content
            # that changed while YARA was reading it; debounce the newest
            # version instead.
            try:
                if self._signature(path) != signature:
                    self.schedule(path)
                    continue
            except OSError:
                # Deletion/move/inaccessibility after a scan is not a threat
                # result; a future file event can schedule a new scan.
                continue

            with self._condition:
                self._completed[key] = (signature, time.monotonic())
                if len(self._completed) > 2000:
                    cutoff = time.monotonic() - 3600
                    self._completed = {
                        completed_key: value
                        for completed_key, value in self._completed.items()
                        if value[1] >= cutoff
                    }
                # Hold the scheduler lock while handing off the completed
                # result.  stop() cannot complete until this short hand-off
                # has finished, so a disconnected/shut-down session cannot
                # emit a new alert after it is declared stopped.
                if not self._running:
                    return
                try:
                    self._on_result(path, result, self._detection_key(path, signature))
                except Exception as exc:
                    # An email, database, or webhook failure must never kill
                    # the scheduler and prevent later file scans.
                    audit_logger.warning(f"[YARA] Detection notification failed: {exc}")

    def _retry_after_scan_error(self, key: str, job: dict, path: str,
                                signature: tuple, result) -> None:
        """Retry a transiently locked/inaccessible file a bounded number of times."""
        with self._condition:
            if not self._running or key in self._pending:
                return
            retries = job["retry_count"] + 1
            if retries > config.YARA_MAX_RETRIES:
                audit_logger.warning(
                    "[YARA] Scan retries exhausted for %s: %s",
                    path, getattr(result, "error", "unknown scan error"),
                )
                return
            now = time.monotonic()
            self._pending[key] = {
                "path": path,
                "first_seen": now,
                "not_before": now + config.YARA_RETRY_SECONDS,
                "signature": signature,
                "stable_since": now,
                "retry_count": retries,
            }
            self._condition.notify()

    @classmethod
    def _detection_key(cls, path: str, signature: tuple) -> str:
        return f"{cls._key(path)}:{signature!r}"


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

    def __init__(self, session: TransferSession, alert_system=None,
                 notifier=None, yara_scanner: Optional[YaraScanner] = None):
        super().__init__()
        self.session = session
        self._yara = yara_scanner or YaraScanner.get()
        self._alert_system = alert_system or getattr(session, "alert_system", None)
        self._notifier = notifier or getattr(session, "notifier", None)
        # dedup dict: key = "path::event_type" → last event timestamp (monotonic)
        self._recent: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._scan_scheduler = _StableYaraScanScheduler(
            self._yara, self._on_stable_yara_result)

    def stop(self) -> None:
        """Stop outstanding delayed scans when its drive watcher stops."""
        self._scan_scheduler.stop()

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

    def _is_on_monitored_drive(self, path: str) -> bool:
        """Return whether the path remains inside this handler's USB volume."""
        if not path:
            return False
        try:
            root = os.path.normcase(os.path.abspath(self.session.drive_letter))
            candidate = os.path.normcase(os.path.abspath(path))
            root_drive = os.path.normcase(os.path.splitdrive(root)[0])
            candidate_drive = os.path.normcase(os.path.splitdrive(candidate)[0])
            if root_drive:
                return root_drive == candidate_drive
            return os.path.commonpath((root, candidate)) == root
        except (OSError, ValueError):
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

        # File-system de-duplication only controls database/log noise.  Every
        # create/modify signal refreshes the independent scan debouncer so a
        # write that continues inside the log de-dup window is not missed.
        self._scan_scheduler.schedule(path)
        if self._is_duplicate(path, "FILE_CREATED"):
            return

        size, sha256 = self._stat(path)
        print_info(f"[FILE CREATED]   {fname:<40} ({size:,} bytes)  "
                   f"{self.session.drive_letter}")
        self._log("FILE_CREATED", path, size, sha256)

    def _on_stable_yara_result(self, path: str, result,
                               detection_key: str) -> None:
        """Receive a completed background scan after the file has stabilized."""
        if result.matched:
            self._log_yara_detection(path, result, detection_key)

    def _log_yara_detection(self, path: str, result,
                            detection_key: str = "") -> None:
        """Persist and notify on a file threat without interrupting auditing."""
        session = self.session
        detail = (f"File: {os.path.basename(path)} | Rules: {', '.join(result.rule_names)} | "
                  f"Severity: {result.severity} | "
                  f"Details: {'; '.join(result.descriptions)}")
        try:
            db = get_db()
            db.log_event("YARA_THREAT_DETECTED", session.device_fp,
                         session.drive_letter, detail, result.severity)
            if result.severity in ("HIGH", "CRITICAL"):
                from types import SimpleNamespace
                device = SimpleNamespace(
                    fingerprint=session.device_fp,
                    description=session.description or "Monitored USB device",
                )
                db.log_violation(
                    "YARA_THREAT_DETECTED", device, result.severity,
                    "File logged for security review; device remains monitored",
                    detail,
                )
        except Exception as exc:
            # A database failure must not prevent the independent alert
            # channels below from reporting a confirmed YARA detection.
            audit_logger.warning(f"[YARA] Could not record detection: {exc}")

        try:
            if self._alert_system:
                self._alert_system.send_yara_alert(
                    path, result.rule_names, result.severity,
                    drive_letter=session.drive_letter,
                    device_fp=session.device_fp,
                    device_description=session.description,
                    vendor_id=session.vid,
                    product_id=session.pid,
                    serial=session.serial,
                    descriptions=result.descriptions,
                    categories=result.categories,
                    detection_key=detection_key,
                )
            else:
                audit_logger.warning(
                    "[YARA] Email alert skipped because no AlertSystem is attached: %s",
                    path,
                )
        except Exception as exc:
            audit_logger.warning(f"[YARA] Could not queue email alert: {exc}")

        try:
            notifier = self._notifier or get_notifier()
            notifier.send_yara_hit(
                path, result.rule_names, result.severity, session.device_fp)
        except Exception as exc:
            audit_logger.warning(f"[YARA] Could not queue webhook alert: {exc}")

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path  = event.src_path
        fname = os.path.basename(path)

        self._scan_scheduler.schedule(path)
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

        self._scan_scheduler.cancel(path)
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

        # Always cancel a source scan, even if logging this move is a
        # duplicate. A stale source path must never be left pending.
        self._scan_scheduler.cancel(src)
        if self._is_duplicate(src, "FILE_MOVED"):
            return

        # A source file may have been queued just before it was renamed or
        # moved.  Do not scan a now-invalid source path; enqueue the current
        # destination instead if it remains on the monitored volume.
        # Distinguish rename (same directory) from move (different directory)
        same_dir    = (os.path.dirname(src) == os.path.dirname(dst))
        event_type  = "FILE_RENAMED" if same_dir else "FILE_MOVED"

        if same_dir:
            print_info(f"[FILE RENAMED]   {fname:<20} → {dname:<20}  "
                       f"{self.session.drive_letter}")
        else:
            try:
                rel_src = os.path.relpath(src, self.session.drive_letter)
                rel_dst = os.path.relpath(dst, self.session.drive_letter)
            except ValueError:
                # Windows cannot form a relative path across volumes.
                rel_src, rel_dst = src, dst
            print_info(f"[FILE MOVED]     {rel_src} → {rel_dst}  "
                       f"{self.session.drive_letter}")

        self._log(event_type, src, dest_path=dst)
        if self._is_on_monitored_drive(dst):
            self._scan_scheduler.schedule(dst)


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

    def __init__(self, alert_system=None, notifier=None):
        # drive_letter (normalised, e.g. "E:\\") → (Observer, TransferSession)
        self._watchers: Dict[str, tuple] = {}
        self._handlers: Dict[str, FileAuditHandler] = {}
        self._lock = threading.Lock()
        self._alert_system = alert_system
        self._notifier = notifier

    def start_watching(
            self,
            drive_letter: str,
            device_fp:    str = "",
            vid:          str = "",
            pid:          str = "",
            serial:       str = "",
            description:  str = "",
            alert_system=None,
            notifier=None,
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

            active_alert_system = alert_system or self._alert_system
            active_notifier = notifier or self._notifier
            session             = TransferSession(
                drive, alert_system=active_alert_system,
                notifier=active_notifier)
            session.device_fp   = device_fp
            session.vid         = vid
            session.pid         = pid
            session.serial      = serial
            session.description = description

            handler  = FileAuditHandler(
                session, alert_system=active_alert_system,
                notifier=active_notifier)
            observer = Observer()
            observer.schedule(handler, path=drive, recursive=True)
            observer.start()
            self._watchers[drive] = (observer, session)
            self._handlers[drive] = handler

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
            handler = self._handlers.pop(drive, None)
            observer.stop()
            observer.join(timeout=5)
            if handler:
                handler.stop()

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
