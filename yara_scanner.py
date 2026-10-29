"""Optional, resilient YARA scanning for files created on USB volumes."""

import os
import threading
from dataclasses import dataclass, field
from typing import List, Optional

import config
from logger_setup import audit_logger, print_alert, print_info, print_warn

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:  # Optional dependency: monitoring must still start.
    yara = None
    YARA_AVAILABLE = False


@dataclass
class YaraScanResult:
    file_path: str
    matched: bool = False
    rule_names: List[str] = field(default_factory=list)
    severity: str = "INFO"
    descriptions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    # The file auditor uses these fields to retry transiently locked files
    # without treating an inaccessible scan as a clean result.
    error: Optional[str] = None
    retryable: bool = False

    @property
    def summary(self) -> str:
        if not self.matched:
            return f"CLEAN: {os.path.basename(self.file_path)}"
        return (f"YARA HIT [{self.severity}]: {os.path.basename(self.file_path)} | "
                f"Rules: {', '.join(self.rule_names)}")


class YaraScanner:
    """Thread-safe shared scanner which compiles its rules once."""

    _instance: Optional["YaraScanner"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._rules = None
        self._enabled = False
        self._rules_path = config.YARA_RULES_FILE
        self._load_rules()

    @classmethod
    def get(cls) -> "YaraScanner":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @property
    def is_enabled(self) -> bool:
        return self._enabled and self._rules is not None

    def _load_rules(self) -> None:
        if not config.YARA_ENABLED:
            audit_logger.info("[YARA] File scanning disabled by configuration.")
            return
        if not YARA_AVAILABLE:
            print_warn("[YARA] yara-python is not installed; file scanning is disabled.")
            return
        if not os.path.isfile(self._rules_path):
            print_warn(f"[YARA] Rules file not found: {self._rules_path}")
            return
        try:
            self._rules = yara.compile(filepath=self._rules_path)
            self._enabled = True
            print_info(f"[YARA] Scanner ready: {self._rules_path}")
        except Exception as exc:
            audit_logger.warning(f"[YARA] Rule compilation failed: {exc}")
            self._rules = None

    def reload_rules(self) -> bool:
        """Recompile configured rules without restarting USB monitoring."""
        self._rules = None
        self._enabled = False
        self._rules_path = config.YARA_RULES_FILE
        self._load_rules()
        return self.is_enabled

    def scan(self, file_path: str) -> YaraScanResult:
        """Scan one file and always return a result instead of raising."""
        result = YaraScanResult(file_path=file_path)
        if not self.is_enabled:
            return result

        try:
            size = os.path.getsize(file_path)
            max_size = max(0, config.YARA_MAX_FILE_SIZE_MB) * 1024 * 1024
            if size == 0 or size > max_size:
                audit_logger.debug(f"[YARA] Skipped file outside scan limit: {file_path}")
                return result
        except OSError as exc:
            result.error = f"File unavailable: {exc}"
            result.retryable = True
            audit_logger.debug(f"[YARA] File unavailable before scan: {file_path}")
            return result

        try:
            matches = self._rules.match(file_path, timeout=10)
        except Exception as exc:
            # yara-python uses specialised timeout/error types, but catching
            # broadly keeps optional scanning from ever stopping monitoring.
            audit_logger.warning(f"[YARA] Scan failed for {file_path}: {exc}")
            result.error = str(exc)
            result.retryable = True
            return result

        if not matches:
            return result

        result.matched = True
        severity_rank = {"INFO": 0, "HIGH": 1, "CRITICAL": 2}
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            severity = str(meta.get("severity", "HIGH")).upper()
            if severity not in severity_rank:
                severity = "HIGH"
            result.rule_names.append(str(getattr(match, "rule", "unknown")))
            result.descriptions.append(str(meta.get("description", match.rule)))
            result.categories.append(str(meta.get("category", "unknown")))
            if severity_rank[severity] > severity_rank[result.severity]:
                result.severity = severity

        self._apply_double_extension_check(result)
        audit_logger.warning(result.summary)
        (print_alert if result.severity == "CRITICAL" else print_warn)(
            f"[YARA] {result.summary}")
        return result

    @staticmethod
    def _apply_double_extension_check(result: YaraScanResult) -> None:
        """Escalate a PE whose filename uses a deceptive double extension."""
        if "PE_Executable" not in result.rule_names:
            return
        parts = os.path.basename(result.file_path).lower().split(".")
        dangerous = {"exe", "dll", "sys", "scr", "com"}
        if len(parts) >= 3 and parts[-1] in dangerous:
            result.severity = "CRITICAL"
            result.descriptions.append(
                f"Double extension masquerade: {os.path.basename(result.file_path)}")
            result.categories.append("masquerade")
