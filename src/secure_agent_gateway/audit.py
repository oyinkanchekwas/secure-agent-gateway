from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from threading import Lock
from typing import Any, Mapping

from secure_agent_gateway.auth import canonical_json


class AuditIntegrityError(ValueError):
    pass


_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = re.compile(
    r"^(?:access[_-]?token|api[_-]?key|authorization|credential|password|secret|token)$",
    re.IGNORECASE,
)


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _REDACTED if _SENSITIVE_KEYS.match(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[INVALID_NUMBER]"
    return f"[UNSUPPORTED:{type(value).__name__}]"


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch(mode=0o600)
        self._lock = Lock()
        self._sequence = 0
        self._last_hash = "0" * 64
        if self.path.exists() and self.path.stat().st_size:
            records = self.verify()
            self._sequence = records[-1]["sequence"]
            self._last_hash = records[-1]["event_hash"]

    def append(self, event: Mapping[str, Any], *, timestamp: int) -> str:
        with self._lock:
            sequence = self._sequence + 1
            event_id = f"audit-{sequence:08d}"
            record = {
                "event_id": event_id,
                "sequence": sequence,
                "timestamp": timestamp,
                "previous_hash": self._last_hash,
                "event": redact(dict(event)),
            }
            record["event_hash"] = _record_hash(record)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._sequence = sequence
            self._last_hash = record["event_hash"]
            return event_id

    def verify(self) -> list[dict[str, Any]]:
        previous_hash = "0" * 64
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for expected_sequence, line in enumerate(handle, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError("audit.invalid_json") from exc
                if not isinstance(record, Mapping):
                    raise AuditIntegrityError("audit.invalid_record")
                if record.get("sequence") != expected_sequence:
                    raise AuditIntegrityError("audit.sequence_gap")
                if record.get("previous_hash") != previous_hash:
                    raise AuditIntegrityError("audit.chain_broken")
                observed_hash = record.get("event_hash")
                if not isinstance(observed_hash, str) or observed_hash != _record_hash(record):
                    raise AuditIntegrityError("audit.hash_mismatch")
                previous_hash = observed_hash
                records.append(record)
        return records


def _record_hash(record: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
