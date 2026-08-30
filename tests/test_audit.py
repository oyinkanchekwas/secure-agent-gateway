from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from secure_agent_gateway.audit import AuditIntegrityError, AuditLog


class AuditLogTests(unittest.TestCase):
    def test_records_are_redacted_and_hash_chained(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = AuditLog(path)
            audit.append(
                {"arguments": {"query": "ok", "api_key": "private-value"}},
                timestamp=10,
            )
            audit.append({"status": "succeeded"}, timestamp=11)
            records = audit.verify()
            raw = path.read_text(encoding="utf-8")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["event"]["arguments"]["api_key"], "[REDACTED]")
        self.assertNotIn("private-value", raw)
        self.assertEqual(records[1]["previous_hash"], records[0]["event_hash"])

    def test_tampering_is_detected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = AuditLog(path)
            audit.append({"status": "succeeded"}, timestamp=10)
            record = json.loads(path.read_text(encoding="utf-8"))
            record["event"]["status"] = "denied"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditIntegrityError, "audit.hash_mismatch"):
                audit.verify()

    def test_reopened_log_continues_existing_chain(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            AuditLog(path).append({"status": "first"}, timestamp=10)
            reopened = AuditLog(path)
            event_id = reopened.append({"status": "second"}, timestamp=11)
            records = reopened.verify()
        self.assertEqual(event_id, "audit-00000002")
        self.assertEqual(len(records), 2)

    def test_non_object_record_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditIntegrityError, "audit.invalid_record"):
                AuditLog(path)


if __name__ == "__main__":
    unittest.main()
