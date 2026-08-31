from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
import unittest

from secure_agent_gateway.models import Control
from secure_agent_gateway.session import (
    InMemorySessionStore,
    SequencePolicy,
    SequenceRule,
)

from tests.support import NOW, make_gateway, make_request, sign


class SecureAgentGatewayTests(unittest.TestCase):
    def test_transaction_exit_failure_has_no_success_record(self) -> None:
        class ExitFailureStore(InMemorySessionStore):
            @contextmanager
            def serialise(self, principal_id, session_id):
                with super().serialise(principal_id, session_id):
                    yield
                raise RuntimeError("commit failed")

        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                session_store=ExitFailureStore(),
            )
            result = fixture.gateway.submit(sign(make_request()), now=NOW)
            statuses = [
                record["event"]["status"] for record in fixture.audit.verify()
            ]

        self.assertEqual(result.status, "execution_uncertain")
        self.assertEqual(result.error_code, "state.commit_failed")
        self.assertEqual(len(fixture.calls), 1)
        self.assertEqual(statuses, ["execution_started", "execution_uncertain"])

    def test_transaction_entry_failure_denies_before_adapter_execution(self) -> None:
        class EntryFailureStore(InMemorySessionStore):
            @contextmanager
            def serialise(self, principal_id, session_id):
                del principal_id, session_id
                raise RuntimeError("state unavailable")
                yield

        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                session_store=EntryFailureStore(),
            )
            result = fixture.gateway.submit(sign(make_request()), now=NOW)

        self.assertEqual(result.status, "denied")
        self.assertEqual(result.error_code, "state.unavailable")
        self.assertEqual(fixture.calls, [])

    def test_approval_resume_reports_transaction_exit_failure(self) -> None:
        class ExitFailureStore(InMemorySessionStore):
            @contextmanager
            def serialise(self, principal_id, session_id):
                with super().serialise(principal_id, session_id):
                    yield
                raise RuntimeError("commit failed")

        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(
                base,
                session_store=ExitFailureStore(),
            )
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            result = fixture.gateway.resume(
                request.request_id,
                receipt,
                now=NOW + 2,
            )
            statuses = [
                record["event"]["status"] for record in fixture.audit.verify()
            ]

        self.assertEqual(pending.status, "pending_approval")
        self.assertEqual(result.status, "execution_uncertain")
        self.assertEqual(result.approval_id, receipt.approval_id)
        self.assertEqual(statuses[-2:], ["execution_started", "execution_uncertain"])
        self.assertNotIn("succeeded", statuses)

    def test_state_commit_failure_reports_an_uncertain_execution(self) -> None:
        class FailingCommitStore(InMemorySessionStore):
            def record_success(self, *args, **kwargs):
                raise RuntimeError("state unavailable")

        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                session_store=FailingCommitStore(),
            )
            result = fixture.gateway.submit(sign(make_request()), now=NOW)
            records = fixture.audit.verify()

        self.assertEqual(result.status, "execution_uncertain")
        self.assertEqual(result.error_code, "state.commit_failed")
        self.assertEqual(len(fixture.calls), 1)
        self.assertEqual(records[-1]["event"]["status"], "execution_uncertain")
        self.assertNotIn("state unavailable", str(records))

    def test_sequence_approval_cannot_override_host_denial(self) -> None:
        sequence_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="review-customer-data-post",
                    target_tools=frozenset({"post_results"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.REQUIRE_APPROVAL,
                    reason_code="sequence.customer_data_review",
                )
            ]
        )
        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                sequence_policy=sequence_policy,
            )
            read = make_request(tool="read_customer", arguments={})
            fixture.gateway.submit(sign(read), now=NOW)
            post = make_request(
                request_id="req-2",
                nonce="nonce-2",
                tool="post_results",
                arguments={
                    "destination": "https://denied.example.test/results",
                    "payload": {"result": "fixture"},
                },
            )
            result = fixture.gateway.submit(sign(post), now=NOW + 1)

        self.assertEqual(result.status, "denied")
        self.assertEqual(result.error_code, "network.host_denied")
        self.assertEqual(len(fixture.calls), 1)

    def test_allowed_call_executes_registered_adapter(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            result = fixture.gateway.submit(sign(make_request()), now=NOW)
            statuses = [record["event"]["status"] for record in fixture.audit.verify()]
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.output, {"tool": "search_docs", "accepted": True})
        self.assertEqual(len(fixture.calls), 1)
        self.assertEqual(statuses, ["execution_started", "succeeded"])

    def test_denied_path_never_reaches_adapter(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            request = make_request(
                tool="delete_file",
                arguments={"path": "/tmp/outside.txt"},
            )
            result = fixture.gateway.submit(sign(request), now=NOW)
        self.assertEqual(result.status, "denied")
        self.assertEqual(result.error_code, "path.outside_allowed_root")
        self.assertEqual(fixture.calls, [])

    def test_destructive_call_executes_after_bound_approval(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
                approval_id="approval-1",
            )
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
        self.assertEqual(pending.status, "pending_approval")
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.approval_id, "approval-1")
        self.assertEqual(len(fixture.calls), 1)

    def test_invalid_approval_keeps_adapter_blocked(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            changed = replace(receipt, request_digest="b" * 64)
            result = fixture.gateway.resume(request.request_id, changed, now=NOW + 2)
        self.assertEqual(result.status, "denied")
        self.assertEqual(result.error_code, "approval.invalid_signature")
        self.assertEqual(fixture.calls, [])

    def test_pending_call_executes_once_under_competing_approvals(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipts = [
                fixture.approvals.issue(
                    pending.decision,
                    approver_id="reviewer-1",
                    now=NOW + 1,
                    approval_id=f"approval-{index}",
                )
                for index in (1, 2)
            ]
            barrier = Barrier(2)
            outcomes: list[str] = []

            def resume(receipt) -> None:
                barrier.wait()
                try:
                    result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
                except KeyError:
                    outcomes.append("unavailable")
                else:
                    outcomes.append(result.status)

            threads = [Thread(target=resume, args=(receipt,)) for receipt in receipts]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertCountEqual(outcomes, ["succeeded", "unavailable"])
        self.assertEqual(len(fixture.calls), 1)

    def test_duplicate_request_id_cannot_replace_pending_call(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            first = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "one.txt")},
            )
            fixture.gateway.submit(sign(first), now=NOW)
            second = make_request(
                request_id=first.request_id,
                nonce="nonce-2",
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "two.txt")},
            )
            result = fixture.gateway.submit(sign(second), now=NOW + 1)
        self.assertEqual(result.error_code, "request.duplicate_id")
        self.assertEqual(fixture.calls, [])

    def test_mutating_original_arguments_does_not_change_pending_call(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            original_path = str(base / "workspace" / "one.txt")
            arguments = {"path": original_path}
            request = make_request(tool="delete_file", arguments=arguments)
            pending = fixture.gateway.submit(sign(request), now=NOW)
            arguments["path"] = str(base / "workspace" / "two.txt")
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(fixture.calls[0][1]["path"], original_path)

    def test_policy_change_invalidates_pending_approval(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            fixture.policy.policy_version = "policy-2026-08-30-revised"
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
        self.assertEqual(result.error_code, "approval.policy_changed")
        self.assertEqual(fixture.calls, [])

    def test_path_is_rechecked_after_approval(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            inside = workspace / "inside"
            outside = base / "outside"
            inside.mkdir(parents=True)
            outside.mkdir()
            link = workspace / "current"
            link.symlink_to(inside, target_is_directory=True)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(link / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            link.unlink()
            link.symlink_to(outside, target_is_directory=True)
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
        self.assertEqual(result.error_code, "path.outside_allowed_root")
        self.assertEqual(fixture.calls, [])

    def test_replayed_signed_request_is_denied(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            envelope = sign(make_request())
            first = fixture.gateway.submit(envelope, now=NOW)
            second = fixture.gateway.submit(envelope, now=NOW + 1)
        self.assertEqual(first.status, "succeeded")
        self.assertEqual(second.error_code, "auth.replayed_nonce")
        self.assertEqual(len(fixture.calls), 1)

    def test_oversized_unauthenticated_arguments_are_not_written_to_audit(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            request = make_request(arguments={"query": "x" * 70_000})
            result = fixture.gateway.submit(sign(request), now=NOW)
            records = fixture.audit.verify()
        self.assertEqual(result.error_code, "auth.request_too_large")
        self.assertEqual(records[-1]["event"]["arguments"], "[UNTRUSTED]")

    def test_server_credential_stays_out_of_audit_after_adapter_use(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="post_results",
                arguments={
                    "destination": "https://research.example.test/results",
                    "payload": {"result": "accepted"},
                },
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 2)
            audit_text = (base / "audit.jsonl").read_text(encoding="utf-8")
            audit_records = fixture.audit.verify()
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(fixture.calls[0][2], "fixture-service-value")
        self.assertEqual(fixture.calls[0][1]["payload"], {"result": "accepted"})
        self.assertNotIn("fixture-service-value", audit_text)
        self.assertNotIn("accepted", audit_text)
        self.assertTrue(
            all(record["event"]["arguments"]["payload"] == "[REDACTED]" for record in audit_records)
        )

    def test_adapter_error_is_reported_without_exception_text(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(tool="broken_adapter", arguments={})
            result = fixture.gateway.submit(sign(request), now=NOW)
            raw = (base / "audit.jsonl").read_text(encoding="utf-8")
        self.assertEqual(result.status, "execution_failed")
        self.assertEqual(result.error_code, "adapter.failure")
        self.assertNotIn("adapter broke", raw)

    def test_expired_pending_call_is_removed(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(
                tool="delete_file",
                arguments={"path": str(base / "workspace" / "old.txt")},
            )
            pending = fixture.gateway.submit(sign(request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                ttl_seconds=300,
                now=NOW + 1,
            )
            result = fixture.gateway.resume(request.request_id, receipt, now=NOW + 121)
        self.assertEqual(result.error_code, "approval.pending_expired")
        self.assertEqual(fixture.calls, [])

    def test_malformed_arguments_are_denied_and_audited(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = make_gateway(base)
            request = make_request(arguments=[])  # type: ignore[arg-type]
            result = fixture.gateway.submit(sign(request), now=NOW)
            record = fixture.audit.verify()[0]
        self.assertEqual(result.status, "denied")
        self.assertEqual(result.error_code, "auth.invalid_request_shape")
        self.assertEqual(record["event"]["arguments"], "[UNTRUSTED]")


if __name__ == "__main__":
    unittest.main()
