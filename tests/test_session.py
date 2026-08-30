from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest

from secure_agent_gateway.approvals import ApprovalAuthority
from secure_agent_gateway.audit import AuditLog
from secure_agent_gateway.auth import Authenticator, PrincipalCredential
from secure_agent_gateway.gateway import SecureAgentGateway
from secure_agent_gateway.models import (
    Control,
    ExecutionContext,
    PolicyDecision,
    Principal,
)
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.rate_limit import RateLimit
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec
from secure_agent_gateway.session import (
    SequencePolicy,
    SequenceRule,
    SessionEvent,
    SessionSnapshot,
)

from tests.support import APPROVAL_KEY, AUTH_KEY, NOW, make_gateway, make_request, sign


def exfiltration_rule(*, window_events: int | None = None) -> SequenceRule:
    return SequenceRule(
        rule_id="customer-data-egress",
        target_tools=frozenset({"send_message"}),
        required_effects=frozenset({"data.customer"}),
        control=Control.DENY,
        reason_code="sequence.customer_data_egress",
        window_events=window_events,
    )


class SequencePolicyTests(unittest.TestCase):
    def test_base_denial_cannot_be_downgraded_to_approval(self) -> None:
        policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="approval-after-customer-read",
                    target_tools=frozenset({"send_message"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.REQUIRE_APPROVAL,
                    reason_code="sequence.customer_data_review",
                )
            ]
        )
        snapshot = SessionSnapshot(
            "agent-1",
            "session-1",
            (SessionEvent(1, "req-1", "read_customer", frozenset({"data.customer"})),),
        )
        base = PolicyDecision(
            control=Control.DENY,
            reason_codes=("network.host_denied",),
            evidence_fields=("arguments.destination",),
            request_digest="a" * 64,
            policy_version="test-policy",
        )
        request = make_request(
            request_id="req-2",
            nonce="nonce-2",
            tool="send_message",
            arguments={"destination": "https://denied.example.test"},
        )

        decision = policy.evaluate(request, snapshot, base)

        self.assertEqual(decision.control, Control.DENY)
        self.assertEqual(decision.reason_codes, base.reason_codes)
        self.assertEqual(decision.evidence_fields, base.evidence_fields)

    def test_base_denial_keeps_its_cause_when_sequence_also_denies(self) -> None:
        policy = SequencePolicy([exfiltration_rule()])
        snapshot = SessionSnapshot(
            "agent-1",
            "session-1",
            (SessionEvent(1, "req-1", "read_customer", frozenset({"data.customer"})),),
        )
        base = PolicyDecision(
            control=Control.DENY,
            reason_codes=("network.host_denied",),
            evidence_fields=("arguments.destination",),
            request_digest="a" * 64,
            policy_version="test-policy",
        )
        request = make_request(
            request_id="req-2",
            nonce="nonce-2",
            tool="send_message",
            arguments={"destination": "https://denied.example.test"},
        )

        decision = policy.evaluate(request, snapshot, base)

        self.assertEqual(decision.control, Control.DENY)
        self.assertEqual(decision.reason_codes, ("network.host_denied",))
        self.assertEqual(decision.evidence_fields, ("arguments.destination",))

    def test_base_approval_and_sequence_approval_keep_both_causes(self) -> None:
        policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="approval-after-customer-read",
                    target_tools=frozenset({"send_message"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.REQUIRE_APPROVAL,
                    reason_code="sequence.customer_data_review",
                )
            ]
        )
        snapshot = SessionSnapshot(
            "agent-1",
            "session-1",
            (SessionEvent(1, "req-1", "read_customer", frozenset({"data.customer"})),),
        )
        base = PolicyDecision(
            control=Control.REQUIRE_APPROVAL,
            reason_codes=("tool.approval_required",),
            evidence_fields=("tool",),
            request_digest="a" * 64,
            policy_version="test-policy",
        )
        request = make_request(
            request_id="req-2",
            nonce="nonce-2",
            tool="send_message",
            arguments={"destination": "https://external.example.test"},
        )

        decision = policy.evaluate(request, snapshot, base)

        self.assertEqual(decision.control, Control.REQUIRE_APPROVAL)
        self.assertEqual(
            decision.reason_codes,
            ("tool.approval_required", "sequence.customer_data_review"),
        )
        self.assertIn(
            "session.events.req-1.effects.data.customer",
            decision.evidence_fields,
        )

    def test_sequence_denial_strengthens_base_approval(self) -> None:
        policy = SequencePolicy([exfiltration_rule()])
        snapshot = SessionSnapshot(
            "agent-1",
            "session-1",
            (SessionEvent(1, "req-1", "read_customer", frozenset({"data.customer"})),),
        )
        base = PolicyDecision(
            control=Control.REQUIRE_APPROVAL,
            reason_codes=("tool.approval_required",),
            evidence_fields=("tool",),
            request_digest="a" * 64,
            policy_version="test-policy",
        )
        request = make_request(
            request_id="req-2",
            nonce="nonce-2",
            tool="send_message",
            arguments={"destination": "https://external.example.test"},
        )

        decision = policy.evaluate(request, snapshot, base)

        self.assertEqual(decision.control, Control.DENY)
        self.assertEqual(decision.reason_codes, ("sequence.customer_data_egress",))

    def test_prior_effect_blocks_later_sink_with_event_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                sequence_policy=SequencePolicy([exfiltration_rule()]),
            )
            read = make_request(tool="read_customer", arguments={})
            send = make_request(
                request_id="req-2",
                nonce="nonce-2",
                tool="send_message",
                arguments={"destination": "https://external.example.test/inbox"},
            )
            read_result = fixture.gateway.submit(sign(read), now=NOW)
            send_result = fixture.gateway.submit(sign(send), now=NOW + 1)
            records = fixture.audit.verify()
        self.assertEqual(read_result.status, "succeeded")
        self.assertEqual(send_result.error_code, "sequence.customer_data_egress")
        self.assertIn(
            "session.events.req-1.effects.data.customer",
            send_result.decision.evidence_fields,
        )
        self.assertEqual(records[1]["event"]["session_sequence"], 1)
        self.assertEqual(records[1]["event"]["emitted_effects"], ["data.customer"])

    def test_effects_do_not_cross_session_boundary(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                sequence_policy=SequencePolicy([exfiltration_rule()]),
            )
            read = make_request(tool="read_customer", arguments={}, session_id="session-1")
            send = make_request(
                request_id="req-2",
                nonce="nonce-2",
                tool="send_message",
                arguments={"destination": "https://external.example.test/inbox"},
                session_id="session-2",
            )
            fixture.gateway.submit(sign(read), now=NOW)
            result = fixture.gateway.submit(sign(send), now=NOW + 1)
        self.assertEqual(result.status, "succeeded")

    def test_failed_read_does_not_seed_sequence_rule(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                sequence_policy=SequencePolicy([exfiltration_rule()]),
            )
            failed_read = make_request(tool="broken_sensitive_read", arguments={})
            send = make_request(
                request_id="req-2",
                nonce="nonce-2",
                tool="send_message",
                arguments={"destination": "https://external.example.test/inbox"},
            )
            failed = fixture.gateway.submit(sign(failed_read), now=NOW)
            result = fixture.gateway.submit(sign(send), now=NOW + 1)
        self.assertEqual(failed.status, "execution_failed")
        self.assertEqual(result.status, "succeeded")

    def test_window_excludes_an_older_effect(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(
                Path(directory),
                sequence_policy=SequencePolicy([exfiltration_rule(window_events=1)]),
            )
            requests = [
                make_request(tool="read_customer", arguments={}),
                make_request(request_id="req-2", nonce="nonce-2"),
                make_request(
                    request_id="req-3",
                    nonce="nonce-3",
                    tool="send_message",
                    arguments={"destination": "https://external.example.test/inbox"},
                ),
            ]
            results = [
                fixture.gateway.submit(sign(request), now=NOW + index)
                for index, request in enumerate(requests)
            ]
        self.assertEqual([result.status for result in results], ["succeeded"] * 3)

    def test_intervening_success_invalidates_pending_approval(self) -> None:
        with TemporaryDirectory() as directory:
            fixture = make_gateway(Path(directory))
            pending_request = make_request(
                tool="post_results",
                arguments={
                    "destination": "https://research.example.test/results",
                    "payload": {"result": "accepted"},
                },
            )
            pending = fixture.gateway.submit(sign(pending_request), now=NOW)
            receipt = fixture.approvals.issue(
                pending.decision,
                approver_id="reviewer-1",
                now=NOW + 1,
            )
            other = make_request(request_id="req-2", nonce="nonce-2")
            fixture.gateway.submit(sign(other), now=NOW + 2)
            result = fixture.gateway.resume(pending_request.request_id, receipt, now=NOW + 3)
        self.assertEqual(result.error_code, "approval.context_changed")

    def test_session_lock_serialises_effect_commit_before_sink_policy(self) -> None:
        read_started = Event()
        release_read = Event()
        principal = Principal("agent-1", frozenset({"researcher"}))
        registry = ToolRegistry()

        def read_handler(arguments, context: ExecutionContext):
            read_started.set()
            release_read.wait(timeout=2)
            return {"record": "fixture"}

        registry.register(
            ToolSpec(
                "read_customer",
                {},
                frozenset({"researcher"}),
                emitted_effects=frozenset({"data.customer"}),
            ),
            read_handler,
        )
        registry.register(
            ToolSpec(
                "send_message",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
                rate_limit=RateLimit(5, 60),
            ),
            lambda arguments, context: {"sent": True},
        )
        with TemporaryDirectory() as directory:
            gateway = SecureAgentGateway(
                authenticator=Authenticator(
                    {
                        "agent-key": PrincipalCredential(
                            "agent-key",
                            principal,
                            AUTH_KEY,
                        )
                    }
                ),
                policy=PolicyEngine(registry, policy_version="sequence-race-test"),
                approvals=ApprovalAuthority(APPROVAL_KEY, {"reviewer-1"}),
                audit_log=AuditLog(Path(directory) / "audit.jsonl"),
                sequence_policy=SequencePolicy([exfiltration_rule()]),
            )
            outcomes: dict[str, str] = {}
            read_request = make_request(tool="read_customer", arguments={})
            send_request = make_request(
                request_id="req-2",
                nonce="nonce-2",
                tool="send_message",
                arguments={"destination": "external"},
            )
            read_thread = Thread(
                target=lambda: outcomes.setdefault(
                    "read",
                    gateway.submit(sign(read_request), now=NOW).status,
                )
            )
            send_thread = Thread(
                target=lambda: outcomes.setdefault(
                    "send",
                    gateway.submit(sign(send_request), now=NOW + 1).status,
                )
            )
            read_thread.start()
            self.assertTrue(read_started.wait(timeout=1))
            send_thread.start()
            release_read.set()
            read_thread.join(timeout=2)
            send_thread.join(timeout=2)
        self.assertEqual(outcomes, {"read": "succeeded", "send": "denied"})

    def test_removed_rule_allows_the_same_composed_action(self) -> None:
        policy = SequencePolicy([exfiltration_rule()])
        self.assertEqual(policy.without_rule("customer-data-egress").rules, ())

    def test_sequence_policy_rejects_unknown_registry_references(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolSpec("search_docs", {}, frozenset({"researcher"})),
            lambda arguments, context: None,
        )
        with self.assertRaisesRegex(ValueError, "unknown tools or effects"):
            SequencePolicy([exfiltration_rule()]).validate_registry(registry)


if __name__ == "__main__":
    unittest.main()
