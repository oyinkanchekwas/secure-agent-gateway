from __future__ import annotations

from dataclasses import replace
import unittest

from secure_agent_gateway.models import Control, ExecutionContext, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule
from secure_agent_gateway.trajectory import (
    PairedTrajectoryContract,
    SequenceMutationAnalyser,
    TrajectoryCase,
    TrajectoryContractRunner,
)

from tests.support import make_request


def no_op(arguments, context: ExecutionContext):
    return None


class TrajectoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.principal = Principal("agent-1", frozenset({"researcher"}))
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                "read_customer",
                {},
                frozenset({"researcher"}),
                emitted_effects=frozenset({"data.customer"}),
            ),
            no_op,
        )
        registry.register(
            ToolSpec(
                "read_public",
                {},
                frozenset({"researcher"}),
                emitted_effects=frozenset({"data.public"}),
            ),
            no_op,
        )
        registry.register(
            ToolSpec(
                "search_docs",
                {"query": FieldSpec("string")},
                frozenset({"researcher"}),
            ),
            no_op,
        )
        registry.register(
            ToolSpec(
                "send_message",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
            ),
            no_op,
        )
        self.policy = PolicyEngine(registry, policy_version="trajectory-test")
        self.sequence_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="customer-data-egress",
                    target_tools=frozenset({"send_message"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.DENY,
                    reason_code="sequence.customer_data_egress",
                )
            ]
        )

    def contract(self) -> PairedTrajectoryContract:
        prohibited = TrajectoryCase(
            case_id="customer-egress-prohibited",
            requests=(
                make_request(
                    request_id="prohibited-read",
                    nonce="prohibited-nonce-1",
                    tool="read_customer",
                    arguments={},
                ),
                make_request(
                    request_id="prohibited-search",
                    nonce="prohibited-nonce-2",
                    tool="search_docs",
                    arguments={"query": "contact record"},
                ),
                make_request(
                    request_id="prohibited-send",
                    nonce="prohibited-nonce-3",
                    tool="send_message",
                    arguments={"destination": "https://external.example.test/inbox"},
                ),
            ),
            expected_controls=(Control.ALLOW, Control.ALLOW, Control.DENY),
            expected_first_intervention=2,
            required_evidence_fields=(
                "session.events.prohibited-read.effects.data.customer",
                "tool",
            ),
        )
        permitted = TrajectoryCase(
            case_id="public-egress-permitted",
            requests=(
                make_request(
                    request_id="permitted-read",
                    nonce="permitted-nonce-1",
                    tool="read_public",
                    arguments={},
                ),
                make_request(
                    request_id="permitted-search",
                    nonce="permitted-nonce-2",
                    tool="search_docs",
                    arguments={"query": "contact record"},
                ),
                make_request(
                    request_id="permitted-send",
                    nonce="permitted-nonce-3",
                    tool="send_message",
                    arguments={"destination": "https://external.example.test/inbox"},
                ),
            ),
            expected_controls=(Control.ALLOW, Control.ALLOW, Control.ALLOW),
            expected_first_intervention=None,
        )
        return PairedTrajectoryContract(
            contract_id="customer-egress-pair",
            policy_family="effect_to_sink",
            principal=self.principal,
            prohibited=prohibited,
            permitted=permitted,
            changed_fields=("requests.0.tool",),
        )

    def test_controlled_trajectory_pair_passes_default_gates(self) -> None:
        report = TrajectoryContractRunner(self.policy, self.sequence_policy).run(
            [self.contract()]
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.metrics["unsafe_sequence_prevention"], 1.0)
        self.assertEqual(report.metrics["permitted_trajectory_completion"], 1.0)
        self.assertEqual(report.metrics["first_intervention_accuracy"], 1.0)
        self.assertEqual(report.metrics["unnecessary_intervention_rate"], 0.0)

    def test_pair_rejects_an_undeclared_change(self) -> None:
        contract = self.contract()
        changed_permitted = replace(
            contract.permitted,
            requests=(
                *contract.permitted.requests[:1],
                replace(
                    contract.permitted.requests[1],
                    arguments={"query": "different query"},
                ),
                contract.permitted.requests[2],
            ),
        )
        with self.assertRaisesRegex(ValueError, "changed_fields"):
            replace(contract, permitted=changed_permitted)

    def test_pair_rejects_a_different_session_handle(self) -> None:
        contract = self.contract()
        changed_permitted = replace(
            contract.permitted,
            requests=tuple(
                replace(request, session_id="another-session")
                for request in contract.permitted.requests
            ),
        )
        with self.assertRaisesRegex(ValueError, "same session handle"):
            replace(contract, permitted=changed_permitted)

    def test_prohibited_trajectory_requires_causal_evidence(self) -> None:
        contract = self.contract()
        without_evidence = replace(
            contract.prohibited,
            required_evidence_fields=(),
        )
        with self.assertRaisesRegex(ValueError, "require causal evidence"):
            replace(contract, prohibited=without_evidence)

    def test_case_must_end_at_first_intervention(self) -> None:
        with self.assertRaisesRegex(ValueError, "must end"):
            TrajectoryCase(
                case_id="invalid",
                requests=(
                    make_request(),
                    make_request(request_id="req-2", nonce="nonce-2"),
                ),
                expected_controls=(Control.DENY, Control.ALLOW),
                expected_first_intervention=0,
            )

    def test_missing_evidence_fails_the_trajectory_gate(self) -> None:
        contract = self.contract()
        prohibited = replace(
            contract.prohibited,
            required_evidence_fields=("session.events.unknown.effects.data.customer",),
        )
        report = TrajectoryContractRunner(self.policy, self.sequence_policy).run(
            [replace(contract, prohibited=prohibited)]
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.metrics["evidence_coverage"], 0.0)

    def test_mutation_analysis_kills_disabled_weakened_and_short_window_rules(self) -> None:
        report = SequenceMutationAnalyser(self.policy, self.sequence_policy).run(
            [self.contract()]
        )
        self.assertEqual(report.mutation_score, 1.0)
        self.assertEqual(report.killed, 3)
        self.assertEqual(report.survived, 0)
        self.assertEqual(
            {outcome.mutation for outcome in report.outcomes},
            {"disabled", "control_weakened", "history_window_reduced"},
        )

    def test_mutation_analysis_rejects_a_failing_baseline(self) -> None:
        with self.assertRaisesRegex(ValueError, "baseline trajectory contracts"):
            SequenceMutationAnalyser(self.policy, SequencePolicy(())).run(
                [self.contract()]
            )

    def test_policy_digest_changes_when_a_rule_changes(self) -> None:
        reduced = SequencePolicy(
            [replace(self.sequence_policy.rules[0], window_events=1)]
        )
        self.assertNotEqual(self.sequence_policy.digest, reduced.digest)

    def test_unknown_rule_cannot_be_removed_silently(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown sequence rule"):
            self.sequence_policy.without_rule("missing")


if __name__ == "__main__":
    unittest.main()
