from __future__ import annotations

import unittest

from secure_agent_gateway.model_checking import (
    BoundedMutationAnalyser,
    BoundedRelationalChecker,
    FlowRequirement,
    InvocationTemplate,
)
from secure_agent_gateway.models import Control, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule


class BoundedRelationalCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = ToolRegistry()
        for name, effects in (
            ("read_customer", frozenset({"data.customer"})),
            ("read_secret", frozenset({"data.secret"})),
            ("search_docs", frozenset()),
            ("send_message", frozenset()),
            ("post_results", frozenset()),
        ):
            registry.register(
                ToolSpec(
                    name=name,
                    fields={},
                    allowed_roles=frozenset({"researcher"}),
                    emitted_effects=effects,
                ),
                lambda arguments, context: {"accepted": True},
            )
        self.policy = PolicyEngine(registry, policy_version="bounded-test")
        self.sequence_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="customer-secret-egress",
                    target_tools=frozenset({"send_message", "post_results"}),
                    required_effects=frozenset({"data.customer", "data.secret"}),
                    control=Control.DENY,
                    reason_code="sequence.customer_secret_egress",
                )
            ]
        )
        self.principal = Principal("agent-1", frozenset({"researcher"}))
        self.templates = (
            InvocationTemplate("customer", "read_customer", {}),
            InvocationTemplate("secret", "read_secret", {}),
            InvocationTemplate("harmless", "search_docs", {}),
            InvocationTemplate("message", "send_message", {}),
            InvocationTemplate("post", "post_results", {}),
        )
        self.requirements = (
            FlowRequirement(
                requirement_id="customer-secret-egress",
                source_effects=frozenset({"data.customer", "data.secret"}),
                sink_tools=frozenset({"send_message", "post_results"}),
                expected_control=Control.DENY,
            ),
        )

    def test_checker_covers_relational_boundary_and_evidence(self) -> None:
        report = BoundedRelationalChecker(
            self.policy,
            self.sequence_policy,
        ).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_events=3,
        )

        self.assertTrue(report.passed)
        self.assertEqual(report.metrics["exact_control_conformance"], 1.0)
        self.assertEqual(report.metrics["relational_boundary_coverage"], 1.0)
        self.assertEqual(report.counterexamples, ())
        self.assertEqual(len(report.boundaries), 1)
        self.assertEqual(report.boundaries[0].changed_index, 1)

    def test_missing_rule_returns_a_shortest_safety_counterexample(self) -> None:
        report = BoundedRelationalChecker(
            self.policy,
            SequencePolicy(()),
        ).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_events=3,
        )

        self.assertFalse(report.passed)
        counterexample = next(
            item for item in report.counterexamples if item.property_name == "safety"
        )
        self.assertEqual(len(counterexample.trace), 3)
        self.assertEqual(counterexample.actual_control, Control.ALLOW)

    def test_suite_rejects_a_template_denied_by_single_call_policy(self) -> None:
        denied = InvocationTemplate("missing-role", "send_message", {})
        principal = Principal("agent-2", frozenset({"viewer"}))

        with self.assertRaisesRegex(ValueError, "must pass single-call policy"):
            BoundedRelationalChecker(self.policy, self.sequence_policy).run(
                principal=principal,
                templates=(*self.templates, denied),
                requirements=self.requirements,
                max_events=3,
            )

    def test_search_limit_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds max_decisions"):
            BoundedRelationalChecker(self.policy, self.sequence_policy).run(
                principal=self.principal,
                templates=self.templates,
                requirements=self.requirements,
                max_events=3,
                max_decisions=4,
            )

    def test_independent_oracle_kills_every_supported_policy_mutant(self) -> None:
        report = BoundedMutationAnalyser(
            self.policy,
            self.sequence_policy,
        ).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_events=3,
        )

        self.assertEqual(report.mutation_score, 1.0)
        self.assertEqual(report.survived, 0)
        self.assertGreaterEqual(report.killed, 7)
        self.assertTrue(all(outcome.counterexample for outcome in report.outcomes))


if __name__ == "__main__":
    unittest.main()
