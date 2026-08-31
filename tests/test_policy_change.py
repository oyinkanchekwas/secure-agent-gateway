from __future__ import annotations

from dataclasses import replace
import unittest

from secure_agent_gateway.model_checking import FlowRequirement, InvocationTemplate
from secure_agent_gateway.models import Control, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.policy_change import (
    PolicyChangeAttestor,
    PolicyChangeChecker,
    PolicyChangeDecision,
)
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule


class PolicyChangeCheckerTests(unittest.TestCase):
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
        self.policy = PolicyEngine(registry, policy_version="change-test")
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
        self.complete = self._policy(
            tools=frozenset({"send_message", "post_results"}),
            effects=frozenset({"data.customer", "data.secret"}),
            control=Control.DENY,
        )

    def test_candidate_can_repair_a_missing_sink_without_hiding_baseline_failure(self) -> None:
        baseline = self._policy(
            tools=frozenset({"send_message"}),
            effects=frozenset({"data.customer", "data.secret"}),
            control=Control.DENY,
        )

        report = self._run(baseline, self.complete)

        self.assertTrue(report.passed)
        self.assertLess(
            report.baseline_metrics["unsafe_action_prevention"],
            report.candidate_metrics["unsafe_action_prevention"],
        )
        self.assertEqual(report.regression_witnesses, ())
        self.assertTrue(report.baseline_witnesses)
        self.assertEqual(report.candidate_witnesses, ())
        safety = next(
            item for item in report.correction_witnesses if item.property_name == "safety"
        )
        self.assertEqual(safety.requirement_id, "customer-secret-egress")
        self.assertEqual(len(safety.trace), 3)
        self.assertEqual(safety.trace[-1], "post")

    def test_removed_sink_is_a_safety_regression_with_a_shortest_witness(self) -> None:
        candidate = self._policy(
            tools=frozenset({"send_message"}),
            effects=frozenset({"data.customer", "data.secret"}),
            control=Control.DENY,
        )

        report = self._run(self.complete, candidate)

        self.assertFalse(report.passed)
        self.assertTrue(report.candidate_witnesses)
        safety = next(
            item for item in report.regression_witnesses if item.property_name == "safety"
        )
        self.assertEqual(len(safety.trace), 3)
        self.assertEqual(safety.trace[-1], "post")
        self.assertEqual(safety.baseline_control, Control.DENY)
        self.assertEqual(safety.candidate_control, Control.ALLOW)

    def test_weakened_control_is_reported_separately_from_prevention(self) -> None:
        candidate = self._policy(
            tools=frozenset({"send_message", "post_results"}),
            effects=frozenset({"data.customer", "data.secret"}),
            control=Control.REQUIRE_APPROVAL,
        )

        report = self._run(self.complete, candidate)

        self.assertFalse(report.passed)
        self.assertEqual(report.candidate_metrics["unsafe_action_prevention"], 1.0)
        self.assertLess(report.candidate_metrics["exact_control_conformance"], 1.0)
        self.assertTrue(
            any(
                item.property_name == "exact_control"
                for item in report.regression_witnesses
            )
        )

    def test_narrowed_evidence_is_visible_even_when_control_is_unchanged(self) -> None:
        candidate = self._policy(
            tools=frozenset({"send_message", "post_results"}),
            effects=frozenset({"data.customer"}),
            control=Control.DENY,
        )

        report = self._run(self.complete, candidate)

        self.assertFalse(report.passed)
        evidence = next(
            item for item in report.regression_witnesses if item.property_name == "evidence"
        )
        self.assertTrue(
            any(field.endswith("data.secret") for field in evidence.missing_evidence_fields)
        )

    def test_identical_policies_have_no_semantic_change(self) -> None:
        report = self._run(self.complete, self.complete)

        self.assertTrue(report.passed)
        self.assertEqual(report.regression_witnesses, ())
        self.assertEqual(report.correction_witnesses, ())
        self.assertEqual(report.change_metrics["semantic_change_rate"], 0.0)
        self.assertEqual(report.baseline_witnesses, ())
        self.assertEqual(report.candidate_witnesses, ())

    def test_union_search_finds_a_candidate_failure_beyond_a_repaired_boundary(self) -> None:
        baseline = SequencePolicy(
            [
                SequenceRule(
                    rule_id="premature-secret-block",
                    target_tools=frozenset({"read_secret"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.DENY,
                    reason_code="sequence.premature_secret_block",
                )
            ]
        )
        candidate = SequencePolicy(())

        report = self._run(baseline, candidate)

        self.assertFalse(report.passed)
        self.assertGreater(report.change_metrics["candidate_only_boundaries"], 0.0)
        safety = next(
            item for item in report.candidate_witnesses if item.property_name == "safety"
        )
        self.assertEqual(safety.trace, ("customer", "secret", "message"))
        regression = next(
            item
            for item in report.regression_witnesses
            if item.property_name == "safety"
        )
        self.assertEqual(regression.trace, safety.trace)
        self.assertFalse(regression.baseline_reachable)
        self.assertTrue(regression.candidate_reachable)

    def test_closed_unsafe_path_keeps_its_access_cost_visible(self) -> None:
        baseline = SequencePolicy(())
        candidate = SequencePolicy(
            [
                SequenceRule(
                    rule_id="block-secret-after-customer",
                    target_tools=frozenset({"read_secret"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.DENY,
                    reason_code="sequence.block_secret_after_customer",
                )
            ]
        )

        report = self._run(baseline, candidate)

        availability = next(
            item
            for item in report.regression_witnesses
            if item.property_name == "availability"
        )
        self.assertEqual(availability.trace, ("customer", "secret"))
        safety = next(
            item
            for item in report.correction_witnesses
            if item.property_name == "safety"
        )
        self.assertEqual(safety.trace, ("customer", "secret", "message"))
        self.assertTrue(safety.baseline_reachable)
        self.assertFalse(safety.candidate_reachable)

    def test_evidence_order_does_not_create_a_semantic_change(self) -> None:
        decision = PolicyChangeDecision(
            trace=("customer", "secret", "message"),
            baseline_reachable=True,
            candidate_reachable=True,
            expected_control=Control.DENY,
            baseline_control=Control.DENY,
            candidate_control=Control.DENY,
            matched_requirements=("customer-secret-egress",),
            required_evidence_fields=("session.effects.data.customer",),
            baseline_evidence_fields=("field.a", "field.b"),
            candidate_evidence_fields=("field.b", "field.a"),
        )

        self.assertFalse(decision.semantic_change)

    def test_attestation_binds_the_full_case_level_report(self) -> None:
        report = self._run(self.complete, self.complete)
        attestor = PolicyChangeAttestor("ci-key", b"p" * 32)
        attestation = attestor.sign(report)

        self.assertTrue(attestor.verify(report, attestation))
        changed = replace(report, max_events=report.max_events + 1)
        self.assertFalse(attestor.verify(changed, attestation))
        changed_budget = replace(report, max_decisions=report.max_decisions + 1)
        self.assertFalse(attestor.verify(changed_budget, attestation))

    def test_search_budget_failure_does_not_return_a_partial_report(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds max_decisions"):
            PolicyChangeChecker(self.policy, self.complete, self.complete).run(
                principal=self.principal,
                templates=self.templates,
                requirements=self.requirements,
                max_events=3,
                max_decisions=4,
            )

    def test_depth_too_small_names_the_uncovered_requirement(self) -> None:
        report = PolicyChangeChecker(
            self.policy,
            self.complete,
            self.complete,
        ).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_events=2,
        )

        self.assertFalse(report.passed)
        self.assertEqual(
            report.candidate_uncovered_requirements,
            ("customer-secret-egress",),
        )

    def _run(
        self,
        baseline: SequencePolicy,
        candidate: SequencePolicy,
    ):
        return PolicyChangeChecker(self.policy, baseline, candidate).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_events=3,
        )

    def _policy(
        self,
        *,
        tools: frozenset[str],
        effects: frozenset[str],
        control: Control,
    ) -> SequencePolicy:
        return SequencePolicy(
            [
                SequenceRule(
                    rule_id="customer-secret-egress",
                    target_tools=tools,
                    required_effects=effects,
                    control=control,
                    reason_code="sequence.customer_secret_egress",
                )
            ]
        )


if __name__ == "__main__":
    unittest.main()
