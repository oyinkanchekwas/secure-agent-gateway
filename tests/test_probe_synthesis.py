from __future__ import annotations

import unittest

from secure_agent_gateway.model_checking import FlowRequirement, InvocationTemplate
from secure_agent_gateway.models import Control, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.probe_synthesis import (
    ContrastProbe,
    RequirementProbeSynthesiser,
)
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule
from secure_agent_gateway.trajectory import (
    SequenceMutationAnalyser,
    TrajectoryContractRunner,
)


class RequirementProbeSynthesiserTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = ToolRegistry()
        for name, effects in (
            ("read_customer", frozenset({"data.customer"})),
            ("read_customer_cache", frozenset({"data.customer"})),
            ("read_secret", frozenset({"data.secret"})),
            ("search_docs", frozenset()),
            ("send_message", frozenset()),
            ("export_summary", frozenset()),
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
        self.policy = PolicyEngine(registry, policy_version="probe-test")
        self.principal = Principal("agent-1", frozenset({"researcher"}))
        self.templates = (
            InvocationTemplate("customer", "read_customer", {}),
            InvocationTemplate("customer-cache", "read_customer_cache", {}),
            InvocationTemplate("secret", "read_secret", {}),
            InvocationTemplate("harmless", "search_docs", {}),
            InvocationTemplate("message", "send_message", {}),
            InvocationTemplate("export", "export_summary", {}),
        )
        self.requirements = (
            FlowRequirement(
                requirement_id="customer-secret-egress",
                source_effects=frozenset({"data.customer", "data.secret"}),
                sink_tools=frozenset({"send_message"}),
                expected_control=Control.DENY,
            ),
            FlowRequirement(
                requirement_id="customer-export-review",
                source_effects=frozenset({"data.customer"}),
                sink_tools=frozenset({"export_summary"}),
                expected_control=Control.REQUIRE_APPROVAL,
            ),
        )
        self.sequence_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id="customer-secret-egress",
                    target_tools=frozenset({"send_message"}),
                    required_effects=frozenset(
                        {"data.customer", "data.secret"}
                    ),
                    control=Control.DENY,
                    reason_code="sequence.customer_secret_egress",
                ),
                SequenceRule(
                    rule_id="customer-export-review",
                    target_tools=frozenset({"export_summary"}),
                    required_effects=frozenset({"data.customer"}),
                    control=Control.REQUIRE_APPROVAL,
                    reason_code="sequence.customer_export_review",
                ),
            ]
        )

    def test_synthesised_contracts_pass_the_runtime_sequence_policy(self) -> None:
        report = self._run()

        self.assertTrue(report.passed)
        self.assertEqual(report.metrics["requirement_probe_coverage"], 1.0)
        self.assertEqual(report.metrics["source_effect_probe_coverage"], 1.0)
        self.assertEqual(report.metrics["temporal_probe_coverage"], 1.0)
        self.assertEqual(len(report.probes), 4)
        contracts = report.build_contracts()
        evaluated = TrajectoryContractRunner(
            self.policy,
            self.sequence_policy,
        ).run(contracts)
        self.assertTrue(evaluated.passed)
        self.assertEqual(len(contracts), 4)

    def test_causal_basis_kills_every_supported_rule_mutation(self) -> None:
        contracts = self._run().build_contracts()

        mutation = SequenceMutationAnalyser(
            self.policy,
            self.sequence_policy,
        ).run(contracts)

        self.assertEqual(mutation.mutation_score, 1.0)
        self.assertEqual(mutation.survived, 0)

    def test_probe_is_causally_minimal_and_reports_equal_alternatives(self) -> None:
        report = self._run()
        probes = [
            item
            for item in report.probes
            if item.requirement_id == "customer-secret-egress"
            and item.probe_kind == "source_effect"
        ]
        probe = next(item for item in probes if item.isolated_effect == "data.customer")

        self.assertEqual(len(probes), 2)
        self.assertEqual(len(probe.prohibited_trace), 3)
        self.assertEqual(probe.prohibited_trace[-1], "message")
        self.assertNotEqual(
            probe.prohibited_trace[probe.changed_index],
            probe.permitted_trace[probe.changed_index],
        )
        self.assertEqual(probe.isolated_effect, "data.customer")
        self.assertTrue(
            all(item.indispensable_effects for item in probe.causal_contributions)
        )
        self.assertGreater(probe.minimal_pair_count, 1)

    def test_missing_source_effect_is_a_named_gap(self) -> None:
        requirement = FlowRequirement(
            requirement_id="payroll-egress",
            source_effects=frozenset({"data.payroll"}),
            sink_tools=frozenset({"send_message"}),
            expected_control=Control.DENY,
        )

        report = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=(requirement,),
        )

        self.assertFalse(report.passed)
        self.assertEqual(report.probes, ())
        self.assertEqual(report.gaps[0].code, "missing_source_effect")
        with self.assertRaisesRegex(ValueError, "incomplete probe suite"):
            report.build_contracts()

    def test_no_neutral_replacement_is_reported(self) -> None:
        registry = ToolRegistry()
        for name in ("read_x", "send_x"):
            registry.register(
                ToolSpec(
                    name=name,
                    fields={},
                    allowed_roles=frozenset({"researcher"}),
                    emitted_effects=frozenset({"data.x"}),
                ),
                lambda arguments, context: None,
            )
        policy = PolicyEngine(registry, policy_version="no-contrast")
        templates = (
            InvocationTemplate("source", "read_x", {}),
            InvocationTemplate("sink", "send_x", {}),
        )
        requirement = FlowRequirement(
            requirement_id="x-egress",
            source_effects=frozenset({"data.x"}),
            sink_tools=frozenset({"send_x"}),
            expected_control=Control.DENY,
        )

        report = RequirementProbeSynthesiser(policy).run(
            principal=self.principal,
            templates=templates,
            requirements=(requirement,),
        )

        self.assertFalse(report.passed)
        self.assertEqual(report.gaps[0].code, "non_isolatable_source_effect")

    def test_stronger_requirement_can_shadow_an_approval_probe(self) -> None:
        deny = FlowRequirement(
            requirement_id="customer-export-deny",
            source_effects=frozenset({"data.customer"}),
            sink_tools=frozenset({"export_summary"}),
            expected_control=Control.DENY,
        )
        approval = self.requirements[1]

        report = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=(deny, approval),
        )

        gap = next(
            item
            for item in report.gaps
            if item.requirement_id == approval.requirement_id
        )
        self.assertEqual(gap.code, "no_selectable_prohibited_trace")

    def test_finite_window_uses_the_existing_multi_event_trace(self) -> None:
        requirement = FlowRequirement(
            requirement_id="windowed-customer-secret-egress",
            source_effects=frozenset({"data.customer", "data.secret"}),
            sink_tools=frozenset({"send_message"}),
            expected_control=Control.DENY,
            window_events=2,
        )

        report = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=(requirement,),
            max_source_events=3,
        )

        self.assertTrue(report.passed)
        temporal = next(
            probe for probe in report.probes if probe.tests_history_window
        )
        self.assertEqual(len(temporal.prohibited_trace), 3)
        self.assertEqual(temporal.isolated_effect_age, 2)

    def test_finite_window_probe_detects_a_one_event_contraction(self) -> None:
        requirement = FlowRequirement(
            requirement_id="windowed-customer-export",
            source_effects=frozenset({"data.customer"}),
            sink_tools=frozenset({"export_summary"}),
            expected_control=Control.REQUIRE_APPROVAL,
            window_events=4,
        )
        report = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=(requirement,),
            max_source_events=3,
        )

        self.assertTrue(report.passed)
        temporal = next(
            probe for probe in report.probes if probe.probe_kind == "history_window"
        )
        self.assertEqual(temporal.isolated_effect_age, 4)
        self.assertEqual(len(temporal.prohibited_trace), 5)

        expected_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id=requirement.requirement_id,
                    target_tools=requirement.sink_tools,
                    required_effects=requirement.source_effects,
                    control=requirement.expected_control,
                    reason_code="sequence.windowed_customer_export",
                    window_events=4,
                )
            ]
        )
        shortened_policy = SequencePolicy(
            [
                SequenceRule(
                    rule_id=requirement.requirement_id,
                    target_tools=requirement.sink_tools,
                    required_effects=requirement.source_effects,
                    control=requirement.expected_control,
                    reason_code="sequence.windowed_customer_export",
                    window_events=3,
                )
            ]
        )
        contracts = report.build_contracts()

        expected = TrajectoryContractRunner(
            self.policy,
            expected_policy,
        ).run(contracts)
        shortened = TrajectoryContractRunner(
            self.policy,
            shortened_policy,
        ).run(contracts)

        self.assertTrue(expected.passed)
        self.assertFalse(shortened.passed)

    def test_candidate_limit_fails_without_a_partial_report(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds max_candidates"):
            self._run(max_candidates=1)

    def test_history_boundary_respects_the_trace_limit(self) -> None:
        requirement = FlowRequirement(
            requirement_id="long-window-customer-export",
            source_effects=frozenset({"data.customer"}),
            sink_tools=frozenset({"export_summary"}),
            expected_control=Control.REQUIRE_APPROVAL,
            window_events=100_000,
        )

        report = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=(requirement,),
            max_trace_events=16,
        )

        self.assertFalse(report.passed)
        self.assertEqual(report.gaps[0].code, "trace_limit_exhausted")
        self.assertLessEqual(report.explored_candidates, 100_000)

    def test_probe_rejects_inconsistent_effect_age(self) -> None:
        valid = self._run().probes[0]

        with self.assertRaisesRegex(ValueError, "does not match changed_index"):
            ContrastProbe(
                requirement_id=valid.requirement_id,
                probe_kind=valid.probe_kind,
                isolated_effect=valid.isolated_effect,
                expected_control=valid.expected_control,
                prohibited_trace=valid.prohibited_trace,
                permitted_trace=valid.permitted_trace,
                changed_index=valid.changed_index,
                removed_effects=valid.removed_effects,
                effect_distance=valid.effect_distance,
                required_evidence_fields=valid.required_evidence_fields,
                causal_contributions=valid.causal_contributions,
                isolated_effect_age=valid.isolated_effect_age + 1,
                tests_history_window=valid.tests_history_window,
                minimal_pair_count=valid.minimal_pair_count,
            )

    def test_search_limits_are_bound_into_the_suite_digest(self) -> None:
        first = self._run(max_candidates=10_000)
        second = self._run(max_candidates=10_001)

        self.assertNotEqual(first.suite_digest, second.suite_digest)
        self.assertNotEqual(first.report_digest, second.report_digest)

        shorter = RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_source_events=3,
            max_trace_events=63,
            max_candidates=10_000,
        )
        self.assertNotEqual(first.suite_digest, shorter.suite_digest)

    def test_registered_effects_are_bound_into_the_suite_digest(self) -> None:
        registry = ToolRegistry()
        for template in self.templates:
            original = self.policy.registry.get(template.tool)
            self.assertIsNotNone(original)
            effects = original.spec.emitted_effects
            if template.template_id == "harmless":
                effects = frozenset({"data.audit"})
            registry.register(
                ToolSpec(
                    name=template.tool,
                    fields={},
                    allowed_roles=frozenset({"researcher"}),
                    emitted_effects=effects,
                ),
                lambda arguments, context: None,
            )
        changed_policy = PolicyEngine(registry, policy_version="changed-effects")

        baseline = self._run()
        changed = RequirementProbeSynthesiser(changed_policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_source_events=3,
            max_candidates=10_000,
        )

        self.assertNotEqual(baseline.suite_digest, changed.suite_digest)

    def _run(self, *, max_candidates: int = 10_000):
        return RequirementProbeSynthesiser(self.policy).run(
            principal=self.principal,
            templates=self.templates,
            requirements=self.requirements,
            max_source_events=3,
            max_candidates=max_candidates,
        )


if __name__ == "__main__":
    unittest.main()
