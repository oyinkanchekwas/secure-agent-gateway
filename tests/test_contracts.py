from __future__ import annotations

from dataclasses import replace
import unittest

from secure_agent_gateway.contracts import (
    ContractAttestor,
    ContractCase,
    PairedPolicyContract,
    PolicyContractRunner,
)
from secure_agent_gateway.models import Control, ExecutionContext, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.rate_limit import RateLimit
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec

from tests.support import NOW, make_request


def no_op(arguments, context: ExecutionContext):
    return None


class PolicyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.principal = Principal("agent-1", frozenset({"researcher"}))
        self.registry = ToolRegistry()
        self.registry.register(
            ToolSpec(
                "post_results",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
                host_rules={"destination": ("research.example.test",)},
                rate_limit=RateLimit(1, 60),
            ),
            no_op,
        )
        self.policy = PolicyEngine(self.registry, policy_version="policy-contract-test")

    def contract(self, *, evidence: tuple[str, ...] = ("arguments.destination",)):
        prohibited = ContractCase(
            "host-prohibited",
            make_request(
                request_id="contract-prohibited",
                nonce="contract-nonce-prohibited",
                tool="post_results",
                arguments={"destination": "https://drop.example.test"},
            ),
            Control.DENY,
            evidence,
        )
        permitted = ContractCase(
            "host-permitted",
            make_request(
                request_id="contract-permitted",
                nonce="contract-nonce-permitted",
                tool="post_results",
                arguments={"destination": "https://research.example.test"},
            ),
            Control.ALLOW,
        )
        return PairedPolicyContract(
            contract_id="host-boundary-pair",
            policy_family="network_destination",
            principal=self.principal,
            prohibited=prohibited,
            permitted=permitted,
            changed_fields=("arguments.destination",),
        )

    def test_controlled_pair_passes_all_default_gates(self) -> None:
        report = PolicyContractRunner(self.policy).run([self.contract()])
        self.assertTrue(report.passed)
        self.assertEqual(report.metrics["unsafe_action_prevention"], 1.0)
        self.assertEqual(report.metrics["permitted_task_retention"], 1.0)
        self.assertEqual(report.metrics["unnecessary_intervention_rate"], 0.0)

    def test_contract_inspection_does_not_consume_runtime_rate_limit(self) -> None:
        PolicyContractRunner(self.policy).run([self.contract()])
        request = make_request(
            tool="post_results",
            arguments={"destination": "https://research.example.test"},
        )
        decision = self.policy.evaluate(self.principal, request, now=NOW)
        self.assertEqual(decision.control, Control.ALLOW)

    def test_changed_fields_must_describe_the_observed_pair(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(ValueError, "changed_fields"):
            replace(contract, changed_fields=("tool",))

    def test_missing_causal_evidence_fails_the_acceptance_gate(self) -> None:
        report = PolicyContractRunner(self.policy).run(
            [self.contract(evidence=("arguments.payload",))]
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.metrics["evidence_coverage"], 0.0)

    def test_permissive_policy_exposes_loss_of_prevention(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                "post_results",
                {"destination": FieldSpec("string")},
                frozenset({"researcher"}),
                rate_limit=RateLimit(1, 60),
            ),
            no_op,
        )
        report = PolicyContractRunner(
            PolicyEngine(registry, policy_version="permissive-test")
        ).run([self.contract()])
        self.assertFalse(report.passed)
        self.assertEqual(report.metrics["unsafe_action_prevention"], 0.0)

    def test_attestation_detects_report_changes(self) -> None:
        report = PolicyContractRunner(self.policy).run([self.contract()])
        attestor = ContractAttestor("ci-key", b"contract-test-key-material")
        attestation = attestor.sign(report)
        self.assertTrue(attestor.verify(report, attestation))
        self.assertFalse(
            attestor.verify(replace(report, policy_version="changed-policy"), attestation)
        )

    def test_mutated_case_is_rejected_before_evaluation(self) -> None:
        contract = self.contract()
        contract.permitted.request.arguments["destination"] = "https://another.example.test"
        with self.assertRaisesRegex(ValueError, "contract content changed"):
            PolicyContractRunner(self.policy).run([contract])

    def test_duplicate_contract_identifiers_are_rejected(self) -> None:
        contract = self.contract()
        with self.assertRaisesRegex(ValueError, "contract identifiers"):
            PolicyContractRunner(self.policy).run([contract, contract])


if __name__ == "__main__":
    unittest.main()
