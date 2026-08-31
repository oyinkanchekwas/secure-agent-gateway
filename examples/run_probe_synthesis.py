from __future__ import annotations

import argparse
import json
from pathlib import Path

from secure_agent_gateway.model_checking import FlowRequirement, InvocationTemplate
from secure_agent_gateway.models import Control, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.probe_synthesis import RequirementProbeSynthesiser
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule
from secure_agent_gateway.trajectory import (
    SequenceMutationAnalyser,
    TrajectoryContractRunner,
)


def no_op(arguments, context):
    return None


def build_model():
    principal = Principal("agent-1", frozenset({"researcher"}))
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
                name,
                {},
                principal.roles,
                emitted_effects=effects,
            ),
            no_op,
        )
    policy = PolicyEngine(registry, policy_version="probe-synthesis-v0.5")
    sequence_policy = SequencePolicy(
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
    templates = (
        InvocationTemplate("customer", "read_customer", {}),
        InvocationTemplate("customer-cache", "read_customer_cache", {}),
        InvocationTemplate("secret", "read_secret", {}),
        InvocationTemplate("harmless", "search_docs", {}),
        InvocationTemplate("message", "send_message", {}),
        InvocationTemplate("export", "export_summary", {}),
    )
    requirements = (
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
    return principal, policy, sequence_policy, templates, requirements


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    principal, policy, sequence_policy, templates, requirements = build_model()
    synthesis = RequirementProbeSynthesiser(policy).run(
        principal=principal,
        templates=templates,
        requirements=requirements,
        max_source_events=3,
        max_trace_events=16,
        max_candidates=10_000,
    )
    contracts = synthesis.build_contracts()
    trajectory = TrajectoryContractRunner(policy, sequence_policy).run(contracts)
    mutation = SequenceMutationAnalyser(policy, sequence_policy).run(contracts)
    payload = {
        "probe_synthesis": synthesis.to_mapping(),
        "probe_synthesis_digest": synthesis.report_digest,
        "trajectory_evaluation": trajectory.to_mapping(),
        "trajectory_evaluation_digest": trajectory.report_digest,
        "mutation_analysis": mutation.to_mapping(),
        "mutation_analysis_digest": mutation.report_digest,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
