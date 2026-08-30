from __future__ import annotations

import argparse
import json
from pathlib import Path

from secure_agent_gateway.models import Control, ExecutionContext, Principal, ToolRequest
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


def no_op(arguments, context: ExecutionContext):
    return None


def request(request_id: str, tool: str, arguments: dict) -> ToolRequest:
    return ToolRequest(
        request_id=request_id,
        principal_id="agent-1",
        tool=tool,
        arguments=arguments,
        issued_at=1_800_000_000,
        nonce=f"nonce-{request_id}",
        session_id="assurance-session",
    )


def build_suite():
    principal = Principal("agent-1", frozenset({"researcher"}))
    registry = ToolRegistry()
    for name, effects in (
        ("read_customer", frozenset({"data.customer"})),
        ("read_public", frozenset({"data.public"})),
    ):
        registry.register(
            ToolSpec(name, {}, principal.roles, emitted_effects=effects),
            no_op,
        )
    registry.register(
        ToolSpec(
            "search_docs",
            {"query": FieldSpec("string", max_length=200)},
            principal.roles,
        ),
        no_op,
    )
    registry.register(
        ToolSpec(
            "send_message",
            {"destination": FieldSpec("string")},
            principal.roles,
        ),
        no_op,
    )
    policy = PolicyEngine(registry, policy_version="sequence-assurance-v0.2")
    sequence_policy = SequencePolicy(
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
    prohibited = TrajectoryCase(
        case_id="customer-egress-prohibited",
        requests=(
            request("prohibited-read", "read_customer", {}),
            request("prohibited-search", "search_docs", {"query": "contact record"}),
            request(
                "prohibited-send",
                "send_message",
                {"destination": "https://external.example.test/inbox"},
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
            request("permitted-read", "read_public", {}),
            request("permitted-search", "search_docs", {"query": "contact record"}),
            request(
                "permitted-send",
                "send_message",
                {"destination": "https://external.example.test/inbox"},
            ),
        ),
        expected_controls=(Control.ALLOW, Control.ALLOW, Control.ALLOW),
        expected_first_intervention=None,
    )
    contract = PairedTrajectoryContract(
        contract_id="customer-egress-pair",
        policy_family="effect_to_sink",
        principal=principal,
        prohibited=prohibited,
        permitted=permitted,
        changed_fields=("requests.0.tool",),
    )
    return policy, sequence_policy, (contract,)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    policy, sequence_policy, contracts = build_suite()
    trajectory = TrajectoryContractRunner(policy, sequence_policy).run(contracts)
    mutations = SequenceMutationAnalyser(policy, sequence_policy).run(contracts)
    payload = {
        "trajectory_report": trajectory.to_mapping(),
        "trajectory_report_digest": trajectory.report_digest,
        "mutation_report": mutations.to_mapping(),
        "mutation_report_digest": mutations.report_digest,
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
