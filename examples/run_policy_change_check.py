from __future__ import annotations

import argparse
import json
from pathlib import Path

from secure_agent_gateway.model_checking import FlowRequirement, InvocationTemplate
from secure_agent_gateway.models import Control, Principal
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.policy_change import PolicyChangeChecker
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.session import SequencePolicy, SequenceRule


def no_op(arguments, context):
    return None


def build_model():
    principal = Principal("agent-1", frozenset({"researcher"}))
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
                name,
                {},
                principal.roles,
                emitted_effects=effects,
            ),
            no_op,
        )
    policy = PolicyEngine(registry, policy_version="policy-change-v0.4")
    baseline = SequencePolicy(
        [
            SequenceRule(
                rule_id="customer-secret-egress",
                target_tools=frozenset({"send_message"}),
                required_effects=frozenset({"data.customer", "data.secret"}),
                control=Control.DENY,
                reason_code="sequence.customer_secret_egress",
            )
        ]
    )
    candidate = SequencePolicy(
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
    templates = (
        InvocationTemplate("customer", "read_customer", {}),
        InvocationTemplate("secret", "read_secret", {}),
        InvocationTemplate("harmless", "search_docs", {}),
        InvocationTemplate("message", "send_message", {}),
        InvocationTemplate("post", "post_results", {}),
    )
    requirements = (
        FlowRequirement(
            requirement_id="customer-secret-egress",
            source_effects=frozenset({"data.customer", "data.secret"}),
            sink_tools=frozenset({"send_message", "post_results"}),
            expected_control=Control.DENY,
        ),
    )
    return principal, policy, baseline, candidate, templates, requirements


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    principal, policy, baseline, candidate, templates, requirements = build_model()
    report = PolicyChangeChecker(policy, baseline, candidate).run(
        principal=principal,
        templates=templates,
        requirements=requirements,
        max_events=3,
    )
    payload = {
        "policy_change": report.to_mapping(),
        "policy_change_digest": report.report_digest,
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
