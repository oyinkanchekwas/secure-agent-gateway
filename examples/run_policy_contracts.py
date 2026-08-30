from __future__ import annotations

import json

from secure_agent_gateway import (
    ContractAttestor,
    ContractCase,
    Control,
    FieldSpec,
    PairedPolicyContract,
    PolicyContractRunner,
    PolicyEngine,
    Principal,
    ToolRegistry,
    ToolRequest,
    ToolSpec,
)
from secure_agent_gateway.rate_limit import RateLimit


def no_op(arguments, context):
    return None


def request(request_id: str, nonce: str, destination: str) -> ToolRequest:
    return ToolRequest(
        request_id=request_id,
        principal_id="research-agent",
        tool="post_results",
        arguments={"destination": destination},
        issued_at=1_800_000_000,
        nonce=nonce,
    )


registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="post_results",
        fields={"destination": FieldSpec("string")},
        allowed_roles=frozenset({"researcher"}),
        host_rules={"destination": ("research.example.test",)},
        rate_limit=RateLimit(calls=10, period_seconds=60),
    ),
    no_op,
)
policy = PolicyEngine(registry, policy_version="policy-example-1")
principal = Principal("research-agent", frozenset({"researcher"}))
contract = PairedPolicyContract(
    contract_id="post-results-host-boundary",
    policy_family="network_destination",
    principal=principal,
    prohibited=ContractCase(
        case_id="post-results-unlisted-host",
        request=request(
            "contract-prohibited",
            "contract-nonce-prohibited",
            "https://drop.example.test",
        ),
        expected_control=Control.DENY,
        required_evidence_fields=("arguments.destination",),
    ),
    permitted=ContractCase(
        case_id="post-results-listed-host",
        request=request(
            "contract-permitted",
            "contract-nonce-permitted",
            "https://research.example.test",
        ),
        expected_control=Control.ALLOW,
    ),
    changed_fields=("arguments.destination",),
)

report = PolicyContractRunner(policy).run([contract])
attestor = ContractAttestor("local-example", b"local-contract-key-do-not-deploy")
payload = {
    "report": report.to_mapping(),
    "report_digest": report.report_digest,
    "attestation": attestor.sign(report).to_mapping(),
}
print(json.dumps(payload, indent=2, sort_keys=True))
