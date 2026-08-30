from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from secure_agent_gateway.approvals import ApprovalAuthority
from secure_agent_gateway.audit import AuditLog
from secure_agent_gateway.auth import Authenticator, PrincipalCredential, sign_request
from secure_agent_gateway.gateway import SecureAgentGateway
from secure_agent_gateway.models import ExecutionContext, Principal, RiskLevel, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.rate_limit import RateLimit
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec
from secure_agent_gateway.secrets import MappingSecretProvider


NOW = 1_800_000_000
AUTH_KEY = b"test-auth-key-material-32-bytes!!"
APPROVAL_KEY = b"test-approval-key"


def make_request(
    *,
    request_id: str = "req-1",
    nonce: str = "nonce-1",
    tool: str = "search_docs",
    arguments: Mapping[str, Any] | None = None,
    issued_at: int = NOW,
    principal_id: str = "agent-1",
) -> ToolRequest:
    return ToolRequest(
        request_id=request_id,
        principal_id=principal_id,
        tool=tool,
        arguments={"query": "policy"} if arguments is None else arguments,
        issued_at=issued_at,
        nonce=nonce,
    )


def sign(request: ToolRequest):
    return sign_request(request, "agent-key", AUTH_KEY)


@dataclass
class GatewayFixture:
    gateway: SecureAgentGateway
    approvals: ApprovalAuthority
    audit: AuditLog
    policy: PolicyEngine
    calls: list[tuple[str, Mapping[str, Any], str | None]]


def make_gateway(tmp_path: Path) -> GatewayFixture:
    calls: list[tuple[str, Mapping[str, Any], str | None]] = []
    principal = Principal("agent-1", frozenset({"researcher", "operator"}))
    authenticator = Authenticator(
        {
            "agent-key": PrincipalCredential(
                key_id="agent-key",
                principal=principal,
                secret=AUTH_KEY,
            )
        }
    )
    registry = ToolRegistry()

    def handler(name: str):
        def run(arguments: Mapping[str, Any], context: ExecutionContext) -> dict[str, Any]:
            calls.append((name, arguments, context.credential))
            return {"tool": name, "accepted": True}

        return run

    registry.register(
        ToolSpec(
            name="search_docs",
            fields={"query": FieldSpec("string", max_length=200)},
            allowed_roles=frozenset({"researcher"}),
            rate_limit=RateLimit(5, 60),
        ),
        handler("search_docs"),
    )
    registry.register(
        ToolSpec(
            name="delete_file",
            fields={"path": FieldSpec("string")},
            allowed_roles=frozenset({"operator"}),
            risk=RiskLevel.DESTRUCTIVE,
            path_rules={"path": (str(tmp_path / "workspace"),)},
            rate_limit=RateLimit(5, 60),
        ),
        handler("delete_file"),
    )
    registry.register(
        ToolSpec(
            name="post_results",
            fields={
                "destination": FieldSpec("string"),
                "payload": FieldSpec("object", redact=True),
            },
            allowed_roles=frozenset({"researcher"}),
            approval_required=True,
            host_rules={"destination": ("research.example.test",)},
            credential_alias="research-service",
            rate_limit=RateLimit(5, 60),
        ),
        handler("post_results"),
    )
    registry.register(
        ToolSpec(
            name="broken_adapter",
            fields={},
            allowed_roles=frozenset({"researcher"}),
            rate_limit=RateLimit(5, 60),
        ),
        lambda arguments, context: (_ for _ in ()).throw(RuntimeError("adapter broke")),
    )

    approvals = ApprovalAuthority(APPROVAL_KEY, {"reviewer-1"})
    audit = AuditLog(tmp_path / "audit.jsonl")
    policy = PolicyEngine(registry, policy_version="policy-2026-08-30")
    gateway = SecureAgentGateway(
        authenticator=authenticator,
        policy=policy,
        approvals=approvals,
        audit_log=audit,
        secret_provider=MappingSecretProvider({"research-service": "fixture-service-value"}),
        pending_ttl_seconds=120,
    )
    return GatewayFixture(
        gateway=gateway,
        approvals=approvals,
        audit=audit,
        policy=policy,
        calls=calls,
    )
