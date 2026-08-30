from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class Control(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class RiskLevel(StrEnum):
    LOW = "low"
    ELEVATED = "elevated"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    roles: frozenset[str]


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    principal_id: str
    tool: str
    arguments: Mapping[str, Any]
    issued_at: int
    nonce: str
    session_id: str = "default"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "principal_id": self.principal_id,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class SignedRequest:
    key_id: str
    request: ToolRequest
    signature: str


@dataclass(frozen=True)
class PolicyDecision:
    control: Control
    reason_codes: tuple[str, ...]
    evidence_fields: tuple[str, ...]
    request_digest: str
    policy_version: str
    context_digest: str = "0" * 64

    def to_mapping(self) -> dict[str, Any]:
        return {
            "control": self.control.value,
            "reason_codes": list(self.reason_codes),
            "evidence_fields": list(self.evidence_fields),
            "request_digest": self.request_digest,
            "policy_version": self.policy_version,
            "context_digest": self.context_digest,
        }


@dataclass(frozen=True)
class GatewayResult:
    status: str
    decision: PolicyDecision
    output: Any = None
    error_code: str | None = None
    audit_event_id: str | None = None
    approval_id: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        payload = {
            "status": self.status,
            "decision": self.decision.to_mapping(),
            "error_code": self.error_code,
            "audit_event_id": self.audit_event_id,
            "approval_id": self.approval_id,
        }
        if self.output is not None:
            payload["output"] = self.output
        return payload


@dataclass(frozen=True)
class ExecutionContext:
    principal: Principal
    credential: str | None = field(default=None, repr=False)
