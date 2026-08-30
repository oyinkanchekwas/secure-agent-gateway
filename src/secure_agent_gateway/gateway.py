from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from threading import Lock
import time
from typing import Any, Mapping

from secure_agent_gateway.approvals import ApprovalAuthority, ApprovalError, ApprovalReceipt
from secure_agent_gateway.audit import AuditLog, redact
from secure_agent_gateway.auth import (
    AuthenticationError,
    Authenticator,
    canonical_json,
    request_digest,
)
from secure_agent_gateway.models import (
    Control,
    ExecutionContext,
    GatewayResult,
    PolicyDecision,
    Principal,
    SignedRequest,
    ToolRequest,
)
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.registry import RegisteredTool
from secure_agent_gateway.secrets import SecretProvider


@dataclass(frozen=True)
class PendingCall:
    request: ToolRequest
    principal: Principal
    decision: PolicyDecision
    created_at: int


class SecureAgentGateway:
    def __init__(
        self,
        *,
        authenticator: Authenticator,
        policy: PolicyEngine,
        approvals: ApprovalAuthority,
        audit_log: AuditLog,
        secret_provider: SecretProvider | None = None,
        pending_ttl_seconds: int = 900,
    ) -> None:
        self._authenticator = authenticator
        self._policy = policy
        self._approvals = approvals
        self._audit = audit_log
        self._secret_provider = secret_provider
        self._pending_ttl_seconds = pending_ttl_seconds
        self._pending: dict[str, PendingCall] = {}
        self._request_ids: set[str] = set()
        self._state_lock = Lock()

    def submit(self, envelope: SignedRequest, *, now: int | None = None) -> GatewayResult:
        observed_now = int(time.time()) if now is None else now
        envelope = _snapshot_envelope(envelope)
        request = envelope.request
        try:
            principal = self._authenticator.authenticate(envelope, now=observed_now)
        except AuthenticationError as exc:
            decision = PolicyDecision(
                control=Control.DENY,
                reason_codes=(exc.code,),
                evidence_fields=("signature",),
                request_digest=_safe_request_digest(request),
                policy_version=self._policy.policy_version,
            )
            event_id = self._record(
                request,
                decision,
                status="denied",
                now=observed_now,
                include_arguments=False,
            )
            return GatewayResult(
                status="denied",
                decision=decision,
                error_code=exc.code,
                audit_event_id=event_id,
            )

        with self._state_lock:
            duplicate_request_id = request.request_id in self._request_ids
            if not duplicate_request_id:
                self._request_ids.add(request.request_id)
        if duplicate_request_id:
            decision = PolicyDecision(
                control=Control.DENY,
                reason_codes=("request.duplicate_id",),
                evidence_fields=("request_id",),
                request_digest=request_digest(request),
                policy_version=self._policy.policy_version,
            )
            event_id = self._record(request, decision, status="denied", now=observed_now)
            return GatewayResult(
                status="denied",
                decision=decision,
                error_code="request.duplicate_id",
                audit_event_id=event_id,
            )
        decision = self._policy.evaluate(principal, request, now=observed_now)
        if decision.control == Control.DENY:
            event_id = self._record(request, decision, status="denied", now=observed_now)
            return GatewayResult(
                status="denied",
                decision=decision,
                error_code=decision.reason_codes[0],
                audit_event_id=event_id,
            )
        if decision.control == Control.REQUIRE_APPROVAL:
            with self._state_lock:
                self._pending[request.request_id] = PendingCall(
                    request=request,
                    principal=principal,
                    decision=decision,
                    created_at=observed_now,
                )
            event_id = self._record(request, decision, status="pending_approval", now=observed_now)
            return GatewayResult(
                status="pending_approval",
                decision=decision,
                audit_event_id=event_id,
            )
        return self._execute(
            request=request,
            principal=principal,
            decision=decision,
            now=observed_now,
        )

    def resume(
        self,
        request_id: str,
        receipt: ApprovalReceipt,
        *,
        now: int | None = None,
    ) -> GatewayResult:
        observed_now = int(time.time()) if now is None else now
        approval_error: ApprovalError | None = None
        expired = False
        with self._state_lock:
            pending = self._pending.get(request_id)
            if pending is None:
                raise KeyError("pending request is unavailable")
            if observed_now - pending.created_at > self._pending_ttl_seconds:
                del self._pending[request_id]
                expired = True
            elif pending.decision.policy_version != self._policy.policy_version:
                del self._pending[request_id]
                approval_error = ApprovalError("approval.policy_changed")
            else:
                try:
                    self._approvals.verify_and_consume(receipt, pending.decision, now=observed_now)
                except ApprovalError as exc:
                    approval_error = exc
                else:
                    del self._pending[request_id]

        if expired:
            decision = _approval_denial(pending.decision, "approval.pending_expired")
            event_id = self._record(
                pending.request,
                decision,
                status="denied",
                now=observed_now,
                approval_id=receipt.approval_id,
            )
            return GatewayResult(
                status="denied",
                decision=decision,
                error_code="approval.pending_expired",
                audit_event_id=event_id,
                approval_id=receipt.approval_id,
            )
        if approval_error is not None:
            decision = _approval_denial(pending.decision, approval_error.code)
            event_id = self._record(
                pending.request,
                decision,
                status="denied",
                now=observed_now,
                approval_id=receipt.approval_id,
            )
            return GatewayResult(
                status="denied",
                decision=decision,
                error_code=approval_error.code,
                audit_event_id=event_id,
                approval_id=receipt.approval_id,
            )

        return self._execute(
            request=pending.request,
            principal=pending.principal,
            decision=pending.decision,
            now=observed_now,
            approval_id=receipt.approval_id,
        )

    def _execute(
        self,
        *,
        request: ToolRequest,
        principal: Principal,
        decision: PolicyDecision,
        now: int,
        approval_id: str | None = None,
    ) -> GatewayResult:
        if decision.policy_version != self._policy.policy_version:
            changed = _approval_denial(decision, "policy.version_changed")
            event_id = self._record(
                request,
                changed,
                status="denied",
                now=now,
                approval_id=approval_id,
            )
            return GatewayResult(
                status="denied",
                decision=changed,
                error_code="policy.version_changed",
                audit_event_id=event_id,
                approval_id=approval_id,
            )
        current = self._policy.revalidate(principal, request)
        if current.control == Control.DENY:
            event_id = self._record(
                request,
                current,
                status="denied",
                now=now,
                approval_id=approval_id,
            )
            return GatewayResult(
                status="denied",
                decision=current,
                error_code=current.reason_codes[0],
                audit_event_id=event_id,
                approval_id=approval_id,
            )
        registered = self._policy.registry.get(request.tool)
        if registered is None:
            raise RuntimeError("authorised tool disappeared from registry")
        self._record(
            request,
            decision,
            status="execution_started",
            now=now,
            approval_id=approval_id,
        )
        try:
            context = self._execution_context(registered, principal)
            output = registered.handler(dict(request.arguments), context)
        except Exception:
            event_id = self._record(
                request,
                decision,
                status="execution_failed",
                now=now,
                approval_id=approval_id,
            )
            return GatewayResult(
                status="execution_failed",
                decision=decision,
                error_code="adapter.failure",
                audit_event_id=event_id,
                approval_id=approval_id,
            )
        event_id = self._record(
            request,
            decision,
            status="succeeded",
            now=now,
            approval_id=approval_id,
        )
        return GatewayResult(
            status="succeeded",
            decision=decision,
            output=output,
            audit_event_id=event_id,
            approval_id=approval_id,
        )

    def _execution_context(
        self,
        registered: RegisteredTool,
        principal: Principal,
    ) -> ExecutionContext:
        alias = registered.spec.credential_alias
        if alias is None:
            return ExecutionContext(principal=principal)
        if self._secret_provider is None:
            raise KeyError("secret provider is unavailable")
        return ExecutionContext(principal=principal, credential=self._secret_provider.get(alias))

    def _record(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        *,
        status: str,
        now: int,
        approval_id: str | None = None,
        include_arguments: bool = True,
    ) -> str:
        event: dict[str, Any] = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "tool": request.tool,
            "arguments": self._audit_arguments(request) if include_arguments else "[UNTRUSTED]",
            "control": decision.control.value,
            "reason_codes": list(decision.reason_codes),
            "evidence_fields": list(decision.evidence_fields),
            "request_digest": decision.request_digest,
            "policy_version": decision.policy_version,
            "status": status,
        }
        if approval_id is not None:
            event["approval_id"] = approval_id
        return self._audit.append(event, timestamp=now)

    def _audit_arguments(self, request: ToolRequest) -> dict[str, Any]:
        arguments = _safe_arguments(request)
        registered = self._policy.registry.get(request.tool)
        if registered is not None:
            for field_name, field_spec in registered.spec.fields.items():
                if field_spec.redact and field_name in arguments:
                    arguments[field_name] = "[REDACTED]"
        return redact(arguments)


def _approval_denial(decision: PolicyDecision, code: str) -> PolicyDecision:
    return PolicyDecision(
        control=Control.DENY,
        reason_codes=(code,),
        evidence_fields=("approval",),
        request_digest=decision.request_digest,
        policy_version=decision.policy_version,
    )


def _safe_request_digest(request: ToolRequest) -> str:
    try:
        return request_digest(request)
    except (TypeError, ValueError):
        return hashlib.sha256(b"invalid-request").hexdigest()


def _safe_arguments(request: ToolRequest) -> dict[str, Any]:
    if isinstance(request.arguments, Mapping):
        return dict(request.arguments)
    return {"invalid_arguments_type": type(request.arguments).__name__}


def _snapshot_envelope(envelope: SignedRequest) -> SignedRequest:
    if not isinstance(envelope.request.arguments, Mapping):
        return envelope
    try:
        payload = json.loads(canonical_json(envelope.request.to_mapping()))
    except (TypeError, ValueError):
        return envelope
    request = ToolRequest(
        request_id=payload["request_id"],
        principal_id=payload["principal_id"],
        tool=payload["tool"],
        arguments=payload["arguments"],
        issued_at=payload["issued_at"],
        nonce=payload["nonce"],
    )
    return SignedRequest(key_id=envelope.key_id, request=request, signature=envelope.signature)
