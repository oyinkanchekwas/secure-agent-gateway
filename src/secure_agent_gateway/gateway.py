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
from secure_agent_gateway.session import (
    InMemorySessionStore,
    SequencePolicy,
    SessionEvent,
    SessionSnapshot,
    SessionStore,
)


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
        session_store: SessionStore | None = None,
        sequence_policy: SequencePolicy | None = None,
    ) -> None:
        self._authenticator = authenticator
        self._policy = policy
        self._approvals = approvals
        self._audit = audit_log
        self._secret_provider = secret_provider
        self._pending_ttl_seconds = pending_ttl_seconds
        self._sessions = (
            session_store if session_store is not None else InMemorySessionStore()
        )
        self._sequence_policy = sequence_policy or SequencePolicy(())
        self._sequence_policy.validate_registry(self._policy.registry)
        self._pending: dict[str, PendingCall] = {}
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

        try:
            request_claimed = self._sessions.claim_request(
                request.request_id,
                principal.principal_id,
                now=observed_now,
            )
        except Exception:
            return self._session_failure_result(
                request=request,
                result=None,
                fallback_decision=None,
                now=observed_now,
            )
        if not request_claimed:
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
        result: GatewayResult | None = None
        session_event: SessionEvent | None = None
        transaction_entered = False
        transaction_body_completed = False
        try:
            with self._sessions.serialise(principal.principal_id, request.session_id):
                transaction_entered = True
                try:
                    snapshot = self._sessions.snapshot(
                        principal.principal_id,
                        request.session_id,
                    )
                except Exception:
                    result = self._session_failure_result(
                        request=request,
                        result=None,
                        fallback_decision=None,
                        now=observed_now,
                    )
                else:
                    decision = self._policy.evaluate(
                        principal,
                        request,
                        now=observed_now,
                    )
                    decision = self._sequence_policy.evaluate(request, snapshot, decision)
                    if decision.control == Control.DENY:
                        event_id = self._record(
                            request,
                            decision,
                            status="denied",
                            now=observed_now,
                        )
                        result = GatewayResult(
                            status="denied",
                            decision=decision,
                            error_code=decision.reason_codes[0],
                            audit_event_id=event_id,
                        )
                    elif decision.control == Control.REQUIRE_APPROVAL:
                        with self._state_lock:
                            self._pending[request.request_id] = PendingCall(
                                request=request,
                                principal=principal,
                                decision=decision,
                                created_at=observed_now,
                            )
                        event_id = self._record(
                            request,
                            decision,
                            status="pending_approval",
                            now=observed_now,
                        )
                        result = GatewayResult(
                            status="pending_approval",
                            decision=decision,
                            audit_event_id=event_id,
                        )
                    else:
                        result, session_event = self._execute(
                            request=request,
                            principal=principal,
                            decision=decision,
                            snapshot=snapshot,
                            now=observed_now,
                        )
                transaction_body_completed = True
        except Exception:
            if not transaction_entered or transaction_body_completed:
                return self._session_failure_result(
                    request=request,
                    result=result,
                    fallback_decision=None,
                    now=observed_now,
                )
            raise
        if result is None:
            raise RuntimeError("session transaction produced no result")
        return self._finalise_session_result(
            request=request,
            result=result,
            session_event=session_event,
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

        result = None
        session_event = None
        transaction_entered = False
        transaction_body_completed = False
        try:
            with self._sessions.serialise(
                pending.principal.principal_id,
                pending.request.session_id,
            ):
                transaction_entered = True
                try:
                    snapshot = self._sessions.snapshot(
                        pending.principal.principal_id,
                        pending.request.session_id,
                    )
                except Exception:
                    result = self._session_failure_result(
                        request=pending.request,
                        result=None,
                        fallback_decision=pending.decision,
                        now=observed_now,
                        approval_id=receipt.approval_id,
                    )
                else:
                    if snapshot.digest != pending.decision.context_digest:
                        decision = _approval_denial(
                            pending.decision,
                            "approval.context_changed",
                        )
                        event_id = self._record(
                            pending.request,
                            decision,
                            status="denied",
                            now=observed_now,
                            approval_id=receipt.approval_id,
                        )
                        result = GatewayResult(
                            status="denied",
                            decision=decision,
                            error_code="approval.context_changed",
                            audit_event_id=event_id,
                            approval_id=receipt.approval_id,
                        )
                    else:
                        result, session_event = self._execute(
                            request=pending.request,
                            principal=pending.principal,
                            decision=pending.decision,
                            snapshot=snapshot,
                            now=observed_now,
                            approval_id=receipt.approval_id,
                        )
                transaction_body_completed = True
        except Exception:
            if not transaction_entered or transaction_body_completed:
                return self._session_failure_result(
                    request=pending.request,
                    result=result,
                    fallback_decision=pending.decision,
                    now=observed_now,
                    approval_id=receipt.approval_id,
                )
            raise
        if result is None:
            raise RuntimeError("session transaction produced no result")
        return self._finalise_session_result(
            request=pending.request,
            result=result,
            session_event=session_event,
            now=observed_now,
            approval_id=receipt.approval_id,
        )

    def _execute(
        self,
        *,
        request: ToolRequest,
        principal: Principal,
        decision: PolicyDecision,
        snapshot: SessionSnapshot,
        now: int,
        approval_id: str | None = None,
    ) -> tuple[GatewayResult, SessionEvent | None]:
        if decision.policy_version != self._policy.policy_version:
            changed = _approval_denial(decision, "policy.version_changed")
            event_id = self._record(
                request,
                changed,
                status="denied",
                now=now,
                approval_id=approval_id,
            )
            return (
                GatewayResult(
                    status="denied",
                    decision=changed,
                    error_code="policy.version_changed",
                    audit_event_id=event_id,
                    approval_id=approval_id,
                ),
                None,
            )
        current = self._policy.revalidate(principal, request)
        current = self._sequence_policy.evaluate(request, snapshot, current)
        if current.control == Control.DENY:
            event_id = self._record(
                request,
                current,
                status="denied",
                now=now,
                approval_id=approval_id,
            )
            return (
                GatewayResult(
                    status="denied",
                    decision=current,
                    error_code=current.reason_codes[0],
                    audit_event_id=event_id,
                    approval_id=approval_id,
                ),
                None,
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
            return (
                GatewayResult(
                    status="execution_failed",
                    decision=decision,
                    error_code="adapter.failure",
                    audit_event_id=event_id,
                    approval_id=approval_id,
                ),
                None,
            )
        try:
            session_event = self._sessions.record_success(
                principal.principal_id,
                request.session_id,
                request.request_id,
                request.tool,
                registered.spec.emitted_effects,
            )
        except Exception:
            return (
                self._execution_uncertain_result(
                    request=request,
                    decision=decision,
                    now=now,
                    approval_id=approval_id,
                ),
                None,
            )
        return (
            GatewayResult(
                status="succeeded",
                decision=decision,
                output=output,
                approval_id=approval_id,
            ),
            session_event,
        )

    def _finalise_session_result(
        self,
        *,
        request: ToolRequest,
        result: GatewayResult,
        session_event: SessionEvent | None,
        now: int,
        approval_id: str | None = None,
    ) -> GatewayResult:
        if result.status != "succeeded":
            return result
        if session_event is None:
            raise RuntimeError("successful execution has no committed session event")
        event_id = self._record(
            request,
            result.decision,
            status="succeeded",
            now=now,
            approval_id=approval_id,
            session_event=session_event,
        )
        return GatewayResult(
            status="succeeded",
            decision=result.decision,
            output=result.output,
            audit_event_id=event_id,
            approval_id=approval_id,
        )

    def _session_failure_result(
        self,
        *,
        request: ToolRequest,
        result: GatewayResult | None,
        fallback_decision: PolicyDecision | None,
        now: int,
        approval_id: str | None = None,
    ) -> GatewayResult:
        if result is not None:
            if result.status == "succeeded":
                return self._execution_uncertain_result(
                    request=request,
                    decision=result.decision,
                    now=now,
                    approval_id=approval_id,
                )
            return result
        basis = fallback_decision
        decision = PolicyDecision(
            control=Control.DENY,
            reason_codes=("state.unavailable",),
            evidence_fields=("session_id",),
            request_digest=(
                basis.request_digest if basis is not None else request_digest(request)
            ),
            policy_version=(
                basis.policy_version
                if basis is not None
                else self._policy.policy_version
            ),
            context_digest=(basis.context_digest if basis is not None else "0" * 64),
        )
        event_id = self._record(
            request,
            decision,
            status="denied",
            now=now,
            approval_id=approval_id,
        )
        return GatewayResult(
            status="denied",
            decision=decision,
            error_code="state.unavailable",
            audit_event_id=event_id,
            approval_id=approval_id,
        )

    def _execution_uncertain_result(
        self,
        *,
        request: ToolRequest,
        decision: PolicyDecision,
        now: int,
        approval_id: str | None = None,
    ) -> GatewayResult:
        event_id = self._record(
            request,
            decision,
            status="execution_uncertain",
            now=now,
            approval_id=approval_id,
        )
        return GatewayResult(
            status="execution_uncertain",
            decision=decision,
            error_code="state.commit_failed",
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
        session_event: SessionEvent | None = None,
    ) -> str:
        event: dict[str, Any] = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "session_id": request.session_id,
            "tool": request.tool,
            "arguments": self._audit_arguments(request) if include_arguments else "[UNTRUSTED]",
            "control": decision.control.value,
            "reason_codes": list(decision.reason_codes),
            "evidence_fields": list(decision.evidence_fields),
            "request_digest": decision.request_digest,
            "policy_version": decision.policy_version,
            "context_digest": decision.context_digest,
            "status": status,
        }
        if approval_id is not None:
            event["approval_id"] = approval_id
        if session_event is not None:
            event["session_sequence"] = session_event.sequence
            event["emitted_effects"] = sorted(session_event.effects)
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
        context_digest=decision.context_digest,
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
        session_id=payload["session_id"],
    )
    return SignedRequest(key_id=envelope.key_id, request=request, signature=envelope.signature)
