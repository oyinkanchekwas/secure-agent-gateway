from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import time
from threading import Lock
from typing import Any
from uuid import uuid4

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.models import Control, PolicyDecision


class ApprovalError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    request_digest: str
    policy_version: str
    context_digest: str
    approver_id: str
    issued_at: int
    expires_at: int
    signature: str

    def unsigned_mapping(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "request_digest": self.request_digest,
            "policy_version": self.policy_version,
            "context_digest": self.context_digest,
            "approver_id": self.approver_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


class ApprovalAuthority:
    def __init__(
        self,
        signing_key: bytes,
        approver_ids: set[str] | frozenset[str],
        *,
        max_ttl_seconds: int = 3600,
    ) -> None:
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            raise ValueError("approval signing key must contain at least 16 bytes")
        if not approver_ids:
            raise ValueError("at least one approver is required")
        if max_ttl_seconds < 1:
            raise ValueError("max_ttl_seconds must be positive")
        self._signing_key = signing_key
        self._approver_ids = frozenset(approver_ids)
        self._max_ttl_seconds = max_ttl_seconds
        self._consumed: set[str] = set()
        self._lock = Lock()

    def issue(
        self,
        decision: PolicyDecision,
        *,
        approver_id: str,
        ttl_seconds: int = 300,
        now: int | None = None,
        approval_id: str | None = None,
    ) -> ApprovalReceipt:
        if decision.control != Control.REQUIRE_APPROVAL:
            raise ApprovalError("approval.not_required")
        if approver_id not in self._approver_ids:
            raise ApprovalError("approval.approver_denied")
        if ttl_seconds < 1 or ttl_seconds > self._max_ttl_seconds:
            raise ApprovalError("approval.invalid_ttl")
        issued_at = int(time.time()) if now is None else now
        unsigned = {
            "approval_id": approval_id or str(uuid4()),
            "request_digest": decision.request_digest,
            "policy_version": decision.policy_version,
            "context_digest": decision.context_digest,
            "approver_id": approver_id,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
        }
        signature = self._sign(unsigned)
        return ApprovalReceipt(signature=signature, **unsigned)

    def verify_and_consume(
        self,
        receipt: ApprovalReceipt,
        decision: PolicyDecision,
        *,
        now: int | None = None,
    ) -> None:
        observed_now = int(time.time()) if now is None else now
        try:
            expected = self._sign(receipt.unsigned_mapping())
        except (TypeError, ValueError) as exc:
            raise ApprovalError("approval.invalid_receipt") from exc
        if not hmac.compare_digest(expected, receipt.signature):
            raise ApprovalError("approval.invalid_signature")
        if receipt.request_digest != decision.request_digest:
            raise ApprovalError("approval.request_mismatch")
        if receipt.policy_version != decision.policy_version:
            raise ApprovalError("approval.policy_mismatch")
        if receipt.context_digest != decision.context_digest:
            raise ApprovalError("approval.context_mismatch")
        if receipt.approver_id not in self._approver_ids:
            raise ApprovalError("approval.approver_denied")
        if observed_now < receipt.issued_at:
            raise ApprovalError("approval.not_yet_valid")
        if receipt.expires_at <= receipt.issued_at:
            raise ApprovalError("approval.invalid_ttl")
        if receipt.expires_at - receipt.issued_at > self._max_ttl_seconds:
            raise ApprovalError("approval.invalid_ttl")
        if observed_now > receipt.expires_at:
            raise ApprovalError("approval.expired")
        with self._lock:
            if receipt.approval_id in self._consumed:
                raise ApprovalError("approval.replayed")
            self._consumed.add(receipt.approval_id)

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self._signing_key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
