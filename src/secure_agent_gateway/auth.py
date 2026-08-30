from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
from threading import Lock
import time
from typing import Any, Mapping

from secure_agent_gateway.models import Principal, SignedRequest, ToolRequest


class AuthenticationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def request_digest(request: ToolRequest) -> str:
    return hashlib.sha256(canonical_json(request.to_mapping()).encode("utf-8")).hexdigest()


def _signature_message(key_id: str, request: ToolRequest) -> bytes:
    payload = {"key_id": key_id, "request": request.to_mapping()}
    return canonical_json(payload).encode("utf-8")


def sign_request(request: ToolRequest, key_id: str, secret: bytes) -> SignedRequest:
    signature = hmac.new(secret, _signature_message(key_id, request), hashlib.sha256).hexdigest()
    return SignedRequest(key_id=key_id, request=request, signature=signature)


@dataclass(frozen=True)
class PrincipalCredential:
    key_id: str
    principal: Principal
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.key_id or len(self.key_id) > 256:
            raise ValueError("credential key_id is invalid")
        if not isinstance(self.secret, bytes) or len(self.secret) < 16:
            raise ValueError("credential secret must contain at least 16 bytes")


class NonceStore:
    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    def consume(self, key_id: str, nonce: str, *, now: int, retention_seconds: int) -> bool:
        marker = (key_id, nonce)
        with self._lock:
            expired = [known for known, expiry in self._seen.items() if expiry < now]
            for known in expired:
                del self._seen[known]
            if marker in self._seen:
                return False
            self._seen[marker] = now + retention_seconds
            return True


class Authenticator:
    def __init__(
        self,
        credentials: Mapping[str, PrincipalCredential],
        *,
        max_clock_skew_seconds: int = 300,
        max_request_bytes: int = 65_536,
        nonce_store: NonceStore | None = None,
    ) -> None:
        if max_clock_skew_seconds < 1:
            raise ValueError("max_clock_skew_seconds must be positive")
        if max_request_bytes < 1:
            raise ValueError("max_request_bytes must be positive")
        for key_id, credential in credentials.items():
            if key_id != credential.key_id:
                raise ValueError("credential map key does not match credential key_id")
        self._credentials = dict(credentials)
        self._max_clock_skew_seconds = max_clock_skew_seconds
        self._max_request_bytes = max_request_bytes
        self._nonce_store = nonce_store or NonceStore()

    def authenticate(self, envelope: SignedRequest, *, now: int | None = None) -> Principal:
        observed_now = int(time.time()) if now is None else now
        _validate_request_shape(envelope)
        credential = self._credentials.get(envelope.key_id)
        if credential is None:
            raise AuthenticationError("auth.unknown_key")

        try:
            message = _signature_message(envelope.key_id, envelope.request)
        except (TypeError, ValueError) as exc:
            raise AuthenticationError("auth.invalid_request_encoding") from exc
        if len(message) > self._max_request_bytes:
            raise AuthenticationError("auth.request_too_large")
        expected = hmac.new(credential.secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, envelope.signature):
            raise AuthenticationError("auth.invalid_signature")
        if credential.principal.principal_id != envelope.request.principal_id:
            raise AuthenticationError("auth.principal_mismatch")
        if abs(observed_now - envelope.request.issued_at) > self._max_clock_skew_seconds:
            raise AuthenticationError("auth.stale_request")
        if not self._nonce_store.consume(
            envelope.key_id,
            envelope.request.nonce,
            now=observed_now,
            retention_seconds=(self._max_clock_skew_seconds * 2) + 1,
        ):
            raise AuthenticationError("auth.replayed_nonce")
        return credential.principal


def _validate_request_shape(envelope: SignedRequest) -> None:
    request = envelope.request
    strings = (
        envelope.key_id,
        envelope.signature,
        request.request_id,
        request.principal_id,
        request.tool,
        request.nonce,
    )
    if any(not isinstance(value, str) or not value or len(value) > 256 for value in strings):
        raise AuthenticationError("auth.invalid_request_shape")
    if not isinstance(request.arguments, Mapping):
        raise AuthenticationError("auth.invalid_request_shape")
    if not isinstance(request.issued_at, int) or isinstance(request.issued_at, bool):
        raise AuthenticationError("auth.invalid_request_shape")
