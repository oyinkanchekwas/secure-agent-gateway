from __future__ import annotations

from dataclasses import replace
import unittest

from secure_agent_gateway.auth import (
    AuthenticationError,
    Authenticator,
    NonceStore,
    PrincipalCredential,
)
from secure_agent_gateway.models import Principal, SignedRequest, ToolRequest

from tests.support import AUTH_KEY, NOW, make_request, sign


class AuthenticatorTests(unittest.TestCase):
    def setUp(self) -> None:
        principal = Principal("agent-1", frozenset({"researcher"}))
        self.authenticator = Authenticator(
            {
                "agent-key": PrincipalCredential(
                    key_id="agent-key",
                    principal=principal,
                    secret=AUTH_KEY,
                )
            }
        )

    def test_valid_signature_authenticates_principal(self) -> None:
        principal = self.authenticator.authenticate(sign(make_request()), now=NOW)
        self.assertEqual(principal.principal_id, "agent-1")

    def test_nonce_replay_is_rejected(self) -> None:
        envelope = sign(make_request())
        self.authenticator.authenticate(envelope, now=NOW)
        with self.assertRaisesRegex(AuthenticationError, "auth.replayed_nonce"):
            self.authenticator.authenticate(envelope, now=NOW)

    def test_changed_request_breaks_signature(self) -> None:
        envelope = sign(make_request())
        changed = replace(envelope, request=replace(envelope.request, tool="delete_file"))
        with self.assertRaisesRegex(AuthenticationError, "auth.invalid_signature"):
            self.authenticator.authenticate(changed, now=NOW)

    def test_changed_session_breaks_signature(self) -> None:
        envelope = sign(make_request())
        changed = replace(
            envelope,
            request=replace(envelope.request, session_id="another-session"),
        )
        with self.assertRaisesRegex(AuthenticationError, "auth.invalid_signature"):
            self.authenticator.authenticate(changed, now=NOW)

    def test_stale_signed_request_is_rejected(self) -> None:
        envelope = sign(make_request(issued_at=NOW - 301))
        with self.assertRaisesRegex(AuthenticationError, "auth.stale_request"):
            self.authenticator.authenticate(envelope, now=NOW)

    def test_principal_is_bound_to_key(self) -> None:
        envelope = sign(make_request(principal_id="another-agent"))
        with self.assertRaisesRegex(AuthenticationError, "auth.principal_mismatch"):
            self.authenticator.authenticate(envelope, now=NOW)

    def test_malformed_request_is_rejected_before_signature_work(self) -> None:
        request = ToolRequest(
            request_id="req-bad",
            principal_id="agent-1",
            tool="search_docs",
            arguments=[],  # type: ignore[arg-type]
            issued_at=NOW,
            nonce="nonce-bad",
        )
        envelope = SignedRequest(key_id="agent-key", request=request, signature="invalid")
        with self.assertRaisesRegex(AuthenticationError, "auth.invalid_request_shape"):
            self.authenticator.authenticate(envelope, now=NOW)

    def test_nonce_store_discards_expired_markers(self) -> None:
        store = NonceStore()
        self.assertTrue(store.consume("key", "nonce", now=10, retention_seconds=5))
        self.assertFalse(store.consume("key", "nonce", now=14, retention_seconds=5))
        self.assertTrue(store.consume("key", "nonce", now=16, retention_seconds=5))

    def test_non_finite_number_is_rejected_as_invalid_encoding(self) -> None:
        request = make_request(arguments={"query": float("nan")})
        envelope = SignedRequest(key_id="agent-key", request=request, signature="invalid")
        with self.assertRaisesRegex(AuthenticationError, "auth.invalid_request_encoding"):
            self.authenticator.authenticate(envelope, now=NOW)

    def test_oversized_request_is_rejected_before_signature_verification(self) -> None:
        authenticator = Authenticator(
            {
                "agent-key": PrincipalCredential(
                    key_id="agent-key",
                    principal=Principal("agent-1", frozenset({"researcher"})),
                    secret=AUTH_KEY,
                )
            },
            max_request_bytes=128,
        )
        envelope = sign(make_request(arguments={"query": "x" * 256}))
        with self.assertRaisesRegex(AuthenticationError, "auth.request_too_large"):
            authenticator.authenticate(envelope, now=NOW)

    def test_credential_representation_does_not_expose_secret(self) -> None:
        credential = PrincipalCredential(
            key_id="agent-key",
            principal=Principal("agent-1", frozenset({"researcher"})),
            secret=AUTH_KEY,
        )
        self.assertNotIn(AUTH_KEY.decode("ascii"), repr(credential))

    def test_short_credential_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 16 bytes"):
            PrincipalCredential(
                key_id="agent-key",
                principal=Principal("agent-1", frozenset({"researcher"})),
                secret=b"short",
            )

    def test_credential_map_key_must_match_key_id(self) -> None:
        credential = PrincipalCredential(
            key_id="agent-key",
            principal=Principal("agent-1", frozenset({"researcher"})),
            secret=AUTH_KEY,
        )
        with self.assertRaisesRegex(ValueError, "map key"):
            Authenticator({"different-key": credential})

    def test_session_scoped_credential_rejects_another_session(self) -> None:
        credential = PrincipalCredential(
            key_id="agent-key",
            principal=Principal("agent-1", frozenset({"researcher"})),
            secret=AUTH_KEY,
            allowed_session_ids=frozenset({"session-1"}),
        )
        authenticator = Authenticator({"agent-key": credential})
        envelope = sign(make_request(session_id="session-2"))
        with self.assertRaisesRegex(AuthenticationError, "auth.session_mismatch"):
            authenticator.authenticate(envelope, now=NOW)


if __name__ == "__main__":
    unittest.main()
