# Threat model

## Protected assets

- Registered tool authority and adapter selection.
- Files reachable through tool adapters.
- Outbound destinations and transmitted data.
- Server-held credentials.
- Approval decisions and audit records.
- Session history and sequence-policy decisions.
- Service availability within configured rate limits.

## Attacker capabilities

An attacker may control an agent prompt, retrieved document, tool arguments, request ordering, and
repeated call attempts. A compromised agent key permits requests only for the bound principal and
its roles. The attacker may inspect returned tool output.

## Controls

| Risk | Control |
| --- | --- |
| Forged caller | HMAC envelope and principal-to-key binding |
| Replayed request | Timestamp window, nonce consumption, and unique request identifier |
| Unregistered capability | Tool registry and role allowlist |
| Malformed parameters | Closed field set and runtime type checks |
| Filesystem escape | Absolute-path requirement and resolved-root containment |
| Outbound exfiltration | HTTPS requirement, exact host allowlist, and effect-to-sink sequence rules |
| Agent-supplied credentials | Credential-field rejection and server-selected aliases |
| Destructive operation | Request-bound, session-bound, expiring, one-use approval receipt |
| Concurrent sequence bypass | Per-principal and per-session serialisation |
| Session substitution | Signed session handle and optional credential-to-session binding |
| Repeated calls | Per-principal and per-tool sliding window |
| Audit modification | Redaction and hash-linked records |
| Process restart replay | Persistent request claims in `SQLiteSessionStore` |
| Cross-process sequence race | Immediate SQLite transaction around evaluation and effect commit |

## Assumptions

The host protects signing keys, policy configuration, effect labels, and session handles. Adapter
code is reviewed and runs with the minimum operating-system permissions needed for its task.
Approvers authenticate outside the agent session. System time is trustworthy enough for request and
receipt expiry. Filesystem adapters use race-safe operating-system calls after the gateway path
check. Host-issued session handles are opaque, time-bounded, and checked against caller authority.

## Outside this release

This release does not sandbox adapters, distribute keys, rotate credentials, or terminate TLS. It
does not infer effects from tool output or inspect the semantic content of permitted payloads.
Pending approvals, nonce windows, and rate counters are not persisted by `SQLiteSessionStore`.
Host applications must add controls for those responsibilities.
