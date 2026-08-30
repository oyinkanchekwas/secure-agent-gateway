# Threat model

## Protected assets

- Registered tool authority and adapter selection.
- Files reachable through tool adapters.
- Outbound destinations and transmitted data.
- Server-held credentials.
- Approval decisions and audit records.
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
| Outbound exfiltration | HTTPS requirement and exact host allowlist |
| Agent-supplied credentials | Credential-field rejection and server-selected aliases |
| Destructive operation | Request-bound, expiring, one-use approval receipt |
| Repeated calls | Per-principal and per-tool sliding window |
| Audit modification | Redaction and hash-linked records |

## Assumptions

The host protects signing keys and policy configuration. Adapter code is reviewed and runs with the
minimum operating-system permissions needed for its task. Approvers authenticate outside the agent
session. System time is trustworthy enough for request and receipt expiry. Filesystem adapters use
race-safe operating-system calls after the gateway path check.

## Outside this release

This release does not sandbox adapters, distribute keys, rotate credentials, terminate TLS, or
provide a shared state store. It does not inspect the semantic content of permitted payloads. Host
applications must add controls for those responsibilities.
