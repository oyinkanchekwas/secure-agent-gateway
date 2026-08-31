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
repeated call attempts. A compromised agent key restricts requests to the bound principal and
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
| Unsafe policy replacement | Union-state change check against separate flow requirements |

## Assumptions

The host protects signing keys, policy configuration, effect labels, and session handles. Adapter
code is reviewed and runs with the minimum operating-system permissions needed for its task.
Approvers authenticate outside the agent session. System time is trustworthy enough for request and
receipt expiry. Filesystem adapters use race-safe operating-system calls after the gateway path
check. Host-issued session handles are opaque, time-bounded, and checked against caller authority.

Policy-change checks assume that the invocation templates and flow requirements were reviewed
outside the runtime policy implementation. An incomplete alphabet or shallow event limit can leave
a flow requirement uncovered; the report names each uncovered requirement.

Probe synthesis assumes that each registered tool's declared effects match its successful adapter
effects. Generated probes cover policy evaluation. Adapter effect accuracy and undeclared external
changes remain outside their evidence.

## Host responsibilities

Host applications supply adapter sandboxing, distributed key management, credential rotation, and
TLS termination. Effect inference from tool output and semantic payload inspection lie outside this
release. `SQLiteSessionStore` keeps pending approvals, nonce windows, and rate counters in memory.
