# Secure Agent Gateway

Secure Agent Gateway controls how a coding agent reaches registered tools. An agent submits a
signed request; the gateway checks identity, role, parameters, rate, and policy before any adapter
runs.

Version `0.3.0` provides:

- HMAC-signed request envelopes with timestamp and nonce checks.
- Role and tool allowlists with strict parameter rules.
- Filesystem-root and HTTPS destination checks.
- Sliding-window rate limits.
- One-use approval receipts bound to the request digest and policy version.
- Session-bound approvals that expire when an intervening tool succeeds.
- Server-side credential injection after policy approval.
- Redacted JSONL audit records linked by SHA-256 hashes.
- Paired policy contracts for prevention, retained access, and evidence checks.
- Sequence rules over recorded tool effects, with causal event evidence.
- Paired trajectory contracts with first-intervention checks.
- Mutation analysis for disabled, weakened, and narrowed sequence rules.
- Bounded state exploration checked against separately authored flow requirements.
- Shortest safety, availability, control, and evidence counterexamples.
- A SQLite session store for persistent request claims and successful effects.
- An explicit uncertain outcome when an adapter finishes before state commit fails.
- An MCP host adapter for the `2026-07-28` tool result format.
- Python 3.11 and 3.12 tests for permitted calls and attack cases.

## Request path

```text
agent request
    |
    v
signature and replay checks
    |
    v
role, schema, destination, path, and rate policy
    |                    |
    |                    +--> deny
    v
session sequence policy
    |                    |
    |                    +--> deny
    v
allow or pending approval
    |
    v
registered adapter
    |
    v
redacted audit record
```

Approval receipts contain the request digest, policy version, session-context digest, approver
identity, issue time, expiry, and a one-use identifier. A changed request, policy version, or
session history invalidates the receipt.

Tool credentials are configured on the registered adapter. They do not appear in the agent request
or audit record.

## Paired policy contracts

The contract runner evaluates a prohibited request beside a permitted counterpart. It verifies the
declared field changes, checks the expected controls and causal evidence fields, and records both
unsafe-action prevention and permitted-task retention. The complete report can be signed for a
specific policy version.

```bash
PYTHONPATH=src python3.11 examples/run_policy_contracts.py
```

See [Paired policy contracts](docs/POLICY_CONTRACTS.md) for the data model, metrics, and limits.

## Sequence assurance

A registered tool may declare stable effects such as `data.customer`. Effects enter session history
only after the adapter succeeds. A sequence rule can then intervene when a later tool would combine
with those effects. Decisions identify the earlier event that supplied each causal effect.

The trajectory runner tests a prohibited sequence beside a minimally changed permitted sequence.
It checks the full control path, the first intervention, causal evidence, and retained task access.
The mutation analyser removes or weakens sequence rules and records which changes the suite catches.

```bash
PYTHONPATH=src python3.11 examples/run_sequence_assurance.py
PYTHONPATH=src python3.11 scripts/benchmark_sequence_policy.py --iterations 10000
```

The checked report is at
[`reports/v0.2-sequence-assurance.json`](reports/v0.2-sequence-assurance.json). See
[Sequence assurance](docs/SEQUENCE_ASSURANCE.md) for the contract model and limits.

## Bounded relational checking

The bounded checker enumerates tool sequences up to a configured depth. Runtime decisions come
from the gateway policy. Expected decisions come from separate `FlowRequirement` objects, so the
checker does not use `SequenceRule.match` as its oracle. It records controlled permitted and
prohibited boundaries, and returns the shortest counterexample found for each failed property.

```bash
PYTHONPATH=src python3.11 examples/run_bounded_check.py
```

The frozen example is at [`reports/v0.3-bounded-check.json`](reports/v0.3-bounded-check.json). See
[Bounded relational checking](docs/BOUNDED_CHECKING.md) for the model and scope.

## Persistent session state

`SQLiteSessionStore` preserves successful effects and claimed request identifiers across gateway
restarts. Session evaluation and effect recording share an immediate transaction, so another
process using the same database observes the committed order.

If the adapter returns and the following state commit fails, the gateway reports
`execution_uncertain`. A host can then check the provider-side outcome before deciding whether any
new action is safe.

```python
from secure_agent_gateway import SQLiteSessionStore

store = SQLiteSessionStore("gateway-state.sqlite3")
gateway = SecureAgentGateway(..., session_store=store)
```

See [Persistent session state](docs/PERSISTENT_STATE.md) for transaction behaviour and operational
limits.

## MCP host adapter

`MCPGatewayAdapter` converts an authorised MCP tool call into a signed gateway request. Tool
discovery is sorted, restricted to a host-supplied set, and marked for private caching. The adapter
uses an opaque, host-issued session handle for sequence state and keeps pending approval identifiers
out of model-visible tool content.

See [MCP host adapter](docs/MCP_ADAPTER.md) for integration requirements.

## Run the checks

```bash
git clone https://github.com/oyinkanchekwas/secure-agent-gateway.git
cd secure-agent-gateway
make PYTHON=python3.11 check
```

Run a local permitted request and verify its audit chain:

```bash
PYTHONPATH=src python3.11 -m secure_agent_gateway.cli demo --audit-log /tmp/gateway-audit.jsonl
PYTHONPATH=src python3.11 -m secure_agent_gateway.cli verify-audit /tmp/gateway-audit.jsonl
```

## Register a tool

```python
from secure_agent_gateway import FieldSpec, ToolSpec
from secure_agent_gateway.rate_limit import RateLimit

spec = ToolSpec(
    name="search_docs",
    fields={"query": FieldSpec("string", max_length=200)},
    allowed_roles=frozenset({"researcher"}),
    rate_limit=RateLimit(calls=30, period_seconds=60),
)
registry.register(spec, search_docs)
```

The gateway calls `search_docs(arguments, execution_context)` only after the request passes policy.
The execution context carries the authenticated principal and any server-selected credential.

## Project records

- [Design](docs/DESIGN.md)
- [Attack cases](docs/ATTACK_CASES.md)
- [Related work](docs/RELATED_WORK.md)
- [Bounded relational checking](docs/BOUNDED_CHECKING.md)
- [Persistent session state](docs/PERSISTENT_STATE.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)

## Current limits

Nonce, rate, and pending-approval state is held in memory. The SQLite store can persist request
claims and successful effects, though it does not preserve pending approvals. Registered adapters
run as trusted application code and are not sandboxed. The audit chain detects record edits;
external anchoring is needed to detect truncation or replacement of the complete file.

Bounded checking covers only the supplied templates, flow requirements, principal, and depth. A
passing report is evidence about that finite model. It is not a proof for arbitrary adapter code or
unmodelled tool arguments.

Path rules are checked again immediately before adapter execution. An adapter that opens files must
still use operating-system controls that resist symlink changes between validation and file access.

The repository contains fixture adapters and inert test values. It has not been evaluated as a
deployed network service.

## Licence

Code is available under the [MIT Licence](LICENSE).
