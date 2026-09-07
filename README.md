# Secure Agent Gateway

Secure Agent Gateway controls how a coding agent reaches registered tools. An agent submits a
signed request; the gateway checks identity, role, parameters, rate, and policy before any adapter
runs.

Version `0.5.0` provides:

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
- Bounded semantic comparison of old and proposed sequence policies.
- Union-state exploration that follows paths reachable under either policy.
- Separate witnesses for existing defects, proposal defects, regressions, and corrections.
- Signed policy-change reports bound to the complete case-level result.
- Requirement-driven synthesis of paired policy probes.
- Causal contrasts for each source effect and temporal probes for history windows.
- Named synthesis gaps, ambiguity counts, and mutation-tested generated contracts.
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

Registered adapters hold tool credentials. Agent requests and audit records remain free of
credential values.

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

A registered tool may declare stable effects such as `data.customer`. Successful adapter completion
precedes effect insertion into session history. A sequence rule can then intervene when a later tool
would combine with those effects. Decisions identify the earlier event that supplied each causal
effect.

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
from the gateway policy. Separate `FlowRequirement` objects supply expected decisions and keep the
oracle independent of `SequenceRule.match`. The checker records controlled permitted and
prohibited boundaries, and returns the shortest counterexample found for each failed property.

```bash
PYTHONPATH=src python3.11 examples/run_bounded_check.py
```

The frozen example is at [`reports/v0.3-bounded-check.json`](reports/v0.3-bounded-check.json). See
[Bounded relational checking](docs/BOUNDED_CHECKING.md) for the model and scope.

## Policy change checking

`PolicyChangeChecker` evaluates an old sequence policy and its proposed replacement against the
same independent flow requirements. It explores every branch reachable under either policy, so a
newly opened path is checked beyond the first changed decision.

The report separates defects already present in the old policy from defects introduced or repaired
by the proposal. Safety, permitted access, control strength, causal evidence, and requirement
coverage retain separate results. Each failed property carries its shortest trace witness.

```bash
PYTHONPATH=src python3.11 examples/run_policy_change_check.py
```

The checked report is at [`reports/v0.4-policy-change.json`](reports/v0.4-policy-change.json). See
[Policy change checking](docs/POLICY_CHANGE_CHECKING.md) for report fields and limits.

## Causal-temporal probe synthesis

`RequirementProbeSynthesiser` converts independent `FlowRequirement` objects into controlled
trajectory pairs. For each source effect, it finds a shortest prohibited trace and a one-event
replacement that removes that effect and retains the others. A temporal probe pads any minimum
trace ending before the declared history boundary with neutral events. The
isolated source effect then occupies the oldest visible position.

The synthesiser reports missing source producers, shadowed controls, and conditions lacking
one-event isolation in the supplied invocation alphabet. Equally minimal pairs remain counted in
the report.
Generated probes compile into `PairedTrajectoryContract` objects and can be checked with the normal
trajectory runner and mutation analyser. Separate source-depth, trace-length, and candidate limits
bound the search.

```bash
PYTHONPATH=src python3.11 examples/run_probe_synthesis.py
```

The reproducible result is at
[`reports/v0.5-causal-temporal-probes.json`](reports/v0.5-causal-temporal-probes.json). See
[Causal-temporal probe synthesis](docs/PROBE_SYNTHESIS.md) for the search method and limits.

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

The gateway calls `search_docs(arguments, execution_context)` after the request passes policy.
The execution context carries the authenticated principal and any server-selected credential.

## Project records

- [Design](docs/DESIGN.md)
- [Attack cases](docs/ATTACK_CASES.md)
- [Related work](docs/RELATED_WORK.md)
- [Bounded relational checking](docs/BOUNDED_CHECKING.md)
- [Policy change checking](docs/POLICY_CHANGE_CHECKING.md)
- [Causal-temporal probe synthesis](docs/PROBE_SYNTHESIS.md)
- [Persistent session state](docs/PERSISTENT_STATE.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)

## Citation

Citation metadata is available in [`CITATION.cff`](CITATION.cff). Cite version `0.5.0` when using
the causal-temporal probe synthesis report or its generated contracts.

## Current limits

Nonce, rate, and pending-approval state is held in memory. The SQLite store can persist request
claims and successful effects. Pending approvals remain memory-resident. Registered adapters run
as trusted application code outside a sandbox. The audit chain detects record edits;
external anchoring is needed to detect truncation or replacement of the complete file.

Bounded-checking evidence applies to the supplied templates, flow requirements, principal, and
depth. Arbitrary adapter code and unmodelled tool arguments remain outside that finite model.

Probe synthesis uses declared tool effects. Adapter implementation and correspondence to external
effects lie outside the synthesis model. Generated traces evaluate policy contracts with adapter
execution disabled.

Path rules are checked again immediately before adapter execution. An adapter that opens files must
still use operating-system controls that resist symlink changes between validation and file access.

Evaluation has covered fixture adapters and inert test values. Deployed network-service behaviour
remains untested.

## Licence

Code is available under the [MIT Licence](LICENSE).
