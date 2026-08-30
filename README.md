# Secure Agent Gateway

Secure Agent Gateway controls how a coding agent reaches registered tools. An agent submits a
signed request; the gateway checks identity, role, parameters, rate, and policy before any adapter
runs.

Version `0.1.0` provides:

- HMAC-signed request envelopes with timestamp and nonce checks.
- Role and tool allowlists with strict parameter rules.
- Filesystem-root and HTTPS destination checks.
- Sliding-window rate limits.
- One-use approval receipts bound to the request digest and policy version.
- Server-side credential injection after policy approval.
- Redacted JSONL audit records linked by SHA-256 hashes.
- Paired policy contracts for prevention, retained access, and evidence checks.
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
allow or pending approval
    |
    v
registered adapter
    |
    v
redacted audit record
```

Approval receipts contain the request digest, policy version, approver identity, issue time, expiry,
and a one-use identifier. A changed request or policy version invalidates the receipt.

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
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)

## Current limits

Nonce, rate, request, and pending-approval state is held in memory. A multi-process service needs a
shared transactional store. Registered adapters run as trusted application code and are not
sandboxed. The audit chain detects record edits; external anchoring is needed to detect truncation
or replacement of the complete file.

Path rules are checked again immediately before adapter execution. An adapter that opens files must
still use operating-system controls that resist symlink changes between validation and file access.

The repository contains fixture adapters and inert test values. It has not been evaluated as a
deployed network service.

## Licence

Code is available under the [MIT Licence](LICENSE).
