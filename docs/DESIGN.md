# Design

## Trust boundary

Agent requests are untrusted input. Identity records, tool registration, policy configuration,
approval signing keys, credential aliases, and adapters belong to the host application.

The agent may select a registered tool and provide fields declared by that tool. It cannot add a
credential, change the tool policy, choose an adapter, or approve its own pending call.

## Request envelope

A request contains:

```text
request_id
principal_id
tool
arguments
issued_at
nonce
session_id
```

The key identifier and request are signed together with HMAC-SHA-256. Authentication checks the
signature before principal binding, clock skew, and nonce consumption. The in-memory nonce store
rejects a second use of the same key and nonce.

The session identifier is part of the signed request. A credential can be restricted to an explicit
set of session identifiers.

## Policy order

Policy evaluation follows this order:

1. Registered tool lookup and role check.
2. Rejection of agent-supplied credential fields.
3. Required fields, types, choices, sizes, and numeric bounds.
4. Rate consumption.
5. Filesystem-root and HTTPS-host checks.
6. Approval selection for destructive or configured operations.
7. Sequence evaluation against successful prior events in the same principal session.

Each decision records machine-readable reason codes and the fields that caused it. Adapters receive
only requests that reach `allow` or carry a valid approval receipt.

Policy composition is monotonic. A base denial remains a denial. A sequence denial can strengthen
an approval decision, and equal approval decisions retain evidence from both policy layers.

Successful adapter calls append declared effects to the session history. Evaluation and effect
recording share a per-session lock, so concurrent calls cannot observe a partially committed
sequence.

## Request-bound approval

The first pass stores an authenticated pending call. An approver signs its request digest, policy
version, session-context digest, expiry, and one-use identifier. Resumption verifies and consumes
the receipt while holding the pending-state lock. It then checks the current session history under
the session lock. Competing valid receipts therefore produce one adapter execution.

The signing authority must remain outside agent control. An approval service can wrap the supplied
`ApprovalAuthority` interface while keeping its key in a managed secret store.

## Credential handling

Tool registration can declare a credential alias. The host resolves that alias after policy and
approval checks, then supplies the value through `ExecutionContext`. Agent arguments cannot select
the alias. Audit records omit the execution context and adapter output.

## Audit records

Each JSONL record includes the previous record hash. Recalculation detects edited, inserted, and
reordered records. Sensitive argument names are redacted before serialisation.

Requests that fail authentication record `[UNTRUSTED]` in place of their arguments. This keeps an
oversized or malformed unauthenticated body out of the audit file.

File deletion or full replacement requires an external checkpoint, signed digest, or remote append
store. The current implementation does not create such a checkpoint.

## Policy acceptance

Paired policy contracts exercise a prohibited request and a permitted counterpart through the same
policy. The pair records every semantic field that changes. A contract cannot be constructed when
the requests differ elsewhere.

Reports retain case-level decisions and evidence fields, then calculate prevention, retained access,
evidence coverage, exact control accuracy, and unnecessary intervention. A report digest binds those
results to the policy version and suite digest. This acceptance layer is separate from request-time
rate state.

Paired trajectory contracts apply the same controlled-pair rule to multi-call workflows. They stop
at the first intervention and record its index and causal session evidence. Mutation analysis tests
whether the suite notices removed or weakened sequence rules.

## Bounded relational check

`BoundedRelationalChecker` explores the configured invocation alphabet breadth first. It extends
only traces whose latest runtime decision is `allow`, matching the histories that can be produced
without approval. The search stops at the supplied event depth and decision budget.

`FlowRequirement` supplies the expected effect-to-sink relation through a separate data model. The
oracle reads successful events and does not invoke the runtime sequence matcher. Reports include
controlled permitted and prohibited boundaries, finite-model metrics, and shortest
counterexamples. Mutation analysis reruns the same independent requirements against changed
runtime policies.

## Session stores

`InMemorySessionStore` is the default. `SQLiteSessionStore` stores request claims and successful
effects on disk. An immediate SQLite transaction covers the session snapshot, policy evaluation,
adapter call, and effect commit. SQLite permits one writer at a time, so this implementation favours
strict ordering over write concurrency.

A successful adapter result remains provisional until the session transaction exits. The gateway
writes the success audit record after commit. Commit failure produces `execution_uncertain`; a
session-store failure before execution produces `state.unavailable` and a denial.

## Policy change gate

The change checker evaluates the active and proposed sequence policies over one union-state search.
A branch continues while either policy allows its latest action. Decisions retain separate
reachability flags, which prevents proposal-only paths from disappearing behind an earlier policy
difference.

Expected controls and evidence come from `FlowRequirement`, not from either runtime policy. The
report records old-policy defects, proposal defects, regressions, corrections, and uncovered
requirements separately. Its digest includes every explored decision, while the default rendering
keeps the case-level table optional.
