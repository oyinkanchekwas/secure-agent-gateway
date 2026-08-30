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
```

The key identifier and request are signed together with HMAC-SHA-256. Authentication checks the
signature before principal binding, clock skew, and nonce consumption. The in-memory nonce store
rejects a second use of the same key and nonce.

## Policy order

Policy evaluation follows this order:

1. Registered tool lookup and role check.
2. Rejection of agent-supplied credential fields.
3. Required fields, types, choices, sizes, and numeric bounds.
4. Rate consumption.
5. Filesystem-root and HTTPS-host checks.
6. Approval selection for destructive or configured operations.

Each decision records machine-readable reason codes and the fields that caused it. Adapters receive
only requests that reach `allow` or carry a valid approval receipt.

## Request-bound approval

The first pass stores an authenticated pending call. An approver signs its request digest and policy
version with an expiry and one-use identifier. Resumption verifies and consumes the receipt while
holding the pending-state lock. Competing valid receipts therefore produce one adapter execution.

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
