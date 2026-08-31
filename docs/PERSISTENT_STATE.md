# Persistent session state

`SQLiteSessionStore` is an optional store for a single host or several gateway processes sharing a
local database file. It persists two records:

- claimed request identifiers, which prevent a repeated identifier after restart; and
- successful session events, including tool names and declared effects.

The store uses WAL mode, full synchronous writes, foreign-key checks, a busy timeout, and
owner-restricted file permissions. Session processing starts with `BEGIN IMMEDIATE`. The transaction
remains open
through snapshot reading, policy evaluation, adapter execution, and successful effect recording.
Another writer sees the committed order after that transaction ends.

SQLite permits one active writer, so separate sessions can wait behind each other during adapter
execution. Hosts needing greater write concurrency should implement the `SessionStore` protocol
with a database that offers transaction-scoped row or advisory locks.

## Restart behaviour

Successful effects and claimed request identifiers survive reconstruction of the gateway and store.
The following state remains process-local:

- pending approval calls;
- consumed authentication nonces;
- sliding-window rate counters; and
- consumed approval identifiers.

An interrupted approved call can have an ambiguous outcome if the adapter performs an external
effect and the process stops before recording success. Adapters should use idempotency keys and
provider-side status checks for operations where that ambiguity has consequences.

If an adapter returns and session-state commit then fails, the gateway records
`execution_uncertain` with `state.commit_failed`. The host must check the provider-side outcome
before any retry. The original request identifier remains claimed.

The enclosing session transaction commits before the gateway writes its `succeeded` audit record.
A pre-execution transaction failure returns `state.unavailable` and leaves the adapter call count
at zero.

## Retention

The host application owns expiry, compaction, and schema migration. The database belongs
to the host application. Back-up, retention, and removal procedures need to match its policy and
audit requirements.
