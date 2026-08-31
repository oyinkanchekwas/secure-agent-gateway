# Changelog

## 0.4.0 - 2026-08-31

- Added bounded comparison of old and proposed sequence policies.
- Explored the union of states reachable under either policy.
- Separated old-policy defects, proposal defects, regressions, and corrections.
- Classified failed candidate-only paths as regressions caused by newly reachable state.
- Added policy reachability to each witness so counterfactual controls remain identifiable.
- Bound the event limit and decision budget into the signed report.
- Added shortest witnesses for safety, access, control strength, and causal evidence.
- Reported requirements left untested by the chosen invocation alphabet or depth.
- Added signed attestations that bind the full case-level change report.

## 0.3.1 - 2026-08-31

- Delayed success results and audit records until session transaction commit.
- Converted commit-time failures after adapter execution to `execution_uncertain`.
- Added a `state.unavailable` denial when session state fails before execution.

## 0.3.0 - 2026-08-31

- Prevented sequence rules from weakening base policy denials.
- Separated MCP adapter failures from policy-denial messages.
- Added finite sequence exploration against independent flow requirements.
- Added controlled relational boundaries and shortest counterexamples.
- Added mutation checks driven by the independent requirement model.
- Added SQLite persistence for request claims and successful session effects.
- Added `execution_uncertain` for adapter success followed by session-state commit failure.

## 0.2.0 - 2026-08-31

- Added signed session identifiers and optional credential-to-session binding.
- Added sequence rules over effects from successful tool calls.
- Added per-session serialisation and session-bound approval receipts.
- Added paired trajectory contracts with intervention and evidence metrics.
- Added sequence-policy mutation analysis and a checked assurance report.
- Added an MCP host adapter for the `2026-07-28` tool result format.

## 0.1.0 - 2026-08-31

- Added signed request envelopes with replay checks and principal binding.
- Added role, schema, path, host, secret-field, and rate policies.
- Added request-bound approval receipts and atomic pending-call resumption.
- Added server-selected credential injection and adapter execution.
- Added redacted hash-linked audit records.
- Added controlled-pair policy contracts with acceptance metrics and signed result digests.
- Added attack-case tests and Python 3.11/3.12 CI.
