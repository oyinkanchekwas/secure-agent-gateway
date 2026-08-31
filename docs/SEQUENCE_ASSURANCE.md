# Sequence assurance

Single-call policy checks miss risks created by a sequence of permitted actions. A document read and
an outbound message may each be acceptable in isolation. Sending data obtained by the first action
can violate policy.

## Runtime model

`ToolSpec.emitted_effects` declares stable labels for a successful tool result. The gateway records
those labels after a successful adapter return. Failed and denied calls add zero effects.

A `SequenceRule` contains:

- one rule identifier and reason code;
- one or more target tools;
- one or more required prior effects;
- a `deny` or `require_approval` control; and
- an optional history window measured in successful events.

When a rule matches, its evidence fields point to the prior request that supplied each effect. A
denial takes precedence if several rules match the same call. Sequence evaluation preserves or
strengthens a denial produced by role, schema, rate, path, host, or secret checks.

Session history is keyed by authenticated principal and session handle. Calls sharing that key are
serialised through policy evaluation and effect recording. A later sink waits for an earlier
source to commit its effect before policy evaluation.

## Approval binding

A pending call records the digest of its session history. Its receipt signs that digest alongside
the request and policy version. Any successful call in the same session changes the history digest,
so resumption fails with `approval.context_changed`.

This is deliberately conservative. A host that permits unrelated work during an approval wait can
place that work in another authorised session.

## Paired trajectory contracts

Each contract contains a prohibited trajectory and a permitted trajectory of equal length. The
declared `changed_fields` must match every semantic difference between them. Semantic comparison
excludes transport fields such as nonces and request identifiers.

A prohibited trajectory ends at its first expected intervention. Its permitted counterpart must
complete with `allow` on every step. The report contains:

- exact control accuracy;
- unsafe-sequence prevention;
- permitted-trajectory completion;
- first-intervention accuracy;
- causal-evidence coverage; and
- unnecessary-intervention rate.

The sequence-policy digest, contract-suite digest, thresholds, decisions, and metrics are included
in the report digest.

## Mutation analysis

`SequenceMutationAnalyser` first requires the unmodified policy to pass. It then constructs
supported faults for each rule:

- remove the rule;
- change `deny` to `require_approval`;
- reduce an unbounded or multi-event history window to one event;
- remove one required effect when a rule has several effects; and
- remove one target when a rule covers several tools.

A mutant is killed when the same trajectory suite fails its configured thresholds. Surviving
mutants identify a contract gap or a mutation that is behaviourally equivalent for the supplied
cases. The score's evidentiary scope is limited to those cases.

Run the checked example:

```bash
PYTHONPATH=src python3.11 examples/run_sequence_assurance.py
```

## Limits

Trusted host code registers effect labels. Tool output has zero authority over those labels. Static
labels may over-approximate what a particular call returned, so contracts should
include benign sequences that expose unnecessary interventions.

The in-memory session store has unbounded retention and process-local coordination.
`SQLiteSessionStore` supplies shared transactional ordering, persistent request claims, and
persistent successful effects. Retention policy and policy-version migration belong to the host
application. Session handles must be opaque and checked against
caller authority on every request.
