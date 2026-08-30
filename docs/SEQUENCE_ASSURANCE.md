# Sequence assurance

Single-call policy checks miss risks created by a sequence of permitted actions. A document read may
be acceptable, and an outbound message may be acceptable, while sending data obtained by the first
action can violate policy.

## Runtime model

`ToolSpec.emitted_effects` declares stable labels for a successful tool result. The gateway records
those labels after the adapter returns without error. Failed and denied calls add no effects.

A `SequenceRule` contains:

- one rule identifier and reason code;
- one or more target tools;
- one or more required prior effects;
- a `deny` or `require_approval` control; and
- an optional history window measured in successful events.

When a rule matches, its evidence fields point to the prior request that supplied each effect. A
denial takes precedence if several rules match the same call.

Session history is keyed by authenticated principal and session handle. Calls sharing that key are
serialised through policy evaluation and effect recording, preventing a later sink from passing
policy while an earlier source is still committing its effect.

## Approval binding

A pending call records the digest of its session history. Its receipt signs that digest alongside
the request and policy version. Any successful call in the same session changes the history digest,
so resumption fails with `approval.context_changed`.

This is deliberately conservative. A host that permits unrelated work during an approval wait can
place that work in another authorised session.

## Paired trajectory contracts

Each contract contains a prohibited trajectory and a permitted trajectory of equal length. The
declared `changed_fields` must match every semantic difference between them. Transport fields such
as nonces and request identifiers do not count as semantic changes.

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

`SequenceMutationAnalyser` first requires the unmodified policy to pass. It then constructs supported
faults for each rule:

- remove the rule;
- change `deny` to `require_approval`;
- reduce an unbounded or multi-event history window to one event;
- remove one required effect when a rule has several effects; and
- remove one target when a rule covers several tools.

A mutant is killed when the same trajectory suite fails its configured thresholds. Surviving
mutants identify a contract gap or a mutation that is behaviourally equivalent for the supplied
cases. The score does not establish that untested sequences are controlled.

Run the checked example:

```bash
PYTHONPATH=src python3.11 examples/run_sequence_assurance.py
```

## Limits

Effect labels are registered by trusted host code. The gateway does not infer them from arbitrary
tool output. Static labels may over-approximate what a particular call returned, so contracts should
include benign sequences that expose unnecessary interventions.

The in-memory session store has no expiry or size bound. Long-running services need retention rules,
a transactional shared store, and policy-version migration. Session handles must be opaque and
checked against caller authority on every request.
