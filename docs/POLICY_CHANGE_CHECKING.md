# Policy change checking

`PolicyChangeChecker` examines a proposed sequence policy before it replaces the active one. Both
policies are evaluated over the same invocation alphabet and against the same `FlowRequirement`
objects.

## Union-state search

The checker starts with an empty session and explores tool sequences breadth first. A branch stays
in the search whenever either policy permits it. This exposes two kinds of state:

- sessions reached by both policies; and
- sessions opened or closed by the proposal.

The second case is easy to miss when two policies are checked in separate runs. A proposal may
correct an early denial, expose a later tool sequence, and then permit a prohibited sink. The union
search evaluates that later boundary and records it as a proposal defect.

Each decision records whether the old policy and the proposal could reach its parent state. Metrics
for each policy use that policy's reachable decisions.

## Four report views

The report keeps four findings apart:

- `baseline_witnesses` records defects already present in the old policy;
- `candidate_witnesses` records defects in the proposal;
- `regression_witnesses` records behaviour made worse by the proposal; and
- `correction_witnesses` records behaviour repaired by the proposal.

Safety, permitted access, exact control strength, and causal evidence are assessed independently.
For each property and flow requirement, breadth-first order supplies the shortest witness.

`baseline_only_boundaries` and `candidate_only_boundaries` count states reached by one policy. A
failure on a candidate-only path is a regression because the proposal made that path executable. A
failure removed with a baseline-only path is recorded as a correction. The report also lists flow
requirements that lack a controlled prohibited/permitted boundary at the configured depth.

Every witness carries old-policy and proposal reachability flags. Controls evaluated outside a
policy's reachable state space remain visible for diagnosis. The flags identify executable
behaviour.

## Release decision

The default gate requires full proposal conformance, prevention, retained access, evidence, and
relational-boundary coverage. A regression fails the gate even when an aggregate threshold has been
relaxed.

`PolicyChangeAttestor` can sign the complete case-level report digest. A signature therefore binds
the old policy digest, proposal digest, requirement suite, event limit, decision budget, metrics,
and witnesses.

Run the checked example:

```bash
PYTHONPATH=src python3.11 examples/run_policy_change_check.py
```

## Scope

The result applies to the supplied templates, requirements, principal, and event limit. Tool output
is represented by registered effect labels. Adapter code and operating-system effects are outside
the model.

Passing requires acceptable witnesses and complete requirement coverage.
