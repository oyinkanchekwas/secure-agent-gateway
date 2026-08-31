# Causal-temporal probe synthesis

`RequirementProbeSynthesiser` builds policy tests from `FlowRequirement` objects and registered
invocation templates. It uses read-only policy evaluation; adapter execution is disabled.

## Search method

For each requirement, the synthesiser searches template permutations in increasing length. A source
trace is eligible when its declared tool effects cover the requirement's source effects and the
declared sink produces the expected intervention. Another requirement may intervene first; this is
reported as a shadowed requirement.

The synthesiser then replaces one source event and holds the remaining events and sink fixed.
A source-effect probe is accepted when:

- the prohibited trace reaches the expected intervention;
- the replacement trace remains permitted from start to finish;
- exactly one required source effect disappears; and
- every other required source effect remains present.

One probe is required for each source effect. This causal basis detects rules that silently drop a
condition, including cases where another generated pair still exercises the remaining conditions.

## History persistence

A minimum-length trace can leave the latest source event immediately beside the sink. Such a test
leaves a one-event history contraction undetected.

For a finite window, the synthesiser places the isolated source effect at the oldest visible event.
The permitted pair removes that effect and retains the trace length and sink. This detects a
one-event contraction at the declared boundary. An unbounded requirement is tested with evidence
older than the latest action. A missing neutral template or an earlier intervention is recorded as
a synthesis gap.

## Causal contribution and ambiguity

Each source event lists the effects that disappear when that event is removed. Every event in a
minimum-cardinality source trace supplies at least one indispensable effect.

`isolated_effect_age` records the distance from the changed source event to the sink. For a finite
history probe, this equals the requirement's declared window.

Several tools, source orders, or neutral replacements may yield the same minimum score. The chosen
pair is deterministic, and `minimal_pair_count` records how many pairs share its trace length,
single-effect removal, non-sink replacement preference, and effect distance. The count prevents a
deterministic tie-break from being misread as a unique causal explanation.

## Generated contracts

`ProbeSynthesisReport.build_contracts()` converts a complete report into
`PairedTrajectoryContract` objects. The suite digest binds the principal, invocation arguments,
declared tool effects, flow requirements, and search limits. Contract construction repeats the
independent oracle calculation and rejects changed evidence.

The contracts can be passed to `TrajectoryContractRunner` and `SequenceMutationAnalyser`:

```python
synthesis = RequirementProbeSynthesiser(policy).run(
    principal=principal,
    templates=templates,
    requirements=requirements,
)
contracts = synthesis.build_contracts()
trajectory = TrajectoryContractRunner(policy, sequence_policy).run(contracts)
mutation = SequenceMutationAnalyser(policy, sequence_policy).run(contracts)
```

## Gap codes

- `missing_source_effect`: a required effect lacks an emitting template.
- `missing_sink_template`: a declared sink lacks an invocation template.
- `source_limit_exhausted`: the configured event limit is too small.
- `trace_limit_exhausted`: a history boundary exceeds the total trace limit.
- `no_selectable_prohibited_trace`: another requirement intervenes first or changes the control.
- `non_isolatable_source_effect`: supplied replacements fail to isolate one source effect.
- `no_temporal_contrast`: supplied neutral events fail to test state persistence.

Contract compilation requires a complete report.

## Scope

The search is finite and grows with the number of templates. `max_source_events` limits source
search depth, `max_trace_events` bounds padded history probes, and `max_candidates` stops the run
before a partial report is returned. Tool effects are declarations supplied by the host; adapter
code and external side effects remain outside the model. Passing generated contracts establishes
behaviour for the chosen principal, templates, requirements, and search limits.
