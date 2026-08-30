# Bounded relational checking

`BoundedRelationalChecker` checks a finite tool-sequence model before a policy release. It uses four
inputs: an authenticated principal, an invocation alphabet, flow requirements, and an event-depth
limit.

Each `InvocationTemplate` contains one registered tool and fixed canonical JSON arguments. Every
template must pass the single-call policy. This keeps the check centred on sequence behaviour and
prevents a role or schema denial from being mistaken for a sequence result.

Each `FlowRequirement` declares source effects, sink tools, an expected control, and an optional
event window. This model is separate from `SequenceRule`. Expected decisions are computed from the
flow requirements and successful event history; runtime decisions are computed by the gateway
policy.

## Search

The checker explores traces breadth first. An `allow` decision appends the registered tool effects
and permits another extension. A denial or approval request ends that branch. `max_events` bounds
trace length, while `max_decisions` stops an unexpectedly large search with an error.

The report measures:

- exact control conformance;
- unsafe-action prevention;
- permitted-action retention;
- causal-evidence coverage; and
- relational-boundary coverage.

A relational boundary pairs a prohibited trace with a permitted trace of equal length. The final
tool is the same and one earlier template changes. This checks whether a policy distinguishes the
causal source state without blocking the nearby permitted state.

For each failed property and requirement, the checker keeps the shortest counterexample found by
the breadth-first search. Counterexamples cover unsafe allowance, unnecessary intervention,
incorrect control strength, and missing causal evidence.

## Mutation adequacy

`BoundedMutationAnalyser` first requires the original runtime policy to pass. It then reruns the
independent flow requirements against supported policy changes: disabled rules, weakened denials,
shortened windows, removed effects, and removed sinks.

A surviving mutation records a gap between the requirement model, invocation alphabet, depth
bound, and runtime policy. The report does not hide survivors behind an aggregate score.

## Scope

The search covers only fixed arguments in the invocation alphabet. It does not inspect adapter
source code, model arbitrary tool output, or prove behaviour beyond the configured depth. Runtime
effect labels remain trusted declarations from the host application.

Run the checked example:

```bash
PYTHONPATH=src python3.11 examples/run_bounded_check.py
```
