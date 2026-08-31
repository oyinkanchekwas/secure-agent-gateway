from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from itertools import permutations
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.model_checking import (
    FlowRequirement,
    InvocationTemplate,
    evaluate_flow_requirements,
)
from secure_agent_gateway.models import Control, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.session import SessionEvent
from secure_agent_gateway.trajectory import PairedTrajectoryContract, TrajectoryCase


@dataclass(frozen=True)
class CausalContribution:
    event_index: int
    template_id: str
    indispensable_effects: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.event_index < 0 or not self.template_id:
            raise ValueError("causal contribution needs an event and template")
        if not self.indispensable_effects:
            raise ValueError("causal contribution needs an indispensable effect")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "template_id": self.template_id,
            "indispensable_effects": list(self.indispensable_effects),
        }


@dataclass(frozen=True)
class ContrastProbe:
    requirement_id: str
    probe_kind: str
    isolated_effect: str
    expected_control: Control
    prohibited_trace: tuple[str, ...]
    permitted_trace: tuple[str, ...]
    changed_index: int
    removed_effects: tuple[str, ...]
    effect_distance: int
    required_evidence_fields: tuple[str, ...]
    causal_contributions: tuple[CausalContribution, ...]
    isolated_effect_age: int
    tests_history_window: bool
    minimal_pair_count: int

    def __post_init__(self) -> None:
        if self.probe_kind not in {"source_effect", "history_window"}:
            raise ValueError("probe_kind is invalid")
        if self.expected_control not in {Control.DENY, Control.REQUIRE_APPROVAL}:
            raise ValueError("probe must expect an intervention")
        if not self.prohibited_trace or len(self.prohibited_trace) != len(
            self.permitted_trace
        ):
            raise ValueError("probe traces must have equal non-zero length")
        differences = tuple(
            index
            for index, pair in enumerate(
                zip(self.prohibited_trace, self.permitted_trace)
            )
            if pair[0] != pair[1]
        )
        if differences != (self.changed_index,):
            raise ValueError("probe traces must differ at changed_index only")
        if self.changed_index >= len(self.prohibited_trace) - 1:
            raise ValueError("probe cannot replace its sink")
        if self.prohibited_trace[-1] != self.permitted_trace[-1]:
            raise ValueError("probe traces must retain the same sink")
        if self.removed_effects != (self.isolated_effect,):
            raise ValueError("probe must isolate exactly one named effect")
        observed_age = len(self.prohibited_trace) - 1 - self.changed_index
        if self.isolated_effect_age != observed_age:
            raise ValueError("isolated_effect_age does not match changed_index")
        if self.effect_distance < 1 or self.isolated_effect_age < 1:
            raise ValueError("probe distances must be positive")
        if self.changed_index not in {
            contribution.event_index for contribution in self.causal_contributions
        }:
            raise ValueError("changed event needs a causal contribution")
        if not self.required_evidence_fields or self.minimal_pair_count < 1:
            raise ValueError("probe needs evidence and a minimal pair")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "probe_kind": self.probe_kind,
            "isolated_effect": self.isolated_effect,
            "expected_control": self.expected_control.value,
            "prohibited_trace": list(self.prohibited_trace),
            "permitted_trace": list(self.permitted_trace),
            "changed_index": self.changed_index,
            "removed_effects": list(self.removed_effects),
            "effect_distance": self.effect_distance,
            "required_evidence_fields": list(self.required_evidence_fields),
            "causal_contributions": [
                contribution.to_mapping() for contribution in self.causal_contributions
            ],
            "isolated_effect_age": self.isolated_effect_age,
            "tests_history_window": self.tests_history_window,
            "minimal_pair_count": self.minimal_pair_count,
        }


@dataclass(frozen=True)
class ProbeSynthesisGap:
    requirement_id: str
    code: str
    detail: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "requirement_id": self.requirement_id,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ProbeSynthesisReport:
    suite_digest: str
    max_source_events: int
    max_trace_events: int
    max_candidates: int
    explored_candidates: int
    metrics: Mapping[str, float]
    passed: bool
    probes: tuple[ContrastProbe, ...]
    gaps: tuple[ProbeSynthesisGap, ...]
    _templates: tuple[InvocationTemplate, ...] = field(repr=False)
    _requirements: tuple[FlowRequirement, ...] = field(repr=False)
    _principal: Principal = field(repr=False)
    _effects: Mapping[str, frozenset[str]] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metrics", MappingProxyType(dict(self.metrics)))
        object.__setattr__(self, "_effects", MappingProxyType(dict(self._effects)))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "suite_digest": self.suite_digest,
            "max_source_events": self.max_source_events,
            "max_trace_events": self.max_trace_events,
            "max_candidates": self.max_candidates,
            "explored_candidates": self.explored_candidates,
            "metrics": dict(self.metrics),
            "passed": self.passed,
            "probes": [probe.to_mapping() for probe in self.probes],
            "gaps": [gap.to_mapping() for gap in self.gaps],
        }

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_mapping()).encode("utf-8")
        ).hexdigest()

    def build_contracts(self) -> tuple[PairedTrajectoryContract, ...]:
        if not self.passed:
            raise ValueError("cannot build contracts from an incomplete probe suite")
        observed = probe_suite_digest(
            self._principal,
            self._templates,
            self._requirements,
            self._effects,
            self.max_source_events,
            self.max_trace_events,
            self.max_candidates,
        )
        if observed != self.suite_digest:
            raise ValueError("probe suite inputs changed after synthesis")
        templates = {template.template_id: template for template in self._templates}
        requirements = {
            requirement.requirement_id: requirement
            for requirement in self._requirements
        }
        return tuple(
            _build_contract(
                probe,
                self._principal,
                templates,
                self._effects,
                self._requirements,
                requirements[probe.requirement_id],
            )
            for probe in self.probes
        )


class RequirementProbeSynthesiser:
    def __init__(self, policy: PolicyEngine) -> None:
        self._policy = policy

    def run(
        self,
        *,
        principal: Principal,
        templates: Iterable[InvocationTemplate],
        requirements: Iterable[FlowRequirement],
        max_source_events: int = 6,
        max_trace_events: int = 64,
        max_candidates: int = 100_000,
    ) -> ProbeSynthesisReport:
        alphabet = tuple(sorted(templates, key=lambda item: item.template_id))
        specification = tuple(
            sorted(requirements, key=lambda item: item.requirement_id)
        )
        _validate_inputs(
            self._policy,
            principal,
            alphabet,
            specification,
            max_source_events,
            max_trace_events,
            max_candidates,
        )
        counter = _CandidateCounter(max_candidates)
        effects = {
            template.template_id: self._effects(template) for template in alphabet
        }
        probes: list[ContrastProbe] = []
        gaps: list[ProbeSynthesisGap] = []
        for requirement in specification:
            requirement_probes, requirement_gaps = self._synthesise_requirement(
                alphabet,
                specification,
                requirement,
                effects,
                max_source_events,
                max_trace_events,
                counter,
            )
            probes.extend(requirement_probes)
            gaps.extend(requirement_gaps)
        metrics = _synthesis_metrics(probes, specification)
        return ProbeSynthesisReport(
            suite_digest=probe_suite_digest(
                principal,
                alphabet,
                specification,
                effects,
                max_source_events,
                max_trace_events,
                max_candidates,
            ),
            max_source_events=max_source_events,
            max_trace_events=max_trace_events,
            max_candidates=max_candidates,
            explored_candidates=counter.value,
            metrics=metrics,
            passed=not gaps,
            probes=tuple(probes),
            gaps=tuple(gaps),
            _templates=alphabet,
            _requirements=specification,
            _principal=principal,
            _effects=effects,
        )

    def _synthesise_requirement(
        self,
        templates: tuple[InvocationTemplate, ...],
        requirements: tuple[FlowRequirement, ...],
        requirement: FlowRequirement,
        effects: Mapping[str, frozenset[str]],
        max_source_events: int,
        max_trace_events: int,
        counter: _CandidateCounter,
    ) -> tuple[tuple[ContrastProbe, ...], tuple[ProbeSynthesisGap, ...]]:
        source_templates = tuple(
            template
            for template in templates
            if effects[template.template_id] & requirement.source_effects
        )
        available_effects = frozenset().union(
            *(effects[template.template_id] for template in source_templates)
        )
        missing = requirement.source_effects - available_effects
        if missing:
            return (), (
                ProbeSynthesisGap(
                    requirement.requirement_id,
                    "missing_source_effect",
                    f"no template emits: {', '.join(sorted(missing))}",
                ),
            )
        sinks = tuple(
            template for template in templates if template.tool in requirement.sink_tools
        )
        if not sinks:
            return (), (
                ProbeSynthesisGap(
                    requirement.requirement_id,
                    "missing_sink_template",
                    "no invocation template uses a declared sink tool",
                ),
            )
        source_sequences = _minimal_source_sequences(
            source_templates,
            effects,
            requirement.source_effects,
            min(max_source_events, max_trace_events - 1),
            counter,
        )
        if not source_sequences:
            return (), (
                ProbeSynthesisGap(
                    requirement.requirement_id,
                    "source_limit_exhausted",
                    "the source effects need more events than the configured limit",
                ),
            )

        prohibited: list[_ProhibitedCandidate] = []
        template_map = {template.template_id: template for template in templates}
        for source_trace in source_sequences:
            for sink in sinks:
                counter.take()
                trace = (*source_trace, sink.template_id)
                evaluation = _evaluate_trace(
                    trace,
                    template_map,
                    effects,
                    requirements,
                    request_prefix=f"probe-{requirement.requirement_id}-p",
                )
                if (
                    evaluation.controls[:-1] == (Control.ALLOW,) * len(source_trace)
                    and evaluation.controls[-1] == requirement.expected_control
                    and requirement.requirement_id in evaluation.final_matches
                ):
                    prohibited.append(
                        _ProhibitedCandidate(
                            trace=trace,
                            evidence_fields=evaluation.final_evidence,
                        )
                    )
        if not prohibited:
            return (), (
                ProbeSynthesisGap(
                    requirement.requirement_id,
                    "no_selectable_prohibited_trace",
                    "another requirement intervenes first or changes the final control",
                ),
            )

        pairs: list[_PairCandidate] = []
        for candidate in prohibited:
            pairs.extend(
                _contrast_pairs(
                    candidate,
                    len(candidate.trace) - 1,
                    templates,
                    template_map,
                    effects,
                    requirements,
                    requirement,
                    counter,
                )
            )

        probes: list[ContrastProbe] = []
        gaps: list[ProbeSynthesisGap] = []
        for effect in sorted(requirement.source_effects):
            isolating = [pair for pair in pairs if pair.removed_effects == (effect,)]
            if not isolating:
                gaps.append(
                    ProbeSynthesisGap(
                        requirement.requirement_id,
                        "non_isolatable_source_effect",
                        f"no one-event contrast isolates: {effect}",
                    )
                )
                continue
            probes.append(
                _make_probe(
                    requirement,
                    "source_effect",
                    effect,
                    isolating,
                )
            )

        if requirement.window_events != 1 and not any(
            probe.tests_history_window for probe in probes
        ):
            source_event_count = len(source_sequences[0])
            temporal_candidates: list[_ProhibitedCandidate] = []
            neutral = [
                template
                for template in templates
                if not effects[template.template_id] & requirement.source_effects
            ]
            padding = (
                requirement.window_events - source_event_count
                if requirement.window_events is not None
                else 1
            )
            if source_event_count + padding + 1 > max_trace_events:
                gaps.append(
                    ProbeSynthesisGap(
                        requirement.requirement_id,
                        "trace_limit_exhausted",
                        "the history boundary exceeds the configured trace limit",
                    )
                )
                return tuple(probes), tuple(gaps)
            for candidate in prohibited:
                for spacer in neutral:
                    counter.take()
                    trace = (
                        *candidate.trace[:-1],
                        *((spacer.template_id,) * padding),
                        candidate.trace[-1],
                    )
                    evaluation = _evaluate_trace(
                        trace,
                        template_map,
                        effects,
                        requirements,
                        request_prefix=f"probe-{requirement.requirement_id}-p",
                    )
                    if (
                        evaluation.controls[:-1]
                        == (Control.ALLOW,) * (len(trace) - 1)
                        and evaluation.controls[-1] == requirement.expected_control
                        and requirement.requirement_id in evaluation.final_matches
                    ):
                        temporal_candidates.append(
                            _ProhibitedCandidate(
                                trace=trace,
                                evidence_fields=evaluation.final_evidence,
                            )
                        )
            temporal_pairs: list[_PairCandidate] = []
            for candidate in temporal_candidates:
                temporal_pairs.extend(
                    _contrast_pairs(
                        candidate,
                        source_event_count,
                        templates,
                        template_map,
                        effects,
                        requirements,
                        requirement,
                        counter,
                    )
                )
            isolating_temporal = [
                pair
                for pair in temporal_pairs
                if len(pair.removed_effects) == 1
                and _tests_history_boundary(pair, requirement)
            ]
            if isolating_temporal:
                ordered_temporal = sorted(
                    isolating_temporal,
                    key=_pair_sort_key,
                )
                effect = ordered_temporal[0].removed_effects[0]
                same_effect = [
                    pair
                    for pair in ordered_temporal
                    if pair.removed_effects == (effect,)
                ]
                probes.append(
                    _make_probe(
                        requirement,
                        "history_window",
                        effect,
                        same_effect,
                    )
                )
            else:
                gaps.append(
                    ProbeSynthesisGap(
                        requirement.requirement_id,
                        "no_temporal_contrast",
                        "no neutral event tests persistence beyond the latest action",
                    )
                )
        return tuple(probes), tuple(gaps)

    def _effects(self, template: InvocationTemplate) -> frozenset[str]:
        registered = self._policy.registry.get(template.tool)
        if registered is None:
            raise RuntimeError("validated probe template disappeared")
        return registered.spec.emitted_effects


def _contrast_pairs(
    candidate: _ProhibitedCandidate,
    source_event_count: int,
    templates: tuple[InvocationTemplate, ...],
    template_map: Mapping[str, InvocationTemplate],
    effects: Mapping[str, frozenset[str]],
    requirements: tuple[FlowRequirement, ...],
    requirement: FlowRequirement,
    counter: _CandidateCounter,
) -> tuple[_PairCandidate, ...]:
    source_trace = candidate.trace[:source_event_count]
    original_contributions = _causal_contributions(
        source_trace,
        effects,
        requirement.source_effects,
    )
    sink_tools = {
        sink
        for declared in requirements
        for sink in declared.sink_tools
    }
    pairs: list[_PairCandidate] = []
    for changed_index, original_id in enumerate(source_trace):
        for replacement in templates:
            if replacement.template_id == original_id:
                continue
            counter.take()
            permitted = list(candidate.trace)
            permitted[changed_index] = replacement.template_id
            evaluation = _evaluate_trace(
                tuple(permitted),
                template_map,
                effects,
                requirements,
                request_prefix=f"probe-{requirement.requirement_id}-a",
            )
            if evaluation.controls != (Control.ALLOW,) * len(permitted):
                continue
            remaining_effects = frozenset().union(
                *(effects[template_id] for template_id in permitted[:-1])
            )
            removed = requirement.source_effects - remaining_effects
            if not removed:
                continue
            distance = len(effects[original_id] ^ effects[replacement.template_id])
            pairs.append(
                _PairCandidate(
                    prohibited=candidate,
                    permitted_trace=tuple(permitted),
                    changed_index=changed_index,
                    removed_effects=tuple(sorted(removed)),
                    replacement_sink_penalty=int(replacement.tool in sink_tools),
                    effect_distance=distance,
                    contributions=original_contributions,
                )
            )
    return tuple(pairs)


def _make_probe(
    requirement: FlowRequirement,
    probe_kind: str,
    isolated_effect: str,
    pairs: Sequence[_PairCandidate],
) -> ContrastProbe:
    ordered = sorted(pairs, key=_pair_sort_key)
    best = ordered[0]
    best_shape = _pair_shape(best)
    minimal_pair_count = sum(_pair_shape(pair) == best_shape for pair in ordered)
    isolated_effect_age = len(best.prohibited.trace) - 1 - best.changed_index
    return ContrastProbe(
        requirement_id=requirement.requirement_id,
        probe_kind=probe_kind,
        isolated_effect=isolated_effect,
        expected_control=requirement.expected_control,
        prohibited_trace=best.prohibited.trace,
        permitted_trace=best.permitted_trace,
        changed_index=best.changed_index,
        removed_effects=best.removed_effects,
        effect_distance=best.effect_distance,
        required_evidence_fields=best.prohibited.evidence_fields,
        causal_contributions=best.contributions,
        isolated_effect_age=isolated_effect_age,
        tests_history_window=_tests_history_boundary(best, requirement),
        minimal_pair_count=minimal_pair_count,
    )


def _tests_history_boundary(
    pair: _PairCandidate,
    requirement: FlowRequirement,
) -> bool:
    age = len(pair.prohibited.trace) - 1 - pair.changed_index
    if requirement.window_events is None:
        return age >= 2
    return age == requirement.window_events


@dataclass
class _CandidateCounter:
    limit: int
    value: int = 0

    def take(self) -> None:
        if self.value >= self.limit:
            raise ValueError("probe synthesis exceeds max_candidates")
        self.value += 1


@dataclass(frozen=True)
class _TraceEvaluation:
    controls: tuple[Control, ...]
    final_matches: tuple[str, ...]
    final_evidence: tuple[str, ...]


@dataclass(frozen=True)
class _ProhibitedCandidate:
    trace: tuple[str, ...]
    evidence_fields: tuple[str, ...]


@dataclass(frozen=True)
class _PairCandidate:
    prohibited: _ProhibitedCandidate
    permitted_trace: tuple[str, ...]
    changed_index: int
    removed_effects: tuple[str, ...]
    replacement_sink_penalty: int
    effect_distance: int
    contributions: tuple[CausalContribution, ...]


def probe_suite_digest(
    principal: Principal,
    templates: Sequence[InvocationTemplate],
    requirements: Sequence[FlowRequirement],
    effects: Mapping[str, frozenset[str]],
    max_source_events: int,
    max_trace_events: int,
    max_candidates: int,
) -> str:
    payload = {
        "principal": {
            "principal_id": principal.principal_id,
            "roles": sorted(principal.roles),
        },
        "templates": [template.to_mapping() for template in templates],
        "emitted_effects": {
            template.template_id: sorted(effects[template.template_id])
            for template in templates
        },
        "requirements": [requirement.to_mapping() for requirement in requirements],
        "max_source_events": max_source_events,
        "max_trace_events": max_trace_events,
        "max_candidates": max_candidates,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _validate_inputs(
    policy: PolicyEngine,
    principal: Principal,
    templates: tuple[InvocationTemplate, ...],
    requirements: tuple[FlowRequirement, ...],
    max_source_events: int,
    max_trace_events: int,
    max_candidates: int,
) -> None:
    if not templates or not requirements:
        raise ValueError("probe synthesis needs templates and requirements")
    if max_source_events < 1 or max_trace_events < 2 or max_candidates < 1:
        raise ValueError("probe synthesis limits must be positive")
    template_ids = [template.template_id for template in templates]
    requirement_ids = [requirement.requirement_id for requirement in requirements]
    if len(template_ids) != len(set(template_ids)):
        raise ValueError("template identifiers must be unique")
    if len(requirement_ids) != len(set(requirement_ids)):
        raise ValueError("requirement identifiers must be unique")
    for template in templates:
        request = _request(
            template,
            principal,
            "probe-validation",
            f"probe-validate-{template.template_id}",
        )
        if policy.registry.get(template.tool) is None:
            raise ValueError(f"template tool is not registered: {template.tool}")
        if policy.inspect(principal, request).control != Control.ALLOW:
            raise ValueError(
                f"template must pass single-call policy: {template.template_id}"
            )


def _minimal_source_sequences(
    source_templates: tuple[InvocationTemplate, ...],
    effects: Mapping[str, frozenset[str]],
    required_effects: frozenset[str],
    max_source_events: int,
    counter: _CandidateCounter,
) -> tuple[tuple[str, ...], ...]:
    identifiers = tuple(template.template_id for template in source_templates)
    max_depth = min(max_source_events, len(identifiers))
    for depth in range(1, max_depth + 1):
        matches: list[tuple[str, ...]] = []
        for sequence in permutations(identifiers, depth):
            counter.take()
            observed = frozenset().union(*(effects[item] for item in sequence))
            if required_effects.issubset(observed):
                matches.append(sequence)
        if matches:
            return tuple(sorted(matches))
    return ()


def _evaluate_trace(
    trace: tuple[str, ...],
    templates: Mapping[str, InvocationTemplate],
    effects: Mapping[str, frozenset[str]],
    requirements: tuple[FlowRequirement, ...],
    *,
    request_prefix: str,
) -> _TraceEvaluation:
    controls: list[Control] = []
    events: list[SessionEvent] = []
    final_matches: tuple[str, ...] = ()
    final_evidence: tuple[str, ...] = ()
    for index, template_id in enumerate(trace):
        template = templates[template_id]
        control, matches, evidence = evaluate_flow_requirements(
            template.tool,
            tuple(events),
            requirements,
        )
        controls.append(control)
        final_matches = matches
        final_evidence = evidence
        if control != Control.ALLOW:
            break
        events.append(
            SessionEvent(
                sequence=index + 1,
                request_id=f"{request_prefix}-{index + 1}",
                tool=template.tool,
                effects=effects[template_id],
            )
        )
    return _TraceEvaluation(tuple(controls), final_matches, final_evidence)


def _causal_contributions(
    source_trace: tuple[str, ...],
    effects: Mapping[str, frozenset[str]],
    required_effects: frozenset[str],
) -> tuple[CausalContribution, ...]:
    contributions: list[CausalContribution] = []
    for index, template_id in enumerate(source_trace):
        without = frozenset().union(
            *(effects[item] for position, item in enumerate(source_trace) if position != index)
        )
        indispensable = tuple(sorted(required_effects - without))
        if not indispensable:
            raise RuntimeError("minimal source sequence contains a redundant event")
        contributions.append(
            CausalContribution(index, template_id, indispensable)
        )
    return tuple(contributions)


def _pair_shape(pair: _PairCandidate) -> tuple[int, int, int, int]:
    return (
        len(pair.prohibited.trace),
        len(pair.removed_effects),
        pair.replacement_sink_penalty,
        pair.effect_distance,
    )


def _pair_sort_key(pair: _PairCandidate) -> tuple[Any, ...]:
    return (
        *_pair_shape(pair),
        pair.prohibited.trace,
        pair.permitted_trace,
        pair.changed_index,
    )


def _synthesis_metrics(
    probes: Sequence[ContrastProbe],
    requirements: Sequence[FlowRequirement],
) -> dict[str, float]:
    if not probes:
        temporal_required = any(
            requirement.window_events != 1 for requirement in requirements
        )
        return {
            "requirement_probe_coverage": 0.0,
            "source_effect_probe_coverage": 0.0,
            "temporal_probe_coverage": 0.0 if temporal_required else 1.0,
            "unique_minimal_pair_rate": 1.0,
            "mean_source_events": 0.0,
            "mean_effect_distance": 0.0,
            "mean_isolated_effect_age": 0.0,
        }
    covered_requirements = {probe.requirement_id for probe in probes}
    covered_effects = {
        (probe.requirement_id, probe.isolated_effect) for probe in probes
        if probe.probe_kind == "source_effect"
    }
    expected_effects = {
        (requirement.requirement_id, effect)
        for requirement in requirements
        for effect in requirement.source_effects
    }
    temporal_requirements = {
        requirement.requirement_id
        for requirement in requirements
        if requirement.window_events != 1
    }
    temporal_covered = {
        probe.requirement_id
        for probe in probes
        if probe.tests_history_window
    }
    return {
        "requirement_probe_coverage": len(covered_requirements) / len(requirements),
        "source_effect_probe_coverage": len(covered_effects) / len(expected_effects),
        "temporal_probe_coverage": (
            len(temporal_covered) / len(temporal_requirements)
            if temporal_requirements
            else 1.0
        ),
        "unique_minimal_pair_rate": sum(
            probe.minimal_pair_count == 1 for probe in probes
        )
        / len(probes),
        "mean_source_events": sum(
            len(probe.causal_contributions) for probe in probes
        )
        / len(probes),
        "mean_effect_distance": sum(probe.effect_distance for probe in probes)
        / len(probes),
        "mean_isolated_effect_age": sum(
            probe.isolated_effect_age for probe in probes
        )
        / len(probes),
    }


def _build_contract(
    probe: ContrastProbe,
    principal: Principal,
    templates: Mapping[str, InvocationTemplate],
    effects: Mapping[str, frozenset[str]],
    requirements: tuple[FlowRequirement, ...],
    requirement: FlowRequirement,
) -> PairedTrajectoryContract:
    session_id = f"probe-{probe.requirement_id}"
    prohibited_requests = _requests_for_trace(
        probe.prohibited_trace,
        templates,
        principal,
        session_id,
        "p",
    )
    permitted_requests = _requests_for_trace(
        probe.permitted_trace,
        templates,
        principal,
        session_id,
        "a",
    )
    prohibited_controls, evidence = _controls_for_requests(
        prohibited_requests,
        probe.prohibited_trace,
        effects,
        requirements,
    )
    permitted_controls, _ = _controls_for_requests(
        permitted_requests,
        probe.permitted_trace,
        effects,
        requirements,
    )
    if prohibited_controls[-1] != requirement.expected_control:
        raise ValueError("probe no longer reaches its expected intervention")
    if evidence != probe.required_evidence_fields:
        raise ValueError("probe evidence changed after synthesis")
    if any(control != Control.ALLOW for control in permitted_controls):
        raise ValueError("probe contrast is no longer permitted")
    changed_fields = tuple(
        sorted(
            _changed_fields(
                [_semantic_request(request) for request in prohibited_requests],
                [_semantic_request(request) for request in permitted_requests],
                "requests",
            )
        )
    )
    return PairedTrajectoryContract(
        contract_id=(
            f"probe:{probe.requirement_id}:{probe.probe_kind}:{probe.isolated_effect}"
        ),
        policy_family=probe.requirement_id,
        principal=principal,
        prohibited=TrajectoryCase(
            case_id=(
                f"probe:{probe.requirement_id}:{probe.probe_kind}:"
                f"{probe.isolated_effect}:prohibited"
            ),
            requests=prohibited_requests,
            expected_controls=prohibited_controls,
            expected_first_intervention=len(prohibited_controls) - 1,
            required_evidence_fields=evidence,
        ),
        permitted=TrajectoryCase(
            case_id=(
                f"probe:{probe.requirement_id}:{probe.probe_kind}:"
                f"{probe.isolated_effect}:permitted"
            ),
            requests=permitted_requests,
            expected_controls=permitted_controls,
            expected_first_intervention=None,
        ),
        changed_fields=changed_fields,
    )


def _requests_for_trace(
    trace: tuple[str, ...],
    templates: Mapping[str, InvocationTemplate],
    principal: Principal,
    session_id: str,
    variant: str,
) -> tuple[ToolRequest, ...]:
    return tuple(
        _request(
            templates[template_id],
            principal,
            session_id,
            f"{session_id}-{variant}-{index + 1}",
        )
        for index, template_id in enumerate(trace)
    )


def _request(
    template: InvocationTemplate,
    principal: Principal,
    session_id: str,
    request_id: str,
) -> ToolRequest:
    return ToolRequest(
        request_id=request_id,
        principal_id=principal.principal_id,
        tool=template.tool,
        arguments=dict(template.arguments),
        issued_at=1_800_000_000,
        nonce=f"nonce-{request_id}",
        session_id=session_id,
    )


def _controls_for_requests(
    requests: tuple[ToolRequest, ...],
    trace: tuple[str, ...],
    effects: Mapping[str, frozenset[str]],
    requirements: tuple[FlowRequirement, ...],
) -> tuple[tuple[Control, ...], tuple[str, ...]]:
    if len(requests) != len(trace):
        raise ValueError("probe requests and trace must have equal length")
    events: list[SessionEvent] = []
    controls: list[Control] = []
    final_evidence: tuple[str, ...] = ()
    for index, (request, template_id) in enumerate(zip(requests, trace)):
        control, _, evidence = evaluate_flow_requirements(
            request.tool,
            tuple(events),
            requirements,
        )
        controls.append(control)
        final_evidence = evidence
        if control != Control.ALLOW:
            break
        events.append(
            SessionEvent(
                sequence=index + 1,
                request_id=request.request_id,
                tool=request.tool,
                effects=effects[template_id],
            )
        )
    return tuple(controls), final_evidence


def _semantic_request(request: ToolRequest) -> dict[str, Any]:
    return {
        "principal_id": request.principal_id,
        "tool": request.tool,
        "arguments": dict(request.arguments),
    }


def _changed_fields(left: Any, right: Any, prefix: str = "") -> set[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        changed: set[str] = set()
        for key in set(left) | set(right):
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                changed.add(path)
            else:
                changed.update(_changed_fields(left[key], right[key], path))
        return changed
    if (
        isinstance(left, Sequence)
        and isinstance(right, Sequence)
        and not isinstance(left, (str, bytes))
        and not isinstance(right, (str, bytes))
    ):
        changed: set[str] = set()
        for index in range(max(len(left), len(right))):
            path = f"{prefix}.{index}" if prefix else str(index)
            if index >= len(left) or index >= len(right):
                changed.add(path)
            else:
                changed.update(_changed_fields(left[index], right[index], path))
        return changed
    return set() if left == right else {prefix}
