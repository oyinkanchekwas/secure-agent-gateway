from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.models import Control, PolicyDecision, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.session import SequencePolicy, SessionEvent, SessionSnapshot
from secure_agent_gateway.trajectory import generate_sequence_policy_mutants


_IDENTIFIER = r"[a-z][a-z0-9_.:-]{0,127}"


@dataclass(frozen=True)
class InvocationTemplate:
    template_id: str
    tool: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not re.fullmatch(_IDENTIFIER, self.template_id):
            raise ValueError("template_id is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", self.tool):
            raise ValueError("template tool is invalid")
        try:
            copied = json.loads(canonical_json(dict(self.arguments)))
        except (TypeError, ValueError) as exc:
            raise ValueError("template arguments must be canonical JSON") from exc
        object.__setattr__(self, "arguments", MappingProxyType(copied))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "tool": self.tool,
            "arguments": dict(self.arguments),
        }


@dataclass(frozen=True)
class FlowRequirement:
    requirement_id: str
    source_effects: frozenset[str]
    sink_tools: frozenset[str]
    expected_control: Control
    window_events: int | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(_IDENTIFIER, self.requirement_id):
            raise ValueError("requirement_id is invalid")
        if not self.source_effects or not self.sink_tools:
            raise ValueError("flow requirements need source effects and sink tools")
        if self.expected_control not in {Control.DENY, Control.REQUIRE_APPROVAL}:
            raise ValueError("flow requirements must expect an intervention")
        if self.window_events is not None and self.window_events < 1:
            raise ValueError("window_events must be positive")
        if any(not re.fullmatch(_IDENTIFIER, effect) for effect in self.source_effects):
            raise ValueError("flow requirement effects are invalid")
        if any(
            not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", tool)
            for tool in self.sink_tools
        ):
            raise ValueError("flow requirement tools are invalid")
        object.__setattr__(self, "source_effects", frozenset(self.source_effects))
        object.__setattr__(self, "sink_tools", frozenset(self.sink_tools))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "source_effects": sorted(self.source_effects),
            "sink_tools": sorted(self.sink_tools),
            "expected_control": self.expected_control.value,
            "window_events": self.window_events,
        }


@dataclass(frozen=True)
class BoundedCheckThresholds:
    min_exact_control_conformance: float = 1.0
    min_unsafe_action_prevention: float = 1.0
    min_permitted_action_retention: float = 1.0
    min_evidence_coverage: float = 1.0
    min_relational_boundary_coverage: float = 1.0

    def __post_init__(self) -> None:
        if any(not 0.0 <= value <= 1.0 for value in self.to_mapping().values()):
            raise ValueError("bounded-check thresholds must be between zero and one")

    def to_mapping(self) -> dict[str, float]:
        return {
            "min_exact_control_conformance": self.min_exact_control_conformance,
            "min_unsafe_action_prevention": self.min_unsafe_action_prevention,
            "min_permitted_action_retention": self.min_permitted_action_retention,
            "min_evidence_coverage": self.min_evidence_coverage,
            "min_relational_boundary_coverage": self.min_relational_boundary_coverage,
        }


@dataclass(frozen=True)
class CheckedDecision:
    trace: tuple[str, ...]
    expected_control: Control
    actual_control: Control
    matched_requirements: tuple[str, ...]
    required_evidence_fields: tuple[str, ...]
    actual_evidence_fields: tuple[str, ...]
    reason_codes: tuple[str, ...]

    @property
    def control_correct(self) -> bool:
        return self.expected_control == self.actual_control

    @property
    def evidence_complete(self) -> bool:
        return set(self.required_evidence_fields).issubset(self.actual_evidence_fields)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "trace": list(self.trace),
            "expected_control": self.expected_control.value,
            "actual_control": self.actual_control.value,
            "matched_requirements": list(self.matched_requirements),
            "required_evidence_fields": list(self.required_evidence_fields),
            "actual_evidence_fields": list(self.actual_evidence_fields),
            "reason_codes": list(self.reason_codes),
            "control_correct": self.control_correct,
            "evidence_complete": self.evidence_complete,
        }


@dataclass(frozen=True)
class RelationalBoundary:
    requirement_id: str
    prohibited_trace: tuple[str, ...]
    permitted_trace: tuple[str, ...]
    changed_index: int

    def to_mapping(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "prohibited_trace": list(self.prohibited_trace),
            "permitted_trace": list(self.permitted_trace),
            "changed_index": self.changed_index,
        }


@dataclass(frozen=True)
class ModelCounterexample:
    property_name: str
    requirement_id: str
    trace: tuple[str, ...]
    expected_control: Control
    actual_control: Control
    missing_evidence_fields: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "property_name": self.property_name,
            "requirement_id": self.requirement_id,
            "trace": list(self.trace),
            "expected_control": self.expected_control.value,
            "actual_control": self.actual_control.value,
            "missing_evidence_fields": list(self.missing_evidence_fields),
        }


@dataclass(frozen=True)
class BoundedCheckReport:
    policy_version: str
    sequence_policy_digest: str
    suite_digest: str
    max_events: int
    explored_decisions: int
    metrics: Mapping[str, float]
    thresholds: BoundedCheckThresholds
    passed: bool
    boundaries: tuple[RelationalBoundary, ...]
    counterexamples: tuple[ModelCounterexample, ...]
    decisions: tuple[CheckedDecision, ...] = field(repr=False)

    def to_mapping(self, *, include_decisions: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "policy_version": self.policy_version,
            "sequence_policy_digest": self.sequence_policy_digest,
            "suite_digest": self.suite_digest,
            "max_events": self.max_events,
            "explored_decisions": self.explored_decisions,
            "metrics": dict(self.metrics),
            "thresholds": self.thresholds.to_mapping(),
            "passed": self.passed,
            "boundaries": [boundary.to_mapping() for boundary in self.boundaries],
            "counterexamples": [item.to_mapping() for item in self.counterexamples],
        }
        if include_decisions:
            payload["decisions"] = [decision.to_mapping() for decision in self.decisions]
        return payload

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_mapping(include_decisions=True)).encode("utf-8")
        ).hexdigest()


class BoundedRelationalChecker:
    def __init__(
        self,
        policy: PolicyEngine,
        sequence_policy: SequencePolicy,
    ) -> None:
        self._policy = policy
        self._sequence_policy = sequence_policy
        self._sequence_policy.validate_registry(self._policy.registry)

    def run(
        self,
        *,
        principal: Principal,
        templates: Iterable[InvocationTemplate],
        requirements: Iterable[FlowRequirement],
        max_events: int,
        max_decisions: int = 100_000,
        thresholds: BoundedCheckThresholds | None = None,
    ) -> BoundedCheckReport:
        alphabet = tuple(sorted(templates, key=lambda item: item.template_id))
        specification = tuple(sorted(requirements, key=lambda item: item.requirement_id))
        _validate_suite(
            self._policy,
            principal,
            alphabet,
            specification,
            max_events,
            max_decisions,
        )
        active_thresholds = thresholds or BoundedCheckThresholds()
        suite_payload = {
            "principal": {
                "principal_id": principal.principal_id,
                "roles": sorted(principal.roles),
            },
            "templates": [template.to_mapping() for template in alphabet],
            "requirements": [requirement.to_mapping() for requirement in specification],
            "max_events": max_events,
        }
        suite_digest = hashlib.sha256(
            canonical_json(suite_payload).encode("utf-8")
        ).hexdigest()
        decisions: list[CheckedDecision] = []
        frontier: list[tuple[tuple[str, ...], tuple[SessionEvent, ...]]] = [((), ())]
        for _ in range(max_events):
            next_frontier: list[tuple[tuple[str, ...], tuple[SessionEvent, ...]]] = []
            for trace, events in frontier:
                for template in alphabet:
                    if len(decisions) >= max_decisions:
                        raise ValueError("bounded check exceeds max_decisions")
                    checked, event = self._evaluate_extension(
                        principal,
                        trace,
                        events,
                        template,
                        specification,
                    )
                    decisions.append(checked)
                    if checked.actual_control == Control.ALLOW:
                        next_frontier.append((checked.trace, events + (event,)))
            frontier = next_frontier
            if not frontier:
                break

        boundaries = _find_boundaries(decisions, specification)
        counterexamples = _find_counterexamples(decisions)
        metrics = _calculate_metrics(decisions, boundaries, specification)
        passed = _passes(metrics, active_thresholds)
        return BoundedCheckReport(
            policy_version=self._policy.policy_version,
            sequence_policy_digest=self._sequence_policy.digest,
            suite_digest=suite_digest,
            max_events=max_events,
            explored_decisions=len(decisions),
            metrics=metrics,
            thresholds=active_thresholds,
            passed=passed,
            boundaries=boundaries,
            counterexamples=counterexamples,
            decisions=tuple(decisions),
        )

    def _evaluate_extension(
        self,
        principal: Principal,
        trace: tuple[str, ...],
        events: tuple[SessionEvent, ...],
        template: InvocationTemplate,
        requirements: tuple[FlowRequirement, ...],
    ) -> tuple[CheckedDecision, SessionEvent]:
        sequence = len(events) + 1
        request_id = f"model-{sequence}-{template.template_id}"
        request = ToolRequest(
            request_id=request_id,
            principal_id=principal.principal_id,
            tool=template.tool,
            arguments=dict(template.arguments),
            issued_at=1_800_000_000,
            nonce=f"nonce-{request_id}",
            session_id="bounded-check",
        )
        snapshot = SessionSnapshot(principal.principal_id, request.session_id, events)
        base = self._policy.inspect(principal, request)
        actual = self._sequence_policy.evaluate(request, snapshot, base)
        expected, matched, evidence = _oracle_decision(template.tool, events, requirements)
        registered = self._policy.registry.get(template.tool)
        if registered is None:
            raise RuntimeError("validated model-checking tool disappeared")
        event = SessionEvent(
            sequence=sequence,
            request_id=request_id,
            tool=template.tool,
            effects=registered.spec.emitted_effects,
        )
        return (
            CheckedDecision(
                trace=trace + (template.template_id,),
                expected_control=expected,
                actual_control=actual.control,
                matched_requirements=matched,
                required_evidence_fields=evidence,
                actual_evidence_fields=actual.evidence_fields,
                reason_codes=actual.reason_codes,
            ),
            event,
        )


@dataclass(frozen=True)
class BoundedMutationOutcome:
    mutant_id: str
    rule_id: str
    mutation: str
    killed: bool
    counterexample: ModelCounterexample | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "mutant_id": self.mutant_id,
            "rule_id": self.rule_id,
            "mutation": self.mutation,
            "killed": self.killed,
            "counterexample": (
                None if self.counterexample is None else self.counterexample.to_mapping()
            ),
        }


@dataclass(frozen=True)
class BoundedMutationReport:
    baseline_report_digest: str
    mutation_score: float
    killed: int
    survived: int
    outcomes: tuple[BoundedMutationOutcome, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "baseline_report_digest": self.baseline_report_digest,
            "mutation_score": self.mutation_score,
            "killed": self.killed,
            "survived": self.survived,
            "outcomes": [outcome.to_mapping() for outcome in self.outcomes],
        }

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()


class BoundedMutationAnalyser:
    def __init__(self, policy: PolicyEngine, sequence_policy: SequencePolicy) -> None:
        self._policy = policy
        self._sequence_policy = sequence_policy

    def run(
        self,
        *,
        principal: Principal,
        templates: Iterable[InvocationTemplate],
        requirements: Iterable[FlowRequirement],
        max_events: int,
        max_decisions: int = 100_000,
        thresholds: BoundedCheckThresholds | None = None,
    ) -> BoundedMutationReport:
        alphabet = tuple(templates)
        specification = tuple(requirements)
        baseline = BoundedRelationalChecker(
            self._policy, self._sequence_policy
        ).run(
            principal=principal,
            templates=alphabet,
            requirements=specification,
            max_events=max_events,
            max_decisions=max_decisions,
            thresholds=thresholds,
        )
        if not baseline.passed:
            raise ValueError("baseline bounded check must pass before mutation analysis")
        outcomes: list[BoundedMutationOutcome] = []
        for mutant in generate_sequence_policy_mutants(self._sequence_policy):
            report = BoundedRelationalChecker(self._policy, mutant.policy).run(
                principal=principal,
                templates=alphabet,
                requirements=specification,
                max_events=max_events,
                max_decisions=max_decisions,
                thresholds=thresholds,
            )
            counterexample = report.counterexamples[0] if report.counterexamples else None
            outcomes.append(
                BoundedMutationOutcome(
                    mutant_id=mutant.mutant_id,
                    rule_id=mutant.rule_id,
                    mutation=mutant.mutation,
                    killed=not report.passed,
                    counterexample=counterexample,
                )
            )
        if not outcomes:
            raise ValueError("sequence policy produced no supported mutations")
        killed = sum(outcome.killed for outcome in outcomes)
        return BoundedMutationReport(
            baseline_report_digest=baseline.report_digest,
            mutation_score=killed / len(outcomes),
            killed=killed,
            survived=len(outcomes) - killed,
            outcomes=tuple(outcomes),
        )


def _validate_suite(
    policy: PolicyEngine,
    principal: Principal,
    templates: tuple[InvocationTemplate, ...],
    requirements: tuple[FlowRequirement, ...],
    max_events: int,
    max_decisions: int,
) -> None:
    if not templates or not requirements:
        raise ValueError("bounded checking needs templates and requirements")
    if max_events < 1 or max_decisions < 1:
        raise ValueError("bounded-check limits must be positive")
    template_ids = [template.template_id for template in templates]
    requirement_ids = [requirement.requirement_id for requirement in requirements]
    if len(template_ids) != len(set(template_ids)):
        raise ValueError("template identifiers must be unique")
    if len(requirement_ids) != len(set(requirement_ids)):
        raise ValueError("requirement identifiers must be unique")

    declared_effects: set[str] = set()
    template_tools = {template.tool for template in templates}
    for template in templates:
        registered = policy.registry.get(template.tool)
        if registered is None:
            raise ValueError(f"template tool is not registered: {template.tool}")
        request = ToolRequest(
            request_id=f"validate-{template.template_id}",
            principal_id=principal.principal_id,
            tool=template.tool,
            arguments=dict(template.arguments),
            issued_at=1_800_000_000,
            nonce=f"validate-nonce-{template.template_id}",
            session_id="bounded-check-validation",
        )
        if policy.inspect(principal, request).control != Control.ALLOW:
            raise ValueError(
                f"template must pass single-call policy: {template.template_id}"
            )
        declared_effects.update(registered.spec.emitted_effects)
    for requirement in requirements:
        if not requirement.source_effects.issubset(declared_effects):
            raise ValueError(
                f"requirement has effects absent from the alphabet: {requirement.requirement_id}"
            )
        if not requirement.sink_tools.issubset(template_tools):
            raise ValueError(
                f"requirement has sinks absent from the alphabet: {requirement.requirement_id}"
            )


def _oracle_decision(
    tool: str,
    events: tuple[SessionEvent, ...],
    requirements: tuple[FlowRequirement, ...],
) -> tuple[Control, tuple[str, ...], tuple[str, ...]]:
    matches: list[tuple[FlowRequirement, tuple[str, ...]]] = []
    for requirement in requirements:
        if tool not in requirement.sink_tools:
            continue
        visible = events
        if requirement.window_events is not None:
            visible = events[-requirement.window_events :]
        evidence: list[str] = []
        for effect in sorted(requirement.source_effects):
            source = next(
                (event for event in reversed(visible) if effect in event.effects),
                None,
            )
            if source is None:
                break
            evidence.append(f"session.events.{source.request_id}.effects.{effect}")
        else:
            evidence.append("tool")
            matches.append((requirement, tuple(evidence)))
    if not matches:
        return Control.ALLOW, (), ()
    control = (
        Control.DENY
        if any(requirement.expected_control == Control.DENY for requirement, _ in matches)
        else Control.REQUIRE_APPROVAL
    )
    selected = [item for item in matches if item[0].expected_control == control]
    return (
        control,
        tuple(requirement.requirement_id for requirement, _ in selected),
        tuple(dict.fromkeys(field for _, evidence in selected for field in evidence)),
    )


def _find_boundaries(
    decisions: Sequence[CheckedDecision],
    requirements: tuple[FlowRequirement, ...],
) -> tuple[RelationalBoundary, ...]:
    permitted = [item for item in decisions if item.expected_control == Control.ALLOW]
    boundaries: list[RelationalBoundary] = []
    for requirement in requirements:
        unsafe = [
            item for item in decisions if requirement.requirement_id in item.matched_requirements
        ]
        candidates: list[RelationalBoundary] = []
        for prohibited in unsafe:
            for allowed in permitted:
                if len(prohibited.trace) != len(allowed.trace):
                    continue
                if prohibited.trace[-1] != allowed.trace[-1]:
                    continue
                changed = [
                    index
                    for index, pair in enumerate(zip(prohibited.trace, allowed.trace))
                    if pair[0] != pair[1]
                ]
                if len(changed) == 1:
                    candidates.append(
                        RelationalBoundary(
                            requirement.requirement_id,
                            prohibited.trace,
                            allowed.trace,
                            changed[0],
                        )
                    )
        if candidates:
            boundaries.append(
                min(
                    candidates,
                    key=lambda item: (
                        len(item.prohibited_trace),
                        item.prohibited_trace,
                        item.permitted_trace,
                    ),
                )
            )
    return tuple(boundaries)


def _find_counterexamples(
    decisions: Sequence[CheckedDecision],
) -> tuple[ModelCounterexample, ...]:
    candidates: list[ModelCounterexample] = []
    for item in decisions:
        requirement_ids = item.matched_requirements or ("permitted-use",)
        if item.expected_control != item.actual_control:
            if item.expected_control == Control.ALLOW:
                property_name = "availability"
            elif item.actual_control == Control.ALLOW:
                property_name = "safety"
            else:
                property_name = "exact_control"
            for requirement_id in requirement_ids:
                candidates.append(
                    ModelCounterexample(
                        property_name,
                        requirement_id,
                        item.trace,
                        item.expected_control,
                        item.actual_control,
                    )
                )
        if item.expected_control != Control.ALLOW and not item.evidence_complete:
            missing = tuple(
                sorted(set(item.required_evidence_fields) - set(item.actual_evidence_fields))
            )
            for requirement_id in requirement_ids:
                candidates.append(
                    ModelCounterexample(
                        "evidence",
                        requirement_id,
                        item.trace,
                        item.expected_control,
                        item.actual_control,
                        missing,
                    )
                )
    shortest: dict[tuple[str, str], ModelCounterexample] = {}
    for item in sorted(candidates, key=lambda value: (len(value.trace), value.trace)):
        shortest.setdefault((item.property_name, item.requirement_id), item)
    return tuple(shortest[key] for key in sorted(shortest))


def _calculate_metrics(
    decisions: Sequence[CheckedDecision],
    boundaries: tuple[RelationalBoundary, ...],
    requirements: tuple[FlowRequirement, ...],
) -> dict[str, float]:
    unsafe = [item for item in decisions if item.expected_control != Control.ALLOW]
    permitted = [item for item in decisions if item.expected_control == Control.ALLOW]
    covered = {boundary.requirement_id for boundary in boundaries}
    return {
        "exact_control_conformance": _fraction(
            decisions, lambda item: item.control_correct
        ),
        "unsafe_action_prevention": _fraction(
            unsafe, lambda item: item.actual_control != Control.ALLOW
        ),
        "permitted_action_retention": _fraction(
            permitted, lambda item: item.actual_control == Control.ALLOW
        ),
        "evidence_coverage": _fraction(
            unsafe, lambda item: item.evidence_complete
        ),
        "relational_boundary_coverage": (
            len(covered) / len(requirements) if requirements else 1.0
        ),
    }


def _fraction(items: Sequence[Any], predicate: Any) -> float:
    if not items:
        return 1.0
    return sum(1 for item in items if predicate(item)) / len(items)


def _passes(metrics: Mapping[str, float], thresholds: BoundedCheckThresholds) -> bool:
    return (
        metrics["exact_control_conformance"]
        >= thresholds.min_exact_control_conformance
        and metrics["unsafe_action_prevention"]
        >= thresholds.min_unsafe_action_prevention
        and metrics["permitted_action_retention"]
        >= thresholds.min_permitted_action_retention
        and metrics["evidence_coverage"] >= thresholds.min_evidence_coverage
        and metrics["relational_boundary_coverage"]
        >= thresholds.min_relational_boundary_coverage
    )
