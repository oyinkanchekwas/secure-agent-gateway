from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from typing import Any, Iterable, Mapping, Sequence

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.model_checking import (
    BoundedCheckThresholds,
    FlowRequirement,
    InvocationTemplate,
    evaluate_flow_requirements,
    model_suite_digest,
    validate_model_suite,
)
from secure_agent_gateway.models import Control, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.session import SequencePolicy, SessionEvent, SessionSnapshot


@dataclass(frozen=True)
class PolicyChangeDecision:
    trace: tuple[str, ...]
    baseline_reachable: bool
    candidate_reachable: bool
    expected_control: Control
    baseline_control: Control
    candidate_control: Control
    matched_requirements: tuple[str, ...]
    required_evidence_fields: tuple[str, ...]
    baseline_evidence_fields: tuple[str, ...]
    candidate_evidence_fields: tuple[str, ...]

    @property
    def baseline_evidence_complete(self) -> bool:
        return set(self.required_evidence_fields).issubset(
            self.baseline_evidence_fields
        )

    @property
    def candidate_evidence_complete(self) -> bool:
        return set(self.required_evidence_fields).issubset(
            self.candidate_evidence_fields
        )

    @property
    def semantic_change(self) -> bool:
        return (
            self.baseline_control != self.candidate_control
            or self.baseline_evidence_fields != self.candidate_evidence_fields
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "trace": list(self.trace),
            "baseline_reachable": self.baseline_reachable,
            "candidate_reachable": self.candidate_reachable,
            "expected_control": self.expected_control.value,
            "baseline_control": self.baseline_control.value,
            "candidate_control": self.candidate_control.value,
            "matched_requirements": list(self.matched_requirements),
            "required_evidence_fields": list(self.required_evidence_fields),
            "baseline_evidence_fields": list(self.baseline_evidence_fields),
            "candidate_evidence_fields": list(self.candidate_evidence_fields),
            "baseline_evidence_complete": self.baseline_evidence_complete,
            "candidate_evidence_complete": self.candidate_evidence_complete,
            "semantic_change": self.semantic_change,
        }


@dataclass(frozen=True)
class PolicyChangeWitness:
    property_name: str
    requirement_id: str
    trace: tuple[str, ...]
    expected_control: Control
    baseline_control: Control
    candidate_control: Control
    missing_evidence_fields: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "property_name": self.property_name,
            "requirement_id": self.requirement_id,
            "trace": list(self.trace),
            "expected_control": self.expected_control.value,
            "baseline_control": self.baseline_control.value,
            "candidate_control": self.candidate_control.value,
            "missing_evidence_fields": list(self.missing_evidence_fields),
        }


@dataclass(frozen=True)
class PolicyChangeReport:
    policy_version: str
    baseline_policy_digest: str
    candidate_policy_digest: str
    suite_digest: str
    max_events: int
    explored_decisions: int
    baseline_metrics: Mapping[str, float]
    candidate_metrics: Mapping[str, float]
    change_metrics: Mapping[str, float]
    thresholds: BoundedCheckThresholds
    passed: bool
    baseline_uncovered_requirements: tuple[str, ...]
    candidate_uncovered_requirements: tuple[str, ...]
    baseline_witnesses: tuple[PolicyChangeWitness, ...]
    candidate_witnesses: tuple[PolicyChangeWitness, ...]
    regression_witnesses: tuple[PolicyChangeWitness, ...]
    correction_witnesses: tuple[PolicyChangeWitness, ...]
    decisions: tuple[PolicyChangeDecision, ...] = field(repr=False)

    def to_mapping(self, *, include_decisions: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "policy_version": self.policy_version,
            "baseline_policy_digest": self.baseline_policy_digest,
            "candidate_policy_digest": self.candidate_policy_digest,
            "suite_digest": self.suite_digest,
            "max_events": self.max_events,
            "explored_decisions": self.explored_decisions,
            "baseline_metrics": dict(self.baseline_metrics),
            "candidate_metrics": dict(self.candidate_metrics),
            "change_metrics": dict(self.change_metrics),
            "thresholds": self.thresholds.to_mapping(),
            "passed": self.passed,
            "baseline_uncovered_requirements": list(
                self.baseline_uncovered_requirements
            ),
            "candidate_uncovered_requirements": list(
                self.candidate_uncovered_requirements
            ),
            "baseline_witnesses": [
                witness.to_mapping() for witness in self.baseline_witnesses
            ],
            "candidate_witnesses": [
                witness.to_mapping() for witness in self.candidate_witnesses
            ],
            "regression_witnesses": [
                witness.to_mapping() for witness in self.regression_witnesses
            ],
            "correction_witnesses": [
                witness.to_mapping() for witness in self.correction_witnesses
            ],
        }
        if include_decisions:
            payload["decisions"] = [decision.to_mapping() for decision in self.decisions]
        return payload

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_mapping(include_decisions=True)).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class PolicyChangeAttestation:
    key_id: str
    report_digest: str
    signature: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "report_digest": self.report_digest,
            "signature": self.signature,
        }


class PolicyChangeAttestor:
    def __init__(self, key_id: str, secret: bytes) -> None:
        if not key_id or not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("attestation key id and a key of at least 16 bytes are required")
        self._key_id = key_id
        self._secret = secret

    def sign(self, report: PolicyChangeReport) -> PolicyChangeAttestation:
        digest = report.report_digest
        signature = hmac.new(
            self._secret,
            f"{self._key_id}:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return PolicyChangeAttestation(self._key_id, digest, signature)

    def verify(
        self,
        report: PolicyChangeReport,
        attestation: PolicyChangeAttestation,
    ) -> bool:
        if attestation.key_id != self._key_id:
            return False
        if attestation.report_digest != report.report_digest:
            return False
        return hmac.compare_digest(self.sign(report).signature, attestation.signature)


class PolicyChangeChecker:
    def __init__(
        self,
        policy: PolicyEngine,
        baseline: SequencePolicy,
        candidate: SequencePolicy,
    ) -> None:
        self._policy = policy
        self._baseline = baseline
        self._candidate = candidate
        self._baseline.validate_registry(self._policy.registry)
        self._candidate.validate_registry(self._policy.registry)

    def run(
        self,
        *,
        principal: Principal,
        templates: Iterable[InvocationTemplate],
        requirements: Iterable[FlowRequirement],
        max_events: int,
        max_decisions: int = 100_000,
        thresholds: BoundedCheckThresholds | None = None,
    ) -> PolicyChangeReport:
        alphabet = tuple(sorted(templates, key=lambda item: item.template_id))
        specification = tuple(sorted(requirements, key=lambda item: item.requirement_id))
        validate_model_suite(
            self._policy,
            principal,
            alphabet,
            specification,
            max_events,
            max_decisions,
        )
        active_thresholds = thresholds or BoundedCheckThresholds()
        suite_digest = model_suite_digest(
            principal,
            alphabet,
            specification,
            max_events,
        )

        decisions: list[PolicyChangeDecision] = []
        frontier: list[
            tuple[tuple[str, ...], tuple[SessionEvent, ...], bool, bool]
        ] = [((), (), True, True)]
        for _ in range(max_events):
            next_frontier: list[
                tuple[tuple[str, ...], tuple[SessionEvent, ...], bool, bool]
            ] = []
            for trace, events, baseline_reachable, candidate_reachable in frontier:
                for template in alphabet:
                    if len(decisions) >= max_decisions:
                        raise ValueError("policy change check exceeds max_decisions")
                    decision, event = self._evaluate_extension(
                        principal,
                        trace,
                        events,
                        template,
                        specification,
                        baseline_reachable,
                        candidate_reachable,
                    )
                    decisions.append(decision)
                    next_baseline = (
                        baseline_reachable
                        and decision.baseline_control == Control.ALLOW
                    )
                    next_candidate = (
                        candidate_reachable
                        and decision.candidate_control == Control.ALLOW
                    )
                    if next_baseline or next_candidate:
                        next_frontier.append(
                            (
                                decision.trace,
                                events + (event,),
                                next_baseline,
                                next_candidate,
                            )
                        )
            frontier = next_frontier
            if not frontier:
                break

        baseline_witnesses = _find_policy_witnesses(decisions, candidate=False)
        candidate_witnesses = _find_policy_witnesses(decisions, candidate=True)
        regression_witnesses, correction_witnesses = _find_change_witnesses(decisions)
        baseline_decisions = [
            decision for decision in decisions if decision.baseline_reachable
        ]
        candidate_decisions = [
            decision for decision in decisions if decision.candidate_reachable
        ]
        baseline_metrics = _policy_metrics(
            baseline_decisions,
            requirements=specification,
            candidate=False,
        )
        candidate_metrics = _policy_metrics(
            candidate_decisions,
            requirements=specification,
            candidate=True,
        )
        baseline_uncovered = _uncovered_requirements(
            baseline_decisions,
            specification,
        )
        candidate_uncovered = _uncovered_requirements(
            candidate_decisions,
            specification,
        )
        change_metrics = _change_metrics(
            decisions,
            candidate_witnesses,
            regression_witnesses,
            correction_witnesses,
        )
        passed = not regression_witnesses and _metrics_pass(
            candidate_metrics,
            active_thresholds,
        )
        return PolicyChangeReport(
            policy_version=self._policy.policy_version,
            baseline_policy_digest=self._baseline.digest,
            candidate_policy_digest=self._candidate.digest,
            suite_digest=suite_digest,
            max_events=max_events,
            explored_decisions=len(decisions),
            baseline_metrics=baseline_metrics,
            candidate_metrics=candidate_metrics,
            change_metrics=change_metrics,
            thresholds=active_thresholds,
            passed=passed,
            baseline_uncovered_requirements=baseline_uncovered,
            candidate_uncovered_requirements=candidate_uncovered,
            baseline_witnesses=baseline_witnesses,
            candidate_witnesses=candidate_witnesses,
            regression_witnesses=regression_witnesses,
            correction_witnesses=correction_witnesses,
            decisions=tuple(decisions),
        )

    def _evaluate_extension(
        self,
        principal: Principal,
        trace: tuple[str, ...],
        events: tuple[SessionEvent, ...],
        template: InvocationTemplate,
        requirements: tuple[FlowRequirement, ...],
        baseline_reachable: bool,
        candidate_reachable: bool,
    ) -> tuple[PolicyChangeDecision, SessionEvent]:
        sequence = len(events) + 1
        request_id = f"change-{sequence}-{template.template_id}"
        request = ToolRequest(
            request_id=request_id,
            principal_id=principal.principal_id,
            tool=template.tool,
            arguments=dict(template.arguments),
            issued_at=1_800_000_000,
            nonce=f"nonce-{request_id}",
            session_id="policy-change-check",
        )
        snapshot = SessionSnapshot(principal.principal_id, request.session_id, events)
        base = self._policy.inspect(principal, request)
        baseline = self._baseline.evaluate(request, snapshot, base)
        candidate = self._candidate.evaluate(request, snapshot, base)
        expected, matched, evidence = evaluate_flow_requirements(
            template.tool,
            events,
            requirements,
        )
        registered = self._policy.registry.get(template.tool)
        if registered is None:
            raise RuntimeError("validated policy-change tool disappeared")
        event = SessionEvent(
            sequence=sequence,
            request_id=request_id,
            tool=template.tool,
            effects=registered.spec.emitted_effects,
        )
        return (
            PolicyChangeDecision(
                trace=trace + (template.template_id,),
                baseline_reachable=baseline_reachable,
                candidate_reachable=candidate_reachable,
                expected_control=expected,
                baseline_control=baseline.control,
                candidate_control=candidate.control,
                matched_requirements=matched,
                required_evidence_fields=evidence,
                baseline_evidence_fields=baseline.evidence_fields,
                candidate_evidence_fields=candidate.evidence_fields,
            ),
            event,
        )


def _find_change_witnesses(
    decisions: Sequence[PolicyChangeDecision],
) -> tuple[tuple[PolicyChangeWitness, ...], tuple[PolicyChangeWitness, ...]]:
    regressions: list[PolicyChangeWitness] = []
    corrections: list[PolicyChangeWitness] = []
    for decision in decisions:
        if not (decision.baseline_reachable and decision.candidate_reachable):
            continue
        requirement_ids = decision.matched_requirements or ("permitted-use",)
        for property_name in _regression_properties(decision):
            for requirement_id in requirement_ids:
                regressions.append(
                    _witness(property_name, requirement_id, decision, candidate=True)
                )
        for property_name in _correction_properties(decision):
            for requirement_id in requirement_ids:
                corrections.append(
                    _witness(property_name, requirement_id, decision, candidate=False)
                )
    return _shortest(regressions), _shortest(corrections)


def _find_policy_witnesses(
    decisions: Sequence[PolicyChangeDecision],
    *,
    candidate: bool,
) -> tuple[PolicyChangeWitness, ...]:
    witnesses: list[PolicyChangeWitness] = []
    for decision in decisions:
        reachable = (
            decision.candidate_reachable if candidate else decision.baseline_reachable
        )
        if not reachable:
            continue
        actual = decision.candidate_control if candidate else decision.baseline_control
        evidence_complete = (
            decision.candidate_evidence_complete
            if candidate
            else decision.baseline_evidence_complete
        )
        requirement_ids = decision.matched_requirements or ("permitted-use",)
        properties: list[str] = []
        if actual != decision.expected_control:
            if decision.expected_control == Control.ALLOW:
                properties.append("availability")
            elif actual == Control.ALLOW:
                properties.append("safety")
            else:
                properties.append("exact_control")
        if decision.expected_control != Control.ALLOW and not evidence_complete:
            properties.append("evidence")
        for property_name in properties:
            for requirement_id in requirement_ids:
                witnesses.append(
                    _witness(
                        property_name,
                        requirement_id,
                        decision,
                        candidate=candidate,
                    )
                )
    return _shortest(witnesses)


def _regression_properties(decision: PolicyChangeDecision) -> tuple[str, ...]:
    properties: list[str] = []
    if decision.expected_control == Control.ALLOW:
        if (
            decision.baseline_control == Control.ALLOW
            and decision.candidate_control != Control.ALLOW
        ):
            properties.append("availability")
        return tuple(properties)

    if (
        decision.baseline_control != Control.ALLOW
        and decision.candidate_control == Control.ALLOW
    ):
        properties.append("safety")
    if (
        decision.baseline_control == decision.expected_control
        and decision.candidate_control not in {
            decision.expected_control,
            Control.ALLOW,
        }
    ):
        properties.append("exact_control")
    if (
        decision.baseline_evidence_complete
        and not decision.candidate_evidence_complete
    ):
        properties.append("evidence")
    return tuple(properties)


def _correction_properties(decision: PolicyChangeDecision) -> tuple[str, ...]:
    properties: list[str] = []
    if decision.expected_control == Control.ALLOW:
        if (
            decision.baseline_control != Control.ALLOW
            and decision.candidate_control == Control.ALLOW
        ):
            properties.append("availability")
        return tuple(properties)

    if (
        decision.baseline_control == Control.ALLOW
        and decision.candidate_control != Control.ALLOW
    ):
        properties.append("safety")
    if (
        decision.baseline_control != decision.expected_control
        and decision.candidate_control == decision.expected_control
    ):
        properties.append("exact_control")
    if (
        not decision.baseline_evidence_complete
        and decision.candidate_evidence_complete
    ):
        properties.append("evidence")
    return tuple(properties)


def _witness(
    property_name: str,
    requirement_id: str,
    decision: PolicyChangeDecision,
    *,
    candidate: bool,
) -> PolicyChangeWitness:
    missing: tuple[str, ...] = ()
    if property_name == "evidence":
        available = (
            decision.candidate_evidence_fields
            if candidate
            else decision.baseline_evidence_fields
        )
        missing = tuple(sorted(set(decision.required_evidence_fields) - set(available)))
    return PolicyChangeWitness(
        property_name=property_name,
        requirement_id=requirement_id,
        trace=decision.trace,
        expected_control=decision.expected_control,
        baseline_control=decision.baseline_control,
        candidate_control=decision.candidate_control,
        missing_evidence_fields=missing,
    )


def _shortest(
    witnesses: Sequence[PolicyChangeWitness],
) -> tuple[PolicyChangeWitness, ...]:
    shortest: dict[tuple[str, str], PolicyChangeWitness] = {}
    for witness in sorted(witnesses, key=lambda item: (len(item.trace), item.trace)):
        shortest.setdefault((witness.property_name, witness.requirement_id), witness)
    return tuple(shortest[key] for key in sorted(shortest))


def _policy_metrics(
    decisions: Sequence[PolicyChangeDecision],
    *,
    requirements: tuple[FlowRequirement, ...],
    candidate: bool,
) -> dict[str, float]:
    unsafe = [item for item in decisions if item.expected_control != Control.ALLOW]
    permitted = [item for item in decisions if item.expected_control == Control.ALLOW]

    def control(item: PolicyChangeDecision) -> Control:
        return item.candidate_control if candidate else item.baseline_control

    def evidence_complete(item: PolicyChangeDecision) -> bool:
        return (
            item.candidate_evidence_complete
            if candidate
            else item.baseline_evidence_complete
        )

    return {
        "exact_control_conformance": _fraction(
            decisions,
            lambda item: control(item) == item.expected_control,
        ),
        "unsafe_action_prevention": _fraction(
            unsafe,
            lambda item: control(item) != Control.ALLOW,
        ),
        "permitted_action_retention": _fraction(
            permitted,
            lambda item: control(item) == Control.ALLOW,
        ),
        "evidence_coverage": _fraction(unsafe, evidence_complete),
        "relational_boundary_coverage": _relational_boundary_coverage(
            decisions,
            requirements,
        ),
    }


def _change_metrics(
    decisions: Sequence[PolicyChangeDecision],
    candidate_witnesses: tuple[PolicyChangeWitness, ...],
    regressions: tuple[PolicyChangeWitness, ...],
    corrections: tuple[PolicyChangeWitness, ...],
) -> dict[str, float]:
    shared = [
        item for item in decisions if item.baseline_reachable and item.candidate_reachable
    ]
    semantic_changes = [item for item in shared if item.semantic_change]
    baseline_only = [
        item for item in decisions if item.baseline_reachable and not item.candidate_reachable
    ]
    candidate_only = [
        item for item in decisions if item.candidate_reachable and not item.baseline_reachable
    ]
    return {
        "semantic_change_rate": len(semantic_changes) / len(shared) if shared else 0.0,
        "candidate_witnesses": float(len(candidate_witnesses)),
        "regression_witnesses": float(len(regressions)),
        "correction_witnesses": float(len(corrections)),
        "baseline_only_boundaries": float(len(baseline_only)),
        "candidate_only_boundaries": float(len(candidate_only)),
    }


def _metrics_pass(
    metrics: Mapping[str, float],
    thresholds: BoundedCheckThresholds,
) -> bool:
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


def _relational_boundary_coverage(
    decisions: Sequence[PolicyChangeDecision],
    requirements: tuple[FlowRequirement, ...],
) -> float:
    requirement_ids = {requirement.requirement_id for requirement in requirements}
    if not requirement_ids:
        return 1.0
    covered = _covered_requirement_ids(decisions, requirements)
    return len(covered) / len(requirement_ids)


def _covered_requirement_ids(
    decisions: Sequence[PolicyChangeDecision],
    requirements: tuple[FlowRequirement, ...],
) -> set[str]:
    requirement_ids = {requirement.requirement_id for requirement in requirements}
    permitted = [item for item in decisions if item.expected_control == Control.ALLOW]
    covered: set[str] = set()
    for requirement_id in requirement_ids:
        unsafe = [
            item
            for item in decisions
            if requirement_id in item.matched_requirements
        ]
        for prohibited in unsafe:
            for allowed in permitted:
                if len(prohibited.trace) != len(allowed.trace):
                    continue
                if prohibited.trace[-1] != allowed.trace[-1]:
                    continue
                changed = sum(
                    left != right
                    for left, right in zip(prohibited.trace, allowed.trace)
                )
                if changed == 1:
                    covered.add(requirement_id)
                    break
            if requirement_id in covered:
                break
    return covered


def _uncovered_requirements(
    decisions: Sequence[PolicyChangeDecision],
    requirements: tuple[FlowRequirement, ...],
) -> tuple[str, ...]:
    covered = _covered_requirement_ids(decisions, requirements)
    return tuple(
        sorted(
            requirement.requirement_id
            for requirement in requirements
            if requirement.requirement_id not in covered
        )
    )


def _fraction(items: Sequence[Any], predicate: Any) -> float:
    if not items:
        return 1.0
    return sum(1 for item in items if predicate(item)) / len(items)
