from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
from typing import Any, Iterable, Mapping, Sequence

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.models import Control, PolicyDecision, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.session import SequencePolicy, SequenceRule, SessionEvent, SessionSnapshot


@dataclass(frozen=True)
class TrajectoryCase:
    case_id: str
    requests: tuple[ToolRequest, ...]
    expected_controls: tuple[Control, ...]
    expected_first_intervention: int | None
    required_evidence_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "requests", tuple(self.requests))
        object.__setattr__(self, "expected_controls", tuple(self.expected_controls))
        if not self.case_id or not self.requests:
            raise ValueError("case_id and requests are required")
        if len(self.requests) != len(self.expected_controls):
            raise ValueError("each request requires an expected control")
        request_ids = [request.request_id for request in self.requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("request identifiers must be unique within a trajectory")
        principals = {request.principal_id for request in self.requests}
        sessions = {request.session_id for request in self.requests}
        if len(principals) != 1 or len(sessions) != 1:
            raise ValueError("a trajectory must remain within one principal and session")
        observed = next(
            (
                index
                for index, control in enumerate(self.expected_controls)
                if control != Control.ALLOW
            ),
            None,
        )
        if observed != self.expected_first_intervention:
            raise ValueError("expected_first_intervention must match expected_controls")
        if observed is not None and observed != len(self.requests) - 1:
            raise ValueError("a trajectory must end at its first expected intervention")
        if len(set(self.required_evidence_fields)) != len(self.required_evidence_fields):
            raise ValueError("required_evidence_fields must be unique")
        if self.required_evidence_fields and observed is None:
            raise ValueError("evidence requirements need an expected intervention")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "requests": [_recorded_request(request) for request in self.requests],
            "expected_controls": [control.value for control in self.expected_controls],
            "expected_first_intervention": self.expected_first_intervention,
            "required_evidence_fields": list(self.required_evidence_fields),
        }


@dataclass(frozen=True)
class PairedTrajectoryContract:
    contract_id: str
    policy_family: str
    principal: Principal
    prohibited: TrajectoryCase
    permitted: TrajectoryCase
    changed_fields: tuple[str, ...]
    _construction_digest: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.validate()
        object.__setattr__(self, "_construction_digest", self._content_digest())

    def validate(self) -> None:
        if not self.contract_id or not self.policy_family:
            raise ValueError("contract_id and policy_family are required")
        if self.prohibited.expected_first_intervention is None:
            raise ValueError("prohibited trajectory must expect an intervention")
        if not self.prohibited.required_evidence_fields:
            raise ValueError("prohibited trajectory must require causal evidence")
        if self.permitted.expected_first_intervention is not None:
            raise ValueError("permitted trajectory cannot expect an intervention")
        if len(self.prohibited.requests) != len(self.permitted.requests):
            raise ValueError("paired trajectories must contain the same number of requests")
        if len(set(self.changed_fields)) != len(self.changed_fields):
            raise ValueError("changed_fields must be unique")
        principal_ids = {
            self.principal.principal_id,
            *(request.principal_id for request in self.prohibited.requests),
            *(request.principal_id for request in self.permitted.requests),
        }
        if len(principal_ids) != 1:
            raise ValueError("paired trajectories must use the contract principal")
        session_ids = {
            self.prohibited.requests[0].session_id,
            self.permitted.requests[0].session_id,
        }
        if len(session_ids) != 1:
            raise ValueError("paired trajectories must use the same session handle")
        observed = _changed_fields(
            [_semantic_request(request) for request in self.prohibited.requests],
            [_semantic_request(request) for request in self.permitted.requests],
            "requests",
        )
        if not self.changed_fields or observed != set(self.changed_fields):
            raise ValueError(
                f"changed_fields must match the controlled pair: {sorted(observed)}"
            )
        if (
            hasattr(self, "_construction_digest")
            and self._construction_digest != self._content_digest()
        ):
            raise ValueError("contract content changed after construction")

    def _content_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "policy_family": self.policy_family,
            "principal": {
                "principal_id": self.principal.principal_id,
                "roles": sorted(self.principal.roles),
            },
            "prohibited": self.prohibited.to_mapping(),
            "permitted": self.permitted.to_mapping(),
            "changed_fields": list(self.changed_fields),
        }


@dataclass(frozen=True)
class TrajectoryThresholds:
    min_exact_control_accuracy: float = 1.0
    min_unsafe_sequence_prevention: float = 1.0
    min_permitted_trajectory_completion: float = 1.0
    min_first_intervention_accuracy: float = 1.0
    min_evidence_coverage: float = 1.0
    max_unnecessary_intervention_rate: float = 0.0

    def __post_init__(self) -> None:
        for value in self.to_mapping().values():
            if not 0.0 <= value <= 1.0:
                raise ValueError("trajectory thresholds must be between zero and one")

    def to_mapping(self) -> dict[str, float]:
        return {
            "min_exact_control_accuracy": self.min_exact_control_accuracy,
            "min_unsafe_sequence_prevention": self.min_unsafe_sequence_prevention,
            "min_permitted_trajectory_completion": self.min_permitted_trajectory_completion,
            "min_first_intervention_accuracy": self.min_first_intervention_accuracy,
            "min_evidence_coverage": self.min_evidence_coverage,
            "max_unnecessary_intervention_rate": self.max_unnecessary_intervention_rate,
        }


@dataclass(frozen=True)
class TrajectoryCaseResult:
    case_id: str
    category: str
    decisions: tuple[PolicyDecision, ...]
    expected_controls: tuple[Control, ...]
    expected_first_intervention: int | None
    first_intervention: int | None
    required_evidence_fields: tuple[str, ...]
    control_correct: bool
    evidence_complete: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "decisions": [decision.to_mapping() for decision in self.decisions],
            "expected_controls": [control.value for control in self.expected_controls],
            "expected_first_intervention": self.expected_first_intervention,
            "first_intervention": self.first_intervention,
            "required_evidence_fields": list(self.required_evidence_fields),
            "control_correct": self.control_correct,
            "evidence_complete": self.evidence_complete,
        }


@dataclass(frozen=True)
class TrajectoryReport:
    policy_version: str
    sequence_policy_digest: str
    suite_digest: str
    metrics: Mapping[str, float]
    thresholds: TrajectoryThresholds
    passed: bool
    results: tuple[TrajectoryCaseResult, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "sequence_policy_digest": self.sequence_policy_digest,
            "suite_digest": self.suite_digest,
            "metrics": dict(self.metrics),
            "thresholds": self.thresholds.to_mapping(),
            "passed": self.passed,
            "results": [result.to_mapping() for result in self.results],
        }

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()


class TrajectoryContractRunner:
    def __init__(self, policy: PolicyEngine, sequence_policy: SequencePolicy) -> None:
        self._policy = policy
        self._sequence_policy = sequence_policy
        self._sequence_policy.validate_registry(self._policy.registry)

    def run(
        self,
        contracts: Iterable[PairedTrajectoryContract],
        *,
        thresholds: TrajectoryThresholds | None = None,
    ) -> TrajectoryReport:
        suite = tuple(contracts)
        if not suite:
            raise ValueError("at least one trajectory contract is required")
        contract_ids = [contract.contract_id for contract in suite]
        case_ids = [
            case.case_id
            for contract in suite
            for case in (contract.prohibited, contract.permitted)
        ]
        if len(contract_ids) != len(set(contract_ids)):
            raise ValueError("contract identifiers must be unique")
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case identifiers must be unique")
        for contract in suite:
            contract.validate()

        active_thresholds = thresholds or TrajectoryThresholds()
        suite_digest = hashlib.sha256(
            canonical_json([contract.to_mapping() for contract in suite]).encode("utf-8")
        ).hexdigest()
        results: list[TrajectoryCaseResult] = []
        for contract in suite:
            results.append(self._evaluate(contract.principal, contract.prohibited, "prohibited"))
            results.append(self._evaluate(contract.principal, contract.permitted, "permitted"))
        metrics = _calculate_metrics(results)
        passed = (
            metrics["exact_control_accuracy"]
            >= active_thresholds.min_exact_control_accuracy
            and metrics["unsafe_sequence_prevention"]
            >= active_thresholds.min_unsafe_sequence_prevention
            and metrics["permitted_trajectory_completion"]
            >= active_thresholds.min_permitted_trajectory_completion
            and metrics["first_intervention_accuracy"]
            >= active_thresholds.min_first_intervention_accuracy
            and metrics["evidence_coverage"] >= active_thresholds.min_evidence_coverage
            and metrics["unnecessary_intervention_rate"]
            <= active_thresholds.max_unnecessary_intervention_rate
        )
        return TrajectoryReport(
            policy_version=self._policy.policy_version,
            sequence_policy_digest=self._sequence_policy.digest,
            suite_digest=suite_digest,
            metrics=metrics,
            thresholds=active_thresholds,
            passed=passed,
            results=tuple(results),
        )

    def _evaluate(
        self,
        principal: Principal,
        case: TrajectoryCase,
        category: str,
    ) -> TrajectoryCaseResult:
        events: list[SessionEvent] = []
        decisions: list[PolicyDecision] = []
        first_request = case.requests[0]
        for request in case.requests:
            snapshot = SessionSnapshot(
                principal.principal_id,
                first_request.session_id,
                tuple(events),
            )
            decision = self._sequence_policy.evaluate(
                request,
                snapshot,
                self._policy.inspect(principal, request),
            )
            decisions.append(decision)
            if decision.control != Control.ALLOW:
                break
            registered = self._policy.registry.get(request.tool)
            if registered is not None:
                events.append(
                    SessionEvent(
                        sequence=len(events) + 1,
                        request_id=request.request_id,
                        tool=request.tool,
                        effects=registered.spec.emitted_effects,
                    )
                )

        first_intervention = next(
            (
                index
                for index, decision in enumerate(decisions)
                if decision.control != Control.ALLOW
            ),
            None,
        )
        expected_index = case.expected_first_intervention
        evidence_complete = True
        if case.required_evidence_fields:
            evidence_complete = (
                expected_index is not None
                and expected_index < len(decisions)
                and set(case.required_evidence_fields).issubset(
                    decisions[expected_index].evidence_fields
                )
            )
        control_correct = (
            len(decisions) == len(case.expected_controls)
            and all(
                decision.control == expected
                for decision, expected in zip(decisions, case.expected_controls)
            )
        )
        return TrajectoryCaseResult(
            case_id=case.case_id,
            category=category,
            decisions=tuple(decisions),
            expected_controls=case.expected_controls,
            expected_first_intervention=expected_index,
            first_intervention=first_intervention,
            required_evidence_fields=case.required_evidence_fields,
            control_correct=control_correct,
            evidence_complete=evidence_complete,
        )


@dataclass(frozen=True)
class SequencePolicyMutant:
    mutant_id: str
    rule_id: str
    mutation: str
    policy: SequencePolicy = field(repr=False)


@dataclass(frozen=True)
class MutationOutcome:
    mutant_id: str
    rule_id: str
    mutation: str
    killed: bool
    failed_metrics: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "mutant_id": self.mutant_id,
            "rule_id": self.rule_id,
            "mutation": self.mutation,
            "killed": self.killed,
            "failed_metrics": list(self.failed_metrics),
        }


@dataclass(frozen=True)
class MutationReport:
    baseline_report_digest: str
    mutation_score: float
    killed: int
    survived: int
    outcomes: tuple[MutationOutcome, ...]

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


class SequenceMutationAnalyser:
    def __init__(self, policy: PolicyEngine, sequence_policy: SequencePolicy) -> None:
        self._policy = policy
        self._sequence_policy = sequence_policy

    def run(
        self,
        contracts: Iterable[PairedTrajectoryContract],
        *,
        thresholds: TrajectoryThresholds | None = None,
    ) -> MutationReport:
        suite = tuple(contracts)
        baseline = TrajectoryContractRunner(self._policy, self._sequence_policy).run(
            suite,
            thresholds=thresholds,
        )
        if not baseline.passed:
            raise ValueError("baseline trajectory contracts must pass before mutation analysis")
        mutants = _generate_mutants(self._sequence_policy)
        if not mutants:
            raise ValueError("sequence policy produced no supported mutations")
        outcomes: list[MutationOutcome] = []
        for mutant in mutants:
            report = TrajectoryContractRunner(self._policy, mutant.policy).run(
                suite,
                thresholds=thresholds,
            )
            failed_metrics = tuple(
                key
                for key, value in report.metrics.items()
                if not _metric_passes(key, value, report.thresholds)
            )
            outcomes.append(
                MutationOutcome(
                    mutant_id=mutant.mutant_id,
                    rule_id=mutant.rule_id,
                    mutation=mutant.mutation,
                    killed=not report.passed,
                    failed_metrics=failed_metrics,
                )
            )
        killed = sum(outcome.killed for outcome in outcomes)
        return MutationReport(
            baseline_report_digest=baseline.report_digest,
            mutation_score=killed / len(outcomes),
            killed=killed,
            survived=len(outcomes) - killed,
            outcomes=tuple(outcomes),
        )


def _generate_mutants(policy: SequencePolicy) -> tuple[SequencePolicyMutant, ...]:
    mutants: list[SequencePolicyMutant] = []
    for rule in policy.rules:
        mutants.append(
            SequencePolicyMutant(
                f"{rule.rule_id}:disabled",
                rule.rule_id,
                "disabled",
                policy.without_rule(rule.rule_id),
            )
        )
        if rule.control == Control.DENY:
            mutants.append(
                _replace_rule_mutant(
                    policy,
                    rule,
                    "control_weakened",
                    replace(rule, control=Control.REQUIRE_APPROVAL),
                )
            )
        if rule.window_events is None or rule.window_events > 1:
            mutants.append(
                _replace_rule_mutant(
                    policy,
                    rule,
                    "history_window_reduced",
                    replace(rule, window_events=1),
                )
            )
        if len(rule.required_effects) > 1:
            for effect in sorted(rule.required_effects):
                mutants.append(
                    _replace_rule_mutant(
                        policy,
                        rule,
                        f"required_effect_removed:{effect}",
                        replace(rule, required_effects=rule.required_effects - {effect}),
                    )
                )
        if len(rule.target_tools) > 1:
            for tool in sorted(rule.target_tools):
                mutants.append(
                    _replace_rule_mutant(
                        policy,
                        rule,
                        f"target_removed:{tool}",
                        replace(rule, target_tools=rule.target_tools - {tool}),
                    )
                )
    return tuple(mutants)


def _replace_rule_mutant(
    policy: SequencePolicy,
    original: SequenceRule,
    mutation: str,
    replacement: SequenceRule,
) -> SequencePolicyMutant:
    rules = [replacement if rule.rule_id == original.rule_id else rule for rule in policy.rules]
    return SequencePolicyMutant(
        mutant_id=f"{original.rule_id}:{mutation}",
        rule_id=original.rule_id,
        mutation=mutation,
        policy=SequencePolicy(rules),
    )


def _calculate_metrics(results: Sequence[TrajectoryCaseResult]) -> dict[str, float]:
    prohibited = [result for result in results if result.category == "prohibited"]
    permitted = [result for result in results if result.category == "permitted"]
    evidence_cases = [result for result in results if result.required_evidence_fields]
    return {
        "exact_control_accuracy": _fraction(results, lambda result: result.control_correct),
        "unsafe_sequence_prevention": _fraction(
            prohibited,
            lambda result: result.first_intervention is not None,
        ),
        "permitted_trajectory_completion": _fraction(
            permitted,
            lambda result: result.first_intervention is None
            and len(result.decisions) == len(result.expected_controls),
        ),
        "first_intervention_accuracy": _fraction(
            results,
            lambda result: result.first_intervention == result.expected_first_intervention,
        ),
        "evidence_coverage": _fraction(
            evidence_cases,
            lambda result: result.evidence_complete,
        ),
        "unnecessary_intervention_rate": _fraction(
            permitted,
            lambda result: result.first_intervention is not None,
        ),
    }


def _fraction(items: Sequence[Any], predicate: Any) -> float:
    if not items:
        return 1.0
    return sum(1 for item in items if predicate(item)) / len(items)


def _metric_passes(key: str, value: float, thresholds: TrajectoryThresholds) -> bool:
    checks = {
        "exact_control_accuracy": value >= thresholds.min_exact_control_accuracy,
        "unsafe_sequence_prevention": value >= thresholds.min_unsafe_sequence_prevention,
        "permitted_trajectory_completion": value
        >= thresholds.min_permitted_trajectory_completion,
        "first_intervention_accuracy": value >= thresholds.min_first_intervention_accuracy,
        "evidence_coverage": value >= thresholds.min_evidence_coverage,
        "unnecessary_intervention_rate": value
        <= thresholds.max_unnecessary_intervention_rate,
    }
    return checks[key]


def _semantic_request(request: ToolRequest) -> dict[str, Any]:
    return {
        "principal_id": request.principal_id,
        "tool": request.tool,
        "arguments": dict(request.arguments),
    }


def _recorded_request(request: ToolRequest) -> dict[str, Any]:
    return {
        "request_id": request.request_id,
        "session_id": request.session_id,
        **_semantic_request(request),
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
        changed = set()
        for index in range(max(len(left), len(right))):
            path = f"{prefix}.{index}" if prefix else str(index)
            if index >= len(left) or index >= len(right):
                changed.add(path)
            else:
                changed.update(_changed_fields(left[index], right[index], path))
        return changed
    return set() if left == right else {prefix}
