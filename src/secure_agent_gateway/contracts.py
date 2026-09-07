from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from typing import Any, Iterable, Mapping

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.models import Control, PolicyDecision, Principal, ToolRequest
from secure_agent_gateway.policy import PolicyEngine
from secure_agent_gateway.request_diff import semantic_request


@dataclass(frozen=True)
class ContractCase:
    case_id: str
    request: ToolRequest
    expected_control: Control
    required_evidence_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.case_id:
            raise ValueError("case_id is required")
        if len(set(self.required_evidence_fields)) != len(self.required_evidence_fields):
            raise ValueError("required_evidence_fields must be unique")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "request": semantic_request(self.request),
            "expected_control": self.expected_control.value,
            "required_evidence_fields": list(self.required_evidence_fields),
        }


@dataclass(frozen=True)
class PairedPolicyContract:
    contract_id: str
    policy_family: str
    principal: Principal
    prohibited: ContractCase
    permitted: ContractCase
    changed_fields: tuple[str, ...]
    _construction_digest: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.validate()
        object.__setattr__(self, "_construction_digest", self._content_digest())

    def validate(self) -> None:
        if not self.contract_id or not self.policy_family:
            raise ValueError("contract_id and policy_family are required")
        if self.prohibited.expected_control == Control.ALLOW:
            raise ValueError("prohibited case cannot expect allow")
        if self.permitted.expected_control != Control.ALLOW:
            raise ValueError("permitted case must expect allow")
        principal_ids = {
            self.principal.principal_id,
            self.prohibited.request.principal_id,
            self.permitted.request.principal_id,
        }
        if len(principal_ids) != 1:
            raise ValueError("paired cases must use the contract principal")
        observed = _contract_changed_fields(
            semantic_request(self.prohibited.request),
            semantic_request(self.permitted.request),
        )
        declared = set(self.changed_fields)
        if not declared or observed != declared:
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
class ContractThresholds:
    min_exact_control_accuracy: float = 1.0
    min_unsafe_action_prevention: float = 1.0
    min_permitted_task_retention: float = 1.0
    min_evidence_coverage: float = 1.0
    max_unnecessary_intervention_rate: float = 0.0

    def __post_init__(self) -> None:
        for value in self.to_mapping().values():
            if not 0.0 <= value <= 1.0:
                raise ValueError("contract thresholds must be between zero and one")

    def to_mapping(self) -> dict[str, float]:
        return {
            "min_exact_control_accuracy": self.min_exact_control_accuracy,
            "min_unsafe_action_prevention": self.min_unsafe_action_prevention,
            "min_permitted_task_retention": self.min_permitted_task_retention,
            "min_evidence_coverage": self.min_evidence_coverage,
            "max_unnecessary_intervention_rate": self.max_unnecessary_intervention_rate,
        }


@dataclass(frozen=True)
class ContractCaseResult:
    case_id: str
    category: str
    decision: PolicyDecision
    expected_control: Control
    required_evidence_fields: tuple[str, ...]
    control_correct: bool
    evidence_complete: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "decision": self.decision.to_mapping(),
            "expected_control": self.expected_control.value,
            "required_evidence_fields": list(self.required_evidence_fields),
            "control_correct": self.control_correct,
            "evidence_complete": self.evidence_complete,
        }


@dataclass(frozen=True)
class ContractReport:
    policy_version: str
    suite_digest: str
    metrics: Mapping[str, float]
    thresholds: ContractThresholds
    passed: bool
    results: tuple[ContractCaseResult, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "suite_digest": self.suite_digest,
            "metrics": dict(self.metrics),
            "thresholds": self.thresholds.to_mapping(),
            "passed": self.passed,
            "results": [result.to_mapping() for result in self.results],
        }

    @property
    def report_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ContractAttestation:
    key_id: str
    report_digest: str
    signature: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "report_digest": self.report_digest,
            "signature": self.signature,
        }


class ContractAttestor:
    def __init__(self, key_id: str, secret: bytes) -> None:
        if not key_id or len(secret) < 16:
            raise ValueError("attestation key id and a key of at least 16 bytes are required")
        self._key_id = key_id
        self._secret = secret

    def sign(self, report: ContractReport) -> ContractAttestation:
        digest = report.report_digest
        signature = hmac.new(
            self._secret,
            f"{self._key_id}:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return ContractAttestation(self._key_id, digest, signature)

    def verify(self, report: ContractReport, attestation: ContractAttestation) -> bool:
        if attestation.key_id != self._key_id or attestation.report_digest != report.report_digest:
            return False
        expected = self.sign(report)
        return hmac.compare_digest(expected.signature, attestation.signature)


class PolicyContractRunner:
    def __init__(self, policy: PolicyEngine) -> None:
        self._policy = policy

    def run(
        self,
        contracts: Iterable[PairedPolicyContract],
        *,
        thresholds: ContractThresholds | None = None,
    ) -> ContractReport:
        suite = tuple(contracts)
        if not suite:
            raise ValueError("at least one policy contract is required")
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
        active_thresholds = thresholds or ContractThresholds()
        suite_digest = hashlib.sha256(
            canonical_json([contract.to_mapping() for contract in suite]).encode("utf-8")
        ).hexdigest()
        results: list[ContractCaseResult] = []
        for contract in suite:
            results.append(self._evaluate(contract.principal, contract.prohibited, "prohibited"))
            results.append(self._evaluate(contract.principal, contract.permitted, "permitted"))

        metrics = _calculate_metrics(results)
        passed = (
            metrics["exact_control_accuracy"]
            >= active_thresholds.min_exact_control_accuracy
            and metrics["unsafe_action_prevention"]
            >= active_thresholds.min_unsafe_action_prevention
            and metrics["permitted_task_retention"]
            >= active_thresholds.min_permitted_task_retention
            and metrics["evidence_coverage"] >= active_thresholds.min_evidence_coverage
            and metrics["unnecessary_intervention_rate"]
            <= active_thresholds.max_unnecessary_intervention_rate
        )
        return ContractReport(
            policy_version=self._policy.policy_version,
            suite_digest=suite_digest,
            metrics=metrics,
            thresholds=active_thresholds,
            passed=passed,
            results=tuple(results),
        )

    def _evaluate(
        self,
        principal: Principal,
        case: ContractCase,
        category: str,
    ) -> ContractCaseResult:
        decision = self._policy.inspect(principal, case.request)
        required = set(case.required_evidence_fields)
        return ContractCaseResult(
            case_id=case.case_id,
            category=category,
            decision=decision,
            expected_control=case.expected_control,
            required_evidence_fields=case.required_evidence_fields,
            control_correct=decision.control == case.expected_control,
            evidence_complete=required.issubset(decision.evidence_fields),
        )


def _calculate_metrics(results: list[ContractCaseResult]) -> dict[str, float]:
    prohibited = [result for result in results if result.category == "prohibited"]
    permitted = [result for result in results if result.category == "permitted"]
    evidence_cases = [result for result in results if result.required_evidence_fields]
    return {
        "exact_control_accuracy": _fraction(results, lambda result: result.control_correct),
        "unsafe_action_prevention": _fraction(
            prohibited,
            lambda result: result.decision.control != Control.ALLOW,
        ),
        "permitted_task_retention": _fraction(
            permitted,
            lambda result: result.decision.control == Control.ALLOW,
        ),
        "evidence_coverage": _fraction(
            evidence_cases,
            lambda result: result.evidence_complete,
        ),
        "unnecessary_intervention_rate": _fraction(
            permitted,
            lambda result: result.decision.control != Control.ALLOW,
        ),
    }


def _fraction(items: list[ContractCaseResult], predicate: Any) -> float:
    if not items:
        return 1.0
    return sum(1 for item in items if predicate(item)) / len(items)


def _contract_changed_fields(left: Any, right: Any, prefix: str = "") -> set[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        changed: set[str] = set()
        for key in set(left) | set(right):
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                changed.add(path)
            else:
                changed.update(_contract_changed_fields(left[key], right[key], path))
        return changed
    return set() if left == right else {prefix}
