from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import re
from threading import Lock, RLock
from typing import ContextManager, Iterator, Protocol

from secure_agent_gateway.auth import canonical_json
from secure_agent_gateway.models import Control, PolicyDecision, ToolRequest
from secure_agent_gateway.registry import ToolRegistry


@dataclass(frozen=True)
class SessionEvent:
    sequence: int
    request_id: str
    tool: str
    effects: frozenset[str]

    def to_mapping(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "request_id": self.request_id,
            "tool": self.tool,
            "effects": sorted(self.effects),
        }


@dataclass(frozen=True)
class SessionSnapshot:
    principal_id: str
    session_id: str
    events: tuple[SessionEvent, ...]

    @property
    def digest(self) -> str:
        payload = {
            "principal_id": self.principal_id,
            "session_id": self.session_id,
            "events": [event.to_mapping() for event in self.events],
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class SessionStore(Protocol):
    def claim_request(
        self,
        request_id: str,
        principal_id: str,
        *,
        now: int,
    ) -> bool: ...

    def serialise(
        self,
        principal_id: str,
        session_id: str,
    ) -> ContextManager[None]: ...

    def snapshot(self, principal_id: str, session_id: str) -> SessionSnapshot: ...

    def record_success(
        self,
        principal_id: str,
        session_id: str,
        request_id: str,
        tool: str,
        effects: frozenset[str],
    ) -> SessionEvent: ...


class InMemorySessionStore:
    def __init__(self) -> None:
        self._events: dict[tuple[str, str], list[SessionEvent]] = {}
        self._request_ids: set[str] = set()
        self._session_locks: dict[tuple[str, str], RLock] = {}
        self._guard = Lock()

    def claim_request(
        self,
        request_id: str,
        principal_id: str,
        *,
        now: int,
    ) -> bool:
        del principal_id, now
        with self._guard:
            if request_id in self._request_ids:
                return False
            self._request_ids.add(request_id)
            return True

    @contextmanager
    def serialise(self, principal_id: str, session_id: str) -> Iterator[None]:
        lock = self._lock_for(principal_id, session_id)
        with lock:
            yield

    def snapshot(self, principal_id: str, session_id: str) -> SessionSnapshot:
        key = (principal_id, session_id)
        lock = self._lock_for(*key)
        with lock:
            return SessionSnapshot(principal_id, session_id, tuple(self._events.get(key, ())))

    def record_success(
        self,
        principal_id: str,
        session_id: str,
        request_id: str,
        tool: str,
        effects: frozenset[str],
    ) -> SessionEvent:
        key = (principal_id, session_id)
        lock = self._lock_for(*key)
        with lock:
            events = self._events.setdefault(key, [])
            event = SessionEvent(len(events) + 1, request_id, tool, effects)
            events.append(event)
            return event

    def _lock_for(self, principal_id: str, session_id: str) -> RLock:
        key = (principal_id, session_id)
        with self._guard:
            return self._session_locks.setdefault(key, RLock())


@dataclass(frozen=True)
class SequenceRule:
    rule_id: str
    target_tools: frozenset[str]
    required_effects: frozenset[str]
    control: Control
    reason_code: str
    window_events: int | None = None

    def __post_init__(self) -> None:
        identifier = r"[a-z][a-z0-9_.:-]{0,127}"
        if not re.fullmatch(identifier, self.rule_id) or not re.fullmatch(
            identifier, self.reason_code
        ):
            raise ValueError("sequence rule identifiers are required")
        if not self.target_tools or not self.required_effects:
            raise ValueError("sequence rules require tools and prior effects")
        if any(not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", tool) for tool in self.target_tools):
            raise ValueError("sequence rule tools are invalid")
        if any(not re.fullmatch(identifier, effect) for effect in self.required_effects):
            raise ValueError("sequence rule effects are invalid")
        if self.control not in {Control.DENY, Control.REQUIRE_APPROVAL}:
            raise ValueError("sequence rules must intervene")
        if self.window_events is not None and self.window_events < 1:
            raise ValueError("window_events must be positive")
        object.__setattr__(self, "target_tools", frozenset(self.target_tools))
        object.__setattr__(self, "required_effects", frozenset(self.required_effects))

    def match(self, request: ToolRequest, snapshot: SessionSnapshot) -> tuple[str, ...] | None:
        if request.tool not in self.target_tools:
            return None
        events = snapshot.events
        if self.window_events is not None:
            events = events[-self.window_events :]
        evidence: list[str] = []
        for effect in sorted(self.required_effects):
            source = next((event for event in reversed(events) if effect in event.effects), None)
            if source is None:
                return None
            evidence.append(f"session.events.{source.request_id}.effects.{effect}")
        evidence.append("tool")
        return tuple(evidence)

    def to_mapping(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "target_tools": sorted(self.target_tools),
            "required_effects": sorted(self.required_effects),
            "control": self.control.value,
            "reason_code": self.reason_code,
            "window_events": self.window_events,
        }


class SequencePolicy:
    def __init__(self, rules: tuple[SequenceRule, ...] | list[SequenceRule]) -> None:
        self.rules = tuple(rules)
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("sequence rule identifiers must be unique")

    def evaluate(
        self,
        request: ToolRequest,
        snapshot: SessionSnapshot,
        base: PolicyDecision,
    ) -> PolicyDecision:
        if base.control == Control.DENY:
            return _with_context(base, snapshot.digest)

        matches: list[tuple[SequenceRule, tuple[str, ...]]] = []
        for rule in self.rules:
            evidence = rule.match(request, snapshot)
            if evidence is not None:
                matches.append((rule, evidence))
        if not matches:
            return _with_context(base, snapshot.digest)

        selected_control = (
            Control.DENY
            if any(rule.control == Control.DENY for rule, _ in matches)
            else Control.REQUIRE_APPROVAL
        )
        selected = [(rule, evidence) for rule, evidence in matches if rule.control == selected_control]
        reason_codes = tuple(rule.reason_code for rule, _ in selected)
        evidence_fields = tuple(
            dict.fromkeys(field for _, evidence in selected for field in evidence)
        )
        if base.control == Control.REQUIRE_APPROVAL and selected_control == base.control:
            reason_codes = tuple(dict.fromkeys((*base.reason_codes, *reason_codes)))
            evidence_fields = tuple(
                dict.fromkeys((*base.evidence_fields, *evidence_fields))
            )
        return PolicyDecision(
            control=selected_control,
            reason_codes=reason_codes,
            evidence_fields=evidence_fields,
            request_digest=base.request_digest,
            policy_version=base.policy_version,
            context_digest=snapshot.digest,
        )

    def validate_registry(self, registry: ToolRegistry) -> None:
        registered = set(registry.names())
        declared_effects = {
            effect
            for name in registry.names()
            for effect in registry.get(name).spec.emitted_effects
        }
        for rule in self.rules:
            missing_tools = rule.target_tools - registered
            missing_effects = rule.required_effects - declared_effects
            if missing_tools or missing_effects:
                raise ValueError(
                    f"sequence rule {rule.rule_id} has unknown tools or effects"
                )

    def without_rule(self, rule_id: str) -> "SequencePolicy":
        remaining = [rule for rule in self.rules if rule.rule_id != rule_id]
        if len(remaining) == len(self.rules):
            raise ValueError(f"unknown sequence rule: {rule_id}")
        return SequencePolicy(remaining)

    def to_mapping(self) -> dict[str, object]:
        return {"rules": [rule.to_mapping() for rule in self.rules]}

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_mapping()).encode("utf-8")
        ).hexdigest()


def _with_context(decision: PolicyDecision, context_digest: str) -> PolicyDecision:
    return PolicyDecision(
        control=decision.control,
        reason_codes=decision.reason_codes,
        evidence_fields=decision.evidence_fields,
        request_digest=decision.request_digest,
        policy_version=decision.policy_version,
        context_digest=context_digest,
    )
