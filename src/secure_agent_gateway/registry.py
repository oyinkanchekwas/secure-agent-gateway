from __future__ import annotations

from dataclasses import dataclass, field
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from secure_agent_gateway.models import ExecutionContext, RiskLevel
from secure_agent_gateway.rate_limit import RateLimit
from secure_agent_gateway.schema import FieldSpec


ToolHandler = Callable[[Mapping[str, Any], ExecutionContext], Any]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fields: Mapping[str, FieldSpec]
    allowed_roles: frozenset[str]
    risk: RiskLevel = RiskLevel.LOW
    approval_required: bool = False
    path_rules: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    host_rules: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    rate_limit: RateLimit = field(default_factory=lambda: RateLimit(60, 60))
    credential_alias: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", self.name) or not self.allowed_roles:
            raise ValueError("tool name and allowed roles are required")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))
        object.__setattr__(self, "allowed_roles", frozenset(self.allowed_roles))
        object.__setattr__(
            self,
            "path_rules",
            MappingProxyType({name: tuple(roots) for name, roots in self.path_rules.items()}),
        )
        object.__setattr__(
            self,
            "host_rules",
            MappingProxyType({name: tuple(hosts) for name, hosts in self.host_rules.items()}),
        )
        unknown_path_fields = set(self.path_rules) - set(self.fields)
        unknown_host_fields = set(self.host_rules) - set(self.fields)
        if unknown_path_fields or unknown_host_fields:
            raise ValueError("policy rules refer to unknown fields")
        constrained_fields = set(self.path_rules) | set(self.host_rules)
        if any(self.fields[name].kind != "string" for name in constrained_fields):
            raise ValueError("path and host rules require string fields")


@dataclass(frozen=True)
class RegisteredTool:
    spec: ToolSpec
    handler: ToolHandler


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, spec: ToolSpec, handler: ToolHandler) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = RegisteredTool(spec=spec, handler=handler)

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))
