from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from secure_agent_gateway.auth import request_digest
from secure_agent_gateway.models import Control, PolicyDecision, Principal, RiskLevel, ToolRequest
from secure_agent_gateway.rate_limit import SlidingWindowRateLimiter
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import find_secret_arguments, validate_arguments


class PolicyEngine:
    def __init__(
        self,
        registry: ToolRegistry,
        *,
        policy_version: str,
        rate_limiter: SlidingWindowRateLimiter | None = None,
    ) -> None:
        self.registry = registry
        self.policy_version = policy_version
        self._rate_limiter = rate_limiter or SlidingWindowRateLimiter()

    def evaluate(self, principal: Principal, request: ToolRequest, *, now: int) -> PolicyDecision:
        digest = request_digest(request)
        registered = self.registry.get(request.tool)
        if registered is None:
            return self._decision(Control.DENY, ("tool.unknown",), ("tool",), digest)
        spec = registered.spec
        validation = self._validate_request(principal, request, spec, digest)
        if validation is not None:
            return validation

        if not self._rate_limiter.consume(
            principal.principal_id,
            spec.name,
            spec.rate_limit,
            now=now,
        ):
            return self._decision(Control.DENY, ("rate_limit.exceeded",), ("tool",), digest)

        validation = self._validate_targets(request, spec, digest)
        if validation is not None:
            return validation

        return self._terminal_decision(spec, digest)

    def inspect(self, principal: Principal, request: ToolRequest) -> PolicyDecision:
        """Evaluate a policy contract without consuming runtime rate state."""
        digest = request_digest(request)
        registered = self.registry.get(request.tool)
        if registered is None:
            return self._decision(Control.DENY, ("tool.unknown",), ("tool",), digest)
        spec = registered.spec
        validation = self._validate_request(principal, request, spec, digest)
        if validation is not None:
            return validation
        validation = self._validate_targets(request, spec, digest)
        if validation is not None:
            return validation
        return self._terminal_decision(spec, digest)

    def revalidate(self, principal: Principal, request: ToolRequest) -> PolicyDecision:
        digest = request_digest(request)
        registered = self.registry.get(request.tool)
        if registered is None:
            return self._decision(Control.DENY, ("tool.unknown",), ("tool",), digest)
        spec = registered.spec
        validation = self._validate_request(principal, request, spec, digest)
        if validation is not None:
            return validation
        validation = self._validate_targets(request, spec, digest)
        if validation is not None:
            return validation
        return self._decision(Control.ALLOW, ("policy.revalidated",), (), digest)

    def _validate_request(
        self,
        principal: Principal,
        request: ToolRequest,
        spec: ToolSpec,
        digest: str,
    ) -> PolicyDecision | None:
        if principal.roles.isdisjoint(spec.allowed_roles):
            return self._decision(Control.DENY, ("role.denied",), ("principal.roles",), digest)
        secret_fields = find_secret_arguments(request.arguments)
        if secret_fields:
            return self._decision(
                Control.DENY,
                ("secret.agent_supplied",),
                secret_fields,
                digest,
            )
        schema_errors = validate_arguments(spec.fields, request.arguments)
        if schema_errors:
            return self._decision(
                Control.DENY,
                tuple(error.code for error in schema_errors),
                tuple(error.field for error in schema_errors),
                digest,
            )
        return None

    def _validate_targets(
        self,
        request: ToolRequest,
        spec: ToolSpec,
        digest: str,
    ) -> PolicyDecision | None:
        boundary_failure = _check_path_rules(spec, request)
        if boundary_failure is not None:
            return self._decision(
                Control.DENY,
                (boundary_failure[0],),
                (boundary_failure[1],),
                digest,
            )
        host_failure = _check_host_rules(spec, request)
        if host_failure is not None:
            return self._decision(Control.DENY, (host_failure[0],), (host_failure[1],), digest)
        return None

    def _decision(
        self,
        control: Control,
        reason_codes: tuple[str, ...],
        evidence_fields: tuple[str, ...],
        digest: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            control=control,
            reason_codes=reason_codes,
            evidence_fields=evidence_fields,
            request_digest=digest,
            policy_version=self.policy_version,
        )

    def _terminal_decision(self, spec: ToolSpec, digest: str) -> PolicyDecision:
        if spec.approval_required or spec.risk == RiskLevel.DESTRUCTIVE:
            return self._decision(
                Control.REQUIRE_APPROVAL,
                ("approval.required",),
                ("tool",),
                digest,
            )
        return self._decision(Control.ALLOW, ("policy.allowed",), (), digest)


def _check_path_rules(spec: ToolSpec, request: ToolRequest) -> tuple[str, str] | None:
    for field_name, roots in spec.path_rules.items():
        value = request.arguments[field_name]
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            return ("path.absolute_required", f"arguments.{field_name}")
        resolved = candidate.resolve(strict=False)
        allowed = any(
            resolved.is_relative_to(Path(root).expanduser().resolve(strict=False))
            for root in roots
        )
        if not allowed:
            return ("path.outside_allowed_root", f"arguments.{field_name}")
    return None


def _check_host_rules(spec: ToolSpec, request: ToolRequest) -> tuple[str, str] | None:
    for field_name, allowed_hosts in spec.host_rules.items():
        value = request.arguments[field_name]
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError:
            return ("network.invalid_destination", f"arguments.{field_name}")
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or not parsed.hostname
            or port not in (None, 443)
        ):
            return ("network.invalid_destination", f"arguments.{field_name}")
        if parsed.hostname.lower() not in {host.lower() for host in allowed_hosts}:
            return ("network.host_denied", f"arguments.{field_name}")
    return None
