from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

from secure_agent_gateway.approvals import ApprovalReceipt
from secure_agent_gateway.auth import sign_request
from secure_agent_gateway.gateway import SecureAgentGateway
from secure_agent_gateway.models import GatewayResult, ToolRequest
from secure_agent_gateway.registry import ToolRegistry, ToolSpec
from secure_agent_gateway.schema import FieldSpec


class MCPProtocolError(ValueError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class MCPToolCallResult:
    protocol_result: Mapping[str, Any]
    gateway_result: GatewayResult

    def to_mapping(self) -> dict[str, Any]:
        return dict(self.protocol_result)


class MCPGatewayAdapter:
    def __init__(
        self,
        *,
        gateway: SecureAgentGateway,
        registry: ToolRegistry,
        key_id: str,
        signing_secret: bytes,
        principal_id: str,
        session_handle: str,
        allowed_tools: frozenset[str],
        clock: Callable[[], int] | None = None,
        identifier_factory: Callable[[], str] | None = None,
        list_ttl_ms: int = 30_000,
    ) -> None:
        if not key_id or not principal_id or not session_handle:
            raise ValueError("MCP caller identity and session handle are required")
        if not isinstance(signing_secret, bytes) or len(signing_secret) < 16:
            raise ValueError("MCP signing secret must contain at least 16 bytes")
        if list_ttl_ms < 0:
            raise ValueError("MCP list TTL cannot be negative")
        unknown = set(allowed_tools) - set(registry.names())
        if unknown:
            raise ValueError(f"allowed MCP tools are not registered: {sorted(unknown)}")
        self._gateway = gateway
        self._registry = registry
        self._key_id = key_id
        self._secret = signing_secret
        self._principal_id = principal_id
        self._session_handle = session_handle
        self._allowed_tools = frozenset(allowed_tools)
        self._clock = clock or (lambda: int(time.time()))
        self._identifier_factory = identifier_factory or (lambda: str(uuid4()))
        self._list_ttl_ms = list_ttl_ms

    def list_tools(self) -> dict[str, Any]:
        tools = [
            _tool_mapping(self._registry.get(name).spec)
            for name in sorted(self._allowed_tools)
            if self._registry.get(name) is not None
        ]
        return {
            "resultType": "complete",
            "tools": tools,
            "ttlMs": self._list_ttl_ms,
            "cacheScope": "private",
        }

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        now: int | None = None,
    ) -> MCPToolCallResult:
        if name not in self._allowed_tools:
            raise MCPProtocolError(-32602, f"Unknown tool: {name}")
        if arguments is not None and not isinstance(arguments, Mapping):
            raise MCPProtocolError(-32602, "Tool arguments must be an object")
        observed_now = self._clock() if now is None else now
        request = ToolRequest(
            request_id=self._identifier_factory(),
            principal_id=self._principal_id,
            tool=name,
            arguments={} if arguments is None else dict(arguments),
            issued_at=observed_now,
            nonce=self._identifier_factory(),
            session_id=self._session_handle,
        )
        result = self._gateway.submit(
            sign_request(request, self._key_id, self._secret),
            now=observed_now,
        )
        return MCPToolCallResult(_protocol_result(result), result)

    def resume_tool(
        self,
        request_id: str,
        receipt: ApprovalReceipt,
        *,
        now: int | None = None,
    ) -> MCPToolCallResult:
        observed_now = self._clock() if now is None else now
        result = self._gateway.resume(request_id, receipt, now=observed_now)
        return MCPToolCallResult(_protocol_result(result), result)


def _tool_mapping(spec: ToolSpec) -> dict[str, Any]:
    properties = {
        name: _field_schema(field_spec)
        for name, field_spec in sorted(spec.fields.items())
    }
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    required = sorted(name for name, field_spec in spec.fields.items() if field_spec.required)
    if required:
        schema["required"] = required
    tool: dict[str, Any] = {"name": spec.name, "inputSchema": schema}
    if spec.title is not None:
        tool["title"] = spec.title
    if spec.description is not None:
        tool["description"] = spec.description
    return tool


def _field_schema(spec: FieldSpec) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": spec.kind}
    if spec.description is not None:
        schema["description"] = spec.description
    if spec.choices:
        schema["enum"] = list(spec.choices)
    if spec.max_length is not None and spec.kind == "string":
        schema["maxLength"] = spec.max_length
    if spec.minimum is not None:
        schema["minimum"] = spec.minimum
    if spec.maximum is not None:
        schema["maximum"] = spec.maximum
    if spec.kind == "array" and spec.item_kind is not None:
        schema["items"] = {"type": spec.item_kind}
    return schema


def _protocol_result(result: GatewayResult) -> dict[str, Any]:
    if result.status == "succeeded":
        try:
            text = json.dumps(
                result.output,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return {
                "resultType": "complete",
                "content": [
                    {
                        "type": "text",
                        "text": "The tool completed, but its output was not valid JSON.",
                    }
                ],
                "isError": True,
            }
        payload: dict[str, Any] = {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
        if _is_json_value(result.output):
            payload["structuredContent"] = result.output
        return payload
    if result.status == "pending_approval":
        message = "Tool execution requires approval from the host application."
    elif result.status == "denied":
        code = result.error_code or "gateway.denied"
        message = f"Tool execution was denied by gateway policy: {code}."
    elif result.status == "execution_failed":
        code = result.error_code or "adapter.failure"
        message = f"Tool execution failed in the registered adapter: {code}."
    elif result.status == "execution_uncertain":
        code = result.error_code or "state.commit_failed"
        message = f"Tool execution outcome is uncertain: {code}."
    else:
        message = f"Tool execution did not complete: {result.status}."
    return {
        "resultType": "complete",
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def _is_json_value(value: Any) -> bool:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return True
