from __future__ import annotations

from typing import Any, Mapping, Sequence

from secure_agent_gateway.models import ToolRequest


def semantic_request(request: ToolRequest) -> dict[str, Any]:
    return {
        "principal_id": request.principal_id,
        "tool": request.tool,
        "arguments": dict(request.arguments),
    }


def changed_fields(left: Any, right: Any, prefix: str = "") -> set[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        changed: set[str] = set()
        for key in set(left) | set(right):
            path = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                changed.add(path)
            else:
                changed.update(changed_fields(left[key], right[key], path))
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
                changed.update(changed_fields(left[index], right[index], path))
        return changed
    return set() if left == right else {prefix}
