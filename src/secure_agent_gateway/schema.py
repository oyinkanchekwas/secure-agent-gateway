from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping


@dataclass(frozen=True)
class FieldSpec:
    kind: str
    required: bool = True
    redact: bool = False
    choices: tuple[Any, ...] = ()
    max_length: int | None = None
    minimum: float | None = None
    maximum: float | None = None
    item_kind: str | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        supported = {"array", "boolean", "integer", "number", "object", "string"}
        if self.kind not in supported:
            raise ValueError(f"unsupported field kind: {self.kind}")
        if self.description is not None and not self.description.strip():
            raise ValueError("field description cannot be blank")
        if self.item_kind is not None and self.item_kind not in supported:
            raise ValueError(f"unsupported item kind: {self.item_kind}")
        if self.max_length is not None and self.max_length < 0:
            raise ValueError("maximum length cannot be negative")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")


@dataclass(frozen=True)
class SchemaError:
    code: str
    field: str


_FORBIDDEN_SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
}


def validate_arguments(
    fields: Mapping[str, FieldSpec], arguments: Mapping[str, Any]
) -> tuple[SchemaError, ...]:
    errors: list[SchemaError] = []
    for field_name, field_spec in fields.items():
        if field_spec.required and field_name not in arguments:
            errors.append(SchemaError("schema.missing_required", f"arguments.{field_name}"))
            continue
        if field_name not in arguments:
            continue
        value = arguments[field_name]
        if not _matches_kind(value, field_spec.kind):
            errors.append(SchemaError("schema.wrong_type", f"arguments.{field_name}"))
            continue
        if field_spec.choices and value not in field_spec.choices:
            errors.append(SchemaError("schema.choice_not_allowed", f"arguments.{field_name}"))
        if isinstance(value, str) and field_spec.max_length is not None:
            if len(value) > field_spec.max_length:
                errors.append(SchemaError("schema.value_too_long", f"arguments.{field_name}"))
        if _is_number(value):
            if field_spec.minimum is not None and value < field_spec.minimum:
                errors.append(SchemaError("schema.value_too_small", f"arguments.{field_name}"))
            if field_spec.maximum is not None and value > field_spec.maximum:
                errors.append(SchemaError("schema.value_too_large", f"arguments.{field_name}"))
        if isinstance(value, list) and field_spec.item_kind is not None:
            if any(not _matches_kind(item, field_spec.item_kind) for item in value):
                errors.append(SchemaError("schema.invalid_array_item", f"arguments.{field_name}"))

    for unexpected in sorted(set(arguments) - set(fields)):
        errors.append(SchemaError("schema.unexpected_field", f"arguments.{unexpected}"))
    return tuple(errors)


def find_secret_arguments(
    arguments: Mapping[str, Any],
    prefix: str = "arguments",
) -> tuple[str, ...]:
    findings: list[str] = []
    for key, value in arguments.items():
        normalised = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
        current = f"{prefix}.{key}"
        if normalised in _FORBIDDEN_SECRET_KEYS:
            findings.append(current)
        if isinstance(value, Mapping):
            findings.extend(find_secret_arguments(value, current))
    return tuple(sorted(findings))


def _matches_kind(value: Any, kind: str) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return _is_number(value)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "array":
        return isinstance(value, list)
    if kind == "object":
        return isinstance(value, Mapping)
    raise ValueError(f"unsupported field kind: {kind}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)
