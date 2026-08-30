from __future__ import annotations

from typing import Mapping, Protocol


class SecretProvider(Protocol):
    def get(self, alias: str) -> str:
        ...


class MappingSecretProvider:
    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def get(self, alias: str) -> str:
        try:
            return self._values[alias]
        except KeyError as exc:
            raise KeyError("configured credential is unavailable") from exc
