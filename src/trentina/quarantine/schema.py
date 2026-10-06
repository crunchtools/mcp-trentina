"""Every L3 answer against the schema it was asked for, or MalformedResponseError.

The judge reads the content it judges, so the content can steer what it
answers. Only Gemini and OpenAI enforce a response schema; Anthropic gets it
as a hint and Ollama only ``format: json``. An answer that left out
``injection_detected`` used to count as a complete, clean verdict, and an
off-enum ``risk_level`` was L3 prose reaching the agent (#294). So the schema
is checked here, at the provider-response boundary, and anything outside it
is the provider failing: it becomes ``l3_unavailable`` downstream, never clean.

The subset of JSON Schema the Q-Agent's schemas use, and nothing more:
``type`` (object, array, string, boolean, number, integer), ``properties``,
``required``, ``items``, ``enum`` and ``maxLength``. What is returned is a
copy holding only the declared properties, with strings over ``maxLength``
cut to it: a key the schema does not name has no reader, and a long string
is a cap the schema already stated. An optional property sent as null is
dropped, and an off-enum value the caller named a fallback for becomes it.
Every other mismatch raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..errors import MalformedResponseError

if TYPE_CHECKING:
    from collections.abc import Mapping

_INDEX = re.compile(r"\[\d+\]")

_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "boolean": (bool,),
    "number": (int, float),
    "integer": (int,),
}


def conform(value: Any, schema: dict[str, Any], fallbacks: Mapping[str, Any] | None = None) -> Any:
    """*value* reduced to *schema*, or MalformedResponseError.

    *fallbacks* maps a schema path (``$.findings[].type``) to the value an
    off-enum answer there becomes, instead of raising. Only for a field
    that carries no verdict. The error names the schema path, which is
    ours. It never carries the value, which is the judge's.
    """
    return _Conform(fallbacks or {}).walk(value, schema, "$")


@dataclass(frozen=True)
class _Conform:
    fallbacks: Mapping[str, Any]

    def walk(self, value: Any, schema: dict[str, Any], where: str) -> Any:
        kind = schema.get("type")
        if kind is not None:
            expected = _TYPES[kind]
            # bool is an int to Python; to JSON it is neither number nor integer.
            if not isinstance(value, expected) or (isinstance(value, bool) and kind != "boolean"):
                raise MalformedResponseError(f"{where} is not {kind}")
        if "enum" in schema and value not in schema["enum"]:
            path = _INDEX.sub("[]", where)
            if path not in self.fallbacks:
                raise MalformedResponseError(f"{where} is outside its enum")
            return self.fallbacks[path]
        if isinstance(value, dict):
            return self._object(value, schema, where)
        if isinstance(value, list):
            items = schema.get("items")
            if items is None:
                return list(value)
            return [self.walk(v, items, f"{where}[{i}]") for i, v in enumerate(value)]
        if isinstance(value, str) and "maxLength" in schema:
            return value[: schema["maxLength"]]
        return value

    def _object(self, value: dict[str, Any], schema: dict[str, Any], where: str) -> dict[str, Any]:
        properties: dict[str, Any] = schema.get("properties", {})
        required = schema.get("required", ())
        for name in required:
            if name not in value:
                raise MalformedResponseError(f"{where}.{name} is missing")
        # An optional property sent as null is one the model chose not to
        # fill. A required one is checked like any other value, and null
        # fails its type.
        return {
            name: self.walk(value[name], sub, f"{where}.{name}")
            for name, sub in properties.items()
            if name in value and (value[name] is not None or name in required)
        }
