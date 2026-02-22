"""
SEC008 — Missing Input Validation Constraints
Severity: MEDIUM

WHY IT MATTERS
──────────────
The spec is the contract between API consumer and provider.  If schemas
define no constraints (minLength, maxLength, minimum, maximum, pattern,
enum, etc.) then:

  • Backends often skip server-side validation because "the client handles it".
  • Oversized payloads can trigger DoS (buffer overflows, memory exhaustion).
  • Unvalidated string fields become injection vectors (SQLi, XSS, SSRF).
  • Negative numbers may reach business logic expecting positive IDs.

OWASP API8:2023 (Security Misconfiguration) and API6:2023 (Unrestricted
Access to Sensitive Business Flows) both cite missing input validation.

WHAT WE CHECK
─────────────
For every request body schema property and every parameter schema, we check
that at least ONE validation constraint is present.

Constraint sets per type:
  string  → minLength, maxLength, pattern, enum, format
  integer / number → minimum, maximum, exclusiveMinimum, exclusiveMaximum,
                     multipleOf, enum
  array   → minItems, maxItems, uniqueItems
  object  → minProperties, maxProperties, additionalProperties (false)

We limit depth to 2 levels of nested object properties to avoid excessive noise.
"""

from __future__ import annotations

from typing import Any, Dict, List

from backend.models import Finding, Severity
from backend.parser import get_all_operations, get_all_parameters, is_v3

RULE_ID   = "SEC008"
RULE_NAME = "Missing Input Validation Constraints"

_STRING_CONSTRAINTS  = {"minLength", "maxLength", "pattern", "enum", "format"}
_NUMBER_CONSTRAINTS  = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                        "multipleOf", "enum"}
_ARRAY_CONSTRAINTS   = {"minItems", "maxItems", "uniqueItems"}
_OBJECT_CONSTRAINTS  = {"minProperties", "maxProperties", "additionalProperties"}

_TYPE_TO_CONSTRAINTS = {
    "string":  _STRING_CONSTRAINTS,
    "integer": _NUMBER_CONSTRAINTS,
    "number":  _NUMBER_CONSTRAINTS,
    "array":   _ARRAY_CONSTRAINTS,
    "object":  _OBJECT_CONSTRAINTS,
}


def _has_constraints(schema: Dict) -> bool:
    if not isinstance(schema, dict):
        return True   # can't check — assume fine
    typ = schema.get("type", "string")
    required_any = _TYPE_TO_CONSTRAINTS.get(typ, _STRING_CONSTRAINTS)
    return bool(required_any.intersection(schema.keys()))


def _check_schema_properties(
    schema: Dict,
    location: str,
    findings: List[Finding],
    depth: int = 0,
) -> None:
    if depth > 2 or not isinstance(schema, dict):
        return
    props = schema.get("properties", {}) or {}
    for prop_name, prop_schema in props.items():
        if not isinstance(prop_schema, dict):
            continue
        if prop_schema.get("readOnly") or prop_schema.get("writeOnly") == False:
            pass   # still check
        if not _has_constraints(prop_schema):
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.MEDIUM,
                description = (
                    f"Schema property `{prop_name}` at `{location}` has type "
                    f"`{prop_schema.get('type', 'string')}` but defines no validation "
                    "constraints (minLength, maxLength, pattern, minimum, maximum, "
                    "enum, etc.). Unconstrained inputs invite injection and DoS attacks."
                ),
                location       = f"{location}.properties.{prop_name}",
                recommendation = (
                    f"Add appropriate constraints for `{prop_name}`. For strings: "
                    "minLength/maxLength and a pattern regex. For numbers: minimum/maximum. "
                    "For enumerations: use the `enum` keyword. Example:\n"
                    f"  {prop_name}:\n"
                    f"    type: string\n"
                    f"    minLength: 1\n"
                    f"    maxLength: 255"
                ),
            ))
        # Recurse into nested objects
        if prop_schema.get("type") == "object":
            _check_schema_properties(prop_schema, f"{location}.properties.{prop_name}",
                                     findings, depth + 1)


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    # --- Check request body schemas ---
    for op in get_all_operations(spec):
        path   = op["_path"]
        method = op["_method"]
        base   = f"paths.{path}.{method.lower()}"

        if is_v3(spec):
            rb = op.get("requestBody", {}) or {}
            content = rb.get("content", {}) or {}
            for media_type, media_obj in content.items():
                if not isinstance(media_obj, dict):
                    continue
                schema = media_obj.get("schema", {}) or {}
                loc = f"{base}.requestBody.content.{media_type}.schema"
                _check_schema_properties(schema, loc, findings)
        else:
            # Swagger 2 — body parameter
            for param in op.get("parameters", []) or []:
                if isinstance(param, dict) and param.get("in") == "body":
                    schema = param.get("schema", {}) or {}
                    loc = f"{base}.parameters[body].schema"
                    _check_schema_properties(schema, loc, findings)

    # --- Check parameter schemas (non-body) ---
    for location, param in get_all_parameters(spec):
        if param.get("in") in ("body", "formData"):
            continue
        schema = param.get("schema", param)   # v3 uses schema sub-obj; v2 inlines it
        if not _has_constraints(schema):
            name = param.get("name", "?")
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.MEDIUM,
                description = (
                    f"Parameter `{name}` (`{param.get('in', '?')}`) at "
                    f"`{location}` defines no validation constraints. "
                    "Callers can pass arbitrarily large or malformed values."
                ),
                location       = location,
                recommendation = (
                    f"Add constraints to `{name}` appropriate for its type. "
                    "For strings: minLength/maxLength. For integers: minimum/maximum. "
                    "For fixed sets of values: use `enum`."
                ),
            ))

    return findings
