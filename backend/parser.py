"""
Parser, Resolver & Validator

This file is responsible for taking raw text from the user (JSON or YAML) and
turning it into a structured Python Dictionary that our rules can easily understand.

It performs three main jobs:
1. Parsing: Converts raw JSON/YAML text into a Python Dict.
2. Resolving: OpenAPI specs often use `$ref` to point to other parts of the document.
   This resolver replaces those pointers with the actual data, making it easier for
   our rules to analyze without having to follow links manually.
3. Validating: Optionally checks if the resulting Dict is structurally valid
   OpenAPI according to the official schema.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


# ── $ref Resolution ─────────────

def _resolve_refs(spec: dict) -> dict:
    """
    Resolve all internal ``#/`` $ref pointers in *spec* and return a plain dict.

    Strategy
    ────────
    1. ``proxies=False`` (jsonref ≥ 1.0) resolves $refs *eagerly*, replacing
       each proxy with a deep copy of the referenced object.  This avoids the
       ``default=str`` trap where proxy objects are serialised to their string
       repr instead of to their resolved dict values.
    2. ``jsonref.dumps`` is used for the JSON round-trip so that any remaining
       JsonRef proxy objects (e.g. from an older jsonref version) are correctly
       serialised rather than falling back to ``str(proxy)``.
    3. External refs (http://, file://) are NOT followed — loader is left as
       the default but any external-ref fetch errors are caught and ignored.

    If ``jsonref`` is not installed, or resolution fails for any reason, a deep
    copy of the original spec is returned so callers always get a usable dict.
    """
    try:
        import jsonref  # pip install jsonref

        # proxies=False: resolve eagerly and return plain Python objects
        # (no proxy objects remain, so json.dumps needs no special handling)
        try:
            resolved = jsonref.replace_refs(spec, proxies=False)
        except TypeError:
            # Older jsonref that doesn't support proxies=False
            resolved = jsonref.replace_refs(spec)

        # jsonref.dumps knows how to serialise any remaining JsonRef proxies
        return json.loads(jsonref.dumps(resolved))

    except ImportError:
        # jsonref not installed — return an unresolved deep copy
        return copy.deepcopy(spec)

    except Exception as exc:
        # Circular ref, malformed pointer, or other jsonref error — degrade
        # gracefully by returning the original spec unresolved
        logger.debug("$ref resolution failed, continuing with unresolved spec: %s", exc)
        return copy.deepcopy(spec)


# ── Spec Schema Validation ─────────────

def validate_spec_doc(spec: dict) -> List[str]:
    """
    Validate *spec* against the official OpenAPI / Swagger JSON Schema.

    Returns a list of warning strings — these are *non-fatal*.  Callers
    should surface them as INFO findings rather than rejecting the request,
    because openapi-spec-validator is pedantic and many real-world public
    API specs have minor deviations that do not affect analysability.

    An empty list means the spec is valid (or validation was skipped because
    the package is unavailable).

    Supports openapi-spec-validator 0.5.x (validate_spec) and 0.7.x+ (validate).
    If the package is not installed the function returns [] — callers should
    treat this as "unknown validity" rather than "valid".
    """
    try:
        import openapi_spec_validator as osv

        # 0.7.x exposes `validate`; 0.5.x exposes `validate_spec`
        validator_fn = getattr(osv, "validate", None) or getattr(osv, "validate_spec", None)
        if validator_fn is None:
            return []  # Unknown package version — skip

        validator_fn(spec)
        return []  # No exception → valid

    except ImportError:
        return []  # Package not installed — skip validation

    except Exception as exc:
        # Try to extract multiple sub-errors (openapi-spec-validator 0.7+ can
        # expose them via .args or iteration); fall back to str(exc).
        messages: List[str] = []
        try:
            for sub in exc.args:
                msg = str(sub).strip()
                if msg and msg not in messages:
                    messages.append(msg)
        except Exception:
            pass
        return messages if messages else [str(exc)]


# ── Public Parse Entry Point ─────────────

def parse_spec(raw: str) -> Dict[str, Any]:
    """
    Parse *raw* text as JSON first, then YAML, resolve $refs, and return a
    plain dict ready for the rules engine.

    Raises ``ValueError`` with a human-readable message on any failure.

    Changes vs. original
    ────────────────────
    • After parsing, all internal ``$ref`` pointers are resolved inline so
      rules never see a bare ``{"$ref": "…"}`` object.
    """
    # ── 1. Text → dict ───────────────────────────────────────────────────────
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError:
        try:
            spec = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"Cannot parse spec — not valid JSON or YAML: {exc}") from exc

    if not isinstance(spec, dict):
        raise ValueError("Spec must be a JSON/YAML object (mapping), got a different type.")

    # ── 2. Minimal structural check ──────────────────────────────────────────
    if "openapi" not in spec and "swagger" not in spec:
        raise ValueError(
            "Not a valid OpenAPI/Swagger document: "
            "missing top-level 'openapi' (v3) or 'swagger' (v2) key."
        )

    version = spec.get("openapi") or spec.get("swagger", "")
    if str(version).startswith("1"):
        raise ValueError(f"OpenAPI/Swagger version {version} is not supported (need v2.0 or v3.x).")

    # ── 3. Resolve internal $ref pointers ────────────────────────────────────
    spec = _resolve_refs(spec)

    return spec


# ── Version Helpers ─────────────

def is_v3(spec: Dict) -> bool:
    return "openapi" in spec


def get_spec_version(spec: Dict) -> str:
    if "openapi" in spec:
        return f"OpenAPI {spec['openapi']}"
    return f"Swagger {spec.get('swagger', '?')}"


def get_api_title(spec: Dict) -> str:
    return spec.get("info", {}).get("title", "Untitled API")


def get_api_version(spec: Dict) -> str:
    return spec.get("info", {}).get("version", "unknown")


# ── Server URL Helpers ─────────────

def get_server_urls(spec: Dict) -> List[str]:
    """
    Return every server/base URL declared in the spec.

    v3  → servers[].url
    v2  → scheme://host+basePath combos  (one per scheme entry)
    """
    if is_v3(spec):
        return [s.get("url", "") for s in spec.get("servers", [])]
    else:
        host    = spec.get("host", "")
        base    = spec.get("basePath", "/")
        schemes = spec.get("schemes", [])
        if not schemes:
            return [f"{host}{base}"] if host else []
        return [f"{scheme}://{host}{base}" for scheme in schemes]


# ── Operation Iterator ─────────────

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}

def get_all_operations(spec: Dict) -> List[Dict]:
    """
    Return every operation object augmented with two private keys:
        _path   – the path string  (e.g. "/users/{id}")
        _method – upper-case HTTP verb (e.g. "GET")

    Callers can use the operation dict exactly as the OpenAPI spec defines it.
    """
    operations: List[Dict] = []
    paths = spec.get("paths", {}) or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            op = dict(operation)
            op["_path"]   = path
            op["_method"] = method.upper()
            operations.append(op)

    return operations


# ── Security Helpers ─────────────

def get_global_security(spec: Dict) -> Optional[List]:
    """Return the top-level `security` array, or None if absent."""
    return spec.get("security")


def get_security_schemes(spec: Dict) -> Dict:
    """
    Return the dict of defined security schemes.

    v3  → components.securitySchemes
    v2  → securityDefinitions
    """
    if is_v3(spec):
        return spec.get("components", {}).get("securitySchemes", {}) or {}
    return spec.get("securityDefinitions", {}) or {}


# ── Parameter Helpers ─────────────

def get_all_parameters(spec: Dict) -> List[Tuple[str, Dict]]:
    """
    Return every parameter object in the spec as (location_label, param_dict).

    location_label is a dot-path string for reporting, e.g.
        "paths./users.get.parameters[0]"

    Because $refs are now resolved by parse_spec(), callers always receive
    the fully-expanded parameter object rather than a bare {"$ref": "…"}.
    """
    results: List[Tuple[str, Dict]] = []

    paths = spec.get("paths", {}) or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # Path-level params
        for i, param in enumerate(path_item.get("parameters", [])):
            if isinstance(param, dict):
                results.append((f"paths.{path}.parameters[{i}]", param))
        # Operation-level params
        for method in HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            for i, param in enumerate(op.get("parameters", [])):
                if isinstance(param, dict):
                    results.append((f"paths.{path}.{method}.parameters[{i}]", param))

    return results
