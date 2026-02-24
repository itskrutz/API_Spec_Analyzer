"""
Parser, Resolver & Validator
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

    try:
        import jsonref  #
        try:
            resolved = jsonref.replace_refs(spec, proxies=False)
        except TypeError:
            resolved = jsonref.replace_refs(spec)

        return json.loads(jsonref.dumps(resolved))

    except ImportError:
        return copy.deepcopy(spec)

    except Exception as exc:
        logger.debug("$ref resolution failed, continuing with unresolved spec: %s", exc)
        return copy.deepcopy(spec)


# ── Spec Schema Validation ─────────────

def validate_spec_doc(spec: dict) -> List[str]:
    """
    An empty list means the spec is valid (or validation was skipped because
    the package is unavailable).
    """
    try:
        import openapi_spec_validator as osv

        validator_fn = getattr(osv, "validate", None) or getattr(osv, "validate_spec", None)
        if validator_fn is None:
            return []  

        validator_fn(spec)
        return []  

    except ImportError:
        return []

    except Exception as exc:
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
    return spec.get("security")


def get_security_schemes(spec: Dict) -> Dict:
    if is_v3(spec):
        return spec.get("components", {}).get("securitySchemes", {}) or {}
    return spec.get("securityDefinitions", {}) or {}


# ── Parameter Helpers ─────────────

def get_all_parameters(spec: Dict) -> List[Tuple[str, Dict]]:
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
