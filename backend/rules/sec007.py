"""
SEC007 — OAuth2 Flows with Missing or Empty Scopes
Severity: MEDIUM

WHY IT MATTERS
──────────────
OAuth2 scopes implement the principle of least privilege: a token should
grant access only to the specific resources the user consented to.
When scopes are absent or never required on operations:

  • Any valid token grants access to everything — a compromised token is
    as dangerous as admin credentials.
  • The authorization server has no fine-grained policy to enforce.
  • Consent screens cannot show users what they're actually authorising.

OWASP API1:2023 (Broken Object Level Authorization) and OAuth 2.0 Security
Best Current Practice (RFC 9700) both require scope minimisation.

WHAT WE CHECK
─────────────
1. Every OAuth2 security scheme must have at least one scope defined
   across its flows.
2. Every operation that references an OAuth2 scheme must specify at least
   one required scope in its security requirement (not just an empty list `[]`).
"""

from __future__ import annotations

from typing import Dict, List, Set

from backend.models import Finding, Severity
from backend.parser import get_all_operations, get_security_schemes, is_v3

RULE_ID   = "SEC007"
RULE_NAME = "OAuth2 Flows with Missing or Empty Scopes"


def _oauth2_scheme_names(schemes: Dict) -> Set[str]:
    """Return the names of all OAuth2-type security schemes."""
    names: Set[str] = set()
    for name, scheme in schemes.items():
        if isinstance(scheme, dict):
            t = scheme.get("type", "").lower()
            if t in ("oauth2",):
                names.add(name)
    return names


def _scheme_has_scopes(scheme: Dict) -> bool:
    """Check if an OAuth2 scheme has at least one scope defined."""
    # OpenAPI 3 — flows object
    flows = scheme.get("flows", {}) or {}
    for flow in flows.values():
        if isinstance(flow, dict) and flow.get("scopes"):
            return True
    # Swagger 2 — scopes at top level
    if scheme.get("scopes"):
        return True
    return False


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    schemes = get_security_schemes(spec)
    oauth2_names = _oauth2_scheme_names(schemes)

    if not oauth2_names:
        return []   # No OAuth2 in use — rule not applicable

    # 1. Check that each OAuth2 scheme has at least one scope defined
    for name in oauth2_names:
        scheme = schemes[name]
        if not _scheme_has_scopes(scheme):
            loc = (
                f"components.securitySchemes.{name}"
                if is_v3(spec) else
                f"securityDefinitions.{name}"
            )
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.MEDIUM,
                description = (
                    f"OAuth2 scheme `{name}` defines no scopes. Without scopes the "
                    "authorization server cannot enforce least-privilege access, and "
                    "every issued token implicitly grants full access."
                ),
                location       = loc,
                recommendation = (
                    f"Add meaningful scopes to `{name}` that reflect what each token "
                    "should be allowed to do, e.g.:\n"
                    "  scopes:\n"
                    "    read:users: Read user profiles\n"
                    "    write:orders: Create and update orders"
                ),
            ))

    # 2. Check that operations referencing OAuth2 require at least one scope
    for op in get_all_operations(spec):
        path   = op["_path"]
        method = op["_method"]
        sec    = op.get("security", []) or []
        for req in sec:
            if not isinstance(req, dict):
                continue
            for scheme_name, required_scopes in req.items():
                if scheme_name not in oauth2_names:
                    continue
                if not required_scopes:   # empty list []
                    findings.append(Finding(
                        rule_id     = RULE_ID,
                        rule_name   = RULE_NAME,
                        severity    = Severity.MEDIUM,
                        description = (
                            f"{method} {path} references OAuth2 scheme `{scheme_name}` "
                            "but requires no scopes (`[]`). This means any valid token — "
                            "regardless of what it was issued for — can call this endpoint."
                        ),
                        location       = f"paths.{path}.{method.lower()}.security",
                        recommendation = (
                            f"Specify the minimum scopes needed for this operation, e.g.:\n"
                            f"  security:\n"
                            f"    - {scheme_name}:\n"
                            f"        - read:resource"
                        ),
                    ))

    return findings
