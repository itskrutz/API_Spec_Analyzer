"""
SEC001 — Missing Security Scheme Definitions
Severity: HIGH

WHY IT MATTERS
──────────────
If no security schemes are declared (no `securitySchemes` in OpenAPI 3 or
no `securityDefinitions` in Swagger 2), the spec has zero authentication
machinery defined.  Consumers of the spec (code generators, gateway configs,
auditors) have no way to know how to protect endpoints.

This is analogous to shipping a building blueprint with no lock types
specified — the doors are there, but nobody knows which key to use.

WHAT WE CHECK
─────────────
v3: components.securitySchemes must exist and be non-empty.
v2: securityDefinitions must exist and be non-empty.
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_security_schemes, is_v3

RULE_ID   = "SEC001"
RULE_NAME = "Missing Security Scheme Definitions"


def check(spec: dict) -> List[Finding]:
    schemes = get_security_schemes(spec)

    if schemes:
        return []          # At least one scheme defined — pass

    location = "components.securitySchemes" if is_v3(spec) else "securityDefinitions"

    return [
        Finding(
            rule_id        = RULE_ID,
            rule_name      = RULE_NAME,
            severity       = Severity.HIGH,
            description    = (
                "No authentication/security schemes are defined in this specification. "
                "Without scheme definitions the spec cannot describe how clients should "
                "authenticate, making all endpoints effectively undocumented from a "
                "security standpoint."
            ),
            location       = location,
            recommendation = (
                "Add at least one security scheme under "
                f"`{location}`. Common choices: "
                "Bearer JWT (`type: http, scheme: bearer`), "
                "OAuth2 (`type: oauth2`), or API Key (`type: apiKey`). "
                "Then reference it in the global `security` array or per-operation."
            ),
        )
    ]
