"""
SEC004 — Missing Authentication Error Responses (401 / 403)
Severity: MEDIUM

WHY IT MATTERS
──────────────
Endpoints that require authentication should document what happens when
authentication fails (401 Unauthorized) or the caller lacks permission (403
Forbidden).  Without these response codes:

  • API gateways and middleware cannot auto-configure auth error handling.
  • Generated client SDKs don't know when to refresh tokens or handle
    permission errors gracefully.
  • Security reviewers cannot confirm the API enforces access control.

OWASP API Security Top 10 — API2:2023 (Broken Authentication) specifically
calls out the need to reject and communicate auth failures correctly.

WHAT WE CHECK
─────────────
For every operation that carries a non-empty `security` requirement, we check
whether the `responses` object defines BOTH a 4xx auth failure code.
We accept either "401" or "403" (or their numeric equivalents).
If neither is present we flag a MEDIUM finding.
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_all_operations, get_global_security

RULE_ID   = "SEC004"
RULE_NAME = "Missing Authentication Error Responses"

_AUTH_ERROR_CODES = {"401", "403", "4XX"}   # 4XX is a wildcard accepted by OpenAPI 3


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    global_security = get_global_security(spec)
    global_protected = bool(global_security)

    for op in get_all_operations(spec):
        path   = op["_path"]
        method = op["_method"]

        # Determine if this operation requires auth
        op_security = op.get("security")
        if op_security is not None:
            protected = bool(op_security)   # explicit; empty list = public
        else:
            protected = global_protected

        if not protected:
            continue   # public endpoint — no auth error responses needed

        # Check responses
        responses = op.get("responses", {}) or {}
        defined_codes = {str(k) for k in responses.keys()}

        if not defined_codes.intersection(_AUTH_ERROR_CODES):
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.MEDIUM,
                description = (
                    f"{method} {path} requires authentication but defines no "
                    "401 (Unauthorized) or 403 (Forbidden) response. "
                    "Consumers of this spec have no way to know how auth failures "
                    "are communicated."
                ),
                location       = f"paths.{path}.{method.lower()}.responses",
                recommendation = (
                    "Add a 401 response for missing/invalid credentials and a "
                    "403 response for insufficient permissions. Example:\n"
                    "  responses:\n"
                    "    '401':\n"
                    "      description: Unauthorized — missing or invalid credentials\n"
                    "    '403':\n"
                    "      description: Forbidden — caller lacks required permissions"
                ),
            ))

    return findings
