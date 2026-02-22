"""
SEC002 — Unprotected API Endpoints
Severity: CRITICAL

WHY IT MATTERS
──────────────
Every operation that lacks a `security` requirement (and is not covered by
a non-empty global `security` array) is completely unauthenticated by spec.
Real APIs that implement no auth on these paths are trivially exploitable —
and specs that don't document required auth mislead gateway/code-gen tooling
into generating clients that never send credentials.

Explicitly setting `security: []` on an operation is a deliberate opt-out
(e.g. public health-check endpoints) — we flag it only as LOW because the
developer made a conscious choice.  Missing security entirely is CRITICAL.

WHAT WE CHECK
─────────────
1. Read the top-level `security` array (global default).
2. For every operation:
   a. If the operation has `security: []` (empty) → LOW finding (explicit bypass).
   b. If the operation has no `security` key AND the global default is also
      absent/empty → CRITICAL finding (completely unprotected).
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_all_operations, get_global_security

RULE_ID   = "SEC002"
RULE_NAME = "Unprotected API Endpoints"


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    global_security = get_global_security(spec)
    global_protected = bool(global_security)   # non-empty list → True

    for op in get_all_operations(spec):
        path   = op["_path"]
        method = op["_method"]
        label  = f"paths.{path}.{method.lower()}"

        op_security = op.get("security")   # None if key absent, list if present

        if op_security is not None:
            # Developer explicitly set security on this operation
            if len(op_security) == 0:
                # Explicit bypass — flag as LOW (intentional but worth noting)
                findings.append(Finding(
                    rule_id     = RULE_ID,
                    rule_name   = RULE_NAME,
                    severity    = Severity.LOW,
                    description = (
                        f"{method} {path} has `security: []` which explicitly removes "
                        "all authentication requirements for this endpoint. "
                        "This is acceptable for truly public endpoints (e.g. health checks) "
                        "but should be intentional."
                    ),
                    location       = f"{label}.security",
                    recommendation = (
                        "Confirm this endpoint is intentionally public. "
                        "If it returns any sensitive data or performs state changes, "
                        "add an appropriate security requirement."
                    ),
                ))
            # else: operation has explicit non-empty security — fine
        else:
            # Operation has no security key — relies on global default
            if not global_protected:
                findings.append(Finding(
                    rule_id     = RULE_ID,
                    rule_name   = RULE_NAME,
                    severity    = Severity.CRITICAL,
                    description = (
                        f"{method} {path} has no security requirement and there is no "
                        "global security default. This endpoint is completely "
                        "unauthenticated by specification."
                    ),
                    location       = label,
                    recommendation = (
                        f"Add a `security` field to {label} referencing a defined "
                        "security scheme, e.g.:\n"
                        "  security:\n"
                        "    - BearerAuth: []\n"
                        "Or set a global `security` default at the spec root so all "
                        "operations inherit it, then use `security: []` only on "
                        "explicitly public endpoints."
                    ),
                ))

    return findings
