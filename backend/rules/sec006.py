"""
SEC006 — No Rate Limiting / Throttling Response Defined
Severity: MEDIUM

WHY IT MATTERS
──────────────
APIs without documented rate limiting (HTTP 429 Too Many Requests) are
vulnerable to:

  • Brute-force credential attacks (hammering a /login endpoint).
  • Denial-of-service via resource exhaustion.
  • Enumeration of user IDs, order numbers, etc.

OWASP API4:2023 (Unrestricted Resource Consumption) explicitly names the
absence of rate limiting as a top-10 API risk.

While the OpenAPI spec itself cannot *enforce* rate limiting at runtime, the
spec SHOULD document the 429 response so that:
  • Gateway configs (AWS API Gateway, Kong, NGINX) can be validated.
  • Client SDK generators produce correct retry-after logic.
  • Security reviewers know the rate-limiting contract is intended.

WHAT WE CHECK
─────────────
We scan every operation's `responses` object for a 429 or "4XX" key.
If NO operation in the entire spec documents a 429 response, we emit one
spec-level finding (not per-endpoint, to avoid noise).
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_all_operations

RULE_ID   = "SEC006"
RULE_NAME = "No Rate Limiting Response Defined"

_RATE_LIMIT_CODES = {"429", "4XX"}


def check(spec: dict) -> List[Finding]:
    any_429_found = False

    for op in get_all_operations(spec):
        responses  = op.get("responses", {}) or {}
        codes      = {str(k) for k in responses.keys()}
        if codes.intersection(_RATE_LIMIT_CODES):
            any_429_found = True
            break

    if any_429_found:
        return []

    return [
        Finding(
            rule_id     = RULE_ID,
            rule_name   = RULE_NAME,
            severity    = Severity.MEDIUM,
            description = (
                "No operation in this spec documents an HTTP 429 (Too Many Requests) "
                "response. Without a documented rate-limiting contract, generated clients "
                "will not implement back-off logic and gateways cannot be configured "
                "from spec alone. Brute-force and resource-exhaustion attacks become "
                "much easier."
            ),
            location       = "paths (spec-wide)",
            recommendation = (
                "Add a 429 response to every endpoint that should be rate-limited, or "
                "at minimum to security-critical ones (login, password reset, token "
                "refresh). Include a Retry-After header hint. Example:\n"
                "  responses:\n"
                "    '429':\n"
                "      description: Too Many Requests — rate limit exceeded\n"
                "      headers:\n"
                "        Retry-After:\n"
                "          schema:\n"
                "            type: integer\n"
                "Also enforce the limit on your server/gateway (spec alone is not enough)."
            ),
        )
    ]
