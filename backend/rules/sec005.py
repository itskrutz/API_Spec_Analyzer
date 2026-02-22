"""
SEC005 — Sensitive Data Exposed in Query Parameters
Severity: HIGH

WHY IT MATTERS
──────────────
Query parameters are a security anti-pattern for sensitive values because:

  1. They appear in server access logs (tokens logged in plaintext).
  2. They are stored in browser history.
  3. They leak via the `Referer` header to third-party scripts.
  4. They are trivially visible to anyone observing the URL.

OWASP API3:2023 (Broken Object Property Level Authorization) and general
best practice mandate that secrets (tokens, passwords, API keys) travel only
in the Authorization header or in an encrypted request body — never in the URL.

WHAT WE CHECK
─────────────
Every parameter with `in: query` whose name contains a sensitive keyword.
We use a broad keyword list and case-insensitive substring matching to catch
common naming patterns like `api_key`, `apiKey`, `access_token`, etc.
"""

from __future__ import annotations

import re
from typing import List

from backend.models import Finding, Severity
from backend.parser import get_all_parameters

RULE_ID   = "SEC005"
RULE_NAME = "Sensitive Data in Query Parameters"

# Broad keyword list — catches substrings, case-insensitive
_SENSITIVE_KEYWORDS = re.compile(
    r"(password|passwd|pwd|secret|token|api[-_]?key|apikey|"
    r"auth(?:entication|orization)?|credential|session|ssn|"
    r"credit[-_]?card|card[-_]?num|cvv|private[-_]?key|"
    r"access[-_]?key|client[-_]?secret)",
    re.IGNORECASE,
)


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    for location, param in get_all_parameters(spec):
        if param.get("in") != "query":
            continue

        name = param.get("name", "")
        if _SENSITIVE_KEYWORDS.search(name):
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.HIGH,
                description = (
                    f"Query parameter `{name}` appears to carry sensitive data "
                    "(matched keyword pattern). Query parameters are stored in "
                    "server logs, browser history, and the Referer header — all "
                    "of which are reachable by attackers and third-party analytics."
                ),
                location       = f"{location} (in: query, name: {name})",
                recommendation = (
                    f"Move `{name}` out of the query string:\n"
                    "  • Credentials/tokens → Authorization header "
                    "(`Authorization: Bearer <token>`).\n"
                    "  • One-time secrets → POST request body (application/json).\n"
                    "  • Session identifiers → HttpOnly, Secure cookie.\n"
                    "Never log, cache, or forward Authorization headers to third parties."
                ),
            ))

    return findings
