"""
SEC010 — Weak or Insecure Authentication Schemes
Severity: HIGH

WHY IT MATTERS
──────────────
Not all authentication mechanisms are equal.  Common weak schemes:

  • HTTP Basic Auth — Base64-encodes credentials on every request.
    If TLS is misconfigured even briefly, credentials are exposed in cleartext.
    There is no token expiry; credentials must be revoked by changing passwords.

  • API Key in query string — Logged by every proxy, CDN, and web server.
    Violates SEC005 at the scheme definition level (not just parameter level).

  • API Key in cookie without Secure/HttpOnly attributes — Not expressible in
    the spec, but an API-key-in-cookie scheme is itself a weaker pattern.

OWASP API2:2023 (Broken Authentication) specifically flags Basic Auth and
long-lived, non-expiring API keys as high-risk authentication patterns.

WHAT WE CHECK
─────────────
1. Any security scheme using HTTP Basic Authentication.
2. Any apiKey scheme where `in: query` (logged in URLs).
3. Any apiKey scheme where `in: cookie` (CSRF risk on browser clients).
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_security_schemes, is_v3

RULE_ID   = "SEC010"
RULE_NAME = "Weak or Insecure Authentication Scheme"


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []
    schemes = get_security_schemes(spec)

    base_loc = "components.securitySchemes" if is_v3(spec) else "securityDefinitions"

    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue

        scheme_type = scheme.get("type", "").lower()
        loc         = f"{base_loc}.{name}"

        # --- Check 1: HTTP Basic Auth ---
        if scheme_type == "http" and scheme.get("scheme", "").lower() == "basic":
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.HIGH,
                description = (
                    f"Security scheme `{name}` uses HTTP Basic Authentication. "
                    "Basic Auth transmits Base64-encoded credentials on every request, "
                    "offers no token expiry or revocation mechanism (short of a password "
                    "change), and is trivially decodable if TLS is bypassed even once."
                ),
                location       = loc,
                recommendation = (
                    f"Replace `{name}` with a token-based scheme:\n"
                    "  • Bearer JWT (type: http, scheme: bearer, bearerFormat: JWT) "
                    "for stateless, expirable tokens.\n"
                    "  • OAuth2 for delegated authorization with refresh tokens.\n"
                    "  • At minimum, ensure TLS is mandatory and credentials rotate "
                    "frequently if Basic Auth cannot be avoided."
                ),
            ))

        # --- Check 2: API Key in query string ---
        elif scheme_type == "apikey" and scheme.get("in", "").lower() == "query":
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.HIGH,
                description = (
                    f"Security scheme `{name}` passes the API key via query parameter "
                    f"(`{scheme.get('name', 'key')}`). "
                    "Query-string API keys appear in server logs, browser history, "
                    "Referer headers, and CDN caches — all locations an attacker could "
                    "reach without compromising the client directly."
                ),
                location       = loc,
                recommendation = (
                    f"Change `{name}` to pass the API key in a header instead:\n"
                    "  type: apiKey\n"
                    "  in: header\n"
                    f"  name: X-API-Key\n"
                    "Or migrate to Bearer JWT / OAuth2 for a more standard approach."
                ),
            ))

        # --- Check 3: API Key in cookie ---
        elif scheme_type == "apikey" and scheme.get("in", "").lower() == "cookie":
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.MEDIUM,
                description = (
                    f"Security scheme `{name}` passes the API key via cookie "
                    f"(`{scheme.get('name', 'key')}`). "
                    "Cookie-based API keys are vulnerable to Cross-Site Request Forgery "
                    "(CSRF) unless the API also implements CSRF tokens or SameSite=Strict. "
                    "Cookie attributes (Secure, HttpOnly) cannot be verified from the spec."
                ),
                location       = loc,
                recommendation = (
                    "If cookie transport is required, ensure the cookie is set with:\n"
                    "  Secure; HttpOnly; SameSite=Strict\n"
                    "and implement CSRF protection (Double-Submit Cookie or SameSite). "
                    "Consider using Authorization: Bearer in the header instead — it is "
                    "immune to CSRF by design."
                ),
            ))

    return findings
