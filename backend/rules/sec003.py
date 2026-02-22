"""
SEC003 — HTTP (Non-HTTPS) Transport Enforced
Severity: CRITICAL

WHY IT MATTERS
──────────────
Transmitting API traffic over plain HTTP exposes credentials, tokens, and
payload data to anyone performing a network-layer intercept (MITM).  All
production APIs must use HTTPS.  An OpenAPI spec that lists `http://` server
URLs either documents an insecure deployment or (worse) actively instructs
generated clients to send traffic unencrypted.

WHAT WE CHECK
─────────────
v3: servers[].url — flag any that begin with "http://"
v2: schemes[] — flag presence of "http" in the schemes array

One finding per insecure URL/scheme is generated so the developer knows
exactly which server block to fix.
"""

from __future__ import annotations

from typing import List

from backend.models import Finding, Severity
from backend.parser import get_server_urls, is_v3

RULE_ID   = "SEC003"
RULE_NAME = "HTTP (Non-HTTPS) Transport Allowed"


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    if is_v3(spec):
        servers = spec.get("servers", []) or []
        for i, server in enumerate(servers):
            url = server.get("url", "")
            if url.lower().startswith("http://"):
                findings.append(Finding(
                    rule_id     = RULE_ID,
                    rule_name   = RULE_NAME,
                    severity    = Severity.CRITICAL,
                    description = (
                        f"Server #{i} uses plain HTTP: `{url}`. "
                        "All traffic to this server is transmitted unencrypted, "
                        "exposing tokens, credentials, and data to network interception."
                    ),
                    location       = f"servers[{i}].url",
                    recommendation = (
                        f"Change `{url}` to its HTTPS equivalent. "
                        "Obtain a TLS certificate (free via Let's Encrypt) and configure "
                        "your server to redirect all HTTP traffic to HTTPS (HTTP 301)."
                    ),
                ))
    else:
        # Swagger 2.0 — check schemes array
        schemes = spec.get("schemes", []) or []
        if "http" in [s.lower() for s in schemes]:
            findings.append(Finding(
                rule_id     = RULE_ID,
                rule_name   = RULE_NAME,
                severity    = Severity.CRITICAL,
                description = (
                    "The spec's `schemes` array includes `http`, meaning the API "
                    "can be accessed over unencrypted HTTP. "
                    "This exposes all communication to network-layer interception."
                ),
                location       = "schemes",
                recommendation = (
                    "Remove `http` from the `schemes` array and keep only `https`. "
                    "Configure your server to reject or redirect plain HTTP connections."
                ),
            ))

    return findings
