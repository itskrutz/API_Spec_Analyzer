"""
SEC009 — Unconstrained Server URL Variables (Wildcard Servers)
Severity: LOW

WHY IT MATTERS
──────────────
OpenAPI 3 supports server URL templating, e.g.:
    https://{tenant}.api.example.com/v1

If the `{tenant}` variable has no `enum` list of allowed values, two risks
arise:

  1. Code generators may produce clients that accept arbitrary tenant names,
     opening Server-Side Request Forgery (SSRF) if the variable is user-
     controlled at runtime.
  2. Security tooling (fuzz runners, WAF rule generators) cannot enumerate
     valid base URLs, making automated security testing harder.

RFC 3986 and OWASP SSRF guidance both recommend allowlisting URL components
that could be influenced by external input.

WHAT WE CHECK
─────────────
OpenAPI 3 only (Swagger 2 doesn't have server URL variables).
For every server with a `{variable}` in its URL, check that the corresponding
entry in `server.variables` defines an `enum` list with at least one value.
"""

from __future__ import annotations

import re
from typing import List

from backend.models import Finding, Severity
from backend.parser import is_v3

RULE_ID   = "SEC009"
RULE_NAME = "Unconstrained Server URL Variables"

_VARIABLE_RE = re.compile(r"\{(\w+)\}")


def check(spec: dict) -> List[Finding]:
    findings: List[Finding] = []

    if not is_v3(spec):
        return []   # Swagger 2 does not support server URL variables

    servers = spec.get("servers", []) or []
    for i, server in enumerate(servers):
        if not isinstance(server, dict):
            continue
        url = server.get("url", "")
        variables = server.get("variables", {}) or {}

        for var_name in _VARIABLE_RE.findall(url):
            var_def = variables.get(var_name, {}) or {}
            enum    = var_def.get("enum", [])

            if not enum:
                findings.append(Finding(
                    rule_id     = RULE_ID,
                    rule_name   = RULE_NAME,
                    severity    = Severity.LOW,
                    description = (
                        f"Server #{i} URL `{url}` contains variable `{{{var_name}}}` "
                        "with no `enum` allowlist. Without an allowlist, any value can "
                        "be substituted — tools and generated clients may accept "
                        "arbitrary hostnames, creating SSRF risk if the variable is "
                        "ever influenced by user input."
                    ),
                    location       = f"servers[{i}].variables.{var_name}",
                    recommendation = (
                        f"Add an `enum` list to `servers[{i}].variables.{var_name}` "
                        "containing every valid value. Example:\n"
                        f"  variables:\n"
                        f"    {var_name}:\n"
                        f"      default: prod\n"
                        f"      enum: [prod, staging]\n"
                        f"      description: Deployment environment"
                    ),
                ))

    return findings
