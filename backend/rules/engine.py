
from __future__ import annotations

import logging
from collections import defaultdict
from typing import List

logger = logging.getLogger(__name__)

from backend.models import (
    AnalysisResult, Finding, FindingGroup, LocationDetail,
    Severity, SeverityBreakdown,
)
from backend.parser import get_all_operations, get_api_title, get_api_version, get_spec_version

# ── Rule Imports ─────────────────────────────────────────────────────────────

from backend.rules import (
    sec001, sec002, sec003, sec004, sec005,
    sec006, sec007, sec008, sec009, sec010,
)

RULES = [
    sec001,   # Missing security scheme definitions
    sec002,   # Unprotected endpoints
    sec003,   # HTTP (non-HTTPS) servers
    sec004,   # Missing auth error responses
    sec005,   # Sensitive data in query params
    sec006,   # No rate limiting response
    sec007,   # OAuth2 missing scopes
    sec008,   # Missing input validation constraints
    sec009,   # Unconstrained server URL variables
    sec010,   # Weak/insecure auth schemes
]

# ── Rule Weights ──────────────────────────────────────────────────────────────
# Fixed points deducted per rule if it fires — exactly once, total sums to 100.
# CRITICAL=18 pts, HIGH=12 pts, MEDIUM=6 pts, LOW=4 pts.

RULE_WEIGHTS: dict[str, int] = {
    "SEC001": 12,   
    "SEC002": 18,   
    "SEC003": 18,   
    "SEC004":  6,  
    "SEC005": 12,  
    "SEC006":  6,   
    "SEC007":  6,   
    "SEC008":  6,   
    "SEC009":  4,   
    "SEC010": 12,   
}

RULE_DESCRIPTIONS: dict[str, str] = {
    "SEC001": (
        "No authentication or security schemes are defined anywhere in this specification. "
        "Without scheme definitions, the spec cannot describe how clients should authenticate."
    ),
    "SEC002": (
        "One or more API endpoints have no security requirement and there is no global "
        "security default. These endpoints are completely unauthenticated by specification."
    ),
    "SEC003": (
        "The specification allows plain HTTP (non-HTTPS) transport. "
        "All API traffic should be encrypted in transit to prevent eavesdropping."
    ),
    "SEC004": (
        "Some operations are missing 401 or 403 response definitions. "
        "Undocumented auth errors mislead client code and API gateways about expected behaviour."
    ),
    "SEC005": (
        "Potentially sensitive data (passwords, tokens, keys, secrets) appears in query "
        "parameters, which are logged by servers, proxies, and stored in browser history."
    ),
    "SEC006": (
        "No 429 (Too Many Requests) response is documented on some endpoints. "
        "Without this signal, clients and gateways have no throttling guidance."
    ),
    "SEC007": (
        "One or more OAuth2 flows define empty or missing scopes, removing the ability "
        "to enforce least-privilege access control on those flows."
    ),
    "SEC008": (
        "Some request body parameters lack validation constraints (minLength, maxLength, "
        "pattern, minimum, maximum), leaving the API open to oversized or malformed input."
    ),
    "SEC009": (
        "Server URL template variables have no defined enum or default values, allowing "
        "clients to substitute arbitrary values including internal hostnames or paths."
    ),
    "SEC010": (
        "One or more authentication schemes are considered weak or insecure "
        "(e.g. HTTP Basic over plain transport, or non-standard custom schemes)."
    ),
}

_SEV_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


# ── Core Engine Execution ─────────────────────────────────────────────────────

def run_all_rules(spec: dict) -> List[Finding]:
    all_findings: List[Finding] = []

    for rule in RULES:
        try:
            all_findings.extend(rule.check(spec))
        except Exception as exc:
            rule_id = getattr(rule, "RULE_ID", "???")
            logger.warning(
                "Rule %s raised an exception during execution: %s: %s",
                rule_id, type(exc).__name__, exc, exc_info=True,
            )
            all_findings.append(Finding(
                rule_id        = rule_id,
                rule_name      = getattr(rule, "RULE_NAME", "Unknown Rule"),
                severity       = Severity.INFO,
                description    = f"Rule execution failed: {exc}",
                location       = "N/A",
                recommendation = "Check the spec structure around the reported area and retry.",
            ))

    return all_findings


# ── Grouping ──────────────────────────────────────────────────────────────────

def _max_severity(severities: List[Severity]) -> Severity:
    """Return the highest severity from a list."""
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if sev in severities:
            return sev
    return Severity.INFO


def group_findings(findings: List[Finding]) -> List[FindingGroup]:
    """
    Group individual findings by rule_id into FindingGroup objects.

    Each group:
    - Uses the highest severity across all occurrences.
    - Collects all locations as a list of LocationDetail objects.
    - Carries a fixed RULE_WEIGHTS deduction (not per-occurrence).
    - Uses a generic RULE_DESCRIPTIONS description for the group header.
    - Shares one recommendation (from the highest-severity occurrence).
    """
    grouped: dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.rule_id].append(f)

    result: List[FindingGroup] = []
    for rule_id, rule_findings in grouped.items():
        # Sort so highest severity comes first (its recommendation becomes the group rec)
        rule_findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
        first = rule_findings[0]

        result.append(FindingGroup(
            rule_id         = rule_id,
            rule_name       = first.rule_name,
            severity        = _max_severity([f.severity for f in rule_findings]),
            description     = RULE_DESCRIPTIONS.get(rule_id, first.description),
            recommendation  = first.recommendation,
            occurrences     = [
                LocationDetail(location=f.location, detail=f.description)
                for f in rule_findings
            ],
            count           = len(rule_findings),
            points_deducted = RULE_WEIGHTS.get(rule_id, 0),
        ))

    # Sort groups: critical first, then high, medium, low, info
    result.sort(key=lambda g: _SEV_ORDER.get(g.severity, 99))
    return result


# ── Scoring ───────────────────────────────────────────────────────────────────

def compute_score(groups: List[FindingGroup]) -> int:
    """
    Compute the security score from violated rule groups.

    Starts at 100 and subtracts each violated rule's fixed weight exactly once.
    Floored at 0.

    Example
    ───────
    SEC002 (18 pts) + SEC003 (18 pts) both fire:
      score = 100 - 18 - 18 = 64  (same whether 1 or 50 endpoints are affected)
    """
    score = 100
    for g in groups:
        score -= g.points_deducted
    return max(0, score)


def compute_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def build_severity_breakdown(groups: List[FindingGroup]) -> SeverityBreakdown:
    """Count violated rules per severity level (one per rule, not per occurrence)."""
    bd = SeverityBreakdown()
    for g in groups:
        setattr(bd, g.severity.value, getattr(bd, g.severity.value) + 1)
    return bd


# ── Main Analysis Entry ───────────────────────────────────────────────────────

def analyze(spec: dict) -> AnalysisResult:

    findings  = run_all_rules(spec)
    groups    = group_findings(findings)
    score     = compute_score(groups)
    grade     = compute_grade(score)
    breakdown = build_severity_breakdown(groups)
    total_ops = len(get_all_operations(spec))

    return AnalysisResult(
        score              = score,
        grade              = grade,
        spec_version       = get_spec_version(spec),
        api_title          = get_api_title(spec),
        api_version        = get_api_version(spec),
        total_operations   = total_ops,
        total_findings     = len(findings),
        violated_rules     = len(groups),
        severity_breakdown = breakdown,
        findings           = groups,
    )
