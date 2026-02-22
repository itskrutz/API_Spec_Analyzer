"""
Pydantic data models for the API Security Analyzer.

Every Finding produced by a rule is a structured object so the frontend
always gets a consistent, typed response — no loose dicts flying around.

Findings are grouped by rule before being returned to the client:
  Finding        — one occurrence at one location (internal, rule modules only)
  LocationDetail — a location + its occurrence-specific detail (inside a group)
  FindingGroup   — all occurrences of one rule, with a shared recommendation
  AnalysisResult — the full report, scored per violated rule (not per occurrence)
"""

from __future__ import annotations

from enum import Enum
from typing import List

from pydantic import BaseModel, Field


# ── Severity levels ──────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"   # Exploitable immediately, fix now
    HIGH     = "high"       # Significant risk, fix before release
    MEDIUM   = "medium"     # Should be addressed soon
    LOW      = "low"        # Best-practice violation, low impact
    INFO     = "info"       # Informational observation only


# ── Per-finding model (used internally by rule modules) ───────────────────────

class Finding(BaseModel):
    rule_id: str        = Field(..., description="Rule identifier, e.g. SEC001")
    rule_name: str      = Field(..., description="Human-readable rule name")
    severity: Severity
    description: str    = Field(..., description="What was found and why it matters")
    location: str       = Field(..., description="JSON path or spec location of the issue")
    recommendation: str = Field(..., description="Concrete fix suggestion")


# ── Grouped finding models (API response) ────────────────────────────────────

class LocationDetail(BaseModel):
    """One specific occurrence of a rule violation: where it is + what was found."""
    location: str = Field(..., description="JSON path in the spec where the issue occurs")
    detail: str   = Field(..., description="Occurrence-specific description of the issue")


class FindingGroup(BaseModel):
    """
    All occurrences of a single security rule grouped together.

    Instead of one card per occurrence (which inflates counts on large specs),
    the frontend shows one card per rule with a list of affected locations.
    The score is deducted once per violated rule, not once per occurrence.
    """
    rule_id: str
    rule_name: str
    severity: Severity
    description: str     = Field(..., description="Generic rule-level description of the problem")
    recommendation: str  = Field(..., description="Shared fix recommendation for all occurrences")
    occurrences: List[LocationDetail]
    count: int           = Field(..., description="Total number of occurrences across the spec")
    points_deducted: int = Field(..., description="Points this rule costs toward the overall score")


# ── Summary models ────────────────────────────────────────────────────────────

class SeverityBreakdown(BaseModel):
    """Counts violated rules per severity level (not raw occurrence counts)."""
    critical: int = 0
    high: int     = 0
    medium: int   = 0
    low: int      = 0
    info: int     = 0


class AnalysisResult(BaseModel):
    score: int = Field(
        ..., ge=0, le=100,
        description=(
            "Security score 0-100. Each of the 10 rules carries a fixed point weight "
            "(total 100). The score deducts each violated rule's weight exactly once, "
            "regardless of how many times the issue appears in the spec."
        ),
    )
    grade: str = Field(..., description="Letter grade A-F derived from the score")
    spec_version: str
    api_title: str
    api_version: str
    total_operations: int = Field(
        0, description="Number of HTTP operations in the spec."
    )
    total_findings: int = Field(
        ..., description="Total individual occurrences found (sum across all groups)."
    )
    violated_rules: int = Field(
        ..., description="Number of distinct security rules that were violated (max 10)."
    )
    severity_breakdown: SeverityBreakdown
    findings: List[FindingGroup]
