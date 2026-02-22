"""
API Security Analyzer — FastAPI backend entry-point.

This project is an API Security Analyzer that scans OpenAPI/Swagger specifications
for common security misconfigurations.

It provides endpoints to submit specs via direct text paste, file upload, or URL fallback.
All methods funnel into a shared analysis pipeline.

During the process, it parses the spec, validates its structure, runs defined security
rules, and optionally enriches the findings using an AI model (OpenAI GPT-4o mini).
Finally, it can return results as JSON, CSV, or a PDF report format.
"""

from __future__ import annotations

import logging
import os

# httpx is used here as an asynchronous HTTP client to fetch OpenAPI 
# spec files directly from public URLs provided by the user.
import httpx

# FastAPI is the core web framework we use. It's incredibly fast, modern, and 
# natively supports asynchronous Python, which works great with I/O tasks like API calls.
# We also import File, UploadFile for handling file uploads, 
# Query for URL parameter validation, and HTTPException for error responses.
from fastapi import FastAPI, File, HTTPException, Query, UploadFile

# CORSMiddleware is used to handle Cross-Origin Resource Sharing. 
# This tells the browser that our frontend (running perhaps on a different port) 
# is allowed to communicate with this backend without being blocked.
from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import FileResponse, Response

# StaticFiles allows us to serve static content such as the HTML, CSS,
# and JS parts of our frontend straight from this backend server.
from fastapi.staticfiles import StaticFiles

# Pydantic is a data validation library used by FastAPI. We define BaseModel
# classes to strictly control and validate the data format coming from clients.
from pydantic import BaseModel

from backend.ai_enricher import enrich_findings
from backend.exporter import export_result
from backend.models import AnalysisResult, FindingGroup, LocationDetail, Severity
from backend.parser import parse_spec, validate_spec_doc
from backend.rules.engine import analyze

logger = logging.getLogger(__name__)

# ── App setup ─────────────

# We initialize the FastAPI application. This 'app' object acts as the central router 
# and registry for all incoming HTTP requests, middleware, and endpoint logic.
app = FastAPI(
    title="API Security Analyzer",
    description="Scan OpenAPI / Swagger specs for common security misconfigurations.",
    version="2.0.0",
)

# Enabling CORS below. During development, it's very useful to allow all sources ["*"] 
# but in a production environment, you should strictly limit this to your frontend domains.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request Body Models ─────────────

# These Request Body Models use Pydantic to ensure that any data sent to our API 
# endpoints exactly matches our expected structure. If the data is invalid, 
# FastAPI automatically returns an error to the user before reaching our code.

class PasteRequest(BaseModel):
    content: str


class UrlRequest(BaseModel):
    url: str


# ── Shared Pipeline ─────────────

# The Shared Pipeline is the core logic function shared across all endpoints.
# By centralizing this step, we avoid repeating the logic for parsing, validating, 
# scoring, and enriching across the different input methods (Paste, Upload, URL).

def _validation_warnings_group(warnings: list[str]) -> FindingGroup:
    """
    Wrap openapi-spec-validator warnings into an INFO-level FindingGroup.

    These are non-fatal — many public API specs have minor deviations from the
    OpenAPI standard that do not prevent analysis.  Surfacing them as INFO
    findings lets the user see them without rejecting the request.
    """
    return FindingGroup(
        rule_id         = "SPEC-VAL",
        rule_name       = "OpenAPI Spec Validation Warnings",
        severity        = Severity.INFO,
        description     = (
            "The spec has structural issues flagged by openapi-spec-validator. "
            "These do not affect the security score — analysis continues normally. "
            "Minor deviations from the OpenAPI standard are common in real-world specs."
        ),
        recommendation  = (
            "Review the warnings listed below and cross-check your spec against the "
            "OpenAPI specification. Tools such as swagger-editor.io can highlight and "
            "help fix structural problems interactively."
        ),
        occurrences     = [
            LocationDetail(location="spec root", detail=w) for w in warnings
        ],
        count           = len(warnings),
        points_deducted = 0,  # INFO findings never deduct score points
    )


async def _run_pipeline(raw_text: str, ai: bool = False) -> AnalysisResult:
    """
    Core analysis logic shared by all API entry points.

    Fatal failures (not valid JSON/YAML, missing openapi/swagger key) raise
    HTTPException 422.  Spec validation warnings from openapi-spec-validator
    are treated as INFO findings — many real-world public API specs have minor
    structural deviations that do not affect analysability.
    """
    # ── 1. Parse ──────────────────────────────────────────────────────────────
    # Only hard-fail on truly unrecoverable parse errors.
    try:
        spec = parse_spec(raw_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # ── 2. Validate (non-fatal) ───────────────────────────────────────────────
    # openapi-spec-validator is pedantic; surfacing warnings as INFO findings
    # lets the user see them without rejecting perfectly analysable specs.
    validation_warnings = validate_spec_doc(spec)
    if validation_warnings:
        logger.info(
            "Spec has %d openapi-spec-validator warning(s) — continuing as INFO findings",
            len(validation_warnings),
        )

    # ── 3. Security analysis ──────────────────────────────────────────────────
    result = analyze(spec)

    # ── 4. Inject spec-validation warnings as INFO findings (if any) ──────────
    if validation_warnings:
        warn_group = _validation_warnings_group(validation_warnings)
        result = result.model_copy(update={
            "findings":       result.findings + [warn_group],
            "total_findings": result.total_findings + len(validation_warnings),
        })

    # ── 5. AI enrichment (opt-in) ─────────────────────────────────────────────
    if ai:
        if not os.environ.get("OPENAI_API_KEY"):
            raise HTTPException(
                status_code=503,
                detail=(
                    "AI enrichment requested but OPENAI_API_KEY is not configured. "
                    "Set the environment variable and restart the server."
                ),
            )
        try:
            enriched_findings = await enrich_findings(spec, result.findings)
            result = result.model_copy(update={"findings": enriched_findings})
        except Exception as exc:
            # Log so operators can see what went wrong (wrong key, network error, etc.)
            # but don't surface it to the user — fall back to static recommendations.
            logger.warning(
                "AI enrichment failed, using static recommendations: %s: %s",
                type(exc).__name__, exc,
            )

    return result


# ── Endpoints ─────────────

# The API endpoints define the specific URLs that users can interact with. 
# Each endpoint dictates how it accepts input (e.g. text body, file upload, or URL), 
# routes it to the shared pipeline, and formats the output.

@app.post(
    "/analyze/paste",
    summary="Analyze pasted spec text",
    tags=["Analysis"],
)
async def analyze_paste(
    body: PasteRequest,
    format: str = Query(default="json", description="Output format: json | csv | pdf"),
    ai: bool = Query(default=False, description="Enable AI-powered recommendations"),
) -> Response:
    if not body.content or not body.content.strip():
        raise HTTPException(status_code=422, detail="Spec content cannot be empty.")
    result = await _run_pipeline(body.content, ai=ai)
    return export_result(result, format)


@app.post(
    "/analyze/upload",
    summary="Analyze uploaded spec file",
    tags=["Analysis"],
)
async def analyze_upload(
    file: UploadFile = File(...),
    format: str = Query(default="json", description="Output format: json | csv | pdf"),
    ai: bool = Query(default=False, description="Enable AI-powered recommendations"),
) -> Response:
    allowed_types = {
        "application/json", "application/x-yaml",
        "text/yaml", "text/x-yaml", "application/yaml", "text/plain",
    }
    ct = (file.content_type or "").lower()
    filename = (file.filename or "").lower()
    if ct not in allowed_types and not filename.endswith((".json", ".yaml", ".yml")):
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Upload a .json or .yaml/.yml file.",
        )

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="File is not valid UTF-8 text.")

    result = await _run_pipeline(text, ai=ai)
    return export_result(result, format)


@app.post(
    "/analyze/url",
    summary="Analyze spec fetched from a URL",
    tags=["Analysis"],
)
async def analyze_url(
    body: UrlRequest,
    format: str = Query(default="json", description="Output format: json | csv | pdf"),
    ai: bool = Query(default=False, description="Enable AI-powered recommendations"),
) -> Response:
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")

    try:
        # httpx AsyncClient handles network operations without stalling the backend server
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Request to the spec URL timed out.")
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch spec from URL (HTTP {exc.response.status_code}).",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error fetching URL: {exc}") from exc

    result = await _run_pipeline(response.text, ai=ai)
    return export_result(result, format)


# ── Health Check ─────────────

# A basic Health Check endpoint allows deployment platforms (like Docker, Kubernetes) 
# to verify that the application is actively running and ready to handle traffic.

@app.get("/health", tags=["Meta"], summary="Health check")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "API Security Analyzer",
        "version": "2.0.0",
        "ai_available": bool(os.environ.get("OPENAI_API_KEY")),
    }


# ── Serve frontend static files ─────────────

# By mounting the frontend directory statically here, we simplify deployment. 
# You don't need a separate Nginx or Node server to host the HTML files; FastAPI serves it all!

_FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_FRONTEND_DIR):
    app.mount(
        "/",
        StaticFiles(directory=_FRONTEND_DIR, html=True),
        name="frontend",
    )
