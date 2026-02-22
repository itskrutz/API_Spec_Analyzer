# API Security Analyzer

A web-based security linter for OpenAPI / Swagger specifications.
Paste, upload, or point to a spec URL and get an instant security report with a score, grouped findings, and fix recommendations.

---

## How it works

Each submitted spec goes through a shared pipeline:

1. **Parse** — accepts JSON or YAML; resolves internal `$ref` pointers
2. **Validate** — checks structural correctness against the OpenAPI schema (non-fatal warnings are surfaced as findings, not errors)
3. **Analyze** — runs 10 security rule checks covering auth, transport, input validation, and more
4. **Enrich** *(optional)* — sends findings to GPT-4o mini for plain-English explanations
5. **Export** — return results as JSON, CSV, or PDF

The frontend is served by the same FastAPI process — no separate Node server.

---

## Quick start

### Docker (recommended)

```bash
docker compose up --build
```

Open **http://localhost:8000**.

To enable AI recommendations, set your OpenAI key first:

```bash
OPENAI_API_KEY=sk-... docker compose up --build
```

### Local Python

Requires Python 3.11+.

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Open **http://localhost:8000**.

---

## Usage

1. Choose an input method — **Paste**, **Upload** (`.json` / `.yaml`), or **URL**
2. Toggle **Enable AI** if you want GPT-powered explanations (requires `OPENAI_API_KEY`)
3. Click **Analyze Spec**
4. Browse findings — click any card to expand its affected locations and recommendation
5. Use the severity filter buttons to focus on critical or high-severity issues
6. Export the report as **JSON**, **CSV**, or **PDF** from the export bar

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/analyze/paste` | Analyze spec from a raw JSON/YAML string |
| `POST` | `/analyze/upload` | Analyze spec from a multipart file upload |
| `POST` | `/analyze/url` | Fetch and analyze a spec from a public URL |
| `GET`  | `/health` | Health check — includes `ai_available` flag |

All three analyze endpoints accept `?format=json` (default), `?format=csv`, or `?format=pdf` and `?ai=true` to enable AI enrichment.

Interactive docs: **http://localhost:8000/docs**

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | No | Enables AI-powered recommendations via GPT-4o mini |
