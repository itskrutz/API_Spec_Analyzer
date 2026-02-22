# ═══════════════════════════════════════════════════════════════════════════════
# API Security Analyzer  |  Dockerfile
# ═══════════════════════════════════════════════════════════════════════════════
#
# Single-container build:
#   • Installs Python dependencies
#   • Copies backend + frontend
#   • Serves everything via uvicorn on port 8000
#   • Frontend is mounted as StaticFiles at "/" by FastAPI
#
# Build:  docker build -t api-analyzer .
# Run:    docker run -p 8000:8000 api-analyzer
# Then open http://localhost:8000 in your browser.
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim

# Keeps Python from generating .pyc files and enables unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer caching — only re-runs when requirements change)
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

# Expose the port uvicorn listens on
EXPOSE 8000

# Run the server
# --host 0.0.0.0 is required so the port is accessible outside the container
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
