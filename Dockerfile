# ── CC Toolkit — Docker Image ──────────────────────────────────────────────
# Multi-stage build:
#   stage 1: install system dependencies + Python packages
#   stage 2: minimal runtime image
#
# Usage:
#   docker build -t cc-toolkit .
#   docker run -p 5000:5000 -v cc-data:/workspace cc-toolkit web
# ──────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cc-toolkit
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cc-toolkit

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy application code
COPY modules/ modules/
COPY web_dashboard/ web_dashboard/
COPY playbooks/ playbooks/
COPY tools/ tools/
COPY cli.py cc_mcp_server.py run.py ./
COPY requirements.txt .env.example ./

# Create workspace directories
VOLUME /workspace

# Default port
EXPOSE 5000 5001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Entry point
ENTRYPOINT ["python", "run.py"]
CMD ["web"]
