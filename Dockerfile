# Multi-stage Rootless Dockerfile for Security Log Correlation Engine

# Stage 1: Build & Dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install .

# Stage 2: Runtime Container
FROM python:3.12-slim AS runner

# Security: Create non-root system user (UID 10001)
RUN groupadd -g 10001 appsec && \
    useradd -u 10001 -g appsec -s /bin/false -m -d /app appsec

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY src/ ./src/
COPY pyproject.toml ./

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_CORR_DB_PATH="/app/data/correlation_engine.db"

# Ensure data directory exists and is owned by non-root user
RUN mkdir -p /app/data && chown -R appsec:appsec /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "log_corr.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
