# syntax=docker/dockerfile:1

# Stage 1: install Python deps + build tools (WeasyPrint needs Pango/Cairo)
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    fonts-liberation \
    libxml2 \
    libxslt1.1 \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only the manifest first so pip layer is cached unless deps change
COPY pyproject.toml ./

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install \
    "fastapi>=0.111.0" \
    "uvicorn[standard]>=0.29.0" \
    "sqlalchemy[asyncio]>=2.0.0" \
    "aiosqlite>=0.20.0" \
    "pydantic>=2.0.0" \
    "pydantic-settings>=2.0.0" \
    "httpx>=0.27.0" \
    "python-jose[cryptography]>=3.3.0" \
    "passlib[bcrypt]>=1.7.4" \
    "python-multipart>=0.0.9" \
    "weasyprint>=62.0" \
    "click>=8.1.0" \
    "rich>=13.0.0" \
    "slowapi>=0.1.9" \
    "alembic>=1.13.0" \
    "email-validator>=2.1.0"

# Stage 2: lean runtime (no build tools, no gcc)
FROM python:3.11-slim AS runtime

# Only runtime libraries - no gcc/g++
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    fonts-liberation \
    libxml2 \
    libxslt1.1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create the app user and the data directory (for SQLite volume mount) before
# switching to non-root, so the volume is writable by the verity user.
RUN useradd --create-home --shell /bin/bash verity && \
    mkdir -p /app/data && \
    chown -R verity:verity /app

USER verity
WORKDIR /app

COPY --chown=verity:verity app/ ./app/
COPY --chown=verity:verity cli.py ./
COPY --chown=verity:verity migrations/ ./migrations/
COPY --chown=verity:verity alembic.ini ./

EXPOSE 8000

# Run migrations then start the server
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.api.main:app --host 0.0.0.0 --port 8000"]
