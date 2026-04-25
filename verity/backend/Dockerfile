# syntax=docker/dockerfile:1

# Stage 1: build Python deps with uv
FROM python:3.11-slim-bookworm AS builder

# Pull uv binary only — no pip, no virtualenv boilerplate
COPY --from=ghcr.io/astral-sh/uv:0.6 /uv /usr/local/bin/uv

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev fonts-liberation libxml2 libxslt1.1 gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN uv venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy manifests only — installs all deps WITHOUT the project source.
# This layer is cached until pyproject.toml or uv.lock changes, not on every code edit.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_LINK_MODE=copy uv sync --frozen --no-dev --no-install-project

# Now copy source and install the package itself (deps already cached above)
COPY app/ ./app/
COPY cli.py ./
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_LINK_MODE=copy uv sync --frozen --no-dev

# Stage 2: obfuscate source with PyArmor
FROM python:3.11-slim-bookworm AS obfuscator

RUN pip install pyarmor --quiet

WORKDIR /src
COPY app/ ./app/
COPY cli.py ./

# Obfuscate Python source (app package + CLI entry point)
RUN pyarmor gen -O /obfuscated -r app/ && \
    pyarmor gen -O /obfuscated cli.py

# Copy non-Python assets that PyArmor skips (JSON schemas, etc.)
RUN find app/ -not -name "*.py" -not -path "*/__pycache__/*" -type f | \
    while read f; do \
        mkdir -p "/obfuscated/$(dirname $f)"; \
        cp "$f" "/obfuscated/$f"; \
    done

# Stage 3: lean runtime — no build tools, no source
FROM python:3.11-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    fonts-liberation libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Each COPY --link is independently cacheable — doesn't depend on prior layers
COPY --link --from=builder /opt/venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Non-root user for security
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --no-create-home appuser

WORKDIR /app

# Obfuscated source + PyArmor runtime (app/, cli.py, pyarmor_runtime_*)
COPY --link --from=obfuscator /obfuscated/ ./
COPY --link migrations/ ./migrations/
COPY --link alembic.ini ./

RUN mkdir -p /app/data && chown -R appuser:appuser /app /opt/venv

# Pre-compile .pyc for all source — eliminates first-request JIT overhead
RUN python -m compileall -q -j 0 /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.api.main:app --host 0.0.0.0 --port 8000"]
