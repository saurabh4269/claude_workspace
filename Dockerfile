# syntax=docker/dockerfile:1

# ── Stage 1: build frontend ────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY verity/frontend/package.json verity/frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --ignore-scripts

COPY verity/frontend/ .
ENV NODE_ENV=production
RUN npx vite build

# ── Stage 2: build backend deps ────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS backend-builder

COPY --from=ghcr.io/astral-sh/uv:0.6 /uv /usr/local/bin/uv

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev fonts-liberation libxml2 libxslt1.1 gcc g++ \
    && rm -rf /var/lib/apt/lists/*

ENV UV_PROJECT_ENVIRONMENT=/opt/venv

COPY verity/backend/pyproject.toml verity/backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_LINK_MODE=copy uv sync --frozen --no-dev --no-install-project

COPY verity/backend/app/ ./app/
COPY verity/backend/cli.py ./
RUN --mount=type=cache,target=/root/.cache/uv \
    UV_LINK_MODE=copy uv sync --frozen --no-dev

ENV PATH="/opt/venv/bin:$PATH"

# ── Stage 3: obfuscate backend source ─────────────────────────────────────────
FROM python:3.11-slim-bookworm AS obfuscator

RUN pip install pyarmor --quiet

WORKDIR /src
COPY verity/backend/app/ ./app/
COPY verity/backend/cli.py ./

RUN pyarmor gen -O /obfuscated -r app/ && \
    pyarmor gen -O /obfuscated cli.py

RUN find app/ -not -name "*.py" -not -path "*/__pycache__/*" -type f | \
    while read f; do \
        mkdir -p "/obfuscated/$(dirname $f)"; \
        cp "$f" "/obfuscated/$f"; \
    done

# ── Stage 4: all-in-one runtime (nginx + uvicorn via supervisord) ──────────────
FROM python:3.11-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    fonts-liberation libxml2 libxslt1.1 \
    nginx supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY --link --from=backend-builder /opt/venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --link --from=obfuscator /obfuscated/ ./
COPY --link verity/backend/migrations/ ./migrations/
COPY --link verity/backend/alembic.ini ./

# Frontend static files
COPY --link --from=frontend-builder /app/dist /usr/share/nginx/html

COPY --link nginx.conf /etc/nginx/conf.d/default.conf
COPY --link supervisord.conf /etc/supervisor/conf.d/verity.conf
RUN rm -f /etc/nginx/sites-enabled/default

COPY --link entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /app/data && python -m compileall -q -j 0 /app

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=45s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["/entrypoint.sh"]
