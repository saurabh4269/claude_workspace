# syntax=docker/dockerfile:1

# Stage 1: build deps (WeasyPrint needs Pango/Cairo at compile time)
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libffi-dev fonts-liberation libxml2 libxslt1.1 gcc g++ \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml ./
COPY app/ ./app/
COPY cli.py ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && pip install .

# Stage 2: lean runtime (no build tools)
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    fonts-liberation libxml2 libxslt1.1 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY app/ ./app/
COPY migrations/ ./migrations/
COPY cli.py alembic.ini ./

# Pre-create the data dir so the volume mount has a target to bind to.
# Runs as root so there are no permission issues regardless of volume state.
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.api.main:app --host 0.0.0.0 --port 8000"]
