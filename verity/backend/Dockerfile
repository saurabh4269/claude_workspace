# syntax=docker/dockerfile:1

# Stage 1: build Python deps
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

# Stage 2: obfuscate source with PyArmor
FROM python:3.11-slim AS obfuscator

RUN pip install pyarmor --quiet

WORKDIR /src
COPY app/ ./app/
COPY cli.py ./

# Obfuscate Python source (app package + CLI entry point)
RUN pyarmor gen -O /obfuscated -r app/ && \
    pyarmor gen -O /obfuscated cli.py

# PyArmor only processes .py files — copy non-Python assets manually
RUN find app/ -not -name "*.py" -not -path "*/__pycache__/*" -type f | \
    while read f; do \
        mkdir -p "/obfuscated/$(dirname $f)"; \
        cp "$f" "/obfuscated/$f"; \
    done

# Stage 3: lean runtime (no build tools, no source)
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    fonts-liberation libxml2 libxslt1.1 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy obfuscated source + PyArmor runtime (includes app/, cli.py, pyarmor_runtime_*)
COPY --from=obfuscator /obfuscated/ ./

COPY migrations/ ./migrations/
COPY alembic.ini ./

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.api.main:app --host 0.0.0.0 --port 8000"]
