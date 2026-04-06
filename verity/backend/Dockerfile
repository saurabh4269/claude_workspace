# Stage 1: Builder
# Install system dependencies for WeasyPrint and Python packages
FROM python:3.11-slim AS builder

# Install WeasyPrint system dependencies (Pango, Cairo, GDK-PixBuf, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Cairo and Pango are required by WeasyPrint for PDF rendering
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    # Font and image support
    fonts-liberation \
    libxml2 \
    libxslt1.1 \
    # Build tools needed for compiling some Python packages
    gcc \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment to isolate dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build backend
RUN pip install --upgrade pip hatchling

# Copy dependency manifest and install all Python dependencies
WORKDIR /build
COPY pyproject.toml ./
# Install the project dependencies (not the project itself yet)
RUN pip install \
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


# Stage 2: Runtime image
FROM python:3.11-slim AS runtime

# Install only runtime system libraries (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    fonts-liberation \
    libxml2 \
    libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash verity
USER verity
WORKDIR /app

# Copy application source code
COPY --chown=verity:verity app/ ./app/
COPY --chown=verity:verity cli.py ./

# Expose the API port
EXPOSE 8000

# Run the Uvicorn ASGI server
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
