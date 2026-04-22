# Verity

**SBOM Validator and Risk Assessment Platform for TPRM**

Verity automates the validation and risk assessment of Software Bill of Materials (SBOM) files. It checks format compliance against NTIA minimum elements, scores component-level risk, queries live vulnerability databases, and produces structured reports, replacing slow manual reviews with a repeatable, auditable process.

---

## Features

- **Multi-format parsing** — CycloneDX JSON, CycloneDX XML, SPDX JSON, SPDX tag-value
- **NTIA compliance checks** — validates all seven minimum elements from the 2021 NTIA guidance and EO 14028
- **Risk scoring** — per-component scores based on missing fields, license type (AGPL/GPL/LGPL tiers), and CVE severity
- **Live vulnerability lookup** — OSV.dev batch API with optional NVD enrichment (no API key required for OSV)
- **Export** — PDF reports and JSON for downstream tooling
- **Scan history** — stored in SQLite, queryable with filters and pagination
- **Workspaces** — invite teammates, share scans across a team
- **Optional auth** — JWT-based login, disabled by default; toggle on/off from the Settings UI without restarting
- **CLI** — pipe-friendly, CI/CD ready with configurable fail thresholds
- **Web UI** — React dashboard with risk charts, component tables, and export buttons
- **REST API** — OpenAPI docs at `/docs`

---

## Quick Start

### Docker (full stack)

```bash
git clone https://github.com/saurabh4269/claude_workspace.git
cd claude_workspace
docker compose up --build
```

| Service | URL |
|---|---|
| Web UI | http://localhost |
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

### CLI only

```bash
cd verity/backend
pip install .
verity scan path/to/sbom.json
```

---

## CLI Usage

```
verity scan <file> [OPTIONS]

Options:
  --vuln-check / --no-vuln-check   Query OSV.dev for CVEs (default: on)
  --fail-on [LOW|MEDIUM|HIGH|CRITICAL]
                                   Exit 1 if overall risk reaches this level
                                   (default: HIGH)
  --output [text|json]             Output format (default: text)
  --no-save                        Do not store this scan in history

verity version
```

**Examples**

```bash
# Basic scan with colored terminal output
verity scan sbom.json

# CI pipeline gate: fail if any HIGH or CRITICAL risk found
verity scan sbom.cyclonedx.json --fail-on HIGH

# Skip vulnerability lookup for a faster offline scan
verity scan sbom.spdx --no-vuln-check --output json > report.json

# Strict gate: fail on anything above LOW
verity scan sbom.xml --fail-on MEDIUM --no-save
```

---

## Configuration

All settings are driven by environment variables (or a `.env` file in `verity/backend/`).

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:////app/data/verity.db` | SQLAlchemy async DB URL |
| `SECRET_KEY` | `change-me-in-production` | JWT signing key. Change before deploying. |
| `AUTH_ENABLED` | `false` | Enable login / registration |
| `HISTORY_ENABLED` | `true` | Persist scans to the database |
| `VULN_CHECK_ENABLED` | `true` | Enable OSV.dev lookups platform-wide |
| `NVD_API_KEY` | _(unset)_ | NVD API key for CVSS enrichment (optional) |
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum SBOM file size |
| `CORS_ORIGINS` | `["http://localhost", ...]` | Allowed CORS origins |
| `SITE_SETTINGS_PATH` | `/app/data/site_settings.json` | Where UI-driven setting overrides are persisted |

`AUTH_ENABLED`, `HISTORY_ENABLED`, and `VULN_CHECK_ENABLED` can also be toggled live from **Settings → Platform** in the web UI. Changes take effect immediately and are persisted to `SITE_SETTINGS_PATH` so they survive container restarts. Environment variables act as the initial default; UI overrides take precedence once written.

**Enabling authentication for the first time**

1. Go to **Settings → Platform** and toggle **Authentication** on.
2. You will be redirected to the login page — click **Sign up** to create the first account.
3. Subsequent platform-setting changes require admin privileges once auth is on.

**Switching to PostgreSQL**

```bash
DATABASE_URL=postgresql+asyncpg://user:pass@host/verity docker compose up
```

Add `asyncpg` to `pyproject.toml` dependencies and rebuild the image.

---

## Risk Levels

| Level | Score | Meaning |
|---|---|---|
| LOW | 0 - 20 | No significant issues found |
| MEDIUM | 21 - 49 | Minor gaps or low-severity CVEs |
| HIGH | 50 - 79 | Missing critical fields or medium-severity CVEs |
| CRITICAL | 80+ | Copyleft license violations or high-severity CVEs |

**Scoring factors per component**

| Factor | Points added |
|---|---|
| Missing version | +15 |
| Missing PURL and CPE | +20 |
| Missing supplier | +10 |
| No license info | +10 |
| AGPL / SSPL license | +30 |
| GPL-2.0 / GPL-3.0 license | +20 |
| LGPL / MPL license | +10 |
| CVE with CVSS >= 9.0 | +50 |
| CVE with CVSS 7.0 - 8.9 | +35 |
| CVE with CVSS 4.0 - 6.9 | +20 |
| CVE with CVSS < 4.0 | +10 |

The document-level risk is the highest component risk, escalated one level if more than 30% of components score HIGH or above.

---

## API Reference

Interactive docs are available at `http://localhost:8000/docs` when the server is running.

**Key endpoints**

```
POST   /api/v1/scans/upload          Upload and analyse an SBOM file
GET    /api/v1/scans                 List scans (paginated, filterable)
GET    /api/v1/scans/{id}            Full scan detail with components
GET    /api/v1/scans/{id}/export/pdf Download PDF report
GET    /api/v1/scans/{id}/export/json Download JSON report
DELETE /api/v1/scans/{id}           Delete a scan

POST   /api/v1/workspaces            Create a workspace
GET    /api/v1/workspaces            List workspaces
POST   /api/v1/auth/register         Register (AUTH_ENABLED only)
POST   /api/v1/auth/login            Login (AUTH_ENABLED only)
POST   /api/v1/auth/change-password  Change password (AUTH_ENABLED only)
POST   /api/v1/auth/invite/{ws_id}   Generate an invite link

GET    /api/v1/settings              Get current platform settings
PATCH  /api/v1/settings              Update platform settings (admin only when auth on)

GET    /health                       Health check
```

---

## Project Structure

```
verity/
├── backend/
│   ├── app/
│   │   ├── core/          # Parser, validator, risk analyzer, vuln checker
│   │   ├── api/           # FastAPI routes and schemas
│   │   ├── db/            # SQLAlchemy models and session
│   │   ├── auth/          # JWT helpers
│   │   └── exporters/     # PDF and JSON report generation
│   ├── migrations/        # Alembic schema migrations
│   ├── cli.py             # Click CLI entry point
│   └── pyproject.toml     # pip-installable package
└── frontend/
    └── src/
        ├── components/    # UI primitives and shared components
        ├── pages/         # Dashboard, NewScan, ScanDetail, History, Settings
        └── lib/           # API client and utilities
```

---

## Database Migrations

Schema migrations are managed by Alembic. The container runs `alembic upgrade head` automatically on startup.

To create a new migration after changing models:

```bash
cd verity/backend
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, SQLAlchemy (async), aiosqlite |
| Vulnerability data | OSV.dev API, NVD (optional) |
| PDF generation | WeasyPrint |
| Migrations | Alembic |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui |
| Charts | Recharts |
| Container | Docker, nginx |

---

## Sample SBOMs

Two ready-to-use test files are included in `sample-sboms/`:

| File | Format | Components | Expected result |
|---|---|---|---|
| `acme-webapp.cdx.json` | CycloneDX 1.4 JSON | 4 (react, axios, coreutils, legacy-auth) | Risk: HIGH, 3 invalid, 5 NTIA issues |
| `acme-backend.spdx.json` | SPDX 2.3 JSON | 4 (flask, numpy, cryptography, internal-util) | Risk: HIGH, 2 invalid, 5 NTIA issues |

Both files intentionally include components with missing fields and license issues to exercise the full validation pipeline.

---

## Supported SBOM Formats

| Format | Variants |
|---|---|
| CycloneDX | JSON (spec 1.4+), XML (spec 1.4+) |
| SPDX | JSON (2.3), tag-value (.spdx, .tv) |
