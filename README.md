# Verity

**SBOM Validator and Risk Assessment Platform for TPRM**

Verity automates the validation and risk assessment of Software Bill of Materials (SBOM) files. It parses multi-format SBOMs, scores quality across seven weighted categories, checks compliance against major regulatory standards, queries live vulnerability databases, and produces structured reports — replacing slow manual reviews with a repeatable, auditable process.

---

## Features

- **Multi-format parsing** — CycloneDX JSON/XML (1.4–1.6), SPDX JSON/YAML/tag-value (2.2–2.3, 3.0)
- **Quality scoring** — weighted 0–10 score across 7 categories (Structural, Identification, Provenance, Integrity, Licensing, Vulnerability & Traceability, Completeness) with letter grade A–F; base weight total 82
- **Compliance validation** — NTIA Minimum Elements, BSI TR-03183-2 (v1.1 / v2.0 / v2.1), FSCT v3, OpenChain Telco v1.1
- **Scored compliance profiles** — continuous 0–10 profile score against NTIA, BSI v2.1, FSCT v3, or OpenChain Telco; selectable at scan time; exposed in the UI Profile tab and PDF report
- **Risk scoring** — per-component scores based on missing fields, license type (AGPL/GPL/LGPL tiers), and CVE severity; document-level escalation when >30% of components are HIGH+
- **Live vulnerability lookup** — OSV.dev batch API, CISA KEV catalog, EPSS scores (FIRST.org); optional NVD enrichment for CVSS gaps
- **Malicious package detection** — flags OSV advisories with a `MAL-` prefix as malicious (score penalty in Component Security Health)
- **EOL/EOS detection** — queries endoflife.date for each component product; flags end-of-life components in Component Security Health
- **Policy engine** — YAML-based allow/deny rules on licenses, component names, score thresholds, and vulnerability attributes
- **Export** — PDF reports (WeasyPrint, brand-styled; includes profile score section) and JSON for downstream tooling
- **Scan history** — stored in SQLite (or PostgreSQL), queryable with filters and pagination
- **Workspace analytics** — aggregate statistics, risk distribution, score trends, and top vulnerabilities across a workspace
- **Workspaces** — invite teammates, share scans across a team
- **Optional auth** — JWT-based login, disabled by default; toggle on/off from the Settings UI without restarting
- **CLI** — pipe-friendly, CI/CD ready with configurable fail thresholds
- **Web UI** — React dashboard with quality breakdown, NTIA checklist, compliance panel, component tables, profile score tab, and export buttons
- **REST API** — OpenAPI docs at `/docs`; CI integration endpoint for automated pipelines

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

## Quality Scoring

Every scan produces a 0–10 quality score and a letter grade (A–F) computed across seven weighted categories (base weight total: 82):

| Category | Weight | What it measures |
|---|---|---|
| Structural Validity | 8 | Spec declaration, version support, file format, schema validity |
| Identification | 10 | Component names, versions, unique local IDs (PURL/CPE are in Vulnerability & Traceability) |
| Provenance | 12 | Creation timestamp, authors, tool versions, namespace, supplier, lifecycle |
| Integrity | 15 | Checksums (any and strong SHA-256+), document-level signature |
| License Compliance | 15 | License presence, SPDX validity, declared licenses, deprecated/restrictive license detection |
| Vulnerability & Traceability | 10 | PURL and CPE syntax validity; at least one valid identifier per component |
| Completeness | 12 | Primary component, dependency graph, per-component supplier/source/type |

An optional **Component Security Health** category (weight 8) is appended when vulnerability results are available, covering vulnerable components, critical CVEs, EOL components, and malicious packages. It does not contribute to the base denominator.

**Grade scale**

| Score | Grade |
|---|---|
| 9.0 – 10.0 | A — Excellent |
| 8.0 – 8.9 | B — Good |
| 7.0 – 7.9 | C — Acceptable |
| 5.0 – 6.9 | D — Poor |
| < 5.0 | F — Needs major rework |

---

## Compliance Standards

| Standard | Scope | Notes |
|---|---|---|
| NTIA Minimum Elements (2021) | 7 required elements | Per-component name, version, supplier, unique ID; document author, timestamp, dependency relationships |
| BSI TR-03183-2 v1.1 | SHALL + SHOULD tiers | CDX 1.4+ / SPDX ≥ 2.2; creator, SHA-256 hash, license, dependency resolution |
| BSI TR-03183-2 v2.0 | Adds: no vuln data, signature, BOM links | CDX 1.5+ / SPDX 2.2.1+; filename property, completeness declaration |
| BSI TR-03183-2 v2.1 | Latest — CDX 1.6 only | SHA-512 on deployable artifact, declared licenses (acknowledgement field), SBOM URI promoted to SHALL |
| FSCT v3 | Multi-level scoring (0/10/12/15) | SBOM author, lifecycle, relationships, per-component checksum (strong=12), license quality; raw score exposed separately |
| OpenChain Telco v1.1 | SPDX only | 27 document + component checks; org/tool creator split, SHA-256 normalised, PURL, concluded/declared license, copyright text |

### Scored Compliance Profiles

In addition to pass/fail compliance checking, Verity can compute a **continuous 0–10 profile score** against any supported standard. Select a profile at scan time to get a weighted score on just the features that standard cares about. N/A features (not applicable for the SBOM format) are excluded from the denominator.

Available profiles: `ntia`, `bsi` (v2.1), `fsct`, `oct`.

---

## Risk Levels

| Level | Score | Meaning |
|---|---|---|
| LOW | 0 – 20 | No significant issues found |
| MEDIUM | 21 – 49 | Minor gaps or low-severity CVEs |
| HIGH | 50 – 79 | Missing critical fields or medium-severity CVEs |
| CRITICAL | 80+ | Copyleft violations or high-severity CVEs |

**Scoring factors per component**

| Factor | Points |
|---|---|
| Missing version | +15 |
| Missing PURL and CPE | +20 |
| Missing supplier | +10 |
| No license info | +10 |
| AGPL / SSPL license | +30 |
| GPL-2.0 / GPL-3.0 license | +20 |
| LGPL / MPL license | +10 |
| CVE CVSS >= 9.0 | +50 |
| CVE CVSS 7.0 – 8.9 | +35 |
| CVE CVSS 4.0 – 6.9 | +20 |
| CVE CVSS < 4.0 | +10 |

The document-level risk is the highest component risk, escalated one tier if more than 30% of components score HIGH or above.

---

## Policy Engine

Define allow/deny rules in YAML and pass them at scan time:

```yaml
policy:
  - id: no_copyleft
    type: license_denylist
    licenses: [GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only]
    action: fail

  - id: approved_licenses
    type: license_allowlist
    licenses: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
    action: warn

  - id: quality_gate
    type: threshold
    metric: quality_score
    operator: lt
    value: 7.0
    action: fail

  - id: no_kev
    type: vulnerability
    filter:
      in_kev: true
    action: fail
```

Supported rule types: `license_denylist`, `license_allowlist`, `component_denylist` (glob patterns on name/PURL), `threshold` (quality/risk/category scores and field coverage ratios), `vulnerability` (by severity, EPSS, KEV status).

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

`AUTH_ENABLED`, `HISTORY_ENABLED`, and `VULN_CHECK_ENABLED` can be toggled live from **Settings** in the web UI. Changes take effect immediately and survive container restarts. Environment variables act as initial defaults; UI overrides take precedence once written.

**Enabling authentication for the first time**

1. Go to **Settings** and toggle **Authentication** on.
2. You will be redirected to the login page — click **Sign up** to create the first account.
3. Subsequent platform-setting changes require admin privileges once auth is on.

**Switching to PostgreSQL**

```bash
DATABASE_URL=postgresql+asyncpg://user:pass@host/verity docker compose up
```

Add `asyncpg` to `pyproject.toml` dependencies and rebuild the image.

---

## API Reference

Interactive docs are available at `http://localhost:8000/docs` when the server is running.

**Key endpoints**

```
POST   /api/v1/scans/upload              Upload and analyse an SBOM file
                                           Form params: file, vuln_check, save_to_history,
                                           run_compliance, workspace_id, profile
GET    /api/v1/scans                     List scans (paginated, filterable)
GET    /api/v1/scans/{id}               Full scan detail with components
GET    /api/v1/scans/{id}/export/pdf    Download PDF report
GET    /api/v1/scans/{id}/export/json   Download JSON report
DELETE /api/v1/scans/{id}              Delete a scan
GET    /api/v1/scans/{id}/components    Component list (filterable, paginated)

POST   /api/v1/ci/scan                  CI integration: scan and return structured result

GET    /api/v1/workspaces               List workspaces
POST   /api/v1/workspaces              Create a workspace
GET    /api/v1/workspaces/{id}/analytics  Aggregate analytics for a workspace

POST   /api/v1/auth/register            Register (AUTH_ENABLED only)
POST   /api/v1/auth/login               Login (AUTH_ENABLED only)
POST   /api/v1/auth/change-password     Change password (AUTH_ENABLED only)
POST   /api/v1/auth/invite/{ws_id}      Generate an invite link

GET    /api/v1/settings                 Get current platform settings
PATCH  /api/v1/settings                 Update platform settings (admin only when auth on)

GET    /health                          Health check
```

---

## Project Structure

```
verity/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── parser.py          # Multi-format SBOM parser
│   │   │   ├── scorer.py          # Quality scoring engine (7 categories, base weight 82)
│   │   │   ├── risk_analyzer.py   # Per-component and document risk scoring
│   │   │   ├── vuln_checker.py    # OSV, KEV, EPSS, NVD lookup + malicious detection
│   │   │   ├── eol_checker.py     # EOL/EOS detection via endoflife.date API
│   │   │   ├── policy.py          # YAML policy engine
│   │   │   ├── compliance/        # NTIA, BSI, FSCT, OCT pass/fail checkers
│   │   │   ├── profiles/          # Scored compliance profiles (NTIA, BSI, FSCT, OCT)
│   │   │   └── licenses/          # SPDX license database and validator
│   │   ├── api/
│   │   │   ├── routes/            # scans, workspaces, auth, ci, settings
│   │   │   └── schemas.py         # Pydantic request/response models
│   │   ├── db/                    # SQLAlchemy models and session
│   │   ├── auth/                  # JWT helpers
│   │   └── exporters/             # PDF and JSON report generation
│   ├── migrations/                # Alembic schema migrations
│   ├── cli.py                     # Click CLI entry point
│   └── pyproject.toml             # pip-installable package
└── frontend/
    └── src/
        ├── components/            # UI primitives, compliance panel, component table
        ├── pages/                 # Dashboard, NewScan, ScanDetail, History,
        │                          #   Analytics, Settings
        └── lib/                   # API client and utilities
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

## Sample SBOMs

Two ready-to-use test files are included in `sample-sboms/`:

| File | Format | Components | Expected result |
|---|---|---|---|
| `acme-webapp.cdx.json` | CycloneDX 1.4 JSON | 4 | Risk: HIGH, 3 invalid, 5 NTIA issues |
| `acme-backend.spdx.json` | SPDX 2.3 JSON | 4 | Risk: HIGH, 2 invalid, 5 NTIA issues |

Both files intentionally include components with missing fields and license issues to exercise the full validation pipeline.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, SQLAlchemy (async), aiosqlite |
| Vulnerability data | OSV.dev, CISA KEV, EPSS (FIRST.org), NVD (optional) |
| PDF generation | WeasyPrint |
| Migrations | Alembic |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Container | Docker, nginx |
