# Contributing to Verity

## Local Development Setup

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker + Docker Compose (for the full stack)

### Backend only

```bash
cd verity/backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp ../../.env.example .env     # edit as needed

alembic upgrade head
uvicorn app.api.main:app --reload --port 8000
```

API is at `http://localhost:8000`, docs at `http://localhost:8000/docs`.

### Frontend only

```bash
cd verity/frontend
npm install
npm run dev
```

UI is at `http://localhost:5173`. It proxies `/api` to `http://localhost:8000` via Vite's dev server config.

### Full stack (Docker)

```bash
cp .env.example .env           # edit SECRET_KEY at minimum
docker compose up --build
```

UI: `http://localhost` — API: `http://localhost:8000`

---

## Project Structure

```
verity/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/        # FastAPI route handlers (one file per resource)
│   │   │   ├── schemas.py     # All Pydantic request/response models
│   │   │   ├── deps.py        # Shared FastAPI dependencies (auth, db)
│   │   │   └── main.py        # App factory, middleware, router registration
│   │   ├── auth/              # JWT helpers, password hashing
│   │   ├── config.py          # Settings (pydantic-settings), runtime override helpers
│   │   ├── core/              # Parser, validator, risk analyzer, vuln checker
│   │   ├── db/                # SQLAlchemy models, session, init
│   │   └── exporters/         # PDF and JSON report generation
│   ├── migrations/            # Alembic migrations
│   ├── cli.py                 # verity CLI (Click)
│   ├── pyproject.toml         # package + deps (single source of truth)
│   └── ruff.toml              # linter/formatter config
└── frontend/
    └── src/
        ├── components/        # Shared UI components
        ├── pages/             # Route-level page components
        └── lib/
            ├── api.ts         # All API calls (axios, snake→camelCase transform)
            └── utils.ts       # Shared helpers
```

---

## Architecture Notes

### Settings mutation
`app/config.py` holds a module-level `settings` singleton (Pydantic BaseSettings). The `Settings → Platform` UI writes overrides to `/app/data/site_settings.json` via `save_overrides()`, which are re-applied by `load_overrides()` on startup. In-process changes are applied by directly mutating the singleton (`setattr(settings, key, value)`). This is safe because uvicorn runs as a single async process with no shared memory across workers. **Do not run multiple uvicorn workers** without replacing this with a DB-backed settings store.

### API ↔ Frontend contract
The axios interceptor in `src/lib/api.ts` converts all snake_case response keys to camelCase. When adding a new backend field, make sure you reference it as camelCase on the frontend (e.g. `auth_enabled` → `authEnabled`). Request bodies are sent as snake_case (the backend receives them that way).

### Feature flags
`AUTH_ENABLED`, `HISTORY_ENABLED`, `VULN_CHECK_ENABLED` gate entire code paths on both frontend and backend. When adding a feature that depends on one of these, check both sides.

---

## Adding a New Endpoint

1. Add a Pydantic schema to `app/api/schemas.py` (request and response models).
2. Add the route to the appropriate file in `app/api/routes/`.
3. Register the router in `app/api/main.py` if creating a new route file.
4. Add the API call to `verity/frontend/src/lib/api.ts`.

---

## Code Style

**Backend** — uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
cd verity/backend
ruff check .          # lint
ruff format .         # format
```

**Frontend** — TypeScript strict mode is on. Run type checks with:

```bash
cd verity/frontend
npx tsc --noEmit
```

---

## Running Tests

> A test suite is not yet included. Contributions adding pytest coverage for `app/core/` (parser, validator, risk analyzer) and API integration tests are very welcome.

---

## Pull Request Guidelines

- Keep PRs focused — one logical change per PR.
- Update `CONTRIBUTING.md` if you change the dev setup or architecture.
- Update `README.md` if you add a user-facing feature or config variable.
- Make sure `ruff check .` and `npx tsc --noEmit` pass before opening a PR.
