"""
Integration tests for the scan upload and retrieval API.
Uses FastAPI's test client with an in-memory SQLite database.
"""

import io
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.api.main import app
from app.api.deps import get_db
from app.config import settings
from app.db.session import Base

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def engine():
    return create_async_engine(TEST_DATABASE_URL, echo=False)


@pytest_asyncio.fixture(scope="session")
async def db_tables(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(engine, db_tables):
    TestingSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False, autocommit=False, autoflush=False
    )
    async with TestingSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    # Disable auth for tests
    original_auth = settings.AUTH_ENABLED
    settings.AUTH_ENABLED = False

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
    settings.AUTH_ENABLED = original_auth


MINIMAL_CDX = """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {"timestamp": "2024-01-15T12:00:00Z"},
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"license": {"id": "MIT"}}],
      "supplier": {"name": "Lodash Team"}
    }
  ]
}"""


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestScanUpload:
    @pytest.mark.asyncio
    async def test_upload_cdx_json(self, client):
        files = {"file": ("test.json", io.BytesIO(MINIMAL_CDX.encode()), "application/json")}
        data = {"vuln_check": "false", "save_to_history": "false", "run_compliance": "true"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 201
        body = response.json()
        assert body["sbom_format"] == "cyclonedx"
        assert body["total_components"] == 1

    @pytest.mark.asyncio
    async def test_upload_returns_quality_score(self, client):
        files = {"file": ("test.json", io.BytesIO(MINIMAL_CDX.encode()), "application/json")}
        data = {"vuln_check": "false", "save_to_history": "false", "run_compliance": "true"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 201
        body = response.json()
        assert "quality_score" in body
        assert "quality" in body
        if body["quality"]:
            assert "overall_score" in body["quality"]
            assert "grade" in body["quality"]
            assert "categories" in body["quality"]

    @pytest.mark.asyncio
    async def test_upload_returns_compliance(self, client):
        files = {"file": ("test.json", io.BytesIO(MINIMAL_CDX.encode()), "application/json")}
        data = {"vuln_check": "false", "save_to_history": "false", "run_compliance": "true"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 201
        body = response.json()
        assert "compliance" in body
        if body["compliance"]:
            assert "ntia" in body["compliance"] or body["compliance"] is None

    @pytest.mark.asyncio
    async def test_upload_unsupported_extension(self, client):
        files = {"file": ("test.exe", io.BytesIO(b"not a sbom"), "application/octet-stream")}
        data = {"vuln_check": "false", "save_to_history": "false"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_upload_garbage_content(self, client):
        files = {"file": ("test.json", io.BytesIO(b"this is not json"), "application/json")}
        data = {"vuln_check": "false", "save_to_history": "false"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_upload_saves_to_db(self, client):
        files = {"file": ("test.json", io.BytesIO(MINIMAL_CDX.encode()), "application/json")}
        data = {"vuln_check": "false", "save_to_history": "true", "run_compliance": "false"}
        response = await client.post("/api/v1/scans/upload", files=files, data=data)
        assert response.status_code == 201
        scan_id = response.json()["id"]

        # Fetch it back
        get_response = await client.get(f"/api/v1/scans/{scan_id}")
        assert get_response.status_code == 200
        assert get_response.json()["id"] == scan_id


class TestScanList:
    @pytest.mark.asyncio
    async def test_list_empty(self, client):
        response = await client.get("/api/v1/scans")
        assert response.status_code == 200
        body = response.json()
        assert "items" in body
        assert "total" in body
        assert "page" in body

    @pytest.mark.asyncio
    async def test_list_pagination(self, client):
        response = await client.get("/api/v1/scans?page=1&per_page=5")
        assert response.status_code == 200
        body = response.json()
        assert body["page"] == 1
        assert body["per_page"] == 5


class TestScanNotFound:
    @pytest.mark.asyncio
    async def test_get_nonexistent(self, client):
        response = await client.get("/api/v1/scans/nonexistent-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, client):
        response = await client.delete("/api/v1/scans/nonexistent-id")
        assert response.status_code == 404


class TestComponentSearch:
    @pytest.mark.asyncio
    async def test_search_returns_results(self, client):
        response = await client.get("/api/v1/components/search?q=lodash")
        assert response.status_code == 200
        body = response.json()
        assert "query" in body
        assert "results" in body
        assert "total" in body

    @pytest.mark.asyncio
    async def test_search_too_short(self, client):
        response = await client.get("/api/v1/components/search?q=a")
        assert response.status_code == 422
