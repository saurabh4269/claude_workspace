"""
Component search route — full-text search across all scan components.
Uses SQLite FTS5 virtual table when available, falls back to LIKE.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.api.schemas import ComponentSearchOut, ComponentSearchResult
from app.db.models import Scan, ScanComponent, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/components", tags=["components"])


@router.get("/search", response_model=ComponentSearchOut)
async def search_components(
    q: str = Query(..., min_length=2, description="Search term"),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
) -> ComponentSearchOut:
    """
    Search for components by name, version, or PURL across all scans.
    Uses FTS5 when available for fast full-text search.
    """
    results: list[ComponentSearchResult] = []

    try:
        # Try FTS5 first
        fts_rows = await db.execute(
            text(
                """
                SELECT component_id, scan_id
                FROM component_fts
                WHERE component_fts MATCH :query
                LIMIT :limit
                """
            ),
            {"query": q, "limit": limit},
        )
        fts_hits = fts_rows.fetchall()

        if fts_hits:
            comp_ids = [row[0] for row in fts_hits]
            comp_result = await db.execute(
                select(ScanComponent).where(ScanComponent.id.in_(comp_ids))
            )
            db_components = comp_result.scalars().all()
        else:
            db_components = []

    except Exception:
        # FTS5 not available or query error — fall back to LIKE
        logger.debug("FTS5 unavailable, falling back to LIKE search")
        like_q = f"%{q}%"
        comp_result = await db.execute(
            select(ScanComponent).where(
                ScanComponent.name.ilike(like_q)
                | ScanComponent.purl.ilike(like_q)
                | ScanComponent.version.ilike(like_q)
            ).limit(limit)
        )
        db_components = comp_result.scalars().all()

    # Enrich with scan metadata
    scan_ids = list({c.scan_id for c in db_components})
    scan_map: dict[str, Scan] = {}
    if scan_ids:
        scan_result = await db.execute(select(Scan).where(Scan.id.in_(scan_ids)))
        scan_map = {s.id: s for s in scan_result.scalars().all()}

    for comp in db_components:
        scan = scan_map.get(comp.scan_id)
        vuln_count = len(comp.vulnerabilities or [])
        results.append(ComponentSearchResult(
            component_id=comp.id,
            scan_id=comp.scan_id,
            scan_filename=scan.filename if scan else "",
            scan_date=scan.created_at if scan else datetime.utcnow(),
            name=comp.name,
            version=comp.version,
            purl=comp.purl,
            risk_level=comp.risk_level,
            risk_score=comp.risk_score,
            vuln_count=vuln_count,
        ))

    return ComponentSearchOut(query=q, results=results, total=len(results))
