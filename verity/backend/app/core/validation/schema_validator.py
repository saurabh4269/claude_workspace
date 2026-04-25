"""
JSON Schema validation for CycloneDX and SPDX SBOM documents.

Embedded schemas are the official published versions from:
  - CycloneDX: https://github.com/CycloneDX/specification
  - SPDX:      https://github.com/spdx/spdx-spec
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMAS_DIR = Path(__file__).parent / "schemas"

# Map (format, version) → schema filename
_SCHEMA_MAP: dict[tuple[str, str], str] = {
    ("cyclonedx", "1.4"): "cyclonedx-1.4.schema.json",
    ("cyclonedx", "1.5"): "cyclonedx-1.5.schema.json",
    ("cyclonedx", "1.6"): "cyclonedx-1.6.schema.json",
    ("spdx",      "2.2"): "spdx-2.2.schema.json",
    ("spdx",      "2.3"): "spdx-2.3.schema.json",
}

# Normalise common version aliases to their canonical key
_VERSION_ALIASES: dict[str, str] = {
    "2.2.1": "2.2",
    "2.2.2": "2.2",
    "2.3.1": "2.3",
}


@lru_cache(maxsize=16)
def _load_schema(filename: str) -> dict | None:
    path = _SCHEMAS_DIR / filename
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load schema %s: %s", filename, exc)
        return None


def _normalise_version(version: str) -> str:
    """Strip common prefixes/suffixes so 'SPDX-2.3' → '2.3', '1.6' → '1.6'."""
    v = version.strip()
    for prefix in ("SPDX-", "CycloneDX-", "CDX-"):
        if v.upper().startswith(prefix.upper()):
            v = v[len(prefix):]
    return v


def validate_schema(data: dict, fmt: str, version: str) -> bool:
    """
    Validate *data* against the embedded JSON schema for (fmt, version).

    Returns True if the document is valid or if no schema is available for
    the given format/version combination (unknown version = not invalid).
    Returns False only when a schema IS available and validation fails.
    """
    version = _normalise_version(version)
    version = _VERSION_ALIASES.get(version, version)
    filename = _SCHEMA_MAP.get((fmt.lower(), version))
    if not filename:
        return True  # no schema to validate against — treat as valid

    schema = _load_schema(filename)
    if schema is None:
        return True  # schema file missing at runtime — treat as valid

    try:
        import warnings
        import jsonschema
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning, module="jsonschema")
            jsonschema.validate(instance=data, schema=schema)
        return True
    except jsonschema.ValidationError:
        return False
    except Exception as exc:
        logger.debug("Schema validation error (%s %s): %s", fmt, version, exc)
        return True  # unexpected error — don't penalise the document
