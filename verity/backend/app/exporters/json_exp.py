"""
JSON exporter for Verity scan results.
Converts a scan detail dict to a pretty-printed JSON string.
"""

import json


def export_json(scan_detail: dict) -> str:
    """
    Serialize a scan result dict to a pretty-printed JSON string.

    Args:
        scan_detail: Full scan result dictionary (typically from ScanDetailOut.model_dump()).

    Returns:
        JSON string with 2-space indentation and sorted keys for consistency.
    """
    return json.dumps(scan_detail, indent=2, sort_keys=False, default=_json_default)


def _json_default(obj):
    """
    Fallback serializer for types that are not natively JSON-serializable.
    Handles datetime objects and objects with a model_dump method (Pydantic models).
    """
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)
