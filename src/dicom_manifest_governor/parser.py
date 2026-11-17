"""Input validation and record extraction.

Malformed rows are never silently dropped: ``parse_records`` returns them as
structured input errors which block commit unless the batch is explicitly
accepted as partial. ``load_records`` keeps the original strict contract for
the legacy in-memory path.
"""
from __future__ import annotations

REQUIRED_ID_FIELDS = ("patient", "study", "series", "instance")

# Placeholder tag for the legacy boolean ``private`` flag so old payloads get
# the same deny behaviour through the private-tag allowlist mechanism.
LEGACY_PRIVATE_TAG = "__legacy_private__"


def _as_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return str(value)
    if not isinstance(value, str):
        raise ValueError("identifier fields must be strings")
    return value.strip()


def _normalize_file_hash(value) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("file_hash must be a string")
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:"):]
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("file_hash must be a sha256 hex digest")
    return "sha256:" + text


def normalize_record(row: dict, index: int = 0) -> dict:
    if not isinstance(row, dict):
        raise ValueError("row_not_object")
    private_tags = row.get("private_tags", [])
    if not isinstance(private_tags, list) or not all(isinstance(t, str) for t in private_tags):
        raise ValueError("private_tags must be a list of strings")
    tags = sorted(set(private_tags))
    if row.get("private"):
        tags.append(LEGACY_PRIVATE_TAG)

    sensitive = row.get("sensitive_fields", {})
    if not isinstance(sensitive, dict):
        raise ValueError("sensitive_fields must be an object")
    sensitive = {str(k): ("" if v is None else str(v)) for k, v in sensitive.items()}

    pixels_raw = row.get("pixels")
    if pixels_raw is None:
        # Fail closed: unknown pixel state is treated as present so a "deny"
        # policy cannot be bypassed by omitting the field.
        pixels = {"present": True, "burned_in_annotation": False}
    elif isinstance(pixels_raw, dict):
        pixels = {
            "present": bool(pixels_raw.get("present", True)),
            "burned_in_annotation": bool(pixels_raw.get("burned_in_annotation", False)),
        }
    else:
        raise ValueError("pixels must be an object")

    referenced_study = row.get("referenced_study")
    referenced_series = row.get("referenced_series")

    return {
        "patient": _as_str(row.get("patient")),
        "study": _as_str(row.get("study")),
        "series": _as_str(row.get("series")),
        "instance": _as_str(row.get("instance")),
        "modality": _as_str(row.get("modality")) or None,
        "protocol": _as_str(row.get("protocol")) or None,
        "private_tags": tags,
        "sensitive_fields": sensitive,
        "pixels": pixels,
        "file_hash": _normalize_file_hash(row.get("file_hash")),
        "referenced_study": _as_str(referenced_study) or None,
        "referenced_series": _as_str(referenced_series) or None,
        "source_path": _as_str(row.get("source_path")) or None,
        "row_index": index,
    }


def parse_records(payload: dict):
    """Returns (records, input_errors). Never raises on row-level problems."""
    errors = []
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    rows = payload.get("instances", [])
    if not isinstance(rows, list):
        raise ValueError("instances must be a list")
    records = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append({"index": index, "error": "row_not_object"})
            continue
        try:
            records.append(normalize_record(row, index))
        except ValueError as exc:
            errors.append({"index": index, "error": str(exc)})
    return records, errors


def load_records(payload: dict) -> list[dict]:
    """Legacy strict loader: any malformed row is an error, not a silent drop."""
    records, errors = parse_records(payload)
    if errors:
        raise ValueError("invalid instance rows: " + "; ".join(
            f"row {e['index']}: {e['error']}" for e in errors))
    return records
