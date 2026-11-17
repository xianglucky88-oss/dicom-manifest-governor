"""Input validation and record extraction for DICOM manifest payloads.

This is the only module that reads untrusted payload shapes.  It fails closed
on structural contract violations and records per-row problems as stable,
machine-readable reason codes.  Raw identifiers are never copied into rejection
records; ``Record.ref`` is an opaque digest suitable for an audit trail.

Identifier contract
-------------------
``study``, ``series`` and ``instance`` are DICOM UIDs: dot-separated numeric
components without leading zeroes, at most 64 characters.  ``modality`` is
case-insensitive and normalised to upper case by the domain layer.  ``patient``
is an opaque patient identifier and is never published verbatim.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Tuple

from .models import InputError, ParsedPayload, Record

REQUIRED_FIELDS: Tuple[str, ...] = (
    "patient",
    "study",
    "series",
    "instance",
    "modality",
)

_UID_MAX_LENGTH = 64
# DICOM UID: components are decimal without leading zeroes; no empty component.
_UID_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*\Z")
_PATIENT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}\Z")
_MODALITY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,15}\Z")


def canonical_json(value: Any) -> str:
    """Canonical, deterministic JSON used only for digesting."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=repr,
    )


def make_ref(*parts: Any) -> str:
    """Return a stable, non-reversible audit reference."""

    digest = hashlib.sha256("\x1f".join(map(str, parts)).encode("utf-8")).hexdigest()
    return "ref-" + digest[:16]


def _row_ref(row: Any) -> str:
    return make_ref("row", canonical_json(row))


def _is_patient(value: Any) -> bool:
    return isinstance(value, str) and bool(_PATIENT_RE.fullmatch(value))


def _is_uid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _UID_MAX_LENGTH
        and bool(_UID_RE.fullmatch(value))
    )


def _is_modality(value: Any) -> bool:
    return isinstance(value, str) and bool(_MODALITY_RE.fullmatch(value))


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _structural_reasons(row: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    for name in REQUIRED_FIELDS:
        if name not in row:
            reasons.append("missing_field:" + name)

    if "patient" in row and not _is_patient(row.get("patient")):
        reasons.append("invalid_field:patient")

    for name in ("study", "series", "instance"):
        if name in row and not _is_uid(row.get(name)):
            reasons.append("invalid_uid:" + name)

    if "modality" in row and not _is_modality(row.get("modality")):
        reasons.append("invalid_modality")

    if "private" in row and not isinstance(row.get("private"), bool):
        reasons.append("invalid_private")

    if "private_tags" in row:
        tags = row.get("private_tags")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            reasons.append("invalid_private_tags")

    return reasons


def parse_row(index: int, row: Any) -> Record:
    """Parse one row without raising; all row problems become reason codes."""

    if not isinstance(row, dict):
        return Record(
            patient="",
            study="",
            series="",
            instance="",
            modality="",
            reasons=("invalid_record",),
            ref=_row_ref(row),
        )

    reasons = _structural_reasons(row)
    private_flag = row.get("private", False) is True
    private_tags = row.get("private_tags", [])
    has_private_tags = isinstance(private_tags, list) and bool(private_tags)

    content_key = canonical_json(row)
    ref = (
        "ref-" + hashlib.sha256(("row\x1f" + content_key).encode("utf-8")).hexdigest()[:16]
        if reasons
        else make_ref(
            "identity",
            _text(row.get("patient")),
            _text(row.get("study")),
            _text(row.get("series")),
            _text(row.get("instance")),
        )
    )

    return Record(
        patient=_text(row.get("patient")),
        study=_text(row.get("study")),
        series=_text(row.get("series")),
        instance=_text(row.get("instance")),
        modality=_text(row.get("modality")),
        private=private_flag or has_private_tags,
        private_flag=private_flag,
        has_private_tags=has_private_tags,
        reasons=tuple(sorted(set(reasons))),
        ref=ref,
        content_key=content_key,
        identity_ok=not reasons,
    )


def parse_rows(rows: Iterable[Any]) -> Tuple[Record, ...]:
    return tuple(parse_row(index, row) for index, row in enumerate(rows))


def _collect_patients(rows: Iterable[Any]) -> Tuple[str, ...]:
    """Collect raw patient identifiers for the report's re-identification guard.

    Only the five published keys exist in a manifest entry; every other field
    (private tags, unknown extras) is dropped structurally by the report layer
    rather than string-matched.
    """

    patients = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        patient = row.get("patient")
        if isinstance(patient, str) and patient:
            patients.add(patient)
    return tuple(sorted(patients))


def _allowed_modalities(payload: Dict[str, Any]) -> frozenset:
    raw = payload.get("allowed_modalities", [])
    if not isinstance(raw, list):
        raise InputError(
            "allowed_modalities_not_list", "allowed_modalities must be a list"
        )

    allowed = set()
    for position, value in enumerate(raw):
        if not _is_modality(value):
            raise InputError(
                "allowed_modalities_invalid_entry",
                "allowed_modalities[%d] is not a valid modality" % position,
            )
        allowed.add(value.upper())
    return frozenset(allowed)


def load_records(payload: Dict[str, Any]) -> ParsedPayload:
    """Validate payload structure and return immutable parsed records."""

    if not isinstance(payload, dict):
        raise InputError("payload_not_object", "payload must be a JSON object")

    rows = payload.get("instances", [])
    if not isinstance(rows, list):
        raise InputError("instances_not_list", "instances must be a list")

    allowed = _allowed_modalities(payload)
    records = parse_rows(rows)
    return ParsedPayload(
        records=records,
        allowed_modalities=allowed,
        input_count=len(rows),
        patient_values=_collect_patients(rows),
    )
