"""Independent reference model (oracle) for the manifest governor.

This module is intentionally a separate, deliberately naive re-implementation of
the documented semantics.  It must NOT import the production modules: if it did,
a shared bug would make the property tests vacuous.  Keep it slow and obvious.

Reference semantics
-------------------
1. Structural validation per row (``missing_field:*``, ``invalid_uid:*``,
   ``invalid_field:patient``, ``invalid_modality``, ``invalid_private``,
   ``invalid_private_tags``, ``invalid_record``).
2. Policy and cross-record checks apply only to structurally valid rows.
3. Cross-record hierarchy: a study owned by >1 patient, a series owned by >1
   study, or an instance UID under >1 (study, series) yields
   ``hierarchy_conflict:study`` / ``hierarchy_conflict:series`` /
   ``uid_conflict:instance`` for every affected row.
4. Privacy: ``private: true`` -> ``private_record``; non-empty
   ``private_tags`` -> ``private_tag``.  Either quarantines the row.
5. Modality allow-list is case-insensitive; disallowed ->
   ``modality_not_allowed``.
6. Duplicate identity ``(patient, study, series, instance)``: exactly one row is
   published (the canonical minimum of the total key below).  All others get
   ``duplicate_instance``; those differing from the winner in
   (modality, private) also get ``conflicting_duplicate``.
7. Published rows are pseudonymised, upper-cased, sorted by
   (study, series, instance, patient, modality).  Quarantined rows are sorted by
   (ref, reasons).  Input order must not matter.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Tuple

UID_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*\Z")
PATIENT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}\Z")
MODALITY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,15}\Z")
REQUIRED = ("patient", "study", "series", "instance", "modality")


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=repr
    )


def _digest(*parts: Any) -> str:
    raw = "\x1f".join(map(str, parts))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def row_ref(row: Any) -> str:
    return "ref-" + _digest("row", _canonical(row))


def identity_ref(patient: str, study: str, series: str, instance: str) -> str:
    return "ref-" + _digest("identity", patient, study, series, instance)


def pseudo(patient: str) -> str:
    return "pt-" + hashlib.sha256(patient.encode("utf-8")).hexdigest()[:10]


def structural_reasons(row: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for name in REQUIRED:
        if name not in row:
            out.append("missing_field:" + name)

    if "patient" in row:
        value = row.get("patient")
        if not (isinstance(value, str) and PATIENT_RE.fullmatch(value)):
            out.append("invalid_field:patient")

    for name in ("study", "series", "instance"):
        if name in row:
            value = row.get(name)
            ok = (
                isinstance(value, str)
                and 0 < len(value) <= 64
                and UID_RE.fullmatch(value)
            )
            if not ok:
                out.append("invalid_uid:" + name)

    if "modality" in row:
        value = row.get("modality")
        if not (isinstance(value, str) and MODALITY_RE.fullmatch(value)):
            out.append("invalid_modality")

    if "private" in row and not isinstance(row.get("private"), bool):
        out.append("invalid_private")

    if "private_tags" in row:
        tags = row.get("private_tags")
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            out.append("invalid_private_tags")

    return sorted(set(out))


def has_private_tags(row: Dict[str, Any]) -> bool:
    tags = row.get("private_tags", [])
    return isinstance(tags, list) and bool(tags)


def is_private(row: Dict[str, Any]) -> bool:
    return row.get("private") is True or has_private_tags(row)


def identity(row: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (row["patient"], row["study"], row["series"], row["instance"])


def winner_key(row: Dict[str, Any], allowed: frozenset) -> Tuple:
    modality = row.get("modality", "")
    return (
        modality.upper() not in allowed,
        is_private(row),
        row.get("private") is True,
        has_private_tags(row),
        modality.upper(),
        _canonical(row),
    )


def _cross_record(
    row: Dict[str, Any],
    study_owner: Dict[str, set],
    series_owner: Dict[str, set],
    instance_owner: Dict[str, set],
) -> List[str]:
    out: List[str] = []
    if len(study_owner.get(row["study"], ())) > 1:
        out.append("hierarchy_conflict:study")
    if len(series_owner.get(row["series"], ())) > 1:
        out.append("hierarchy_conflict:series")
    if len(instance_owner.get(row["instance"], ())) > 1:
        out.append("uid_conflict:instance")
    return out


def evaluate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{"input_count", "manifest", "rejected"}`` in sealed form."""

    rows = list(payload.get("instances", []))
    allowed = frozenset(m.upper() for m in payload.get("allowed_modalities", []))

    normalised: List[Dict[str, Any]] = []
    non_object: List[bool] = []
    for row in rows:
        if isinstance(row, dict):
            normalised.append(dict(row))
            non_object.append(False)
        else:
            normalised.append({"__non_object__": True})
            non_object.append(True)

    reasons: List[List[str]] = []
    refs: List[str] = []
    for original, row, bad in zip(rows, normalised, non_object):
        if bad:
            reasons.append(["invalid_record"])
            refs.append(row_ref(original))
            continue
        found = structural_reasons(row)
        reasons.append(found)
        if found:
            refs.append(row_ref(row))
        else:
            refs.append(
                identity_ref(row["patient"], row["study"], row["series"], row["instance"])
            )

    # Cross-record indexes over structurally valid rows only.
    study_owner: Dict[str, set] = {}
    series_owner: Dict[str, set] = {}
    instance_owner: Dict[str, set] = {}
    for row, bad, why in zip(normalised, non_object, reasons):
        if bad or why:
            continue
        study_owner.setdefault(row["study"], set()).add(row["patient"])
        series_owner.setdefault(row["series"], set()).add(row["study"])
        instance_owner.setdefault(row["instance"], set()).add(
            (row["study"], row["series"])
        )

    # Policy reasons for structurally valid rows.
    for index, (row, bad) in enumerate(zip(normalised, non_object)):
        if bad or reasons[index]:
            continue
        found = _cross_record(row, study_owner, series_owner, instance_owner)
        if row.get("private") is True:
            found.append("private_record")
        if has_private_tags(row):
            found.append("private_tag")
        if row["modality"].upper() not in allowed:
            found.append("modality_not_allowed")
        reasons[index] = sorted(set(found))

    # Duplicate resolution, grouping structurally valid rows by identity.
    groups: Dict[Tuple[str, str, str, str], List[int]] = {}
    for index, (row, bad) in enumerate(zip(normalised, non_object)):
        if bad or structural_reasons(row):
            continue
        groups.setdefault(identity(row), []).append(index)

    for indexes in groups.values():
        if len(indexes) < 2:
            continue
        ordered = sorted(indexes, key=lambda i: winner_key(normalised[i], allowed))
        winner = normalised[ordered[0]]
        signature = (winner["modality"].upper(), is_private(winner))
        for index in ordered[1:]:
            row = normalised[index]
            extra = ["duplicate_instance"]
            if (row["modality"].upper(), is_private(row)) != signature:
                extra.append("conflicting_duplicate")
            reasons[index] = sorted(set(reasons[index]).union(extra))

    manifest: List[Dict[str, str]] = []
    rejected: List[Dict[str, Any]] = []
    for row, bad, why, ref in zip(normalised, non_object, reasons, refs):
        if why:
            rejected.append({"ref": ref, "reasons": sorted(set(why))})
            continue
        manifest.append(
            {
                "patient": pseudo(row["patient"]),
                "study": row["study"],
                "series": row["series"],
                "instance": row["instance"],
                "modality": row["modality"].upper(),
            }
        )

    manifest.sort(
        key=lambda e: (
            e["study"],
            e["series"],
            e["instance"],
            e["patient"],
            e["modality"],
        )
    )
    rejected.sort(key=lambda r: (r["ref"], tuple(r["reasons"])))
    return {"input_count": len(rows), "manifest": manifest, "rejected": rejected}
