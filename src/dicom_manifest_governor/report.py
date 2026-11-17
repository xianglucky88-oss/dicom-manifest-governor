"""Stable, leak-free output envelope.

The report layer receives an already-computed :class:`Evaluation` plus the
values that must never appear verbatim in output and seals the response:

* published manifest values are checked against the forbidden set;
* every rejection carries at least one stable reason code;
* the envelope is built in a fixed key order and contains only allow-listed
  manifest keys, so raw input rows can never ride along.
"""

from __future__ import annotations

import json
from typing import Any, Dict, FrozenSet, List

from .models import Evaluation, InvariantError, PipelineResult

PROJECT = "dicom-manifest-governor"
SCHEMA_VERSION = "1.0"

_PUBLISHED_KEYS = ("patient", "study", "series", "instance", "modality")


def _assert_no_leak(value: str, forbidden: FrozenSet[str], where: str) -> None:
    if value in forbidden:
        raise InvariantError("forbidden value leaked into " + where)


def _manifest_rows(
    evaluation: Evaluation, raw_patients: FrozenSet[str]
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for entry in evaluation.manifest:
        # Built field-by-field from the sealed dataclass only; no input dict is
        # ever spread into the output, so private tags and extras cannot ride
        # along structurally.
        row = {
            "patient": entry.patient,
            "study": entry.study,
            "series": entry.series,
            "instance": entry.instance,
            "modality": entry.modality,
        }
        if tuple(row) != _PUBLISHED_KEYS:
            raise InvariantError("manifest row has unexpected shape")
        # Re-identification guard: the manifest must never publish a raw patient
        # identifier, only its pseudonym.
        _assert_no_leak(row["patient"], raw_patients, "manifest.patient")
        rows.append(row)
    return rows


def _rejection_rows(evaluation: Evaluation) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rejection in evaluation.rejected:
        if not rejection.reasons:
            raise InvariantError("rejected row lacks an auditable reason")
        for reason in rejection.reasons:
            if not isinstance(reason, str) or not reason:
                raise InvariantError("rejection reason is not a stable code")
        rows.append({"ref": rejection.ref, "reasons": list(rejection.reasons)})
    return rows


def check_conservation(evaluation: Evaluation) -> None:
    published = len(evaluation.manifest)
    quarantined = len(evaluation.rejected)
    if published + quarantined != evaluation.input_count:
        raise InvariantError(
            "published+quarantined=%d != input_count=%d"
            % (published + quarantined, evaluation.input_count)
        )


def build_result(
    project: str,
    evaluation: Evaluation,
    raw_patients: FrozenSet[str] = frozenset(),
) -> Dict[str, Any]:
    check_conservation(evaluation)
    manifest = _manifest_rows(evaluation, frozenset(raw_patients))
    rejected = _rejection_rows(evaluation)
    result = PipelineResult(
        project=project,
        data={
            "schema_version": SCHEMA_VERSION,
            "published_count": len(manifest),
            "quarantined_count": len(rejected),
            "input_count": evaluation.input_count,
            "manifest": manifest,
            "rejected": rejected,
        },
    )
    return {"project": result.project, "status": "ok", **result.data}


def dumps(result: Dict[str, Any]) -> str:
    """Deterministic serialisation used by the CLI and golden tests."""

    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
