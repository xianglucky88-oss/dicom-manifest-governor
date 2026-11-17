"""Domain calculation: policy, hierarchy, conflict resolution, aggregation.

This layer never reads untrusted shapes directly (the parser has already done
that) and never serialises anything (the report layer seals the envelope).  Its
sole job is deterministic decisions and canonical ordering.

Semantic rules
--------------
* A row is structurally rejected if the parser attached any reason code.
* Private rows (``private: true`` or any non-empty ``private_tags``) are
  quarantined even when their modality is allowed.
* Modality matching is case-insensitive; published modalities are upper-cased.
* Studies that span patients and series that span studies are hierarchy
  conflicts and are quarantined with ``hierarchy_conflict:*``.
* Duplicate ``(patient, study, series, instance)`` identities are published at
  most once.  The canonical winner is chosen from content alone; every other
  copy is quarantined with ``duplicate_instance`` and, when its content
  disagrees with the winner, ``conflicting_duplicate``.
* ``patient`` is pseudonymised before publication; raw identifiers never enter
  the manifest or rejection records.
* Manifest entries and rejections are sorted canonically, so identical input
  multisets produce byte-identical output regardless of input order.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple  # Any: mutable (record, reasons) pairs

from .models import Evaluation, ManifestEntry, ParsedPayload, Record, Rejection


def pseudonym(patient: str) -> str:
    return "pt-" + hashlib.sha256(patient.encode("utf-8")).hexdigest()[:10]


def _policy_reasons(record: Record, allowed: frozenset) -> List[str]:
    reasons: List[str] = []
    if record.has_private_tags:
        reasons.append("private_tag")
    if record.private_flag:
        reasons.append("private_record")
    if record.modality.upper() not in allowed:
        reasons.append("modality_not_allowed")
    return reasons


def _identity(record: Record) -> Tuple[str, str, str, str]:
    return (record.patient, record.study, record.series, record.instance)


def _priority(record: Record, allowed: frozenset) -> Tuple:
    """Order-independent winner ordering for one identity.

    Prefer an allowed modality, then a public row, then a stable content key so
    the winner never depends on input position.
    """

    return (
        record.modality.upper() not in allowed,
        record.private,
        record.private_flag,
        record.has_private_tags,
        record.modality.upper(),
        record.content_key,
    )


def evaluate(parsed: ParsedPayload) -> Evaluation:
    allowed = parsed.allowed_modalities

    # Cross-record hierarchy index over structurally valid rows only.
    study_owner: Dict[str, set] = {}
    series_owner: Dict[str, set] = {}
    instance_owner: Dict[str, set] = {}
    for record in parsed.records:
        if record.reasons or not record.identity_ok:
            continue
        study_owner.setdefault(record.study, set()).add(record.patient)
        series_owner.setdefault(record.series, set()).add(record.study)
        instance_owner.setdefault(record.instance, set()).add(
            (record.study, record.series)
        )

    base: List[List[Any]] = []
    for record in parsed.records:
        reasons: List[str] = list(record.reasons)
        if not reasons and record.identity_ok:
            if len(study_owner.get(record.study, ())) > 1:
                reasons.append("hierarchy_conflict:study")
            if len(series_owner.get(record.series, ())) > 1:
                reasons.append("hierarchy_conflict:series")
            if len(instance_owner.get(record.instance, ())) > 1:
                reasons.append("uid_conflict:instance")
            reasons.extend(_policy_reasons(record, allowed))
        base.append([record, sorted(set(reasons))])

    # Group every structurally valid row by identity, even if it already has a
    # policy reason, so duplicates and content conflicts are always auditable.
    groups: Dict[Tuple[str, str, str, str], List[int]] = {}
    for index, (record, _) in enumerate(base):
        if record.identity_ok:
            groups.setdefault(_identity(record), []).append(index)

    for indexes in groups.values():
        if len(indexes) < 2:
            continue
        ordered = sorted(indexes, key=lambda i: _priority(base[i][0], allowed))
        winner = ordered[0]
        winner_signature = (
            base[winner][0].modality.upper(),
            base[winner][0].private,
        )
        for index in ordered[1:]:
            record = base[index][0]
            extra = ["duplicate_instance"]
            if (record.modality.upper(), record.private) != winner_signature:
                extra.append("conflicting_duplicate")
            base[index][1] = sorted(set(base[index][1]).union(extra))
    manifest: List[ManifestEntry] = []
    rejected: List[Rejection] = []
    for record, reasons in base:
        if reasons:
            rejected.append(Rejection(ref=record.ref, reasons=tuple(reasons)))
            continue
        manifest.append(
            ManifestEntry(
                patient=pseudonym(record.patient),
                study=record.study,
                series=record.series,
                instance=record.instance,
                modality=record.modality.upper(),
            )
        )

    manifest.sort(
        key=lambda entry: (
            entry.study,
            entry.series,
            entry.instance,
            entry.patient,
            entry.modality,
        )
    )
    rejected.sort(key=lambda rejection: (rejection.ref, rejection.reasons))

    return Evaluation(
        manifest=tuple(manifest),
        rejected=tuple(rejected),
        input_count=parsed.input_count,
    )
