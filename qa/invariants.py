"""Cross-layer invariants that do not depend on the reference model.

These checks reason only about the sealed envelope.  They are deliberately
redundant with the differential oracle so that a bug shared by the oracle and
the implementation still collides with a structural fact.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List


def _identities(manifest: List[Dict[str, str]]) -> List[tuple]:
    return [
        (entry["study"], entry["series"], entry["instance"], entry["patient"])
        for entry in manifest
    ]


def check(
    result: Dict[str, Any],
    payload: Dict[str, Any],
    run: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> List[str]:
    problems: List[str] = []

    # Conservation.  Non-dict payloads never reach this helper.
    if result["published_count"] + result["quarantined_count"] != result["input_count"]:
        problems.append("conservation")

    # One published row per hierarchy identity.
    identities = _identities(result["manifest"])
    if len(identities) != len(set(identities)):
        problems.append("duplicate identity published")

    # Every manifest entry is fully populated and uses a pseudonym.
    for entry in result["manifest"]:
        if set(entry) != {"patient", "study", "series", "instance", "modality"}:
            problems.append("manifest entry shape")
        if not entry["patient"].startswith("pt-"):
            problems.append("unpseudonymised patient")
        if entry["modality"] != entry["modality"].upper():
            problems.append("modality not normalised")

    # Auditability of every quarantine.
    for rejection in result["rejected"]:
        if not rejection.get("reasons"):
            problems.append("reasonless rejection")
        if not rejection.get("ref", "").startswith("ref-"):
            problems.append("non-opaque rejection ref")

    # Path independence: reverse and rotate the rows.
    instances = payload.get("instances", [])
    if isinstance(instances, list) and len(instances) > 1:
        variants = [list(reversed(instances)), instances[1:] + instances[:1]]
        baseline = _sealed(result)
        for variant in variants:
            permuted = dict(payload)
            permuted["instances"] = variant
            try:
                candidate = run(permuted)
            except Exception:
                problems.append("permutation raised")
                continue
            if _sealed(candidate) != baseline:
                problems.append("output depends on input order")

    # No raw patient identifier in the serialised envelope.
    serialised = json.dumps(result, sort_keys=True)
    for row in instances if isinstance(instances, list) else []:
        if isinstance(row, dict):
            patient = row.get("patient")
            if isinstance(patient, str) and patient and patient in serialised:
                problems.append("raw patient leaked")
                break

    return problems


def _sealed(result: Dict[str, Any]) -> Any:
    return (
        result["input_count"],
        json.dumps(result["manifest"], sort_keys=True),
        json.dumps(result["rejected"], sort_keys=True),
    )
