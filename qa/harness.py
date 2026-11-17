"""Property-based QA harness with differential oracle and counterexample shrinking.

Design goals
------------
* Independence: the oracle lives in ``qa/reference_model.py`` and does not import
  the production package, so a shared bug cannot make these checks vacuous.
* Determinism: every failure is reproducible from ``(seed, case_index)``.
* Shrinking: a failing payload is reduced to a minimal payload that still fails,
  which makes a counterexample directly actionable by layer.

The harness exercises the public orchestration boundary (``pipeline.run``) plus
the sealed envelope, and re-derives expectations from the oracle.  Payload-level
structural errors (non-list ``instances`` or invalid allow-list values) are
covered by dedicated unit tests, not by the random generator.
"""

from __future__ import annotations

import json
import random
from typing import Any, Callable, Dict, List, Optional, Tuple

import reference_model as oracle
import invariants

# Stable reason vocabulary emitted by the production pipeline.
KNOWN_REASONS = frozenset(
    {
        "invalid_record",
        "invalid_private",
        "invalid_private_tags",
        "invalid_modality",
        "invalid_field:patient",
        "invalid_uid:study",
        "invalid_uid:series",
        "invalid_uid:instance",
        "missing_field:patient",
        "missing_field:study",
        "missing_field:series",
        "missing_field:instance",
        "missing_field:modality",
        "private_record",
        "private_tag",
        "modality_not_allowed",
        "hierarchy_conflict:study",
        "hierarchy_conflict:series",
        "uid_conflict:instance",
        "duplicate_instance",
        "conflicting_duplicate",
    }
)

VALID_MODALITIES = ("CT", "MR", "US", "PT", "XA", "NM", "OT")
UID_POOL = (
    "1",
    "1.2",
    "1.2.3",
    "2.25.329800735698586629295641978511506172918",
    "0.0",
    "1.2.840.10008.5.1.4.1.1.2",
    # Invalid on purpose.
    "",
    "01.2",
    "1..2",
    "1.2.",
    ".1.2",
    "1.2.3.",
    "1.2.3 ",
    "abc",
    "1.2.3.4.5.6.7.8.9.0." + "9" * 60,
    "1,2,3",
    "-1.2",
)
PATIENT_POOL = (
    "PATIENT-ALPHA",
    "PATIENT-BETA",
    "p-alpha",
    "",
    "bad patient",
    "P" * 65,
    "patient/with:punctuation",
)
EXTRA_VALUES = ("PRIVATE-EXTRA-VALUE", "vendor-secret", "extra")
PRIVATE_TAG_VALUES = ("0010,0010", "0008,0070", "PRIVATE-TAG-VALUE")


def _uid(rng: random.Random) -> str:
    return rng.choice(UID_POOL)


def random_row(rng: random.Random) -> Any:
    """Generate one row, occasionally a non-object, covering every field path."""

    roll = rng.random()
    if roll < 0.06:
        return rng.choice([None, 3, "not-a-row", [], ["x"], 3.5, True])

    row: Dict[str, Any] = {}
    fields = {
        "patient": rng.choice(PATIENT_POOL),
        "study": _uid(rng),
        "series": _uid(rng),
        "instance": _uid(rng),
        "modality": rng.choice(VALID_MODALITIES + ("ct", "Mr", "us", "pt")),
    }
    for name, value in fields.items():
        if rng.random() < 0.94:
            row[name] = value

    if rng.random() < 0.45:
        row["private"] = rng.choice([True, False])
    if rng.random() < 0.15:
        row["private"] = rng.choice([None, "yes", 1])
    if rng.random() < 0.20:
        row["private_tags"] = rng.choice(
            [[], [rng.choice(PRIVATE_TAG_VALUES)], [rng.choice(PRIVATE_TAG_VALUES)] * 2,
             [1], None, "0010,0010"]
        )
    if rng.random() < 0.12:
        row["extra_field"] = rng.choice(EXTRA_VALUES)
    if rng.random() < 0.06:
        row["patient_alias"] = "ALIAS-" + rng.choice(EXTRA_VALUES)
    return row


def random_payload(rng: random.Random) -> Dict[str, Any]:
    rows = [random_row(rng) for _ in range(rng.randrange(0, 8))]
    allowed = [
        modality
        for modality in VALID_MODALITIES
        if rng.random() < 0.5
    ]
    if rng.random() < 0.5:
        # Duplicate identities and hierarchy collisions are frequent enough to
        # matter, but not so frequent that ordinary rows disappear.
        if rows and isinstance(rows[0], dict):
            rows.append(dict(rows[0]))
        if rows and isinstance(rows[0], dict) and rng.random() < 0.5:
            clone = dict(rows[0])
            clone["modality"] = rng.choice(VALID_MODALITIES + ("ct",))
            clone["private"] = rng.choice([True, False])
            rows.append(clone)
    return {"instances": rows, "allowed_modalities": allowed}


def _string_leaves(value: Any) -> List[str]:
    leaves: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            leaves.append(str(key))
            leaves.extend(_string_leaves(item))
    elif isinstance(value, list):
        for item in value:
            leaves.extend(_string_leaves(item))
    elif isinstance(value, str):
        leaves.append(value)
    return leaves


def _raw_values(payload: Dict[str, Any]) -> List[str]:
    """Values that must never appear verbatim (or as long substrings) in output."""

    values: List[str] = []
    for row in payload.get("instances", []):
        if not isinstance(row, dict):
            continue
        patient = row.get("patient")
        if isinstance(patient, str) and patient:
            values.append(patient)
        for key, value in row.items():
            if key in ("patient", "study", "series", "instance", "modality"):
                continue
            if isinstance(value, str) and value:
                values.append(value)
            elif isinstance(value, list):
                values.extend(
                    item for item in value if isinstance(item, str) and item
                )
    return values


def sealed_view(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "input_count": result["input_count"],
        "manifest": result["manifest"],
        "rejected": result["rejected"],
    }


def check_payload(run: Callable[[Dict[str, Any]], Dict[str, Any]],
                  payload: Dict[str, Any]) -> Optional[str]:
    """Return a failure description, or ``None`` when every property holds."""

    result = run(payload)
    expected = oracle.evaluate(payload)

    if sealed_view(result) != expected:
        return "differential mismatch:\n  got=%s\n  expected=%s" % (
            json.dumps(sealed_view(result), sort_keys=True),
            json.dumps(expected, sort_keys=True),
        )

    # Conservation: every input row is either published or quarantined.
    if result["published_count"] + result["quarantined_count"] != result["input_count"]:
        return "conservation violated"
    if result["published_count"] != len(result["manifest"]):
        return "published_count disagrees with manifest length"
    if result["quarantined_count"] != len(result["rejected"]):
        return "quarantined_count disagrees with rejected length"

    # Auditability: every rejection carries stable, known reason codes and an
    # opaque ref; no rejection may carry raw identifiers.
    for rejection in result["rejected"]:
        if set(rejection) != {"ref", "reasons"}:
            return "rejection has unexpected shape: %r" % (rejection,)
        if not rejection["reasons"]:
            return "rejection without reasons: %r" % (rejection,)
        for reason in rejection["reasons"]:
            if reason not in KNOWN_REASONS:
                return "unknown reason code: %r" % (reason,)
        if not rejection["ref"].startswith("ref-"):
            return "rejection ref is not opaque: %r" % (rejection["ref"],)

    # Canonical ordering: independently sorted copy must equal the output.
    manifest_key = lambda entry: (
        entry["study"], entry["series"], entry["instance"],
        entry["patient"], entry["modality"],
    )
    if result["manifest"] != sorted(result["manifest"], key=manifest_key):
        return "manifest is not canonically ordered"
    rejection_key = lambda rejection: (rejection["ref"], tuple(rejection["reasons"]))
    if result["rejected"] != sorted(result["rejected"], key=rejection_key):
        return "rejections are not canonically ordered"

    # Duplicate replay: publishing at most one row per identity.
    identities = [
        (entry["study"], entry["series"], entry["instance"], entry["patient"])
        for entry in result["manifest"]
    ]
    if len(identities) != len(set(identities)):
        return "duplicate identity survived into manifest"

    # Leakage: no raw identifier or private extra may appear in the JSON output.
    # Values that are legitimately publishable identity/UID fields are excluded,
    # so a private-tag value that coincidentally equals a published UID is not a
    # false positive.
    legitimate = set()
    for entry in result["manifest"]:
        legitimate.update(
            entry[key]
            for key in ("study", "series", "instance", "modality")
        )
    leaves = _string_leaves(result)
    serialised = json.dumps(result, ensure_ascii=False, sort_keys=True)
    for raw in _raw_values(payload):
        if raw in legitimate:
            continue
        if raw in leaves:
            return "raw value leaked verbatim: %r" % (raw,)
        if len(raw) >= 6 and raw in serialised:
            return "raw value leaked as substring: %r" % (raw,)

    # Cross-layer structural invariants (shared-bug safety net).
    for problem in invariants.check(result, payload, run):
        return "invariant violated: " + problem

    # Path independence: a permutation must produce byte-identical semantics.
    rng = random.Random(0xC0FFEE)
    for _ in range(3):
        shuffled = list(payload.get("instances", []))
        rng.shuffle(shuffled)
        permuted = dict(payload)
        permuted["instances"] = shuffled
        if sealed_view(run(permuted)) != sealed_view(result):
            return "output depends on input order"

    return None


# ---------------------------------------------------------------------------
# Counterexample shrinking
# ---------------------------------------------------------------------------

_SIMPLIFICATIONS: Tuple[Tuple[str, Any], ...] = (
    ("patient", "P1"),
    ("study", "1"),
    ("series", "1.2"),
    ("instance", "1.2.3"),
    ("modality", "CT"),
)


def _candidates(payload: Dict[str, Any]):
    """Yield structurally smaller/simpler payloads, deterministic order."""

    rows = list(payload.get("instances", []))

    for index in range(len(rows)):
        candidate = dict(payload)
        candidate["instances"] = rows[:index] + rows[index + 1:]
        yield candidate

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            candidate = dict(payload)
            candidate["instances"] = rows[:index] + [{}] + rows[index + 1:]
            yield candidate
            continue

        for key in sorted(set(row) - {
            "patient", "study", "series", "instance", "modality"
        }):
            smaller = dict(row)
            del smaller[key]
            candidate = dict(payload)
            candidate["instances"] = rows[:index] + [smaller] + rows[index + 1:]
            yield candidate

        for key, simple in _SIMPLIFICATIONS:
            if key in row and row[key] != simple:
                simpler = dict(row)
                simpler[key] = simple
                candidate = dict(payload)
                candidate["instances"] = rows[:index] + [simpler] + rows[index + 1:]
                yield candidate

    for index in range(len(payload.get("allowed_modalities", []))):
        candidate = dict(payload)
        candidate["allowed_modalities"] = (
            payload["allowed_modalities"][:index]
            + payload["allowed_modalities"][index + 1:]
        )
        yield candidate


def shrink(payload: Dict[str, Any],
           predicate: Callable[[Dict[str, Any]], Optional[str]]) -> Tuple[Dict[str, Any], str]:
    """Greedy 1-minimal reduction of a failing payload."""

    current = payload
    failure = predicate(current)
    if failure is None:
        raise ValueError("cannot shrink a passing payload")

    improved = True
    while improved:
        improved = False
        for candidate in _candidates(current):
            candidate_failure = predicate(candidate)
            if candidate_failure is not None:
                current = candidate
                failure = candidate_failure
                improved = True
                break
    return current, failure


def run_properties(run: Callable[[Dict[str, Any]], Dict[str, Any]],
                   seed: int = 20240101, cases: int = 500,
                   shrink_failures: bool = True) -> List[Dict[str, Any]]:
    """Run ``cases`` random payloads; return reproducible failure records."""

    rng = random.Random(seed)
    failures: List[Dict[str, Any]] = []
    for index in range(cases):
        payload = random_payload(rng)

        def predicate(candidate: Dict[str, Any]) -> Optional[str]:
            return check_payload(run, candidate)

        failure = predicate(payload)
        if failure is not None:
            record: Dict[str, Any] = {
                "seed": seed,
                "case": index,
                "failure": failure,
            }
            if shrink_failures:
                minimal, minimal_failure = shrink(payload, predicate)
                record["payload"] = minimal
                record["minimal_failure"] = minimal_failure
            else:
                record["payload"] = payload
            failures.append(record)
            if len(failures) >= 5:
                break
    return failures
