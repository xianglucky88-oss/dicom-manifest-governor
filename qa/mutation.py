"""Self-contained mutation testing for the governance package.

No third-party tooling is required (the environment has no ``pip``).  For each
mutation we copy the production package into a throw-away directory, apply one
surgical source edit, and run the QA suite in a fresh subprocess.  A mutation is
*killed* when the suite fails; *survived* when every check still passes.

The goal is not a coverage number but evidence that the QA gate is sensitive to
defects in each of the four layers:

* parser   -- relaxed UID / field validation, silent row dropping
* engine   -- dropped privacy/modality checks, order-dependent aggregation,
              missing duplicate or hierarchy handling
* report   -- leak / conservation / ordering guards disabled
* pipeline -- orchestration errors swallowed

Run: ``python qa/mutation.py`` (returns non-zero if the gate is weak).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "dicom_manifest_governor"


@dataclass(frozen=True)
class Mutation:
    name: str
    layer: str
    filename: str
    old: str
    new: str


MUTATIONS: List[Mutation] = [
    # ---- parser -----------------------------------------------------------
    Mutation(
        "parser_accepts_leading_zero_uid",
        "parser",
        "parser.py",
        r'_UID_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*\Z")',
        r'_UID_RE = re.compile(r"[0-9][0-9]*(?:\.[0-9][0-9]*)*\Z")',
    ),
    Mutation(
        "parser_skips_missing_field_check",
        "parser",
        "parser.py",
        """    for name in REQUIRED_FIELDS:
        if name not in row:
            reasons.append("missing_field:" + name)""",
        """    for name in REQUIRED_FIELDS:
        if False:
            reasons.append("missing_field:" + name)""",
    ),
    Mutation(
        "parser_drops_non_object_rows",
        "parser",
        "parser.py",
        """    if not isinstance(row, dict):
        return Record(
            patient="",
            study="",
            series="",
            instance="",
            modality="",
            reasons=("invalid_record",),
            ref=_row_ref(row),
        )""",
        """    if not isinstance(row, dict):
        return Record(
            patient="1", study="1", series="1", instance="1", modality="CT"
        )""",
    ),
    Mutation(
        "parser_ignores_private_tags",
        "parser",
        "parser.py",
        "has_private_tags = isinstance(private_tags, list) and bool(private_tags)",
        "has_private_tags = False",
    ),
    Mutation(
        "parser_private_nonbool_accepted",
        "parser",
        "parser.py",
        """    if "private" in row and not isinstance(row.get("private"), bool):
        reasons.append("invalid_private")""",
        """    if False:
        reasons.append("invalid_private")""",
    ),
    # ---- engine -----------------------------------------------------------
    Mutation(
        "engine_ignores_private_flag",
        "engine",
        "engine.py",
        """    if record.private_flag:
        reasons.append("private_record")""",
        """    if False:
        reasons.append("private_record")""",
    ),
    Mutation(
        "engine_case_sensitive_modality",
        "engine",
        "engine.py",
        "    if record.modality.upper() not in allowed:",
        "    if record.modality not in allowed:",
    ),
    Mutation(
        "engine_skips_duplicate_detection",
        "engine",
        "engine.py",
        """    for indexes in groups.values():
        if len(indexes) < 2:
            continue""",
        """    for indexes in groups.values():
        if True:
            continue""",
    ),
    Mutation(
        "engine_order_dependent_priority",
        "engine",
        "engine.py",
        """        ordered = sorted(indexes, key=lambda i: _priority(base[i][0], allowed))
        winner = ordered[0]""",
        """        ordered = list(indexes)
        winner = ordered[0]""",
    ),
    Mutation(
        "engine_skips_instance_conflict",
        "engine",
        "engine.py",
        """            if len(instance_owner.get(record.instance, ())) > 1:
                reasons.append("uid_conflict:instance")""",
        """            if False:
                reasons.append("uid_conflict:instance")""",
    ),
    Mutation(
        "engine_skips_study_conflict",
        "engine",
        "engine.py",
        """            if len(study_owner.get(record.study, ())) > 1:
                reasons.append("hierarchy_conflict:study")""",
        """            if False:
                reasons.append("hierarchy_conflict:study")""",
    ),
    Mutation(
        "engine_unsorted_manifest",
        "engine",
        "engine.py",
        """    manifest.sort(
        key=lambda entry: (
            entry.study,
            entry.series,
            entry.instance,
            entry.patient,
            entry.modality,
        )
    )
    rejected.sort(key=lambda rejection: (rejection.ref, rejection.reasons))""",
        """    pass""",
    ),
    Mutation(
        "engine_publishes_raw_patient",
        "engine",
        "engine.py",
        "                patient=pseudonym(record.patient),",
        "                patient=record.patient,",
    ),
    Mutation(
        "engine_drops_conflicting_duplicate",
        "engine",
        "engine.py",
        """            if (record.modality.upper(), record.private) != winner_signature:
                extra.append("conflicting_duplicate")""",
        """            if False:
                extra.append("conflicting_duplicate")""",
    ),
    # ---- report -----------------------------------------------------------
    Mutation(
        "report_skips_conservation",
        "report",
        "report.py",
        "    if published + quarantined != evaluation.input_count:",
        "    if False:",
    ),
    Mutation(
        "report_skips_leak_guard",
        "report",
        "report.py",
        "        _assert_no_leak(row[\"patient\"], raw_patients, \"manifest.patient\")",
        "        pass",
    ),
    Mutation(
        "report_reasonless_rejection_allowed",
        "report",
        "report.py",
        """        if not rejection.reasons:
            raise InvariantError("rejected row lacks an auditable reason")""",
        """        if False:
            raise InvariantError("rejected row lacks an auditable reason")""",
    ),
    # ---- pipeline ---------------------------------------------------------
    Mutation(
        "pipeline_swallows_all_errors",
        "pipeline",
        "pipeline.py",
        """    try:
        return run(payload)
    except InputError as error:""",
        """    try:
        return run(payload)
    except Exception as error:
        return run({"instances": [], "allowed_modalities": []})
    except InputError as error:""",
    ),
]


@dataclass
class Outcome:
    mutation: Mutation
    killed: bool
    detail: str


def _apply(mutation: Mutation, target: Path) -> bool:
    path = target / mutation.filename
    source = path.read_text(encoding="utf-8")
    if source.count(mutation.old) != 1:
        return False
    path.write_text(source.replace(mutation.old, mutation.new, 1), encoding="utf-8")
    return True


def _suite_command(workdir: Path) -> List[str]:
    return [
        sys.executable,
        "-I",
        str(ROOT / "qa" / "run_suite.py"),
        str(workdir / "src"),
        str(ROOT / "qa"),
    ]


def evaluate(mutation: Mutation, timeout: int = 120) -> Outcome:
    with tempfile.TemporaryDirectory(prefix="mutant-") as tmp:
        workdir = Path(tmp)
        shutil.copytree(SRC, workdir / "src" / "dicom_manifest_governor")
        if not _apply(mutation, workdir / "src" / "dicom_manifest_governor"):
            return Outcome(mutation, False, "PATCH-MISS")

        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            completed = subprocess.run(
                _suite_command(workdir),
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return Outcome(mutation, True, "timeout")
        if completed.returncode != 0:
            tail = (completed.stdout + completed.stderr).strip().splitlines()[-3:]
            return Outcome(mutation, True, " | ".join(tail))
        return Outcome(mutation, False, "survived")


def main(argv: Optional[List[str]] = None) -> int:
    only = None
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        only = set(arguments)

    outcomes = [
        evaluate(mutation)
        for mutation in MUTATIONS
        if only is None or mutation.layer in only or mutation.name in only
    ]

    survivors = [outcome for outcome in outcomes if not outcome.killed]
    for outcome in outcomes:
        status = "KILLED " if outcome.killed else "SURVIVED"
        print(
            "%-8s %-12s %-40s %s"
            % (status, outcome.mutation.layer, outcome.mutation.name, outcome.detail)
        )

    total = len(outcomes)
    killed = total - len(survivors)
    score = (100.0 * killed / total) if total else 100.0
    print("\nmutation score: %d/%d (%.1f%%)" % (killed, total, score))
    return 0 if not survivors else 1


if __name__ == "__main__":
    raise SystemExit(main())
