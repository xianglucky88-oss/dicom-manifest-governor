"""Fault injection around the orchestration, aggregation and report boundaries.

Each check simulates a specific layer misbehaving and asserts that the sealing
layers convert the fault into a deterministic, leak-free failure rather than a
silent bad report.  Faults are injected only into a live module object and are
always restored, so the checks are safe to run in-process.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List


def _row(**overrides: Any) -> Dict[str, Any]:
    row = {
        "patient": "PATIENT-ALPHA",
        "study": "1.2.840",
        "series": "1.2.840.1",
        "instance": "1.2.840.1.1",
        "modality": "CT",
    }
    row.update(overrides)
    return row


def run(pipeline: Any) -> List[str]:
    failures: List[str] = []
    failures.extend(_structural_errors_are_safe(pipeline))
    failures.extend(_report_rejects_bad_evaluation(pipeline))
    failures.extend(_faulty_engine_is_caught(pipeline))
    return failures


def _structural_errors_are_safe(pipeline: Any) -> List[str]:
    failures: List[str] = []
    sensitive = "PATIENT-ALPHA"

    cases = [
        ("payload_not_object", ["not", "an", "object"]),
        ("instances_not_list", {"instances": sensitive, "allowed_modalities": ["CT"]}),
        (
            "allowed_modalities_not_list",
            {"instances": [], "allowed_modalities": sensitive},
        ),
        (
            "allowed_modalities_invalid_entry",
            {
                "instances": [{"patient": sensitive, "study": "1", "series": "1.1",
                               "instance": "1.1.1", "modality": "CT"}],
                "allowed_modalities": ["not a modality!"],
            },
        ),
    ]

    for expected_code, payload in cases:
        envelope = pipeline.run_safe(payload)
        if envelope.get("status") != "error":
            failures.append("fault injection: %s did not fail closed" % expected_code)
            continue
        if envelope.get("error", {}).get("code") != expected_code:
            failures.append(
                "fault injection: expected error code %s, got %r"
                % (expected_code, envelope.get("error", {}).get("code"))
            )
        serialised = json.dumps(envelope, sort_keys=True)
        if sensitive in serialised:
            failures.append(
                "fault injection: %s error envelope echoed payload content"
                % expected_code
            )
    return failures


def _report_rejects_bad_evaluation(pipeline: Any) -> List[str]:
    failures: List[str] = []
    models = __import__("dicom_manifest_governor.models", fromlist=["*"])
    report = __import__("dicom_manifest_governor.report", fromlist=["*"])

    # A manifest row that publishes a raw patient identifier must be refused.
    leaking = models.Evaluation(
        manifest=(models.ManifestEntry(
            patient="PATIENT-ALPHA", study="1", series="1.1",
            instance="1.1.1", modality="CT",
        ),),
        rejected=(),
        input_count=1,
    )
    if not _raises(report.build_result, "proj", leaking,
                   raw_patients=frozenset({"PATIENT-ALPHA"})):
        failures.append("fault injection: report published a raw patient identifier")

    # Conservation: two published rows but input_count of one.
    overcount = models.Evaluation(
        manifest=(
            models.ManifestEntry(patient="pt-a", study="1", series="1.1",
                                 instance="1.1.1", modality="CT"),
            models.ManifestEntry(patient="pt-b", study="1", series="1.1",
                                 instance="1.1.2", modality="CT"),
        ),
        rejected=(),
        input_count=1,
    )
    if not _raises(report.build_result, "proj", overcount):
        failures.append("fault injection: report accepted a conservation violation")

    # Auditability: a rejection with no reasons must be refused.
    reasonless = models.Evaluation(
        manifest=(),
        rejected=(models.Rejection(ref="ref-deadbeef", reasons=()),),
        input_count=1,
    )
    if not _raises(report.build_result, "proj", reasonless):
        failures.append("fault injection: report accepted a reasonless rejection")
    return failures


def _faulty_engine_is_caught(pipeline: Any) -> List[str]:
    """A buggy aggregator that silently drops a row must trip conservation."""

    engine = __import__("dicom_manifest_governor.engine", fromlist=["*"])
    original_engine = engine.evaluate
    original_bound = pipeline.evaluate

    def drops_rows(parsed: Any):
        evaluation = original_engine(parsed)
        return type(evaluation)(
            manifest=evaluation.manifest,
            rejected=evaluation.rejected[:-1],
            input_count=evaluation.input_count,
        )

    # Patch the orchestration binding so the fault is observed exactly where a
    # real defect in the pipeline wiring would be.
    pipeline.evaluate = drops_rows
    try:
        envelope = pipeline.run_safe(
            {
                "instances": [
                    _row(),
                    _row(instance="1.2.840.1.2", private=True),
                ],
                "allowed_modalities": ["CT"],
            }
        )
    finally:
        pipeline.evaluate = original_bound

    failures: List[str] = []
    if envelope.get("status") != "error":
        failures.append("fault injection: dropped-row engine was not caught")
    elif envelope.get("error", {}).get("code") != "invariant_violation":
        failures.append(
            "fault injection: dropped-row engine produced code %r"
            % envelope.get("error", {}).get("code")
        )
    if "PATIENT-ALPHA" in json.dumps(envelope, sort_keys=True):
        failures.append("fault injection: dropped-row envelope leaked identifiers")
    return failures


def _raises(function: Any, *args: Any, **kwargs: Any) -> bool:
    try:
        function(*args, **kwargs)
    except Exception:
        return True
    return False
