"""Hand-written semantic scenarios with explicit expectations.

These complement the random properties: each scenario pins one documented rule
(UID conflict, hierarchy gap, case folding, duplicate replay, combined
rejection, empty input, reordering) to concrete counts and reason codes.  They
are shared by the unit tests and the mutation gate.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _row(patient="P1", study="1", series="1.2", instance="1.2.3",
         modality="CT", **extra) -> Dict[str, Any]:
    row = {
        "patient": patient,
        "study": study,
        "series": series,
        "instance": instance,
        "modality": modality,
    }
    row.update(extra)
    return row


SCENARIOS: List[Dict[str, Any]] = [
    {
        "name": "empty_manifest",
        "payload": {"instances": [], "allowed_modalities": ["CT"]},
        "published": 0,
        "quarantined": 0,
        "reason_sets": [],
    },
    {
        "name": "private_and_allowed",
        "payload": {
            "instances": [
                _row(instance="1.2.3"),
                _row(instance="1.2.4", private=True),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 1,
        "quarantined": 1,
        "reason_sets": [["private_record"]],
    },
    {
        "name": "forbidden_modality",
        "payload": {
            "instances": [_row(modality="MR")],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [["modality_not_allowed"]],
    },
    {
        "name": "private_tag_is_quarantined",
        "payload": {
            "instances": [_row(private_tags=["0010,0010"])],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [["private_tag"]],
    },
    {
        "name": "invalid_uid_rejected",
        "payload": {
            "instances": [_row(study="1..2")],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [["invalid_uid:study"]],
    },
    {
        "name": "missing_hierarchy_field",
        "payload": {
            "instances": [{"patient": "P1", "study": "1", "modality": "CT"}],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [[
            "missing_field:series",
            "missing_field:instance",
        ]],
    },
    {
        "name": "instance_uid_conflict_across_series",
        "payload": {
            "instances": [
                _row(study="1", series="1.2", instance="1.2.3"),
                _row(study="2", series="2.2", instance="1.2.3"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 2,
        "reason_sets": [["uid_conflict:instance"], ["uid_conflict:instance"]],
    },
    {
        "name": "study_spans_patients",
        "payload": {
            "instances": [
                _row(patient="P1", study="1", series="1.2", instance="1.2.3"),
                _row(patient="P2", study="1", series="1.4", instance="1.4.5"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 2,
        "reason_sets": [["hierarchy_conflict:study"], ["hierarchy_conflict:study"]],
    },
    {
        "name": "series_spans_studies",
        "payload": {
            "instances": [
                _row(study="1", series="1.2", instance="1.2.3"),
                _row(study="3", series="1.2", instance="3.2.3"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 2,
        "reason_sets": [["hierarchy_conflict:series"], ["hierarchy_conflict:series"]],
    },
    {
        "name": "modality_case_folded",
        "payload": {
            "instances": [_row(modality="ct")],
            "allowed_modalities": ["CT"],
        },
        "published": 1,
        "quarantined": 0,
        "reason_sets": [],
        "manifest_modalities": ["CT"],
    },
    {
        "name": "allow_list_case_folded",
        "payload": {
            "instances": [_row(modality="CT")],
            "allowed_modalities": ["ct"],
        },
        "published": 1,
        "quarantined": 0,
        "reason_sets": [],
    },
    {
        "name": "duplicate_replay_same_content",
        "payload": {
            "instances": [
                _row(instance="1.2.3"),
                _row(instance="1.2.3"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 1,
        "quarantined": 1,
        "reason_sets": [["duplicate_instance"]],
    },
    {
        "name": "duplicate_replay_conflicting_content",
        "payload": {
            "instances": [
                _row(instance="1.2.3", modality="CT"),
                _row(instance="1.2.3", modality="MR"),
            ],
            "allowed_modalities": ["CT", "MR"],
        },
        "published": 1,
        "quarantined": 1,
        "reason_sets": [["conflicting_duplicate", "duplicate_instance"]],
    },
    {
        "name": "duplicate_case_only_difference",
        "payload": {
            "instances": [
                _row(instance="1.2.3", modality="ct"),
                _row(instance="1.2.3", modality="CT"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 1,
        "quarantined": 1,
        "reason_sets": [["duplicate_instance"]],
    },
    {
        "name": "combined_structural_and_policy",
        "payload": {
            "instances": [
                _row(study="1..2", private=True, modality="MR"),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [["invalid_uid:study"]],
    },
    {
        "name": "combined_policy_reasons_accumulate",
        "payload": {
            "instances": [
                _row(modality="MR", private=True, private_tags=["0008,0070"]),
            ],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [[
            "modality_not_allowed",
            "private_record",
            "private_tag",
        ]],
    },
    {
        "name": "non_object_row_is_auditable",
        "payload": {
            "instances": [None],
            "allowed_modalities": ["CT"],
        },
        "published": 0,
        "quarantined": 1,
        "reason_sets": [["invalid_record"]],
    },
]

# A payload whose rows are deliberately reordered; both orders must agree.
REORDER_PAYLOAD_A = {
    "instances": [
        _row(instance="1.2.3"),
        _row(instance="1.2.4", private=True),
        _row(instance="1.2.3", modality="MR"),
    ],
    "allowed_modalities": ["CT", "MR"],
}
