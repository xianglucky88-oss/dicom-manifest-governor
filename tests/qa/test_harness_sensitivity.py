"""Self-tests for the QA harness itself.

A gate that cannot fail is worthless.  These tests inject known-bad behaviours
into a *copy* of the production pipeline and assert that the harness reports
them, including after shrinking to a minimal payload.
"""

from __future__ import annotations

import copy
import unittest
from typing import Any, Dict

import harness
import reference_model
import scenarios
from dicom_manifest_governor.pipeline import run

GOOD_PAYLOAD = {
    "instances": [
        {"patient": "P1", "study": "1", "series": "1.2", "instance": "1.2.3",
         "modality": "CT"},
        {"patient": "P1", "study": "1", "series": "1.2", "instance": "1.2.4",
         "modality": "CT"},
        {"patient": "P2", "study": "2", "series": "2.2", "instance": "2.2.3",
         "modality": "MR"},
        {"patient": "P3", "study": "3", "series": "3.3", "instance": "3.3.3",
         "modality": "US", "private": True},
    ],
    "allowed_modalities": ["CT"],
}


def _mutant_run(mode: str):
    def mutant(payload: Dict[str, Any]) -> Dict[str, Any]:
        result = run(payload)
        result = copy.deepcopy(result)
        if mode == "drop_quarantine":
            if result["rejected"]:
                result["rejected"].pop()
                result["quarantined_count"] -= 1
        elif mode == "publish_raw_patient":
            for entry in result["manifest"]:
                entry["patient"] = "P1"
        elif mode == "unsorted_manifest":
            result["manifest"].reverse()
        elif mode == "order_dependent":
            # Emit rows in input order instead of canonical order.
            if payload["instances"]:
                result["manifest"].sort(key=lambda e: len(e["instance"]))
        elif mode == "unstable_rejection":
            result["rejected"] = list(reversed(result["rejected"]))
        else:  # pragma: no cover - guard against typos in tests
            raise AssertionError("unknown mode " + mode)
        return result

    return mutant


class TestHarnessSensitivity(unittest.TestCase):
    def test_oracle_disagrees_with_mutants(self):
        for mode in (
            "drop_quarantine",
            "publish_raw_patient",
            "unsorted_manifest",
            "unstable_rejection",
        ):
            with self.subTest(mode=mode):
                self.assertNotEqual(
                    harness.check_payload(_mutant_run(mode), GOOD_PAYLOAD),
                    None,
                )

    def test_clean_pipeline_passes(self):
        self.assertIsNone(harness.check_payload(run, GOOD_PAYLOAD))

    def test_dropped_row_is_reported_by_conservation(self):
        result = run(GOOD_PAYLOAD)
        broken = copy.deepcopy(result)
        broken["manifest"] = []
        broken["published_count"] = 0
        problems = [
            problem
            for problem in __import__("invariants").check(broken, GOOD_PAYLOAD, run)
        ]
        self.assertIn("conservation", problems)


class TestShrinkerReproducibility(unittest.TestCase):
    def test_shrunk_payload_reproduces_failure(self):
        def predicate(payload):
            return harness.check_payload(_mutant_run("drop_quarantine"), payload)

        seed_payload = {
            "instances": [
                {"patient": "P1", "study": "1", "series": "1.2",
                 "instance": "1.2.3", "modality": "CT"},
                {"patient": "P2", "study": "2", "series": "2.2",
                 "instance": "2.2.3", "modality": "MR"},
                {"patient": "P3", "study": "3", "series": "3.3",
                 "instance": "3.3.3", "modality": "US"},
            ],
            "allowed_modalities": ["CT"],
        }
        self.assertIsNotNone(predicate(seed_payload))
        minimal, failure = harness.shrink(seed_payload, predicate)
        self.assertIsNotNone(failure)
        self.assertLessEqual(len(minimal["instances"]), len(seed_payload["instances"]))
        # The shrunk counterexample must still fail under the same predicate.
        self.assertIsNotNone(predicate(minimal))


class TestOracleIndependence(unittest.TestCase):
    def test_oracle_does_not_import_production_package(self):
        source = reference_model.__file__
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("dicom_manifest_governor", text)

    def test_oracle_agrees_on_all_scenarios(self):
        for scenario in scenarios.SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                expected = reference_model.evaluate(scenario["payload"])
                self.assertEqual(expected["input_count"], len(
                    scenario["payload"]["instances"]
                ))


if __name__ == "__main__":
    unittest.main()
