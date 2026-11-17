"""Property, scenario and shrinking tests driven by the independent oracle."""

from __future__ import annotations

import unittest

import harness
import reference_model
import scenarios
from dicom_manifest_governor.pipeline import run


class TestScenarios(unittest.TestCase):
    def test_every_scenario_matches_expectation_and_oracle(self):
        for scenario in scenarios.SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                result = run(scenario["payload"])
                self.assertEqual(
                    harness.sealed_view(result),
                    reference_model.evaluate(scenario["payload"]),
                )
                self.assertEqual(result["published_count"], scenario["published"])
                self.assertEqual(
                    result["quarantined_count"], scenario["quarantined"]
                )


class TestProperties(unittest.TestCase):
    def test_seeded_properties(self):
        failures = harness.run_properties(run, seed=20240101, cases=300)
        self.assertEqual(failures, [], failures[:1])

    def test_second_seed_properties(self):
        failures = harness.run_properties(run, seed=99, cases=200)
        self.assertEqual(failures, [], failures[:1])

    def test_reordering_is_invariant(self):
        base = scenarios.REORDER_PAYLOAD_A
        reversed_payload = dict(base)
        reversed_payload["instances"] = list(reversed(base["instances"]))
        self.assertEqual(
            harness.sealed_view(run(base)),
            harness.sealed_view(run(reversed_payload)),
        )


class TestShrinking(unittest.TestCase):
    def test_shrink_minimises_a_known_failure(self):
        # A deliberately wrong predicate accepts only payloads whose manifest
        # already equals the oracle's; shrink a failing payload to a tiny one.
        def predicate(payload):
            result = harness.sealed_view(run(payload))
            if result == reference_model.evaluate(payload):
                return None
            return "mismatch"

        failing = {
            "instances": [
                {"patient": "P1", "study": "1", "series": "1.2",
                 "instance": "1.2.3", "modality": "CT"},
                {"patient": "P2", "study": "2", "series": "2.2",
                 "instance": "2.2.3", "modality": "MR"},
            ],
            "allowed_modalities": ["CT"],
        }
        # Sanity: the production pipeline passes this predicate today.
        self.assertIsNone(predicate(failing))

        # The shrinker must produce a strictly smaller still-failing payload.
        def fails_while_p2_present(candidate):
            for row in candidate.get("instances", []):
                if isinstance(row, dict) and row.get("patient") == "P2":
                    return "P2 present"
            return None

        minimal, failure = harness.shrink(failing, fails_while_p2_present)
        self.assertEqual(failure, "P2 present")
        self.assertLess(len(minimal["instances"]), len(failing["instances"]))
        # 1-minimal: removing the surviving P2 row eliminates the failure.
        self.assertIsNone(fails_while_p2_present({"instances": []}))
        self.assertTrue(
            any(
                isinstance(row, dict) and row.get("patient") == "P2"
                for row in minimal["instances"]
            )
        )


if __name__ == "__main__":
    unittest.main()
