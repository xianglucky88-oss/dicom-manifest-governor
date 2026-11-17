"""Fault-injection tests at the orchestration and sealing boundaries."""

from __future__ import annotations

import unittest

import fault_injection
import harness
import reference_model
import scenarios
from dicom_manifest_governor import pipeline


class TestFaultInjection(unittest.TestCase):
    def test_all_injected_faults_are_caught(self):
        failures = fault_injection.run(pipeline)
        self.assertEqual(failures, [], failures)


class TestDifferentialCornerCases(unittest.TestCase):
    def test_corner_cases_match_oracle(self):
        for scenario in scenarios.SCENARIOS:
            with self.subTest(scenario=scenario["name"]):
                self.assertEqual(
                    harness.sealed_view(pipeline.run(scenario["payload"])),
                    reference_model.evaluate(scenario["payload"]),
                )


if __name__ == "__main__":
    unittest.main()
