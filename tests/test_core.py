"""Unit and contract tests for the manifest governor.

Run from the repository root:

    PYTHONPATH=src:qa python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from dicom_manifest_governor.models import InputError, InvariantError
from dicom_manifest_governor.parser import load_records
from dicom_manifest_governor.pipeline import run, run_safe

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    return json.loads((ROOT / "fixtures" / "input.json").read_text())


def row(**overrides):
    base = {
        "patient": "PATIENT-ALPHA",
        "study": "1.2.840",
        "series": "1.2.840.1",
        "instance": "1.2.840.1.1",
        "modality": "CT",
    }
    base.update(overrides)
    return base


class TestPipelineContract(unittest.TestCase):
    def test_fixture_publishes_only_public_row(self):
        result = run(fixture())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["project"], "dicom-manifest-governor")
        self.assertEqual(result["input_count"], 2)
        self.assertEqual(result["published_count"], 1)
        self.assertEqual(result["quarantined_count"], 1)
        self.assertEqual(result["rejected"][0]["reasons"], ["private_record"])

    def test_counts_are_conserved(self):
        result = run(fixture())
        self.assertEqual(
            result["published_count"] + result["quarantined_count"],
            result["input_count"],
        )

    def test_manifest_publishes_pseudonym_not_patient(self):
        result = run(fixture())
        published = result["manifest"][0]["patient"]
        self.assertTrue(published.startswith("pt-"))
        self.assertNotIn("PATIENT-ALPHA", json.dumps(result))

    def test_rejections_are_auditable_and_opaque(self):
        result = run(fixture())
        for rejection in result["rejected"]:
            self.assertTrue(rejection["reasons"])
            self.assertTrue(rejection["ref"].startswith("ref-"))
            self.assertEqual(set(rejection), {"ref", "reasons"})

    def test_private_tags_and_extra_fields_never_leak(self):
        payload = fixture()
        payload["instances"][0]["private_tags"] = ["SECRET-TAG-VALUE"]
        payload["instances"][0]["vendor_extra"] = "SECRET-EXTRA-VALUE"
        result = run(payload)
        serialised = json.dumps(result)
        self.assertNotIn("SECRET-TAG-VALUE", serialised)
        self.assertNotIn("SECRET-EXTRA-VALUE", serialised)
        self.assertNotIn("PATIENT-ALPHA", serialised)


class TestStructuralValidation(unittest.TestCase):
    def test_payload_must_be_object(self):
        with self.assertRaises(InputError) as caught:
            load_records([])
        self.assertEqual(caught.exception.code, "payload_not_object")

    def test_instances_must_be_list(self):
        with self.assertRaises(InputError) as caught:
            load_records({"instances": {}})
        self.assertEqual(caught.exception.code, "instances_not_list")

    def test_allowed_modalities_must_be_list(self):
        with self.assertRaises(InputError) as caught:
            load_records({"instances": [], "allowed_modalities": "CT"})
        self.assertEqual(caught.exception.code, "allowed_modalities_not_list")

    def test_allowed_modalities_entry_must_be_valid(self):
        with self.assertRaises(InputError) as caught:
            load_records({"instances": [], "allowed_modalities": ["not a modality!"]})
        self.assertEqual(
            caught.exception.code, "allowed_modalities_invalid_entry"
        )

    def test_run_safe_never_echoes_payload(self):
        secret = "SECRET-PATIENT"
        envelope = run_safe({"instances": secret, "allowed_modalities": ["CT"]})
        self.assertEqual(envelope["status"], "error")
        self.assertEqual(envelope["error"]["code"], "instances_not_list")
        self.assertNotIn(secret, json.dumps(envelope))

    def test_non_object_row_is_quarantined_not_dropped(self):
        result = run({"instances": [None, row()], "allowed_modalities": ["CT"]})
        self.assertEqual(result["input_count"], 2)
        self.assertEqual(result["published_count"], 1)
        self.assertEqual(result["rejected"][0]["reasons"], ["invalid_record"])

    def test_invalid_uid_is_rejected(self):
        for bad in ("1..2", "01.2", "1.2.", ".1.2", "abc", "1" * 65):
            result = run(
                {"instances": [row(study=bad)], "allowed_modalities": ["CT"]}
            )
            self.assertEqual(result["published_count"], 0, bad)
            self.assertIn("invalid_uid:study", result["rejected"][0]["reasons"])


class TestReportSealing(unittest.TestCase):
    def test_raw_patient_is_refused(self):
        from dicom_manifest_governor.models import Evaluation, ManifestEntry
        from dicom_manifest_governor.report import build_result

        evaluation = Evaluation(
            manifest=(
                ManifestEntry(
                    patient="PATIENT-ALPHA",
                    study="1",
                    series="1.1",
                    instance="1.1.1",
                    modality="CT",
                ),
            ),
            rejected=(),
            input_count=1,
        )
        with self.assertRaises(InvariantError):
            build_result("proj", evaluation, raw_patients=frozenset({"PATIENT-ALPHA"}))

    def test_conservation_is_enforced(self):
        from dicom_manifest_governor.models import Evaluation
        from dicom_manifest_governor.report import build_result

        evaluation = Evaluation(manifest=(), rejected=(), input_count=1)
        with self.assertRaises(InvariantError):
            build_result("proj", evaluation)


class TestCli(unittest.TestCase):
    def test_cli_is_deterministic(self):
        import subprocess
        import sys

        command = [
            sys.executable,
            "-m",
            "dicom_manifest_governor.cli",
            str(ROOT / "fixtures" / "input.json"),
        ]
        env = {"PYTHONPATH": str(ROOT / "src")}
        first = subprocess.run(command, capture_output=True, text=True, env=env)
        second = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        payload = json.loads(first.stdout)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
