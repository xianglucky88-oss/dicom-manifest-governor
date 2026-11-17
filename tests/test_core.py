import json
import unittest
from pathlib import Path
from dicom_manifest_governor.pipeline import run
from dicom_manifest_governor.parser import load_records
from dicom_manifest_governor.engine import calculate


def fixture():
    return json.loads((Path(__file__).parents[1] / "fixtures" / "input.json").read_text())


class TestCore(unittest.TestCase):
    def test_pipeline_and_modules(self):
        payload = fixture()
        rows = load_records(payload)
        self.assertTrue(rows)
        data = calculate(rows, payload)
        self.assertIsInstance(data, dict)
        self.assertTrue(data)
        result = run(payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["project"], "dicom-manifest-governor")

        # The private-flagged instance is isolated with a specific reason;
        # the clean instance still publishes (no silent whole-batch failure).
        self.assertEqual(result["published_count"], 1)
        self.assertEqual(result["quarantined_count"], 1)
        self.assertEqual(result["rejected"][0]["reason"], "private_tag_denied")
        self.assertEqual(result["batch_status"], "partial")
        # Legacy path is labelled: pseudonyms use the deterministic dev key.
        self.assertEqual(result["key_mode"], "insecure-development")

    def test_malformed_rows_are_reported_not_dropped(self):
        payload = {"instances": [{"patient": "P1", "study": "S1", "series": "SE1",
                                  "instance": "I1", "modality": "CT"},
                                 "not-a-dict",
                                 {"patient": "P2"}]}
        result = run(payload)
        self.assertEqual(result["published_count"], 1)
        self.assertEqual(len(result["input_errors"]), 1)
        # Row with missing UIDs is quarantined, not silently dropped.
        self.assertTrue(any(q["reason"] == "missing_uid" for q in result["rejected"]))


if __name__ == "__main__":
    unittest.main()
