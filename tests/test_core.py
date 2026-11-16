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
        self.assertEqual(result["project"], 'dicom-manifest-governor')

        assert result["published_count"] == 1 and result["rejected"][0]["reason"] == "policy"
