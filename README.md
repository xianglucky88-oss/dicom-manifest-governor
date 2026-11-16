# DICOM Manifest Governor

Validate DICOM hierarchy and emit deterministic research manifests.

## Modules

- `src/dicom_manifest_governor/models.py`: immutable result contract.
- `src/dicom_manifest_governor/parser.py`: input validation and record extraction.
- `src/dicom_manifest_governor/engine.py`: domain calculation only.
- `src/dicom_manifest_governor/report.py`: stable output envelope.
- `src/dicom_manifest_governor/pipeline.py`: orchestration boundary.
- `src/dicom_manifest_governor/cli.py`: deterministic JSON CLI.

## Run

```bash
PYTHONPATH=src python -m dicom_manifest_governor.cli
PYTHONPATH=src python -m unittest discover -s tests -v
```

The fixture is local and deterministic; no network or credentials are required.
