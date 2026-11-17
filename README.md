# DICOM Manifest Governor

Validate DICOM hierarchy and emit deterministic research manifests.

## Modules

- `src/dicom_manifest_governor/models.py`: immutable result contract.
- `src/dicom_manifest_governor/parser.py`: input validation and record extraction.
- `src/dicom_manifest_governor/engine.py`: domain calculation only.
- `src/dicom_manifest_governor/report.py`: stable output envelope.
- `src/dicom_manifest_governor/pipeline.py`: orchestration boundary.
- `src/dicom_manifest_governor/cli.py`: deterministic JSON CLI.

## Contract

Input is a JSON object with an `instances` list and an `allowed_modalities`
list. `study`, `series` and `instance` are DICOM UIDs; `patient` is an opaque
identifier that is pseudonymised before publication.

Output is a sealed, deterministic envelope:

```json
{
  "project": "dicom-manifest-governor",
  "status": "ok",
  "schema_version": "1.0",
  "input_count": 2,
  "published_count": 1,
  "quarantined_count": 1,
  "manifest": [{"patient": "pt-...", "study": "...", "series": "...", "instance": "...", "modality": "CT"}],
  "rejected": [{"ref": "ref-...", "reasons": ["private_record"]}]
}
```

Guarantees:

- every input row is either published or quarantined (counts are conserved);
- every rejection carries an opaque `ref` and stable reason codes, never raw IDs;
- private rows and private tags are quarantined; published patients are pseudonyms;
- duplicate identities publish at most once, with `duplicate_instance` and
  `conflicting_duplicate` audit reasons;
- UID conflicts and cross-record hierarchy conflicts are quarantined;
- manifest and rejection ordering is canonical, so output is independent of input
  order;
- structural input errors yield a deterministic error envelope that does not echo
  payload content.

## Run

```bash
PYTHONPATH=src python -m dicom_manifest_governor.cli
PYTHONPATH=src:qa python3 -m unittest discover -s tests -t . -v
```

The fixture is local and deterministic; no network or credentials are required.

## Quality gate

An independent assurance harness (reference oracle, property tests, fault
injection, counterexample shrinking, and mutation testing) lives in `qa/`. See
[`qa/README.md`](qa/README.md). The gate does not extend imaging capability or
release workflows.

```bash
python3 qa/run_suite.py     # scenarios + 400 property cases + fault injection
python3 qa/mutation.py      # mutation gate across parser/engine/report/pipeline
```
