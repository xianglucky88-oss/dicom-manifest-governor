# Quality gate: independent DICOM manifest assurance

This harness proves that the manifest governor is **complete** (every input row
is either published or quarantined with a reason) and **leak-free** (raw
identifiers and private-tag values never reach the report) under adversarial and
permuted input. It validates four layers independently:

| Layer | Module | What is assured |
| --- | --- | --- |
| Input parsing | `parser.py` | Structural validation, per-row reason codes, no silent drops, no raw-ID rejection payloads |
| Domain calculation | `engine.py` | Privacy policy, modality allow-list (case-insensitive), hierarchy and UID conflicts, duplicate resolution, canonical ordering |
| Orchestration | `pipeline.py` | Fault containment, deterministic error envelopes, conservation across layers |
| Result envelope | `report.py` | Count conservation, auditable rejections, pseudonym-only publication, fixed allow-listed shape |

It does **not** extend imaging capability or any release/publish workflow. It
only adds a quality gate.

## Layout

```
qa/
  reference_model.py   Independent oracle (does NOT import the package)
  harness.py           Random generator, property checks, shrinking
  scenarios.py         Named semantic cases with explicit expectations
  invariants.py        Shared-bug-safe structural invariants
  fault_injection.py   Boundary faults that must fail closed
  run_suite.py         One-shot gate used by CI and the mutation runner
  mutation.py          Self-contained mutation tester (no pip required)
tests/
  test_core.py                 Unit/contract/CLI tests
  qa/test_properties.py        Scenarios, seeded properties, shrinking
  qa/test_fault_injection.py   Fault injection
  qa/test_harness_sensitivity.py  Proves the gate can fail
  qa/test_mutation_gate.py     Opt-in mutation suite (QA_MUTATION=1)
```

## Run

```bash
# Fast gate (scenarios + 400 property cases + fault injection)
python3 qa/run_suite.py

# Unit + QA tests
PYTHONPATH=src:qa python3 -m unittest discover -s tests -t . -v

# Mutation gate (18 seeded defects across all four layers)
python3 qa/mutation.py
QA_MUTATION=1 PYTHONPATH=src:qa python3 -m unittest tests.qa.test_mutation_gate -v
```

Everything is deterministic: the generator is seeded, the oracle is pure, and
the mutation runner reports an exact score. No network or credentials are used.

## Semantics under test

* **Conservation:** `published_count + quarantined_count == input_count`, and
  each count equals its list length.
* **Auditability:** every rejection has an opaque `ref` and a non-empty set of
  known, stable reason codes. Rejections never carry raw identifiers.
* **Privacy:** `private: true` and any non-empty `private_tags` are quarantined;
  published patient values are pseudonyms only.
* **Policy:** modalities are matched case-insensitively against the allow-list
  and published upper-cased.
* **Hierarchy/UID conflicts:** a study spanning patients, a series spanning
  studies, or an instance UID under two `(study, series)` pairs quarantines all
  affected rows.
* **Duplicates:** an identity `(patient, study, series, instance)` publishes at
  most once; later copies are `duplicate_instance`, and content disagreements
  add `conflicting_duplicate`. The winner is chosen from content, never input
  position.
* **Order independence:** any permutation of `instances` yields byte-identical
  manifest and rejection lists (canonical sort on both).
* **Structural errors:** malformed payload envelopes return a deterministic
  error envelope that does not echo input content.

## Counterexample shrinking

When a property fails, `harness.shrink` greedily reduces the payload (drop rows,
drop fields, simplify identifiers, drop allow-list entries) while the failure
persists. The mutation runner and the `shrink` self-tests demonstrate that a
minimal reproducing payload is produced, which points directly at the failing
layer.

## Mutation gate

`qa/mutation.py` applies one surgical source edit at a time to a throwaway copy
of the package and re-runs the full suite in an isolated subprocess. A mutant is
*killed* when the gate fails. The in-repo set covers relaxed UID checks, dropped
field checks, silent row drops, ignored privacy flags/tags, case-sensitive
modality matching, missing duplicate/UID/hierarchy handling, order-dependent
aggregation, raw-patient publication, unsorted output, disabled conservation and
leak guards, reasonless rejections, and swallowed orchestration errors.

The gate fails if any mutant survives, so it guards its own sensitivity.
