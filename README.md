# DICOM Manifest Governor

Batch-level release governance for local DICOM files: hierarchy integrity,
protocol-scope and privacy-policy validation, deterministic research
manifests, per-instance quarantine, and a hash-chained audit journal with
commit / retract / republish semantics.

## Why not the old one-shot checker

The original pipeline only checked modality + a private flag and emitted
`sha256(patient)[:10]` pseudonyms. That cannot handle UID 断链 (dangling
references), cross-batch patient consistency, or retract/republish, and the
unsalted hash is reversible by dictionary attack. The governed flow fixes
all three:

- **Pseudonyms** are HMAC-SHA256 tokens with per-level domain separation
  (`pt-`/`st-`/`se-`/`in-`). The key comes from `--key-file` or
  `DMG_PSEUDONYM_KEY`, never from the data; the store records only a key
  fingerprint. Same key ⇒ stable across batches; without the key the output
  reveals nothing, and the store keeps no reverse map for published data.
- **Every instance is validated** against hierarchy, reference, protocol,
  private-tag, sensitive-field, pixel and batch-boundary rules. Failures are
  quarantined per-instance with explicit reason codes — the batch result is
  `partial`, never a silent success.
- **The journal is the truth.** `audit.log` is append-only and hash-chained;
  `state.json` is a rebuildable view. A batch is published iff the journal
  holds `COMMITTED` and no later `BATCH_RETRACTED`.

## Architecture

```
parser.py     input validation; malformed rows become errors, never silent drops
scanner.py    directory walk: sha256 of every file + .tags.json sidecar metadata;
              unreadable files/dirs/sidecars become structured scan errors
policy.py     versioned, content-hashed release policy (strict keys)
pseudonym.py  keyed HMAC tokens; key loading fails closed
engine.py     pure validation: no I/O, all quarantine decisions explained
store.py      journal, replay, crash recovery, frozen manifests, boundary check
pipeline.py   orchestration: scan → commit → retract → republish → export
cli.py        governed subcommands + legacy single-shot mode
```

Store layout (internal; only `manifests/` is publishable):

```
store/
  audit.log                 hash-chained JSONL journal (sensitive: internal)
  state.json                materialized view, rebuilt from the journal
  drafts/                   scanned-but-uncommitted batches (internal)
  manifests/<batch_id>.json committed, frozen, content-addressed, exportable
  quarantine/<batch_id>.json raw identifiers for remediation (internal)
  stray/                    uncommitted artifacts moved aside by recovery
```

## Scan strategy: security/performance trade-offs

| | One-shot full scan | Hierarchical index | Incremental manifest |
|---|---|---|---|
| **IO cost** | O(all files) every batch | O(changed files) | O(new files) |
| **Consistency** | Point-in-time snapshot, but files can change mid-scan; no cross-batch memory | Patient/Study/Series index persists; cross-batch conflicts detectable | Detects only new/changed; silent deletions and drift invisible |
| **Sensitive surface** | Nothing persisted | Index holds UID mappings → must be integrity-protected | Depends on history being trustworthy |
| **Failure recovery** | Naturally idempotent | Needs a write-ahead journal | Needs periodic full reconciliation |
| **Tamper evidence** | None | Hash-chained journal protects it | Frozen content-addressed manifests |

This implementation is the **hierarchical index + incremental commit hybrid**:
the journal hash chain protects the index, manifests are content-addressed
and frozen, and `verify` is the periodic reconciliation pass (journal chain,
manifest hashes, state view, release boundary). A pure full scan cannot
detect cross-batch duplicates or enforce UID uniqueness; a pure incremental
manifest cannot notice drift. The hybrid pays O(changed files) per batch and
O(manifests) per verify.

## Commit / retract / recovery boundaries

- **scan** writes a draft + `SCAN_COMPLETED`. Drafts are never publishable.
- **commit** is `COMMIT_PREPARED` → write manifest+quarantine → `COMMITTED`.
  A crash anywhere before `COMMITTED` is journaled leaves nothing that looks
  published: recovery appends `COMMIT_ABORTED`, moves uncommitted manifests
  to `stray/`, keeps the draft for retry, and deletes temp files.
- **retract** appends a tombstone (`BATCH_RETRACTED` + reason). The manifest
  file stays frozen for audit; the batch leaves the published index and
  export is refused.
- **republish** is a *new* single-use label with `--supersedes <batch_id>`;
  the superseded batch must be retracted first. Pseudonyms are stable, so
  lineage is joinable across the retraction.
- **policy upgrades** require a strictly higher version; same version with
  different content, or a downgrade, is refused (override exists for
  emergencies and is journaled). Committed manifests keep their original
  `policy_version`/`policy_hash` forever.
- **partial scans** (unreadable files/dirs, malformed rows) block commit
  unless explicitly accepted with `--allow-partial-scan`; the manifest then
  permanently records `scan.complete: false` and the error count.
- **export** is the only crossing of the release boundary: it requires a
  committed, non-retracted batch and passes a boundary check (token
  structure, exact entry key set, exact-match scan for every raw identifier
  known to the quarantine record). The export itself is journaled.

## CLI

```bash
export PYTHONPATH=src DMG_PSEUDONYM_KEY=<64 hex chars>

python3 -m dicom_manifest_governor.cli                       # legacy fixture run
python3 -m dicom_manifest_governor.cli scan  --store S --label b-2026-11 \
        --dir /data/dicom --policy policy.json               # or --input payload.json
python3 -m dicom_manifest_governor.cli commit --store S --label b-2026-11
python3 -m dicom_manifest_governor.cli status --store S
python3 -m dicom_manifest_governor.cli verify --store S
python3 -m dicom_manifest_governor.cli export --store S --batch-id b-... --out release.json
python3 -m dicom_manifest_governor.cli retract --store S --batch-id b-... --reason "..."
python3 -m dicom_manifest_governor.cli scan --store S --label b-2026-12 \
        --dir /data/dicom --policy policy-v2.json --supersedes b-...     # republish
```

Exit codes: `0` ok, `2` governance refusal (machine-readable `reason`),
`1` error, `3` verify failed.

## Policy

```json
{
  "version": "2.0.0",
  "allowed_modalities": ["CT", "MR"],
  "allowed_protocols": ["PROTO-A"],
  "protocol_modalities": {"PROTO-A": ["CT"]},
  "private_tag_allowlist": ["0013_1010"],
  "sensitive_fields_denylist": ["PatientName", "..."],
  "pixel_policy": "metadata_only",
  "allow_burned_in": false,
  "allow_partial_scan": false
}
```

`pixel_policy`: `allow` (pixels may cross; burned-in annotation quarantines
unless `allow_burned_in`), `metadata_only` (default; `pixels_released: false`
on every entry), `deny` (any pixel-bearing instance is quarantined).
Unknown pixel state is treated as present (fail closed). Sensitive-field
findings record only a sha256 fingerprint of the value, never the value.

## Quarantine reason codes

`missing_uid`, `missing_file_hash`, `hash_conflict`, `uid_conflict`,
`hierarchy_conflict`, `missing_parent_uid`, `protocol_not_allowed`,
`modality_not_allowed`, `private_tag_denied`, `sensitive_field_present`,
`pixels_denied`, `burned_in_annotation`, `cross_batch_duplicate`,
`pseudonym_collision` — plus the informational `duplicate_file` event for
the same file scanned twice (idempotent skip).

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`tests/test_governance.py` composes the required scenarios: cross-batch
pseudonym stability/non-reversibility, missing parent UIDs, private-tag
policy upgrade with retract+republish lineage, duplicate/conflicting
instances, crash recovery (nothing uncommitted ever looks published),
partially unreadable directories, frozen-manifest and journal tamper
detection, and release-boundary proof that raw pixels and sensitive fields
never cross.
