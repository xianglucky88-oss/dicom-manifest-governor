"""Orchestration boundary: scan -> commit -> retract -> republish -> export.

The pipeline sequences pure engine evaluation and store mutations, and
enforces the governance rules that span steps (label uniqueness, policy
version monotonicity, supersedes lineage, partial-scan acceptance).
"""
from __future__ import annotations

import re

from . import engine, scanner
from .parser import parse_records
from .policy import Policy
from .pseudonym import Pseudonymizer, load_key
from .report import build_result
from .store import POLICY_DECLARED, SCAN_COMPLETED, BATCH_RETRACTED, EXPORTED, Store
from .util import hash_obj, sha256_hex

LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class GovernanceError(Exception):
    """A refused governance transition. Carries a stable reason code."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------- legacy

def run(payload: dict) -> dict:
    """Legacy single-shot entry point (no store, no cross-batch state)."""
    records, input_errors = parse_records(payload)
    data = engine.calculate(records, payload)
    if input_errors:
        data["input_errors"] = input_errors
        data["batch_status"] = "partial" if data["published_count"] else "empty"
    return build_result("dicom-manifest-governor", data)


# ----------------------------------------------------------------------- scan

def scan_batch(store: Store, label: str, *, payload=None, directory=None,
               policy_dict=None, key_hex=None, key_file=None, supersedes=None,
               allow_partial_scan=False, allow_policy_downgrade=False,
               allow_dev_key=False) -> dict:
    if not label or not LABEL_PATTERN.fullmatch(label):
        raise GovernanceError("invalid_label", "label must match " + LABEL_PATTERN.pattern)
    if label in store.state["labels"] or label in store.state["drafts"]:
        raise GovernanceError("label_already_used",
                              "labels are single-use; republish with a new label and --supersedes")
    if (payload is None) == (directory is None):
        raise GovernanceError("invalid_input", "provide exactly one of payload or directory")

    policy = Policy.from_dict(policy_dict)
    _check_policy_transition(store, policy, allow_policy_downgrade)

    if supersedes is not None:
        target = store.state["batches"].get(supersedes)
        if target is None:
            raise GovernanceError("unknown_supersedes", supersedes)
        if target["status"] != "retracted":
            raise GovernanceError("supersedes_not_retracted",
                                  "retract the superseded batch before republishing")

    key, key_mode = load_key(key_hex=key_hex, key_file=key_file, allow_dev=allow_dev_key)
    ps = Pseudonymizer(key)

    scan_errors = []
    if directory is not None:
        scanned = scanner.scan_directory(directory)
        raw_rows = scanned["records"]
        scan_errors.extend(scanned["errors"])
        records = []
        from .parser import normalize_record
        for index, row in enumerate(raw_rows):
            try:
                records.append(normalize_record(row, index))
            except ValueError as exc:
                scan_errors.append({"path": row.get("source_path", f"row-{index}"),
                                    "error": str(exc)})
    else:
        records, parse_errors = parse_records(payload)
        scan_errors.extend({"path": f"row-{e['index']}", "error": e["error"]}
                           for e in parse_errors)

    evaluation = engine.evaluate(
        records, policy, store.state["registry"], ps,
        context={"require_file_hash": True, "label": label, "supersedes": supersedes})

    committable = not scan_errors or allow_partial_scan or policy.allow_partial_scan
    quarantine_summary = [
        {
            "instance": ps.instance(q["instance"]) if q["instance"] else None,
            "file_hash": q["file_hash"],
            "reasons": q["reasons"],
        }
        for q in evaluation["quarantine"]
    ]
    counts = {
        "published": len(evaluation["entries"]),
        "quarantined": len(evaluation["quarantine"]),
        "duplicates_skipped": evaluation["stats"]["duplicates_skipped"],
        "scan_errors": len(scan_errors),
    }
    manifest_content = {
        "label": label,
        "supersedes": supersedes,
        "policy_version": policy.version,
        "policy_hash": policy.hash(),
        "pseudonym_key_fingerprint": ps.fingerprint,
        "scan": {"complete": not scan_errors, "error_count": len(scan_errors)},
        "entries": evaluation["entries"],
        "quarantine_summary": sorted(quarantine_summary,
                                     key=lambda q: (q["instance"] or "", q["file_hash"] or "")),
        "counts": counts,
    }
    batch_id = "b-" + hash_obj(manifest_content)[:16]
    manifest = {"format": "dmg-manifest/1", "batch_id": batch_id, **manifest_content}

    draft = {
        "format": "dmg-draft/1",
        "label": label,
        "batch_id": batch_id,
        "key_mode": key_mode,
        "policy": policy.to_dict(),
        "manifest": manifest,
        "pseudonym_registrations": evaluation["registry_delta"]["pseudonyms"],
        "events": evaluation["events"],
        "committable": committable,
    }
    quarantine_record = {
        "format": "dmg-quarantine/1",
        "batch_id": batch_id,
        "label": label,
        "entries": evaluation["quarantine"],
        "scan_errors": scan_errors,
    }
    store.write_draft(label, draft, quarantine_record)
    store.append_event(POLICY_DECLARED, {"version": policy.version, "hash": policy.hash()})
    store.append_event(SCAN_COMPLETED, {
        "label": label,
        "batch_id": batch_id,
        "policy_version": policy.version,
        "policy_hash": policy.hash(),
        "counts": counts,
        "scan_error_count": len(scan_errors),
        "committable": committable,
        "supersedes": supersedes,
    })
    return {
        "status": "scanned",
        "label": label,
        "batch_id": batch_id,
        "batch_status": "clean" if not counts["quarantined"] else (
            "partial" if counts["published"] else "empty"),
        "counts": counts,
        "committable": committable,
        "scan_errors": scan_errors,
        "quarantine": evaluation["quarantine"],
        "key_mode": key_mode,
        "policy_version": policy.version,
    }


def _check_policy_transition(store: Store, policy: Policy, allow_downgrade: bool):
    last = store.state["last_policy"]
    if last is None:
        return
    current, previous = policy.version_tuple(), _version_tuple(last["version"])
    if current < previous and not allow_downgrade:
        raise GovernanceError("policy_downgrade",
                              f"{policy.version} < {last['version']}; "
                              "pass allow_policy_downgrade to override")
    if current == previous and policy.hash() != last["hash"]:
        raise GovernanceError("policy_version_conflict",
                              f"version {policy.version} already used with different content; "
                              "bump the policy version")


def _version_tuple(version: str) -> tuple:
    parts = []
    for chunk in str(version).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


# ---------------------------------------------------------------------- commit

def commit_batch(store: Store, label: str) -> dict:
    draft_info = store.state["drafts"].get(label)
    draft = store.read_draft(label)
    if draft_info is None or draft is None:
        raise GovernanceError("unknown_draft", f"no scanned draft for label {label}")
    if not draft["committable"]:
        raise GovernanceError("incomplete_scan",
                              "scan errors present; rescan with allow_partial_scan to proceed")

    manifest = draft["manifest"]
    last = store.state["last_policy"]
    if last is not None and _version_tuple(manifest["policy_version"]) < _version_tuple(last["version"]):
        raise GovernanceError("stale_policy",
                              "a newer policy was committed after this scan; rescan the batch")

    supersedes = manifest.get("supersedes")
    if supersedes is not None:
        target = store.state["batches"].get(supersedes)
        if target is None or target["status"] != "retracted":
            raise GovernanceError("supersedes_not_retracted",
                                  "superseded batch must be retracted before commit")

    payload = store.commit_draft(
        label, manifest, store.read_draft_quarantine(label),
        draft["pseudonym_registrations"])
    return {
        "status": "committed",
        "label": label,
        "batch_id": payload["batch_id"],
        "counts": payload["counts"],
        "batch_status": "clean" if not payload["counts"]["quarantined"] else (
            "partial" if payload["counts"]["published"] else "empty"),
        "policy_version": payload["policy_version"],
        "supersedes": payload.get("supersedes"),
    }


# --------------------------------------------------------------------- retract

def retract_batch(store: Store, batch_id: str, reason: str) -> dict:
    batch = store.state["batches"].get(batch_id)
    if batch is None:
        raise GovernanceError("unknown_batch", batch_id)
    if batch["status"] == "retracted":
        raise GovernanceError("already_retracted", batch_id)
    if not reason:
        raise GovernanceError("invalid_reason", "a retraction reason is required")
    store.append_event(BATCH_RETRACTED, {"batch_id": batch_id, "reason": reason})
    return {"status": "retracted", "batch_id": batch_id, "reason": reason}


# ---------------------------------------------------------------------- export

def export_batch(store: Store, batch_id: str, out_path: str) -> dict:
    batch = store.state["batches"].get(batch_id)
    if batch is None:
        raise GovernanceError("unknown_batch", batch_id)
    if batch["status"] != "committed":
        raise GovernanceError("batch_not_publishable",
                              f"batch status is {batch['status']}; only committed, "
                              "non-retracted batches may be exported")
    findings = store.boundary_check(batch_id)
    if findings:
        raise GovernanceError("boundary_violation", "; ".join(findings))
    with open(store.manifest_path(batch_id), "rb") as fh:
        data = fh.read()
    from .util import atomic_write
    atomic_write(out_path, data)
    store.append_event(EXPORTED, {"batch_id": batch_id,
                                  "out_sha256": sha256_hex(data)})
    return {"status": "exported", "batch_id": batch_id, "out": out_path,
            "sha256": sha256_hex(data)}
