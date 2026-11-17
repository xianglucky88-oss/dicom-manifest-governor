"""Governed release store: hash-chained journal + derived state.

Design invariants:

- ``audit.log`` is the only source of truth. It is append-only; every line
  carries ``prev``/``hash`` links so tampering or truncation is detectable.
- ``state.json`` is a materialized view, rebuilt from the journal on every
  open and rewritten when it diverges. Deleting it never loses governance
  state.
- A batch is published iff the journal contains COMMITTED and no later
  BATCH_RETRACTED for it. Drafts, PREPARED markers and stray manifest files
  are never treated as published, so an abnormal exit cannot leave behind
  something that looks released.
- Committed manifests are immutable (content-addressed). Retraction is a
  tombstone event, not a deletion; republish is a new batch with a
  ``supersedes`` link.
"""
from __future__ import annotations

import os
import re

from .util import atomic_write, canonical_json, hash_obj, read_json_file, sha256_hex, utc_now

GENESIS_PREV = "0" * 64
JOURNAL_NAME = "audit.log"
STATE_NAME = "state.json"
TMP_PREFIX = ".tmp-"

# Journal event types.
STORE_INIT = "STORE_INIT"
POLICY_DECLARED = "POLICY_DECLARED"
SCAN_COMPLETED = "SCAN_COMPLETED"
COMMIT_PREPARED = "COMMIT_PREPARED"
COMMITTED = "COMMITTED"
COMMIT_ABORTED = "COMMIT_ABORTED"
DRAFT_DISCARDED = "DRAFT_DISCARDED"
BATCH_RETRACTED = "BATCH_RETRACTED"
EXPORTED = "EXPORTED"

TOKEN_PATTERN = re.compile(r"^(pt|st|se|in)-[0-9a-f]{24}$")
MANIFEST_ENTRY_KEYS = {
    "patient", "study", "series", "instance",
    "modality", "protocol", "file_hash", "record_hash", "pixels_released",
}


class StoreCorrupt(Exception):
    """Raised when the journal or a committed artifact fails verification."""


class Store:
    def __init__(self, path: str):
        self.path = path
        self.journal_path = os.path.join(path, JOURNAL_NAME)
        self.state_path = os.path.join(path, STATE_NAME)
        self.recovery_notes = []
        os.makedirs(path, exist_ok=True)
        for sub in ("drafts", "manifests", "quarantine", "stray"):
            os.makedirs(os.path.join(path, sub), exist_ok=True)

        if not os.path.exists(self.journal_path):
            self._events = []
            self._append_line(STORE_INIT, {"store": os.path.basename(os.path.abspath(path))})
        self._events = self._read_and_verify_journal()
        self.state = self._replay(self._events)
        self._recover()
        # Recovery may have appended events; replay once more for a clean view.
        self.state = self._replay(self._events)
        self._sync_state_file()

    # ------------------------------------------------------------------ journal

    def _append_line(self, event_type: str, payload: dict) -> dict:
        prev = self._events[-1]["hash"] if self._events else GENESIS_PREV
        event = {
            "seq": len(self._events),
            "ts": utc_now(),
            "type": event_type,
            "payload": payload,
            "prev": prev,
        }
        event["hash"] = hash_obj(event)
        with open(self.journal_path, "a", encoding="utf-8") as fh:
            fh.write(canonical_json(event) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._events.append(event)
        return event

    def append_event(self, event_type: str, payload: dict) -> dict:
        event = self._append_line(event_type, payload)
        self.state = self._replay(self._events)
        self._sync_state_file()
        return event

    def _read_and_verify_journal(self) -> list:
        events = []
        with open(self.journal_path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                import json
                try:
                    event = json.loads(line)
                except ValueError as exc:
                    raise StoreCorrupt(f"journal line {lineno} is not valid JSON: {exc}")
                expected_prev = events[-1]["hash"] if events else GENESIS_PREV
                if event.get("prev") != expected_prev:
                    raise StoreCorrupt(f"journal line {lineno}: prev hash mismatch")
                declared = event.get("hash")
                recomputed = hash_obj({k: v for k, v in event.items() if k != "hash"})
                if declared != recomputed:
                    raise StoreCorrupt(f"journal line {lineno}: hash mismatch")
                if event.get("seq") != len(events):
                    raise StoreCorrupt(f"journal line {lineno}: sequence gap")
                events.append(event)
        return events

    # ------------------------------------------------------------------- replay

    def _replay(self, events) -> dict:
        state = {
            "batches": {},        # batch_id -> batch record
            "labels": {},         # label -> batch_id (committed)
            "drafts": {},         # label -> draft info
            "prepared": {},       # label -> batch_id (PREPARED, not yet resolved)
            "last_policy": None,  # {"version", "hash"} of newest committed batch
            "journal_head": events[-1]["hash"] if events else GENESIS_PREV,
            "journal_len": len(events),
        }
        committed_order = []
        pseudonym_regs = {}       # batch_id -> {token: patient_key}
        for event in events:
            p = event["payload"]
            t = event["type"]
            if t == POLICY_DECLARED:
                pass  # declaration audit only; committed policy tracked on COMMITTED
            elif t == SCAN_COMPLETED:
                state["drafts"][p["label"]] = {
                    "batch_id": p["batch_id"],
                    "policy_version": p["policy_version"],
                    "committable": p["committable"],
                    "scan_error_count": p["scan_error_count"],
                }
            elif t == DRAFT_DISCARDED:
                state["drafts"].pop(p["label"], None)
                state["prepared"].pop(p["label"], None)
            elif t == COMMIT_PREPARED:
                state["prepared"][p["label"]] = p["batch_id"]
            elif t == COMMIT_ABORTED:
                state["prepared"].pop(p["label"], None)
            elif t == COMMITTED:
                bid = p["batch_id"]
                state["batches"][bid] = {
                    "batch_id": bid,
                    "label": p["label"],
                    "status": "committed",
                    "policy_version": p["policy_version"],
                    "policy_hash": p["policy_hash"],
                    "supersedes": p.get("supersedes"),
                    "counts": p["counts"],
                    "manifest_hash": p["manifest_hash"],
                    "quarantine_hash": p["quarantine_hash"],
                }
                state["labels"][p["label"]] = bid
                state["prepared"].pop(p["label"], None)
                state["drafts"].pop(p["label"], None)
                committed_order.append(bid)
                pseudonym_regs[bid] = p.get("pseudonym_registrations", {})
                state["last_policy"] = {"version": p["policy_version"], "hash": p["policy_hash"]}
            elif t == BATCH_RETRACTED:
                batch = state["batches"].get(p["batch_id"])
                if batch is not None:
                    batch["status"] = "retracted"
                    batch["retract_reason"] = p.get("reason")

        # Registry view from active (committed, not retracted) batches.
        registry = {"instances": {}, "files": {}, "series_map": {}, "study_map": {}, "pseudonyms": {}}
        for bid in committed_order:
            if state["batches"][bid]["status"] != "committed":
                continue
            manifest = self.read_manifest(bid)
            expected = state["batches"][bid]["manifest_hash"]
            actual = hash_obj(manifest)
            if actual != expected:
                raise StoreCorrupt(f"manifest {bid} hash mismatch: {actual} != {expected}")
            for entry in manifest["entries"]:
                registry["instances"][entry["instance"]] = bid
                registry["series_map"][entry["series"]] = entry["study"]
                registry["study_map"][entry["study"]] = entry["patient"]
                if "file_hash" in entry:
                    registry["files"][entry["file_hash"]] = entry["instance"]
            registry["pseudonyms"].update(pseudonym_regs.get(bid, {}))
        state["registry"] = registry
        return state

    # ----------------------------------------------------------------- recovery

    def _recover(self):
        """Resolve crash windows. Never promotes anything to published."""
        # 1. Dangling PREPARED: no COMMITTED followed -> abort explicitly.
        for label, batch_id in sorted(self.state["prepared"].items()):
            stray = os.path.join(self.path, "manifests", f"{batch_id}.json")
            if os.path.exists(stray):
                self._move_to_stray(stray)
                self.recovery_notes.append(f"removed uncommitted manifest {batch_id}")
            self._append_line(COMMIT_ABORTED, {"label": label, "batch_id": batch_id,
                                               "cause": "recovery"})
            self.recovery_notes.append(f"aborted dangling commit for label {label}")

        # 2. Stray manifests with no COMMITTED event at all.
        committed_ids = set(self.state["batches"])
        manifests_dir = os.path.join(self.path, "manifests")
        for name in sorted(os.listdir(manifests_dir)):
            if name.startswith(TMP_PREFIX):
                os.unlink(os.path.join(manifests_dir, name))
                continue
            if name.endswith(".json") and name[:-5] not in committed_ids:
                self._move_to_stray(os.path.join(manifests_dir, name))
                self.recovery_notes.append(f"moved stray manifest {name} to stray/")

        # 3. Orphan drafts (file exists, journal has no SCAN_COMPLETED).
        drafts_dir = os.path.join(self.path, "drafts")
        known_labels = set(self.state["drafts"])
        for name in sorted(os.listdir(drafts_dir)):
            if name.startswith(TMP_PREFIX):
                os.unlink(os.path.join(drafts_dir, name))
                continue
            if name.endswith(".json") and name[:-5] not in known_labels:
                os.unlink(os.path.join(drafts_dir, name))
                self.recovery_notes.append(f"removed orphan draft {name}")

        # 4. Temp files anywhere else in the store.
        for sub in ("quarantine",):
            d = os.path.join(self.path, sub)
            for name in sorted(os.listdir(d)):
                if name.startswith(TMP_PREFIX):
                    os.unlink(os.path.join(d, name))

    def _move_to_stray(self, path: str):
        target = os.path.join(self.path, "stray", os.path.basename(path))
        counter = 1
        base = target
        while os.path.exists(target):
            target = f"{base}.{counter}"
            counter += 1
        os.replace(path, target)

    def _sync_state_file(self):
        disk = None
        if os.path.exists(self.state_path):
            try:
                disk = read_json_file(self.state_path)
            except ValueError:
                disk = None
        if disk != self.state:
            if disk is not None:
                self.recovery_notes.append("state.json diverged from journal; rebuilt")
            atomic_write(self.state_path, (canonical_json(self.state) + "\n").encode("utf-8"))

    # -------------------------------------------------------------- file access

    def _draft_path(self, label: str) -> str:
        return os.path.join(self.path, "drafts", f"{label}.json")

    def manifest_path(self, batch_id: str) -> str:
        return os.path.join(self.path, "manifests", f"{batch_id}.json")

    def _quarantine_path(self, batch_id: str) -> str:
        return os.path.join(self.path, "quarantine", f"{batch_id}.json")

    def write_draft(self, label: str, draft: dict, quarantine: dict):
        atomic_write(self._draft_path(label), (canonical_json(draft) + "\n").encode("utf-8"))
        atomic_write(self._draft_path(label) + ".quarantine",
                     (canonical_json(quarantine) + "\n").encode("utf-8"))

    def read_draft(self, label: str):
        path = self._draft_path(label)
        if not os.path.exists(path):
            return None
        return read_json_file(path)

    def read_draft_quarantine(self, label: str):
        path = self._draft_path(label) + ".quarantine"
        if not os.path.exists(path):
            return None
        return read_json_file(path)

    def discard_draft(self, label: str) -> bool:
        if label not in self.state["drafts"]:
            return False
        for path in (self._draft_path(label), self._draft_path(label) + ".quarantine"):
            if os.path.exists(path):
                os.unlink(path)
        self.append_event(DRAFT_DISCARDED, {"label": label})
        return True

    def commit_draft(self, label: str, manifest: dict, quarantine: dict,
                     pseudonym_registrations: dict) -> dict:
        """Atomic-ish commit: PREPARED -> write artifacts -> COMMITTED.

        A crash anywhere before COMMITTED is journaled leaves no published
        artifact (recovery aborts the prepare and removes stray files); a
        crash after COMMITTED is fully replayed from the journal.
        """
        batch_id = manifest["batch_id"]
        manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")
        quarantine_bytes = (canonical_json(quarantine) + "\n").encode("utf-8")
        manifest_hash = hash_obj(manifest)
        quarantine_hash = hash_obj(quarantine)

        existing = self.manifest_path(batch_id)
        if os.path.exists(existing):
            raise StoreCorrupt(f"manifest {batch_id} already exists; committed manifests are frozen")

        self.append_event(COMMIT_PREPARED, {
            "label": label, "batch_id": batch_id, "manifest_hash": manifest_hash,
        })
        atomic_write(self.manifest_path(batch_id), manifest_bytes)
        atomic_write(self._quarantine_path(batch_id), quarantine_bytes)
        committed = self.append_event(COMMITTED, {
            "label": label,
            "batch_id": batch_id,
            "manifest_hash": manifest_hash,
            "quarantine_hash": quarantine_hash,
            "policy_version": manifest["policy_version"],
            "policy_hash": manifest["policy_hash"],
            "supersedes": manifest.get("supersedes"),
            "counts": manifest["counts"],
            "pseudonym_registrations": pseudonym_registrations,
        })
        for path in (self._draft_path(label), self._draft_path(label) + ".quarantine"):
            if os.path.exists(path):
                os.unlink(path)
        return committed["payload"] | {"seq": committed["seq"]}

    def read_manifest(self, batch_id: str) -> dict:
        path = self.manifest_path(batch_id)
        if not os.path.exists(path):
            raise StoreCorrupt(f"committed manifest {batch_id} is missing")
        return read_json_file(path)

    def read_quarantine(self, batch_id: str) -> dict:
        path = self._quarantine_path(batch_id)
        if not os.path.exists(path):
            raise StoreCorrupt(f"quarantine record {batch_id} is missing")
        return read_json_file(path)

    # -------------------------------------------------------------- verification

    def boundary_check(self, batch_id: str) -> list:
        """Prove a manifest carries no raw identifiers or pixel payloads.

        Checks token structure, the exact entry key set, and exact-match
        leakage of every raw identifier known to the internal quarantine
        record. Returns a list of findings (empty = boundary holds).
        """
        findings = []
        manifest = self.read_manifest(batch_id)
        raw_values = set()
        try:
            quarantine = self.read_quarantine(batch_id)
            for entry in quarantine.get("entries", []):
                for field in ("patient", "study", "series", "instance", "source_path"):
                    value = entry.get(field)
                    if value:
                        raw_values.add(str(value))
        except StoreCorrupt:
            raw_values = set()

        def walk_strings(obj):
            if isinstance(obj, str):
                yield obj
            elif isinstance(obj, dict):
                for value in obj.values():
                    yield from walk_strings(value)
            elif isinstance(obj, list):
                for item in obj:
                    yield from walk_strings(item)

        for entry in manifest.get("entries", []):
            extra_keys = sorted(set(entry) - MANIFEST_ENTRY_KEYS)
            if extra_keys:
                findings.append(f"unexpected manifest keys: {extra_keys}")
            for field in ("patient", "study", "series", "instance"):
                if not TOKEN_PATTERN.match(str(entry.get(field, ""))):
                    findings.append(f"malformed token in field {field}")
            if "pixels" in entry or "pixel_data" in entry:
                findings.append("pixel payload present in manifest")
        for value in walk_strings(manifest):
            if value in raw_values:
                findings.append(f"raw identifier leaked into manifest: {value!r}")
        return sorted(set(findings))

    def verify(self) -> dict:
        checks = []

        def check(name, ok, detail=""):
            checks.append({"check": name, "ok": bool(ok), "detail": detail})
            return ok

        try:
            events = self._read_and_verify_journal()
            check("journal_chain", True, f"{len(events)} events")
        except StoreCorrupt as exc:
            check("journal_chain", False, str(exc))
            return {"ok": False, "checks": checks}

        try:
            state = self._replay(events)
            check("replay", True)
        except StoreCorrupt as exc:
            check("replay", False, str(exc))
            return {"ok": False, "checks": checks}
        ok = True
        for bid, batch in sorted(state["batches"].items()):
            if batch["status"] != "committed":
                continue
            try:
                manifest = self.read_manifest(bid)
                ok &= check(f"manifest_hash[{bid}]", hash_obj(manifest) == batch["manifest_hash"])
                quarantine = self.read_quarantine(bid)
                ok &= check(f"quarantine_hash[{bid}]",
                            hash_obj(quarantine) == batch["quarantine_hash"])
                findings = self.boundary_check(bid)
                ok &= check(f"release_boundary[{bid}]", not findings, "; ".join(findings))
            except StoreCorrupt as exc:
                ok &= check(f"manifest_present[{bid}]", False, str(exc))

        manifests_dir = os.path.join(self.path, "manifests")
        strays = [n for n in os.listdir(manifests_dir)
                  if n.endswith(".json") and n[:-5] not in state["batches"]]
        ok &= check("no_stray_manifests", not strays, ", ".join(strays))

        disk_state = read_json_file(self.state_path) if os.path.exists(self.state_path) else None
        ok &= check("state_matches_journal", disk_state == state)
        return {"ok": bool(ok), "checks": checks}

    def status(self) -> dict:
        return {
            "batches": sorted(self.state["batches"].values(), key=lambda b: b["batch_id"]),
            "drafts": self.state["drafts"],
            "last_policy": self.state["last_policy"],
            "journal": {"events": self.state["journal_len"], "head": self.state["journal_head"]},
            "recovery_notes": list(self.recovery_notes),
        }
