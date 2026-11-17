"""Combination tests for batch-level release governance.

Covered scenarios (composed as required by the release-governance spec):

- cross-batch pseudonym stability and non-reversibility;
- missing parent UIDs (断链) quarantined per-instance;
- private-tag policy upgrade with retract + republish lineage;
- duplicate files, UID conflicts and cross-batch duplicates;
- retract then republish (撤回重发) with stable pseudonyms;
- crash recovery: no artifact is ever mistaken for published;
- partially unreadable directories;
- frozen committed manifests and hash-chained audit journal;
- release boundary: raw pixels and sensitive fields never cross.
"""
import hashlib
import json
import os
import tempfile
import unittest

from dicom_manifest_governor import engine
from dicom_manifest_governor.pipeline import (
    GovernanceError,
    commit_batch,
    export_batch,
    retract_batch,
    scan_batch,
)
from dicom_manifest_governor.pseudonym import Pseudonymizer
from dicom_manifest_governor.store import COMMIT_PREPARED, Store, StoreCorrupt
from dicom_manifest_governor.util import canonical_json

KEY = "ab" * 32
OTHER_KEY = "cd" * 32

POLICY_V1 = {
    "version": "1.0.0",
    "allowed_modalities": ["CT", "MR"],
    "allowed_protocols": ["PROTO-A"],
    "private_tag_allowlist": [],
    "pixel_policy": "metadata_only",
}
POLICY_V2 = dict(POLICY_V1, version="2.0.0", private_tag_allowlist=["0013_1010"])


def h64(seed):
    return "sha256:" + hashlib.sha256(f"file-{seed}".encode()).hexdigest()


def rec(instance="I1", patient="P1", study="ST1", series="SE1", modality="CT",
        protocol="PROTO-A", file_hash=None, **extra):
    row = {
        "patient": patient, "study": study, "series": series, "instance": instance,
        "modality": modality, "protocol": protocol,
        "file_hash": file_hash or h64(instance),
        "pixels": {"present": True, "burned_in_annotation": False},
    }
    row.update(extra)
    return row


def payload(*rows):
    return {"instances": list(rows)}


class GovTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store_path = os.path.join(self._tmp.name, "store")
        self.store = Store(self.store_path)

    def reopen(self):
        self.store = Store(self.store_path)
        return self.store

    def scan(self, label, rows, policy=POLICY_V1, **kw):
        return scan_batch(self.store, label, payload=payload(*rows),
                          policy_dict=policy, key_hex=KEY, **kw)

    def commit(self, label):
        return commit_batch(self.store, label)

    def scan_commit(self, label, rows, policy=POLICY_V1, **kw):
        self.scan(label, rows, policy=policy, **kw)
        return self.commit(label)

    def manifest_of(self, committed):
        return self.store.read_manifest(committed["batch_id"])

    def journal_types(self):
        return [e["type"] for e in self.store._events]


class TestCrossBatchPseudonym(GovTestCase):
    def test_stable_across_batches_and_not_reversible(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        c2 = self.scan_commit("batch-2", [rec(instance="I2", study="ST2", series="SE2",
                                              file_hash=h64("b"))])
        tok1 = self.manifest_of(c1)["entries"][0]["patient"]
        tok2 = self.manifest_of(c2)["entries"][0]["patient"]
        self.assertEqual(tok1, tok2, "same patient must map to the same pseudonym across batches")

        # Keyed: neither the legacy unsalted scheme nor a different key reproduces it.
        self.assertNotEqual(tok1, "pt-" + hashlib.sha256(b"P1").hexdigest()[:24])
        self.assertNotEqual(tok1, Pseudonymizer(bytes.fromhex(OTHER_KEY)).patient("P1"))

        # The published artifact contains no raw identifier material.
        blob = canonical_json(self.manifest_of(c1))
        for raw in ("P1", "ST1", "SE1", "I1"):
            self.assertNotIn(raw, blob)

    def test_different_patients_different_pseudonyms(self):
        c = self.scan_commit("batch-1", [
            rec(instance="I1", patient="P1", file_hash=h64("a")),
            rec(instance="I2", patient="P2", study="ST2", series="SE2", file_hash=h64("b")),
        ])
        tokens = {e["patient"] for e in self.manifest_of(c)["entries"]}
        self.assertEqual(len(tokens), 2)


class TestReferenceIntegrity(GovTestCase):
    def test_missing_parent_uid_quarantined_instance_level(self):
        result = self.scan("batch-1", [
            rec(instance="I1", file_hash=h64("a")),
            rec(instance="I2", series="SE2", file_hash=h64("b"), referenced_study="ST-GHOST"),
        ])
        self.assertEqual(result["counts"]["quarantined"], 1)
        q = result["quarantine"][0]
        self.assertEqual(q["instance"], "I2")
        self.assertIn(engine.MISSING_PARENT_UID, q["reasons"])
        committed = self.commit("batch-1")
        self.assertEqual(committed["batch_status"], "partial")
        manifest = self.manifest_of(committed)
        self.assertEqual(len(manifest["entries"]), 1)
        self.assertEqual(manifest["quarantine_summary"][0]["reasons"], [engine.MISSING_PARENT_UID])

    def test_reference_resolves_against_prior_published_batch(self):
        self.scan_commit("batch-1", [rec(instance="I1", study="ST1", series="SE1", file_hash=h64("a"))])
        # batch-2 references ST1 which is not in batch-2 but is already published.
        result = self.scan("batch-2", [
            rec(instance="I2", study="ST2", series="SE2", file_hash=h64("b"),
                referenced_study="ST1"),
        ])
        self.assertEqual(result["counts"]["quarantined"], 0)


class TestPrivateTagPolicyUpgrade(GovTestCase):
    def test_upgrade_retract_republish_lineage(self):
        tagged = rec(instance="I2", series="SE2", file_hash=h64("b"),
                     private_tags=["0013_1010"])
        clean = rec(instance="I1", file_hash=h64("a"))
        first = self.scan_commit("batch-1", [clean, tagged])
        self.assertEqual(first["counts"], {"published": 1, "quarantined": 1,
                                           "duplicates_skipped": 0, "scan_errors": 0})
        m1 = self.manifest_of(first)
        self.assertEqual(m1["policy_version"], "1.0.0")
        self.assertEqual(m1["quarantine_summary"][0]["reasons"], [engine.PRIVATE_TAG_DENIED])
        m1_bytes = canonical_json(m1)

        # Policy upgrade (protocol amendment): the private tag becomes allowed.
        retracted = retract_batch(self.store, first["batch_id"], "protocol amendment 2.0.0")
        self.assertEqual(retracted["status"], "retracted")
        republished = self.scan_commit("batch-2", [clean, tagged], policy=POLICY_V2,
                                       supersedes=first["batch_id"])
        self.assertEqual(republished["counts"]["published"], 2)
        m2 = self.manifest_of(republished)
        self.assertEqual(m2["policy_version"], "2.0.0")
        self.assertEqual(m2["supersedes"], first["batch_id"])

        # Pseudonyms stable across the republish; old manifest frozen on disk.
        self.assertEqual({e["patient"] for e in m2["entries"]}, {m1["entries"][0]["patient"]})
        self.assertEqual(canonical_json(self.manifest_of(first)), m1_bytes)

        # Audit chain shows the full lineage in order.
        types = self.journal_types()
        self.assertLess(types.index("BATCH_RETRACTED"), len(types) - 1)
        self.assertEqual(types.count("COMMITTED"), 2)

    def test_policy_downgrade_and_version_conflict_refused(self):
        self.scan_commit("batch-1", [rec()], policy=POLICY_V2)
        with self.assertRaises(GovernanceError) as ctx:
            self.scan("batch-2", [rec(instance="I9", file_hash=h64("z"))], policy=POLICY_V1)
        self.assertEqual(ctx.exception.reason, "policy_downgrade")
        same_version_changed = dict(POLICY_V2, allowed_modalities=["CT"])
        with self.assertRaises(GovernanceError) as ctx:
            self.scan("batch-3", [rec(instance="I9", file_hash=h64("z"))],
                      policy=same_version_changed)
        self.assertEqual(ctx.exception.reason, "policy_version_conflict")


class TestDuplicatesAndConflicts(GovTestCase):
    def test_same_file_scanned_twice_is_idempotent(self):
        result = self.scan("batch-1", [rec(instance="I1", file_hash=h64("a")),
                                       rec(instance="I1", file_hash=h64("a"))])
        self.assertEqual(result["counts"]["published"], 1)
        self.assertEqual(result["counts"]["duplicates_skipped"], 1)

    def test_uid_conflict_same_uid_different_content(self):
        result = self.scan("batch-1", [rec(instance="I1", file_hash=h64("a")),
                                       rec(instance="I1", file_hash=h64("b"))])
        self.assertEqual(result["counts"]["published"], 1)
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.UID_CONFLICT])

    def test_hash_conflict_same_content_different_uid(self):
        result = self.scan("batch-1", [rec(instance="I1", file_hash=h64("a")),
                                       rec(instance="I2", file_hash=h64("a"))])
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.HASH_CONFLICT])

    def test_cross_batch_duplicate_and_release_after_retract(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        blocked = self.scan("batch-2", [rec(instance="I1", file_hash=h64("a"))])
        self.assertEqual(blocked["quarantine"][0]["reasons"], [engine.CROSS_BATCH_DUPLICATE])
        self.assertEqual(blocked["quarantine"][0]["detail"]["published_in_batch"],
                         c1["batch_id"])
        # Retract the first batch: the UID is released and can be republished.
        retract_batch(self.store, c1["batch_id"], "superseded")
        allowed = self.scan_commit("batch-3", [rec(instance="I1", file_hash=h64("a"))],
                                   supersedes=c1["batch_id"])
        self.assertEqual(allowed["counts"]["published"], 1)

    def test_hierarchy_conflict_series_under_two_studies(self):
        result = self.scan("batch-1", [
            rec(instance="I1", series="SE1", study="ST1", file_hash=h64("a")),
            rec(instance="I2", series="SE1", study="ST2", file_hash=h64("b")),
        ])
        self.assertEqual(result["counts"]["published"], 1)
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.HIERARCHY_CONFLICT])


class TestRetractRepublishExport(GovTestCase):
    def test_retract_blocks_export_republish_restores(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        out = os.path.join(self._tmp.name, "export.json")
        exported = export_batch(self.store, c1["batch_id"], out)
        self.assertEqual(exported["status"], "exported")
        self.assertTrue(os.path.exists(out))

        retract_batch(self.store, c1["batch_id"], "consent withdrawn")
        with self.assertRaises(GovernanceError) as ctx:
            export_batch(self.store, c1["batch_id"], out)
        self.assertEqual(ctx.exception.reason, "batch_not_publishable")
        status = self.store.status()
        self.assertEqual(status["batches"][0]["status"], "retracted")
        self.assertEqual(status["batches"][0]["retract_reason"], "consent withdrawn")

        c2 = self.scan_commit("batch-2", [rec(instance="I1", file_hash=h64("a"))],
                              supersedes=c1["batch_id"])
        self.assertNotEqual(c2["batch_id"], c1["batch_id"])
        tok_before = self.manifest_of(c1)["entries"][0]["patient"]
        tok_after = self.manifest_of(c2)["entries"][0]["patient"]
        self.assertEqual(tok_before, tok_after, "pseudonyms must survive retract/republish")
        export_batch(self.store, c2["batch_id"], out)

    def test_republish_requires_retracted_supersedes(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        with self.assertRaises(GovernanceError) as ctx:
            self.scan("batch-2", [rec(instance="I1", file_hash=h64("a"))],
                      supersedes=c1["batch_id"])
        self.assertEqual(ctx.exception.reason, "supersedes_not_retracted")

    def test_double_retract_and_unknown_batch_refused(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        retract_batch(self.store, c1["batch_id"], "first")
        with self.assertRaises(GovernanceError) as ctx:
            retract_batch(self.store, c1["batch_id"], "second")
        self.assertEqual(ctx.exception.reason, "already_retracted")
        with self.assertRaises(GovernanceError):
            retract_batch(self.store, "b-doesnotexist", "x")


class TestCrashRecovery(GovTestCase):
    def test_prepared_but_not_committed_is_aborted_not_published(self):
        self.scan("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        draft = self.store.read_draft("batch-1")
        batch_id = draft["batch_id"]
        # Simulate a crash after PREPARED: stray manifest file, tmp junk, no COMMITTED.
        self.store.append_event(COMMIT_PREPARED, {"label": "batch-1", "batch_id": batch_id,
                                                  "manifest_hash": "0" * 64})
        with open(self.store.manifest_path(batch_id), "w") as fh:
            fh.write(canonical_json(draft["manifest"]))
        with open(os.path.join(self.store_path, "manifests", ".tmp-stuck.json"), "w") as fh:
            fh.write("{}")

        store = self.reopen()
        self.assertIn("COMMIT_ABORTED", [e["type"] for e in store._events])
        self.assertEqual(store.status()["batches"], [], "nothing may appear published")
        self.assertFalse(os.path.exists(store.manifest_path(batch_id)))
        self.assertEqual(os.listdir(os.path.join(self.store_path, "stray")),
                         [f"{batch_id}.json"])
        self.assertFalse(any(n.startswith(".tmp-")
                             for n in os.listdir(os.path.join(self.store_path, "manifests"))))
        # The draft survives recovery, so the commit can be retried cleanly.
        committed = self.commit("batch-1")
        self.assertEqual(committed["status"], "committed")
        self.assertTrue(os.path.exists(store.manifest_path(batch_id)))

    def test_orphan_draft_without_journal_entry_is_removed(self):
        self.scan("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        drafts = os.path.join(self.store_path, "drafts")
        with open(os.path.join(drafts, "ghost.json"), "w") as fh:
            fh.write("{}")
        store = self.reopen()
        self.assertNotIn("ghost.json", os.listdir(drafts))
        self.assertTrue(store.status()["recovery_notes"])


class TestPartialScan(GovTestCase):
    def _build_tree(self, root):
        os.makedirs(root)
        with open(os.path.join(root, "good.dcm"), "wb") as fh:
            fh.write(b"good-bytes")
        with open(os.path.join(root, "good.dcm.tags.json"), "w") as fh:
            json.dump({"patient": "P1", "study": "ST1", "series": "SE1",
                       "instance": "I1", "modality": "CT", "protocol": "PROTO-A"}, fh)
        os.symlink("missing-target", os.path.join(root, "broken.dcm"))  # unreadable
        with open(os.path.join(root, "badmeta.dcm"), "wb") as fh:
            fh.write(b"badmeta")
        with open(os.path.join(root, "badmeta.dcm.tags.json"), "w") as fh:
            fh.write("{not json")
        with open(os.path.join(root, "nometa.dcm"), "wb") as fh:  # no sidecar at all
            fh.write(b"nometa")

    def test_unreadable_inputs_block_commit_unless_explicitly_partial(self):
        data_dir = os.path.join(self._tmp.name, "data")
        self._build_tree(data_dir)
        result = scan_batch(self.store, "batch-1", directory=data_dir,
                            policy_dict=POLICY_V1, key_hex=KEY)
        self.assertFalse(result["committable"])
        self.assertEqual(result["counts"]["scan_errors"], 2)  # symlink + bad sidecar
        self.assertEqual(result["counts"]["published"], 1)    # good.dcm
        # nometa.dcm has no identifiers: quarantined, not silently dropped.
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.MISSING_UID])
        with self.assertRaises(GovernanceError) as ctx:
            self.commit("batch-1")
        self.assertEqual(ctx.exception.reason, "incomplete_scan")

        self.store.discard_draft("batch-1")
        partial = scan_batch(self.store, "batch-2", directory=data_dir,
                             policy_dict=POLICY_V1, key_hex=KEY, allow_partial_scan=True)
        self.assertTrue(partial["committable"])
        committed = self.commit("batch-2")
        manifest = self.manifest_of(committed)
        self.assertFalse(manifest["scan"]["complete"])
        self.assertEqual(manifest["scan"]["error_count"], 2)
        self.assertEqual(manifest["counts"]["published"], 1)


class TestFrozenManifestsAndAuditChain(GovTestCase):
    def test_tampered_manifest_detected(self):
        c1 = self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        self.assertTrue(self.store.verify()["ok"])
        path = self.store.manifest_path(c1["batch_id"])
        manifest = self.store.read_manifest(c1["batch_id"])
        manifest["entries"][0]["modality"] = "MR"
        with open(path, "w") as fh:
            fh.write(canonical_json(manifest))
        report = self.store.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any(not chk["ok"] for chk in report["checks"]))
        with self.assertRaises(StoreCorrupt):
            self.reopen()

    def test_tampered_journal_detected(self):
        self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        journal = os.path.join(self.store_path, "audit.log")
        with open(journal, "r") as fh:
            lines = fh.readlines()
        lines[-1] = lines[-1].replace('"COMMITTED"', '"COMMITTEE"', 1)
        with open(journal, "w") as fh:
            fh.writelines(lines)
        with self.assertRaises(StoreCorrupt):
            self.reopen()

    def test_labels_are_single_use(self):
        self.scan_commit("batch-1", [rec(instance="I1", file_hash=h64("a"))])
        with self.assertRaises(GovernanceError) as ctx:
            self.scan("batch-1", [rec(instance="I2", file_hash=h64("b"))])
        self.assertEqual(ctx.exception.reason, "label_already_used")
        with self.assertRaises(GovernanceError) as ctx:
            self.commit("batch-1")
        self.assertEqual(ctx.exception.reason, "unknown_draft")

    def test_commit_is_deterministic(self):
        other_path = os.path.join(self._tmp.name, "store2")
        other = Store(other_path)
        rows = [rec(instance="I1", file_hash=h64("a")), rec(instance="I2", file_hash=h64("b"))]
        scan_batch(self.store, "batch-1", payload=payload(*rows),
                   policy_dict=POLICY_V1, key_hex=KEY)
        scan_batch(other, "batch-1", payload=payload(*rows),
                   policy_dict=POLICY_V1, key_hex=KEY)
        c1, c2 = commit_batch(self.store, "batch-1"), commit_batch(other, "batch-1")
        self.assertEqual(c1["batch_id"], c2["batch_id"])
        with open(self.store.manifest_path(c1["batch_id"]), "rb") as fh:
            b1 = fh.read()
        with open(other.manifest_path(c2["batch_id"]), "rb") as fh:
            b2 = fh.read()
        self.assertEqual(b1, b2)


class TestReleaseBoundary(GovTestCase):
    def test_sensitive_fields_and_pixels_never_cross(self):
        secret_name = "John Q Public"
        rows = [
            rec(instance="I1", file_hash=h64("a")),
            rec(instance="I2", series="SE2", file_hash=h64("b"),
                sensitive_fields={"PatientName": secret_name, "PatientBirthDate": "19500101"}),
            rec(instance="I3", series="SE3", file_hash=h64("c"),
                pixels={"present": True, "burned_in_annotation": True}),
        ]
        result = self.scan("batch-1", rows)
        # I2 quarantined for sensitive fields; I3 publishes as metadata-only
        # because the pixel policy keeps burned-in pixels behind the boundary.
        self.assertEqual(result["counts"]["published"], 2)
        self.assertEqual(result["counts"]["quarantined"], 1)
        reasons = {q["instance"]: q["reasons"] for q in result["quarantine"]}
        self.assertEqual(reasons["I2"], [engine.SENSITIVE_FIELD_PRESENT])
        # The quarantine record holds fingerprints, never the sensitive value.
        self.assertNotIn(secret_name, json.dumps(result["quarantine"]))

        committed = self.commit("batch-1")
        out = os.path.join(self._tmp.name, "release.json")
        export_batch(self.store, committed["batch_id"], out)
        with open(out, "rb") as fh:
            released = fh.read()
        for forbidden in (secret_name, "19500101", "P1", "ST1", "SE1", "I1",
                          "PixelData", "burned_in"):
            self.assertNotIn(forbidden.encode(), released)
        manifest = json.loads(released)
        for entry in manifest["entries"]:
            self.assertLessEqual(set(entry), {"patient", "study", "series", "instance",
                                              "modality", "protocol", "file_hash",
                                              "pixels_released"})
            self.assertFalse(entry["pixels_released"])
        # The store's own boundary audit agrees.
        self.assertEqual(self.store.boundary_check(committed["batch_id"]), [])

    def test_burned_in_pixels_quarantined_when_policy_allows_pixels(self):
        policy = dict(POLICY_V1, pixel_policy="allow")
        result = self.scan("batch-1", [
            rec(instance="I1", file_hash=h64("a"),
                pixels={"present": True, "burned_in_annotation": True}),
        ], policy=policy)
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.BURNED_IN_ANNOTATION])

    def test_pixel_policy_deny_quarantines_pixel_bearers(self):
        policy = dict(POLICY_V1, pixel_policy="deny")
        result = self.scan("batch-1", [rec(instance="I1", file_hash=h64("a"))], policy=policy)
        self.assertEqual(result["quarantine"][0]["reasons"], [engine.PIXELS_DENIED])

    def test_instance_failure_isolation_is_visible_not_silent(self):
        committed = self.scan_commit("batch-1", [
            rec(instance="I1", file_hash=h64("a")),
            rec(instance="I2", series="SE2", file_hash=h64("b"), private=True),
            rec(instance="I3", series="SE3", file_hash=h64("c"), modality="PT"),
        ])
        self.assertEqual(committed["batch_status"], "partial")
        self.assertEqual(committed["counts"]["published"], 1)
        self.assertEqual(committed["counts"]["quarantined"], 2)
        manifest = self.manifest_of(committed)
        reasons = sorted(r for q in manifest["quarantine_summary"] for r in q["reasons"])
        self.assertEqual(reasons, [engine.MODALITY_NOT_ALLOWED, engine.PRIVATE_TAG_DENIED])
        scan_events = [e for e in self.store._events if e["type"] == "SCAN_COMPLETED"]
        self.assertEqual(scan_events[0]["payload"]["counts"]["quarantined"], 2)


if __name__ == "__main__":
    unittest.main()
