"""Pure validation engine.

No I/O happens here: the engine takes normalized records, a Policy, a
read-only registry view (cross-batch state) and a Pseudonymizer, and returns
the publishable entries, per-instance quarantine decisions, audit events and
the registry delta a commit would apply. Instance-level failures isolate the
instance; they never abort the batch and are never silently dropped.
"""
from __future__ import annotations

from .parser import REQUIRED_ID_FIELDS
from .policy import Policy
from .pseudonym import DEV_KEY, Pseudonymizer
from .util import hash_obj, sha256_hex

# Quarantine reason codes (stable vocabulary for audits and tests).
MISSING_UID = "missing_uid"
MISSING_FILE_HASH = "missing_file_hash"
DUPLICATE_FILE = "duplicate_file"          # informational event, not a quarantine
HASH_CONFLICT = "hash_conflict"            # same content, different instance UID
UID_CONFLICT = "uid_conflict"              # same instance UID, different content
HIERARCHY_CONFLICT = "hierarchy_conflict"  # series/study owned by two parents
MISSING_PARENT_UID = "missing_parent_uid"  # dangling reference (UID 断链)
PROTOCOL_NOT_ALLOWED = "protocol_not_allowed"
MODALITY_NOT_ALLOWED = "modality_not_allowed"
PRIVATE_TAG_DENIED = "private_tag_denied"
SENSITIVE_FIELD_PRESENT = "sensitive_field_present"
PIXELS_DENIED = "pixels_denied"
BURNED_IN_ANNOTATION = "burned_in_annotation"
CROSS_BATCH_DUPLICATE = "cross_batch_duplicate"
PSEUDONYM_COLLISION = "pseudonym_collision"

EMPTY_REGISTRY = {
    "instances": {},    # instance token -> batch_id
    "files": {},        # file_hash -> instance token
    "series_map": {},   # series token -> study token
    "study_map": {},    # study token -> patient token
    "pseudonyms": {},   # patient token -> patient key hash
}


def _record_hash(rec: dict) -> str:
    """Content hash over the normalized record; fallback identity when no
    real file hash is available (legacy in-memory path only)."""
    material = {k: v for k, v in rec.items() if k not in ("source_path", "row_index")}
    return "sha256:" + hash_obj(material)


def _value_fingerprint(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))[:12]


def evaluate(records, policy: Policy, registry, ps: Pseudonymizer, context=None) -> dict:
    context = context or {}
    require_file_hash = bool(context.get("require_file_hash", False))
    registry = registry or EMPTY_REGISTRY

    events = []
    quarantine = []
    candidates = []

    # Batch-wide UID sets for reference (parent UID) resolution.
    batch_studies = {r["study"] for r in records if r["study"]}
    batch_series = {r["series"] for r in records if r["series"]}

    seen_content = {}   # effective content hash -> instance uid
    seen_uid = {}       # instance uid -> effective content hash
    series_owner = {}   # series uid -> study uid (intra-batch)
    study_owner = {}    # study uid -> patient uid (intra-batch)

    for rec in records:
        reasons = []
        detail = {}

        missing = [f for f in REQUIRED_ID_FIELDS if not rec[f]]
        if missing:
            quarantine.append(_quarantine_entry(rec, [MISSING_UID], {"fields": missing}))
            continue

        uid = rec["instance"]
        eff_hash = rec["file_hash"] or _record_hash(rec)

        if require_file_hash and rec["file_hash"] is None:
            reasons.append(MISSING_FILE_HASH)

        # --- intra-batch duplicate / conflict detection -------------------
        prior_uid = seen_content.get(eff_hash)
        if prior_uid is not None:
            if prior_uid == uid:
                # Same file scanned twice: idempotent skip, auditable event.
                events.append({"type": DUPLICATE_FILE, "instance": uid, "content": eff_hash})
                continue
            reasons.append(HASH_CONFLICT)
            detail["conflict_with_instance"] = prior_uid
        prior_hash = seen_uid.get(uid)
        if prior_hash is not None and prior_hash != eff_hash:
            reasons.append(UID_CONFLICT)

        # --- hierarchy integrity (intra-batch) -----------------------------
        se, st, pt = rec["series"], rec["study"], rec["patient"]
        if series_owner.get(se) not in (None, st):
            reasons.append(HIERARCHY_CONFLICT)
            detail["series_conflict"] = {"series": se, "studies": sorted({series_owner[se], st})}
        if study_owner.get(st) not in (None, pt):
            reasons.append(HIERARCHY_CONFLICT)
            detail["study_conflict"] = {"study": st, "patients": sorted({study_owner[st], pt})}

        # --- cross-batch registry checks -----------------------------------
        tok_i, tok_se = ps.instance(uid), ps.series(se)
        tok_st, tok_pt = ps.study(st), ps.patient(pt)
        owner_batch = registry["instances"].get(tok_i)
        if owner_batch is not None:
            reasons.append(CROSS_BATCH_DUPLICATE)
            detail["published_in_batch"] = owner_batch
        file_owner = registry["files"].get(rec["file_hash"])
        if file_owner is not None and file_owner != tok_i:
            reasons.append(HASH_CONFLICT)
            detail["file_published_as"] = file_owner
        mapped_study = registry["series_map"].get(tok_se)
        if mapped_study is not None and mapped_study != tok_st:
            reasons.append(HIERARCHY_CONFLICT)
            detail["series_conflict"] = {"series": se, "cross_batch": True}
        mapped_patient = registry["study_map"].get(tok_st)
        if mapped_patient is not None and mapped_patient != tok_pt:
            reasons.append(HIERARCHY_CONFLICT)
            detail["study_conflict"] = {"study": st, "cross_batch": True}

        # --- reference integrity (UID 断链) --------------------------------
        ref_study = rec["referenced_study"]
        if ref_study and ref_study not in batch_studies \
                and ps.study(ref_study) not in registry["study_map"]:
            reasons.append(MISSING_PARENT_UID)
            detail["unresolved_reference"] = {"referenced_study": ref_study}
        ref_series = rec["referenced_series"]
        if ref_series and ref_series not in batch_series \
                and ps.series(ref_series) not in registry["series_map"]:
            reasons.append(MISSING_PARENT_UID)
            detail["unresolved_reference"] = {"referenced_series": ref_series}

        # --- protocol scope -------------------------------------------------
        if policy.allowed_protocols and rec["protocol"] not in policy.allowed_protocols:
            reasons.append(PROTOCOL_NOT_ALLOWED)
            detail["protocol"] = rec["protocol"]
        if policy.allowed_modalities and rec["modality"] not in policy.allowed_modalities:
            reasons.append(MODALITY_NOT_ALLOWED)
            detail["modality"] = rec["modality"]
        proto_mods = policy.protocol_modalities.get(rec["protocol"] or "")
        if proto_mods and rec["modality"] not in proto_mods:
            reasons.append(MODALITY_NOT_ALLOWED)
            detail["protocol_modality"] = {"protocol": rec["protocol"], "modality": rec["modality"]}

        # --- private tags ---------------------------------------------------
        extra_tags = sorted(set(rec["private_tags"]) - set(policy.private_tag_allowlist))
        if extra_tags:
            reasons.append(PRIVATE_TAG_DENIED)
            detail["private_tags"] = extra_tags

        # --- sensitive fields (values fingerprinted, never copied) ---------
        hits = sorted(
            tag for tag, value in rec["sensitive_fields"].items()
            if tag in policy.sensitive_fields_denylist and value.strip()
        )
        if hits:
            reasons.append(SENSITIVE_FIELD_PRESENT)
            detail["sensitive_fields"] = {
                tag: _value_fingerprint(rec["sensitive_fields"][tag]) for tag in hits
            }

        # --- pixel release policy -------------------------------------------
        pixels_released = False
        px = rec["pixels"]
        if policy.pixel_policy == "deny" and px["present"]:
            reasons.append(PIXELS_DENIED)
        elif policy.pixel_policy == "allow" and px["present"]:
            if px["burned_in_annotation"] and not policy.allow_burned_in:
                reasons.append(BURNED_IN_ANNOTATION)
            else:
                pixels_released = True

        # --- pseudonym collision (registry-level alarm) ---------------------
        patient_key = ps.patient_key(pt)
        registered = registry["pseudonyms"].get(tok_pt)
        if registered is not None and registered != patient_key:
            reasons.append(PSEUDONYM_COLLISION)

        if reasons:
            quarantine.append(_quarantine_entry(rec, sorted(set(reasons)), detail))
            continue

        seen_content.setdefault(eff_hash, uid)
        seen_uid.setdefault(uid, eff_hash)
        series_owner.setdefault(se, st)
        study_owner.setdefault(st, pt)

        entry = {
            "patient": tok_pt,
            "study": tok_st,
            "series": tok_se,
            "instance": tok_i,
            "modality": rec["modality"],
            "pixels_released": pixels_released,
        }
        if rec["protocol"]:
            entry["protocol"] = rec["protocol"]
        if rec["file_hash"]:
            entry["file_hash"] = rec["file_hash"]
        else:
            entry["record_hash"] = eff_hash
        candidates.append((rec, entry, patient_key))

    # Deterministic output ordering by tokens (reveals nothing about raw ids).
    entries = sorted((e for _, e, _ in candidates),
                     key=lambda e: (e["patient"], e["study"], e["series"], e["instance"]))
    quarantine.sort(key=lambda q: q["identity"])

    registry_delta = {
        "instances": {e["instance"]: True for _, e, _ in candidates},
        "files": {r["file_hash"]: e["instance"] for r, e, _ in candidates if r["file_hash"]},
        "series_map": {e["series"]: e["study"] for _, e, _ in candidates},
        "study_map": {e["study"]: e["patient"] for _, e, _ in candidates},
        "pseudonyms": {e["patient"]: pk for _, e, pk in candidates},
    }
    stats = {
        "input_records": len(records),
        "publishable": len(entries),
        "quarantined": len(quarantine),
        "duplicates_skipped": sum(1 for ev in events if ev["type"] == DUPLICATE_FILE),
    }
    return {
        "entries": entries,
        "quarantine": quarantine,
        "events": events,
        "registry_delta": registry_delta,
        "stats": stats,
    }


def _quarantine_entry(rec: dict, reasons: list, detail: dict) -> dict:
    identity = rec["instance"] or rec["file_hash"] or rec["source_path"] \
        or f"row-{rec.get('row_index', 0)}"
    return {
        "identity": identity,
        "instance": rec["instance"] or None,
        "patient": rec["patient"] or None,
        "study": rec["study"] or None,
        "series": rec["series"] or None,
        "file_hash": rec["file_hash"],
        "source_path": rec["source_path"],
        "reason": reasons[0],
        "reasons": list(reasons),
        "detail": detail or {},
    }


def calculate(rows, payload):
    """Legacy in-memory entry point, now routed through the governed engine.

    Cross-batch checks are empty (no store) and the key is the deterministic
    development key unless the payload provides ``pseudonym_key``; both facts
    are labelled in the output.
    """
    policy_dict = dict(payload.get("policy") or {})
    if "allowed_modalities" not in policy_dict and "allowed_modalities" in payload:
        policy_dict["allowed_modalities"] = payload["allowed_modalities"]
    policy = Policy.from_dict(policy_dict)

    key_hex = payload.get("pseudonym_key")
    if key_hex:
        ps = Pseudonymizer(bytes.fromhex(key_hex))
        key_mode = "config"
    else:
        ps = Pseudonymizer(DEV_KEY)
        key_mode = "insecure-development"

    result = evaluate(rows, policy, EMPTY_REGISTRY, ps, context={"require_file_hash": False})
    published = len(result["entries"])
    quarantined = len(result["quarantine"])
    return {
        "manifest": result["entries"],
        "rejected": result["quarantine"],
        "published_count": published,
        "quarantined_count": quarantined,
        "batch_status": "clean" if not quarantined else ("partial" if published else "empty"),
        "policy_version": policy.version,
        "policy_hash": policy.hash(),
        "key_mode": key_mode,
        "pseudonym_key_fingerprint": ps.fingerprint,
        "events": result["events"],
    }
