"""Directory scanner: files -> hash + sidecar metadata records.

The governance layer is deliberately decoupled from DICOM parsing: each file
is hashed (sha256) and its metadata comes from a ``<file>.tags.json`` sidecar
(a pydicom-backed extractor can replace the sidecar reader without touching
the engine). Unreadable files, unreadable directories and malformed sidecars
become structured scan errors — they block commit unless the batch is
explicitly accepted as partial.
"""
from __future__ import annotations

import json
import os

from .util import sha256_file

SIDECAR_SUFFIX = ".tags.json"


def scan_directory(root: str) -> dict:
    records = []
    errors = []

    def on_walk_error(exc: OSError):
        errors.append({
            "path": os.path.relpath(getattr(exc, "filename", None) or root, root),
            "error": f"{type(exc).__name__}: {exc}",
        })

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_walk_error):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(SIDECAR_SUFFIX):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            try:
                file_hash = "sha256:" + sha256_file(path)
            except OSError as exc:
                errors.append({"path": rel, "error": f"{type(exc).__name__}: {exc}"})
                continue
            sidecar = path + SIDECAR_SUFFIX
            tags = {}
            try:
                with open(sidecar, "r", encoding="utf-8") as fh:
                    tags = json.load(fh)
                if not isinstance(tags, dict):
                    errors.append({"path": rel + SIDECAR_SUFFIX, "error": "sidecar_not_object"})
                    continue
            except FileNotFoundError:
                pass  # no metadata: record will be quarantined as missing_uid
            except (OSError, json.JSONDecodeError) as exc:
                errors.append({"path": rel + SIDECAR_SUFFIX, "error": f"{type(exc).__name__}: {exc}"})
                continue
            record = dict(tags)
            record["file_hash"] = file_hash
            record["source_path"] = rel
            records.append(record)

    return {"records": records, "errors": sorted(errors, key=lambda e: e["path"])}
