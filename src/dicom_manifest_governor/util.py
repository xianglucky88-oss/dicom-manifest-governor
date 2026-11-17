"""Shared deterministic helpers: canonical JSON, hashing, atomic writes.

Everything that crosses the release boundary (manifests, journal entries,
policy hashes) is serialized through canonical_json so that identical input
produces byte-identical artifacts.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone


def canonical_json(obj) -> str:
    """Deterministic serialization: sorted keys, tight separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    """Content hash of any JSON-serializable object."""
    return sha256_hex(canonical_json(obj).encode("utf-8"))


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk_size), b""):
            h.update(block)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def atomic_write(path: str, data: bytes) -> None:
    """Write via temp file + rename so a crash never leaves a partial file.

    The temp file lives in the same directory (same filesystem) and uses the
    ``.tmp-`` prefix that store recovery cleans up.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def read_json_file(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
