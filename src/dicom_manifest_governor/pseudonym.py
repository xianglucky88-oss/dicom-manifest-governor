"""Keyed pseudonymization.

Pseudonyms are HMAC-SHA256 tokens with domain separation per hierarchy level.
Properties required by the governance flow:

- stable across batches: same key + same identifier -> same token;
- not reversible from output: without the key the token reveals nothing, and
  the store never persists a raw-id -> token reverse map for published data;
- key never leaves the operator's hands: the store records only a key
  *fingerprint* so audits can prove which key produced a manifest.
"""
from __future__ import annotations

import hashlib
import hmac
import os

DOMAIN = "dmg1"
TOKEN_HEX_LEN = 24  # 96 bits: collision-safe for research-scale batches

# Deterministic key for the legacy in-memory path only. Never accepted for
# governed (store-backed) commits unless explicitly overridden.
DEV_KEY = hashlib.sha256(b"dmg-insecure-development-key").digest()

KEY_ENV_VAR = "DMG_PSEUDONYM_KEY"


class Pseudonymizer:
    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("pseudonym key must be at least 16 bytes")
        self._key = bytes(key)
        self.fingerprint = hashlib.sha256(b"dmg1-key-fp|" + self._key).hexdigest()[:16]

    def _mac(self, context: str, value: str) -> str:
        msg = f"{DOMAIN}|{context}|{value}".encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def patient(self, patient_id: str) -> str:
        return "pt-" + self._mac("patient", patient_id)[:TOKEN_HEX_LEN]

    def study(self, study_uid: str) -> str:
        return "st-" + self._mac("study", study_uid)[:TOKEN_HEX_LEN]

    def series(self, series_uid: str) -> str:
        return "se-" + self._mac("series", series_uid)[:TOKEN_HEX_LEN]

    def instance(self, instance_uid: str) -> str:
        return "in-" + self._mac("instance", instance_uid)[:TOKEN_HEX_LEN]

    def patient_key(self, patient_id: str) -> str:
        """Internal registry key used only for cross-batch collision detection."""
        return self._mac("patient-key", patient_id)


def load_key(key_hex: str | None = None,
             key_file: str | None = None,
             env_var: str = KEY_ENV_VAR,
             allow_dev: bool = False):
    """Resolve the pseudonym key. Returns (key_bytes, key_mode).

    Fails closed: governed paths must pass an explicit key or set the
    environment variable; the deterministic development key is only used
    when allow_dev=True and is always labelled in output.
    """
    if key_hex:
        return bytes.fromhex(key_hex.strip()), "config"
    if key_file:
        with open(key_file, "r", encoding="utf-8") as fh:
            return bytes.fromhex(fh.read().strip()), "file"
    env = os.environ.get(env_var)
    if env:
        return bytes.fromhex(env.strip()), "env"
    if allow_dev:
        return DEV_KEY, "insecure-development"
    raise ValueError(
        "pseudonym key required: pass --key-file/--key-hex or set " + env_var)
