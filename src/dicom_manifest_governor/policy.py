"""Release policy: versioned, content-hashed, strict.

The policy is the contract a batch is validated against. Its version and
content hash are recorded in every manifest and journal commit event, so a
protocol upgrade is an explicit, auditable transition rather than a silent
behaviour change.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .util import hash_obj

PIXEL_POLICIES = ("allow", "metadata_only", "deny")

# DICOM attributes that must never cross the release boundary with a value.
DEFAULT_SENSITIVE_DENYLIST = (
    "PatientName",
    "PatientBirthDate",
    "PatientAddress",
    "PatientTelephoneNumbers",
    "OtherPatientIDs",
    "ReferringPhysicianName",
    "PerformingPhysicianName",
    "OperatorsName",
    "NameOfPhysiciansReadingStudy",
    "InstitutionName",
    "InstitutionAddress",
    "AdmissionID",
    "PatientComments",
    "StudyComments",
)

_KNOWN_KEYS = {
    "version",
    "allowed_modalities",
    "allowed_protocols",
    "protocol_modalities",
    "private_tag_allowlist",
    "sensitive_fields_denylist",
    "pixel_policy",
    "allow_burned_in",
    "allow_partial_scan",
}


@dataclass(frozen=True)
class Policy:
    version: str = "1.0.0"
    allowed_modalities: tuple = ()
    allowed_protocols: tuple = ()
    protocol_modalities: dict = field(default_factory=dict)
    private_tag_allowlist: tuple = ()
    sensitive_fields_denylist: tuple = DEFAULT_SENSITIVE_DENYLIST
    pixel_policy: str = "metadata_only"
    allow_burned_in: bool = False
    allow_partial_scan: bool = False

    @staticmethod
    def from_dict(data: dict | None) -> "Policy":
        data = dict(data or {})
        unknown = sorted(set(data) - _KNOWN_KEYS)
        if unknown:
            raise ValueError("unknown policy keys: " + ", ".join(unknown))
        pixel_policy = data.get("pixel_policy", "metadata_only")
        if pixel_policy not in PIXEL_POLICIES:
            raise ValueError(f"pixel_policy must be one of {PIXEL_POLICIES}")
        version = str(data.get("version", "1.0.0")).strip()
        if not version:
            raise ValueError("policy version must be non-empty")
        protocol_modalities = {
            str(proto): tuple(sorted(str(m) for m in mods))
            for proto, mods in (data.get("protocol_modalities") or {}).items()
        }
        return Policy(
            version=version,
            allowed_modalities=tuple(sorted(str(m) for m in data.get("allowed_modalities", ()))),
            allowed_protocols=tuple(sorted(str(p) for p in data.get("allowed_protocols", ()))),
            protocol_modalities=protocol_modalities,
            private_tag_allowlist=tuple(sorted(str(t) for t in data.get("private_tag_allowlist", ()))),
            sensitive_fields_denylist=tuple(sorted(
                str(t) for t in data.get("sensitive_fields_denylist", DEFAULT_SENSITIVE_DENYLIST))),
            pixel_policy=pixel_policy,
            allow_burned_in=bool(data.get("allow_burned_in", False)),
            allow_partial_scan=bool(data.get("allow_partial_scan", False)),
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "allowed_modalities": sorted(self.allowed_modalities),
            "allowed_protocols": sorted(self.allowed_protocols),
            "protocol_modalities": {
                proto: sorted(mods) for proto, mods in sorted(self.protocol_modalities.items())
            },
            "private_tag_allowlist": sorted(self.private_tag_allowlist),
            "sensitive_fields_denylist": sorted(self.sensitive_fields_denylist),
            "pixel_policy": self.pixel_policy,
            "allow_burned_in": self.allow_burned_in,
            "allow_partial_scan": self.allow_partial_scan,
        }

    def hash(self) -> str:
        return hash_obj(self.to_dict())

    def version_tuple(self) -> tuple:
        parts = []
        for chunk in str(self.version).split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)
