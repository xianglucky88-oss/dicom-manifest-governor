from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Tuple


class InputError(ValueError):
    """A structural input-contract violation.

    ``code`` is stable and machine readable; the message never echoes payload
    content so that error envelopes remain safe to log.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class InvariantError(RuntimeError):
    """Raised when an internal conservation/audit invariant is broken."""


@dataclass(frozen=True)
class Record:
    """A single parsed input row.

    ``reasons`` contains only stable machine-readable codes; raw identifiers are
    deliberately not copied into them.  ``ref`` is an opaque, stable reference
    suitable for an audit report.
    """

    patient: str
    study: str
    series: str
    instance: str
    modality: str
    private: bool = False
    private_flag: bool = False
    has_private_tags: bool = False
    reasons: Tuple[str, ...] = ()
    ref: str = ""
    content_key: str = ""
    identity_ok: bool = False


@dataclass(frozen=True)
class ParsedPayload:
    records: Tuple[Record, ...]
    allowed_modalities: FrozenSet[str]
    input_count: int
    patient_values: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ManifestEntry:
    """A publishable manifest row; the patient value is already pseudonymous."""

    patient: str
    study: str
    series: str
    instance: str
    modality: str


@dataclass(frozen=True)
class Rejection:
    """An auditable quarantine record; contains no raw input identifiers."""

    ref: str
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class Evaluation:
    """Full domain evaluation; ordering is already canonical."""

    manifest: Tuple[ManifestEntry, ...]
    rejected: Tuple[Rejection, ...]
    input_count: int


@dataclass(frozen=True)
class PipelineResult:
    project: str
    data: Dict[str, Any]
