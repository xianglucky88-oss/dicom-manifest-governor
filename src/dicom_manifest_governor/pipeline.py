"""Orchestration boundary: parse -> evaluate -> report, with hard invariants."""

from __future__ import annotations

from typing import Any, Dict

from .engine import evaluate
from .models import InputError, InvariantError
from .parser import load_records
from .report import PROJECT, build_result


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    parsed = load_records(payload)
    evaluation = evaluate(parsed)
    result = build_result(
        PROJECT, evaluation, raw_patients=frozenset(parsed.patient_values)
    )
    return result


def run_safe(payload: Any) -> Dict[str, Any]:
    """Return a deterministic error envelope instead of raising.

    The envelope never echoes payload content, so it is safe to log or return
    to an untrusted caller.
    """

    try:
        return run(payload)
    except InputError as error:
        return {
            "project": PROJECT,
            "status": "error",
            "error": {"code": error.code, "message": str(error)},
        }
    except InvariantError:
        return {
            "project": PROJECT,
            "status": "error",
            "error": {
                "code": "invariant_violation",
                "message": "internal invariant violated",
            },
        }
