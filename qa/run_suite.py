"""QA suite entry point used by the mutation gate and by CI.

Runs, in order:
1. the hand-written scenarios (explicit expectations);
2. the seeded differential/property harness against the reference oracle;
3. fault-injection checks around the orchestration and report boundaries.

Exit code 0 means the gate passes.  ``argv[1]`` may override the source path
(used to point at a mutated copy); ``argv[2]`` may override the oracle path.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent


def _configure_paths(arguments: List[str]) -> None:
    src = arguments[0] if len(arguments) > 0 else str(HERE.parent / "src")
    qa = arguments[1] if len(arguments) > 1 else str(HERE)
    for entry in (qa, src):
        while entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)


def _fresh(module_name: str):
    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


def main() -> int:
    _configure_paths(sys.argv[1:])

    failures: List[str] = []

    import harness
    import reference_model  # noqa: F401  (import proves the oracle is reachable)
    import scenarios

    pipeline = _fresh("dicom_manifest_governor.pipeline")

    # 1. Explicit scenarios.
    for scenario in scenarios.SCENARIOS:
        result = pipeline.run(scenario["payload"])
        got_reasons = sorted(sorted(r["reasons"]) for r in result["rejected"])
        want_reasons = sorted(sorted(r) for r in scenario["reason_sets"])
        if result["published_count"] != scenario["published"]:
            failures.append(
                "scenario %s: published %d != %d"
                % (scenario["name"], result["published_count"], scenario["published"])
            )
        if result["quarantined_count"] != scenario["quarantined"]:
            failures.append(
                "scenario %s: quarantined %d != %d"
                % (
                    scenario["name"],
                    result["quarantined_count"],
                    scenario["quarantined"],
                )
            )
        if got_reasons != want_reasons:
            failures.append(
                "scenario %s: reasons %r != %r"
                % (scenario["name"], got_reasons, want_reasons)
            )
        if "manifest_modalities" in scenario:
            got_modalities = [e["modality"] for e in result["manifest"]]
            if got_modalities != scenario["manifest_modalities"]:
                failures.append(
                    "scenario %s: modalities %r != %r"
                    % (
                        scenario["name"],
                        got_modalities,
                        scenario["manifest_modalities"],
                    )
                )

    # 2. Differential properties, seeded for reproducibility.
    property_failures = harness.run_properties(
        pipeline.run, seed=20240101, cases=400
    )
    for failure in property_failures:
        failures.append(
            "property seed=%s case=%s: %s"
            % (failure["seed"], failure["case"], failure["minimal_failure"].splitlines()[0])
        )

    # 3. Deterministic replay: same payload twice -> byte-identical envelope.
    payload = scenarios.REORDER_PAYLOAD_A
    first = json.dumps(pipeline.run(payload), sort_keys=True)
    second = json.dumps(pipeline.run(payload), sort_keys=True)
    if first != second:
        failures.append("non-deterministic output: repeat run differs")

    # 4. Reordering invariance on the explicit reorder payload.
    reversed_payload = dict(payload)
    reversed_payload["instances"] = list(reversed(payload["instances"]))
    if harness.sealed_view(pipeline.run(payload)) != harness.sealed_view(
        pipeline.run(reversed_payload)
    ):
        failures.append("output depends on input order")

    # 5. Fault injection at the orchestration boundary.
    import fault_injection

    failures.extend(fault_injection.run(pipeline))

    if failures:
        for failure in failures:
            print("FAIL: " + failure, file=sys.stderr)
        print("\n%d QA failure(s)" % len(failures), file=sys.stderr)
        return 1

    print(
        "QA gate passed: %d scenarios, 400 property cases, fault injection"
        % len(scenarios.SCENARIOS)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
