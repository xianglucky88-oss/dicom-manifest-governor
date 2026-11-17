import argparse
import json
import sys
from pathlib import Path

from .pipeline import (
    GovernanceError,
    commit_batch,
    export_batch,
    retract_batch,
    run,
    scan_batch,
)
from .store import Store
from .util import read_json_file

COMMANDS = ("scan", "commit", "retract", "discard", "status", "verify", "export")


def _emit(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _legacy(argv) -> int:
    parser = argparse.ArgumentParser(
        description="Validate DICOM hierarchy and emit deterministic research manifests.")
    parser.add_argument("input", nargs="?",
                        default=str(Path(__file__).parents[2] / "fixtures" / "input.json"))
    args = parser.parse_args(argv)
    payload = json.loads(Path(args.input).read_text())
    _emit(run(payload))
    return 0


def _governed(argv) -> int:
    parser = argparse.ArgumentParser(prog="dicom-manifest-governor")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_store(p):
        p.add_argument("--store", required=True, help="governance store directory")

    p_scan = sub.add_parser("scan", help="scan a batch into a draft")
    add_store(p_scan)
    p_scan.add_argument("--label", required=True, help="single-use batch label")
    src = p_scan.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="JSON payload with an instances array")
    src.add_argument("--dir", help="directory of DICOM files (+ .tags.json sidecars)")
    p_scan.add_argument("--policy", help="policy JSON file")
    p_scan.add_argument("--key-file", help="file containing the hex pseudonym key")
    p_scan.add_argument("--key-hex", help="hex pseudonym key (prefer --key-file)")
    p_scan.add_argument("--supersedes", help="batch_id of a retracted batch this replaces")
    p_scan.add_argument("--allow-partial-scan", action="store_true")
    p_scan.add_argument("--allow-policy-downgrade", action="store_true")
    p_scan.add_argument("--allow-dev-key", action="store_true",
                        help="use the deterministic insecure development key")

    p_commit = sub.add_parser("commit", help="commit a scanned draft")
    add_store(p_commit)
    p_commit.add_argument("--label", required=True)

    p_retract = sub.add_parser("retract", help="retract a committed batch")
    add_store(p_retract)
    p_retract.add_argument("--batch-id", required=True)
    p_retract.add_argument("--reason", required=True)

    p_discard = sub.add_parser("discard", help="discard an uncommitted draft")
    add_store(p_discard)
    p_discard.add_argument("--label", required=True)

    p_status = sub.add_parser("status", help="show store status")
    add_store(p_status)

    p_verify = sub.add_parser("verify", help="verify journal, manifests and release boundary")
    add_store(p_verify)

    p_export = sub.add_parser("export", help="export a committed manifest across the release boundary")
    add_store(p_export)
    p_export.add_argument("--batch-id", required=True)
    p_export.add_argument("--out", required=True)

    args = parser.parse_args(argv)
    try:
        store = Store(args.store)
        if args.command == "scan":
            payload = read_json_file(args.input) if args.input else None
            policy_dict = read_json_file(args.policy) if args.policy else None
            result = scan_batch(
                store, args.label, payload=payload, directory=args.dir,
                policy_dict=policy_dict, key_hex=args.key_hex, key_file=args.key_file,
                supersedes=args.supersedes,
                allow_partial_scan=args.allow_partial_scan,
                allow_policy_downgrade=args.allow_policy_downgrade,
                allow_dev_key=args.allow_dev_key)
        elif args.command == "commit":
            result = commit_batch(store, args.label)
        elif args.command == "retract":
            result = retract_batch(store, args.batch_id, args.reason)
        elif args.command == "discard":
            if not store.discard_draft(args.label):
                raise GovernanceError("unknown_draft", args.label)
            result = {"status": "discarded", "label": args.label}
        elif args.command == "status":
            result = store.status()
        elif args.command == "verify":
            report = store.verify()
            _emit(report)
            return 0 if report["ok"] else 3
        elif args.command == "export":
            result = export_batch(store, args.batch_id, args.out)
        else:  # pragma: no cover - argparse enforces the set
            parser.error("unknown command")
    except GovernanceError as exc:
        _emit({"status": "refused", "reason": exc.reason, "detail": exc.detail})
        return 2
    except Exception as exc:  # store corruption, IO errors, bad input
        _emit({"status": "error", "error": type(exc).__name__, "detail": str(exc)})
        return 1
    _emit(result)
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in COMMANDS:
        code = _governed(argv)
    else:
        code = _legacy(argv)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
