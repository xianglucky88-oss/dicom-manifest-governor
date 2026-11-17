import argparse
import json
from pathlib import Path

from .pipeline import run_safe
from .report import dumps


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate DICOM hierarchy and emit deterministic research manifests."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=str(Path(__file__).parents[2] / "fixtures" / "input.json"),
    )
    args = parser.parse_args()

    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # Never echo file content or paths that may be sensitive.
        result = {
            "project": "dicom-manifest-governor",
            "status": "error",
            "error": {"code": "input_unreadable", "message": "input could not be read"},
        }
    else:
        result = run_safe(payload)

    print(dumps(result))


if __name__ == "__main__":
    main()
