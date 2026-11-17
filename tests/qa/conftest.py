"""Make the production package and the QA oracle importable from tests."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for entry in (ROOT / "src", ROOT / "qa"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
