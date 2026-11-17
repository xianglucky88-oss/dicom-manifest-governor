#!/usr/bin/env bash
# One-shot quality gate: QA suite, unit tests, and the mutation gate.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -I qa/run_suite.py
PYTHONPATH=src:qa python3 -m unittest discover -s tests -t . -q
python3 -I qa/mutation.py
