#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -x .venv/bin/python ]] || { echo 'Run bash scripts/install.sh first.'; exit 1; }
.venv/bin/python scripts/doctor.py --require-account
exec .venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
