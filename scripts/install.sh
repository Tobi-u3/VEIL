#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=${PYTHON:-python3}
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/train.py
.venv/bin/python scripts/make_demo.py
.venv/bin/python scripts/train_kitnet.py --synthetic-demo
(cd frontend && npm ci && npm run build)
echo 'Ready. Run bash scripts/start.sh, then open http://127.0.0.1:8000'
