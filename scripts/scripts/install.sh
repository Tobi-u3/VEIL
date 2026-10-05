#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z ${PYTHON:-} ]]; then
  for candidate in python3 python3.14 python3.13 python3.12; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys;sys.exit(not ((3,12)<=sys.version_info[:2]<=(3,14)))'; then
      PYTHON=$candidate; break
    fi
  done
fi
[[ -n ${PYTHON:-} ]] || { echo 'Use an installed Python 3.12–3.14. Example: PYTHON=python3.13 bash scripts/install.sh'; exit 1; }
"$PYTHON" -c 'import sys;sys.exit("This pinned stack requires Python 3.12–3.14; do not change system Python.") if not ((3,12)<=sys.version_info[:2]<=(3,14)) else None'
if [[ ! -x .venv/bin/python ]]; then "$PYTHON" -m venv .venv; fi
.venv/bin/python -c 'import sys;sys.exit("Existing .venv uses an unsupported Python; rename it and rerun installation.") if not ((3,12)<=sys.version_info[:2]<=(3,14)) else None'
.venv/bin/python -m pip install -r requirements.txt
# Preserve existing models. Bundled artifacts match the pinned sklearn version.
[[ -f models/forest.joblib ]] || .venv/bin/python scripts/train.py
[[ -f models/isolation.joblib ]] || .venv/bin/python scripts/train_isolation.py --synthetic-demo
[[ -f data/demo.jsonl ]] || .venv/bin/python scripts/make_demo.py
if [[ ${REBUILD_UI:-0} == 1 || ! -f frontend/dist/index.html ]]; then
  command -v npm >/dev/null || { echo 'Install Node/npm to rebuild the UI. The provided ZIP includes a built UI.'; exit 1; }
  (cd frontend && npm ci && npm run build)
fi
.venv/bin/python scripts/doctor.py
printf '%s\n' 'Installed. Create an account: .venv/bin/python scripts/create_user.py' 'Then run: bash scripts/start.sh'
