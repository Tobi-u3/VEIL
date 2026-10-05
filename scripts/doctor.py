"""Check local runtime before startup; does not inspect or modify network wiring."""
import argparse
import importlib.metadata
import json
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--require-account',action='store_true')
a = p.parse_args()
failed = False
for name in ('fastapi','uvicorn','numpy','pandas','scikit-learn','shap','networkx','scapy','httpx','joblib','scipy','threadpoolctl'):
    try: print('OK',name,importlib.metadata.version(name))
    except importlib.metadata.PackageNotFoundError:
        print('FAIL missing dependency:',name);failed=True
if not (ROOT/'frontend/dist/index.html').exists():
    print('FAIL frontend is missing; REBUILD_UI=1 bash scripts/install.sh');failed=True
if not failed:
    try:
        from backend.ml import Models
        m=Models()
        if m.rf is None or m.isolation is None or m.explainer is None:
            raise ValueError('Train both models and install SHAP before startup')
        print(json.dumps(m.status,indent=2))
    except Exception as exc:
        print('FAIL model loading:',str(exc))
        print('For demonstration artifacts: python scripts/train.py and python scripts/train_isolation.py --synthetic-demo')
        failed=True
from backend.gnn import GraphCorrelation
gnn=GraphCorrelation()
print('GNN:',gnn.status,gnn.error or '')
if a.require_account:
    try:
        from backend.auth import Auth
        if not Auth().credentials: raise ValueError('Create account: .venv/bin/python scripts/create_user.py')
        print('OK operator account configured')
    except Exception as exc: print('FAIL',str(exc));failed=True
if os.getenv('VEIL_LOG'):
    log=Path(os.environ['VEIL_LOG'])
    print('LIVE input:',str(log), '(exists)' if log.exists() else '(waiting for capture to create file)')
else: print('REPLAY mode selected. Live capture requires VEIL_LOG.')
sys.exit(1 if failed else 0)
