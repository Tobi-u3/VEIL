"""Train upstream KitNET on an explicit trusted benign baseline; freeze after training."""
import argparse,sys,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'vendor/KitNET-py'))
import numpy as np,pandas as pd,joblib
from backend.features import FEATURES
from KitNET import KitNET
p=argparse.ArgumentParser();p.add_argument('--benign-csv');p.add_argument('--synthetic-demo',action='store_true');a=p.parse_args()
if bool(a.benign_csv)==bool(a.synthetic_demo):p.error('Choose --benign-csv PATH or --synthetic-demo')
if a.synthetic_demo:
    from benign_baseline import benign_windows
    X=benign_windows(173,2600);scope='independent synthetic benign packet-window baseline'
else:
    X=pd.read_csv(a.benign_csv)[FEATURES];scope='operator supplied benign baseline'
if len(X)<1200 or not np.isfinite(X.values).all():raise SystemExit('Need >=1200 finite, verified benign rows.')
m=KitNET(len(FEATURES),max_autoencoder_size=5,FM_grace_period=100,AD_grace_period=500)
for row in X.iloc[:601].values:m.process(np.asarray(row,dtype=float))
scores=[m.execute(np.asarray(row,dtype=float)) for row in X.iloc[601:].values]
threshold=float(np.quantile(scores,.995))*1.2+1e-8
joblib.dump({'model':m,'threshold':threshold,'scope':scope},ROOT/'models/kitnet.joblib')
(ROOT/'models/kitnet-report.json').write_text(json.dumps({'baseline':scope,'threshold':threshold,'training_rows':601,'calibration_rows':len(scores),'baseline_seed':173 if a.synthetic_demo else None,'attack_rows_in_baseline':0 if a.synthetic_demo else None,'upstream_commit':'02eb5e804568ee9f3968d4fc5bdfd37a9c0bc190'},indent=2))
print('Saved KitNET; never retrain automatically from unverified live alerts.')
