"""Freeze an IsolationForest trained on reviewed benign windows, or demo data."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from backend.features import FEATURES,FEATURE_SCHEMA


def train(frame, scope):
    if 'feature_schema' in frame and not frame['feature_schema'].eq(FEATURE_SCHEMA).all():
        raise ValueError('Baseline uses legacy feature semantics; export new windows before training')
    x = frame[FEATURES].to_numpy(dtype=float)
    if len(x) < 1200 or not np.isfinite(x).all():
        raise ValueError('Need at least 1200 finite, reviewed benign feature rows')
    # Independent calibration split. Neither live alerts nor attack rows train this model.
    indices = np.random.default_rng(26145).permutation(len(x))
    cut = int(.7 * len(x))
    fit, calibration = x[indices[:cut]], x[indices[cut:]]
    model = IsolationForest(n_estimators=100, max_samples=256,
                            random_state=26145, n_jobs=1)
    model.fit(fit)
    scores = -model.score_samples(calibration)
    threshold = float(np.quantile(scores, .995) + .02)
    ROOT.joinpath('models').mkdir(exist_ok=True)
    joblib.dump({'model': model, 'features': FEATURES, 'threshold': threshold,'feature_schema':FEATURE_SCHEMA,
                 'scope': scope}, ROOT / 'models/isolation.joblib')
    report = {'scope': scope, 'fit_rows': len(fit), 'calibration_rows': len(calibration),
              'threshold': threshold, 'score_definition': '-score_samples; larger is more unusual',
              'calibration_exceedance_fraction': float(np.mean(scores > threshold)),
              'warning': 'Calibration fraction is not operational false-positive rate or detection accuracy.'}
    ROOT.joinpath('models/isolation-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--benign-csv', help='Reviewed benign windows with the FEATURES columns')
    group.add_argument('--synthetic-demo', action='store_true')
    args = parser.parse_args()
    if args.synthetic_demo:
        from benign_baseline import benign_windows
        from train import dataset
        frame, labels = dataset(8123, 400)
        frame = pd.concat([benign_windows(173, 2600), frame[np.asarray(labels) == 'benign']], ignore_index=True)
        scope = 'synthetic demonstration benign baseline only'
    else:
        frame = pd.read_csv(args.benign_csv)
        scope = 'operator-supplied reviewed benign baseline; operational validation still required'
    try:
        train(frame, scope)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))
