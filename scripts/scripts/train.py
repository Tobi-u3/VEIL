"""Synthetic smoke-test training. Not a real attack detection accuracy claim."""
import sys, json, argparse
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from backend.features import FEATURES, FEATURE_SCHEMA
ROOT=Path(__file__).resolve().parents[1]

def dataset(seed,n=200):
    rng=np.random.default_rng(seed); rows=[]; labels=[]
    for label in ['benign','ddos','scan','dns_anomaly','beaconing','encrypted_suspicion','large_transfer']:
        for row_index in range(n):
            pps=rng.uniform(1,45); size=rng.uniform(60,1400)
            x=[pps,pps*size,rng.uniform(0,.3),rng.integers(1,7),size,rng.uniform(0,300),0,0,0,rng.uniform(.35,1.5),rng.integers(0,4),0]
            if label=='benign':
                x[3]=rng.choice([0,0,0,1,2])
                if row_index%4==0: # normal high-throughput incoming transfers
                    x[0]=rng.uniform(250,6000);x[4]=rng.uniform(1100,1500);x[1]=x[0]*x[4];x[2]=0;x[3]=0
                elif row_index%4==1: # ordinary ping / sparse service traffic
                    x[0]=rng.uniform(.5,5);x[4]=rng.choice([60,84,128]);x[1]=x[0]*x[4];x[2]=0;x[3]=0;x[5]=0
            if label=='ddos': x[0]=rng.uniform(300,5000);x[1]=x[0]*size;x[2]=rng.uniform(.7,1)
            if label=='scan': x[3]=rng.integers(16,150);x[2]=rng.uniform(.5,1)
            if label=='dns_anomaly': x[6]=rng.uniform(3.9,5.8);x[7]=rng.integers(28,64);x[8]=rng.choice([0,1])
            if label=='beaconing': x[9]=rng.uniform(0,.12);x[10]=rng.integers(6,30)
            if label=='encrypted_suspicion': x[11]=1
            if label=='large_transfer': x[1]=rng.uniform(2e6,15e6);x[0]=x[1]/1400;x[2]=0;x[4]=1400
            rows.append(x); labels.append(label)
    return pd.DataFrame(rows,columns=FEATURES),labels
if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Train demonstration RF or separately labelled train/validation CSVs.')
    parser.add_argument('--train-csv');parser.add_argument('--validation-csv')
    args=parser.parse_args()
    if bool(args.train_csv)!=bool(args.validation_csv):parser.error('Supply both --train-csv and --validation-csv')
    scope='synthetic demonstration'
    if args.train_csv:
        if Path(args.train_csv).resolve()==Path(args.validation_csv).resolve():parser.error('Training and validation must be separate files')
        train=pd.read_csv(args.train_csv);valid=pd.read_csv(args.validation_csv)
        try:
            X=train[FEATURES].astype(float);V=valid[FEATURES].astype(float)
            y=train['label'].astype(str).tolist();z=valid['label'].astype(str).tolist()
        except (KeyError,ValueError) as exc:parser.error(str(exc))
        classes={'benign','ddos','scan','dns_anomaly','beaconing','encrypted_suspicion','large_transfer'}
        if len(X)<100 or len(V)<20 or len(set(y))<2 or 'benign' not in y:parser.error('Need >=100 labelled training rows including benign and an attack class; >=20 validation rows')
        if not (set(y)|set(z))<=classes or not set(z)<=set(y):parser.error('Unknown label or validation class absent from training')
        if not np.isfinite(X.values).all() or not np.isfinite(V.values).all():parser.error('All features must be finite')
        for frame in (train,valid):
            if 'feature_schema' in frame and not frame['feature_schema'].eq(FEATURE_SCHEMA).all():parser.error('Feature schema mismatch')
        if 'timestamp' in train and 'timestamp' in valid and train['timestamp'].max()>=valid['timestamp'].min():parser.error('Use later, time-separated validation windows to avoid leakage')
        scope='operator-labelled traffic; separate validation supplied'
    else:
        X,y=dataset(26145);V,z=dataset(9876,80)
    m=RandomForestClassifier(n_estimators=80,max_depth=10,class_weight='balanced',random_state=26145,n_jobs=1)
    m.fit(X.values,y)
    (ROOT/'models').mkdir(exist_ok=True)
    joblib.dump({'model':m,'features':FEATURES,'scope':scope,'feature_schema':FEATURE_SCHEMA},ROOT/'models/forest.joblib')
    report={'WARNING':'Synthetic generator validation only; NOT real-world accuracy.' if not args.train_csv else 'Metrics apply only to the supplied labelled validation set; not guaranteed future performance.', 'scope':scope, 'feature_schema':FEATURE_SCHEMA,
            'training_rows':len(X),'validation_rows':len(V),'seed':26145,
            'report':classification_report(z,m.predict(V.values),output_dict=True)}
    (ROOT/'models/training-report.json').write_text(json.dumps(report,indent=2))
    if not args.train_csv: X.to_csv(ROOT/'data/synthetic-training-features.csv',index=False)
    print('Saved RandomForest model and validation report. Scope:',scope)
