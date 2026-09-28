"""Synthetic smoke-test training. Not a real attack detection accuracy claim."""
import sys, json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from backend.features import FEATURES
ROOT=Path(__file__).resolve().parents[1]

def dataset(seed,n=200):
    rng=np.random.default_rng(seed); rows=[]; labels=[]
    for label in ['benign','ddos','scan','dns_anomaly','beaconing','encrypted_suspicion','large_transfer']:
        for _ in range(n):
            pps=rng.uniform(1,45); size=rng.uniform(60,1400)
            x=[pps,pps*size,rng.uniform(0,.3),rng.integers(1,7),size,rng.uniform(0,300),0,0,0,rng.uniform(.35,1.5),rng.integers(0,4),0]
            if label=='ddos': x[0]=rng.uniform(300,5000);x[1]=x[0]*size;x[2]=rng.uniform(.7,1)
            if label=='scan': x[3]=rng.integers(16,150);x[2]=rng.uniform(.5,1)
            if label=='dns_anomaly': x[6]=rng.uniform(3.9,5.8);x[7]=rng.integers(28,64);x[8]=rng.choice([0,1])
            if label=='beaconing': x[9]=rng.uniform(0,.12);x[10]=rng.integers(6,30)
            if label=='encrypted_suspicion': x[11]=1
            if label=='large_transfer': x[1]=rng.uniform(2e6,15e6);x[0]=x[1]/1400;x[2]=0;x[4]=1400
            rows.append(x); labels.append(label)
    return pd.DataFrame(rows,columns=FEATURES),labels
if __name__=='__main__':
    X,y=dataset(26145);V,z=dataset(9876,80)
    m=RandomForestClassifier(n_estimators=80,max_depth=10,class_weight='balanced',random_state=26145,n_jobs=1)
    m.fit(X.values,y)
    (ROOT/'models').mkdir(exist_ok=True)
    joblib.dump({'model':m,'features':FEATURES,'scope':'synthetic demonstration'},ROOT/'models/forest.joblib')
    report={'WARNING':'Synthetic held-out generator samples only; NOT real-world accuracy.',
            'training_rows':len(X),'validation_rows':len(V),'seed':26145,
            'report':classification_report(z,m.predict(V.values),output_dict=True)}
    (ROOT/'models/training-report.json').write_text(json.dumps(report,indent=2))
    X.to_csv(ROOT/'data/synthetic-training-features.csv',index=False)
    print('Saved demo model and explicitly labelled synthetic validation report.')
