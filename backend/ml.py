"""RF + upstream KitNET + River ADWIN + SHAP. Status never implies training quality."""
import json, os, sys
from pathlib import Path
import numpy as np
import joblib
from .features import FEATURES
ROOT=Path(__file__).resolve().parents[1]

class Models:
    def __init__(self):
        self.rf=None; self.explainer=None; self.kit=None; self.kit_threshold=None
        self.status={'random_forest':'not trained', 'SHAP':'unavailable', 'KitNET':'not installed',
                     'River_ADWIN':'unavailable', 'model_scope':'synthetic demonstration only'}
        artifact=ROOT/'models/forest.joblib'
        if artifact.exists():
            obj=joblib.load(artifact)  # Only load locally generated/trusted artifacts.
            self.rf=obj['model']; self.status['random_forest']='loaded: synthetic demo training'
            try:
                import shap
                self.explainer=shap.TreeExplainer(self.rf)
                self.status['SHAP']='ready'
            except ImportError: pass
        try:
            from river.drift import ADWIN
            self.drift=ADWIN()
            self.status['River_ADWIN']='ready: rate drift, no automatic retraining'
        except ImportError: self.drift=None
        kit_path=ROOT/'vendor/KitNET-py'
        if (kit_path/'KitNET.py').exists():
            sys.path.insert(0,str(kit_path))
            from KitNET import KitNET
            self.kit=KitNET(len(FEATURES), max_autoencoder_size=5,
                            FM_grace_period=100, AD_grace_period=500)
            self.status['KitNET']='requires clean baseline: run scripts/train_kitnet.py'
            if (ROOT/'models/kitnet.joblib').exists():
                obj=joblib.load(ROOT/'models/kitnet.joblib')
                self.kit=obj['model']; self.kit_threshold=obj['threshold']
                self.status['KitNET']='ready: '+obj.get('scope','baseline unspecified')

    def predict(self, f):
        x=np.array([[f[k] for k in FEATURES]], dtype=float)
        out={'label':None,'confidence':None,'confidence_type':'uncalibrated synthetic-model probability',
             'shap':[], 'kitnet_error':None,'kitnet_anomaly':False,'kitnet_threshold':self.kit_threshold,'drift':False}
        if self.rf:
            p=self.rf.predict_proba(x)[0]; idx=int(np.argmax(p))
            out.update(label=str(self.rf.classes_[idx]), confidence=float(p[idx]))
        if self.kit is not None and self.kit_threshold is not None:
            score=float(self.kit.execute(x[0]))
            out['kitnet_error']=score
            out['kitnet_anomaly']=score > self.kit_threshold
        if self.drift:
            self.drift.update(float(np.log1p(f['pps'])))
            out['drift']=bool(self.drift.drift_detected)
        return out

    def explain_details(self,f,label):
        if self.explainer is None or self.rf is None or label not in self.rf.classes_:
            return {'available':False,'features':[],'reason':'SHAP or the requested model class is unavailable'}
        x=np.array([[f[k] for k in FEATURES]],dtype=float)
        v=self.explainer.shap_values(x)
        idx=list(self.rf.classes_).index(label)
        vals=np.asarray(v[idx][0] if isinstance(v,list) else v[0,:,idx],dtype=float)
        base=float(np.asarray(self.explainer.expected_value)[idx])
        score=float(self.rf.predict_proba(x)[0,idx])
        order=np.argsort(np.abs(vals))[-5:][::-1]
        top=float(sum(vals[i] for i in order));error=abs(base+float(vals.sum())-score)
        return {'available':True,'class':str(label),'base_value':base,'model_score':score,
                'contribution_sum':float(vals.sum()),'other_contribution':float(vals.sum())-top,
                'reconstruction_error':error,'additivity_verified':bool(error<1e-5),
                'units':'class probability contribution; synthetic model, not calibrated attack likelihood',
                'features':[{'feature':FEATURES[i],'value':float(f[FEATURES[i]]),
                             'contribution':float(vals[i])} for i in order]}

    def explain(self,f,label):
        return self.explain_details(f,label)['features']
