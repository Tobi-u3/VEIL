"""RandomForest + IsolationForest with classifier SHAP evidence."""
from pathlib import Path
import numpy as np
import joblib
from .features import FEATURES,FEATURE_SCHEMA
ROOT = Path(__file__).resolve().parents[1]

class Models:
    def __init__(self):
        self.rf = None
        self.explainer = None
        self.isolation = None
        self.isolation_threshold = None
        self.status = {'random_forest': 'not trained', 'isolation_forest': 'not trained',
                       'SHAP': 'unavailable', 'model_scope': 'no model loaded'}
        artifact = ROOT / 'models/forest.joblib'
        if artifact.exists():
            obj = joblib.load(artifact)  # Trusted local artifacts only.
            if obj.get('features') != FEATURES or obj.get('feature_schema')!=FEATURE_SCHEMA:
                raise ValueError('RandomForest feature schema mismatch; retrain locally')
            self.rf = obj['model']
            self.status['random_forest'] = 'loaded: ' + obj.get('scope', 'unspecified training')
            self.status['model_scope'] = obj.get('scope', 'unspecified training')
            try:
                import shap
                self.explainer = shap.TreeExplainer(self.rf)
                self.status['SHAP'] = 'ready: explains RandomForest class vote'
            except ImportError:
                self.status['SHAP'] = 'missing dependency: install requirements.txt'
        artifact = ROOT / 'models/isolation.joblib'
        if artifact.exists():
            obj = joblib.load(artifact)
            if obj.get('features') != FEATURES or obj.get('feature_schema')!=FEATURE_SCHEMA:
                raise ValueError('IsolationForest feature schema mismatch; retrain locally')
            self.isolation = obj['model']
            self.isolation_threshold = float(obj['threshold'])
            self.status['isolation_forest'] = 'loaded: ' + obj.get('scope', 'unspecified baseline')

    def predict(self, f):
        x = np.array([[f[k] for k in FEATURES]], dtype=float)
        if not np.isfinite(x).all():
            raise ValueError('Non-finite model features')
        out = {'label': None, 'confidence': None,
               'confidence_type': 'uncalibrated classifier vote; not attack probability',
               'shap': [], 'isolation_score': None, 'isolation_anomaly': False,
               'isolation_threshold': self.isolation_threshold}
        out['training_scope']=self.status['model_scope']
        if self.rf is not None:
            p = self.rf.predict_proba(x)[0]
            idx = int(np.argmax(p))
            out.update(label=str(self.rf.classes_[idx]), confidence=float(p[idx]))
        if self.isolation is not None and self.isolation_threshold is not None:
            # sklearn score_samples is lower for more unusual samples.
            score = float(-self.isolation.score_samples(x)[0])
            out['isolation_score'] = score
            out['isolation_anomaly'] = score > self.isolation_threshold
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
                'units':'class vote contribution; not calibrated attack likelihood',
                'training_scope':self.status['model_scope'],
                'features':[{'feature':FEATURES[i],'value':float(f[FEATURES[i]]),
                             'contribution':float(vals[i])} for i in order]}

    def explain(self,f,label):
        return self.explain_details(f,label)['features']
