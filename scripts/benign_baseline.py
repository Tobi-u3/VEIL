"""Independent synthetic benign windows for demo IsolationForest baseline/calibration.
Not derived from demo alerts, attack traffic, or real operational captures.
"""
import numpy as np,pandas as pd
from backend.features import Bucket,FEATURES

def benign_windows(seed=173,n=2600):
    rng=np.random.default_rng(seed);rows=[]
    for _ in range(n):
        # Sparse keepalives through ordinary service bursts; valid packet-derived features.
        count=int(rng.choice([1,2,3,4,8,12,20,40,70,100]))
        base_size=int(rng.integers(60,1401));variation=float(rng.choice([0,20,100,300,500]))
        port_count=int(rng.choice([1,1,1,2,3]))
        b=Bucket('192.0.2.1','10.77.0.20',0,0)
        for j in range(count):
            length=int(np.clip(rng.normal(base_size,variation),60,1500))
            b.add({'kind':'packet','ts':j*1.9/count,'length':length,'syn':bool(j==0 and count>=8 and rng.random()<.15),'dport':[443,80,8443][j%port_count],'uid':'benign'})
        rows.append(b.vector(2,[],set()))
    return pd.DataFrame(rows,columns=FEATURES)
