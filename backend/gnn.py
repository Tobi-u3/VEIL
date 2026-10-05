"""Directed GraphSAGE with learned weights, bounded metadata windows and NumPy inference.
No packet transmissions, IP identity features, payloads, or alert-label inputs.
"""
import json, math, os, time
from pathlib import Path
from collections import defaultdict
import numpy as np
from scipy.sparse import csr_matrix
from threadpoolctl import threadpool_limits

SCHEMA='veil-directed-sage-v1'
FEATURES=['out_packets','in_packets','out_bytes','in_bytes','out_syn_fraction','in_syn_fraction','out_probe_ports','in_probe_ports','out_degree','in_degree']
CLASSES=['background','scan_pattern','syn_convergence']
WINDOW=30
ROOT=Path(__file__).resolve().parents[1]

def graph_arrays(edges):
    ids=sorted({e[k] for e in edges for k in ('src','dst')}); ix={ip:i for i,ip in enumerate(ids)}
    x=np.zeros((len(ids),len(FEATURES)),dtype=np.float32); ports_out=defaultdict(set);ports_in=defaultdict(set)
    sources=[];targets=[]
    for e in edges:
        s,t=ix[e['src']],ix[e['dst']];sources.append(s);targets.append(t)
        x[s,0]+=e['packets'];x[t,1]+=e['packets'];x[s,2]+=e['bytes'];x[t,3]+=e['bytes']
        x[s,4]+=e['syn'];x[t,5]+=e['syn'];x[s,8]+=1;x[t,9]+=1
        ports_out[s].update(e['ports']);ports_in[t].update(e['ports'])
    x[:,4]/=np.maximum(x[:,0],1);x[:,5]/=np.maximum(x[:,1],1)
    for i in range(len(ids)):x[i,6]=len(ports_out[i]);x[i,7]=len(ports_in[i])
    raw=x.copy()
    for c,scale in [(0,10000),(1,10000),(2,15000000),(3,15000000),(6,64),(7,64),(8,512),(9,512)]:x[:,c]=np.log1p(x[:,c])/np.log1p(scale)
    x=np.clip(x,0,2)
    n=len(ids);a=csr_matrix((np.ones(len(sources)),(targets,sources)),shape=(n,n),dtype=np.float32)
    def normalize(m):return m.multiply(1/np.maximum(np.asarray(m.sum(axis=1)).ravel(),1)[:,None]).tocsr()
    return ids,x,normalize(a),normalize(a.T.tocsr()),raw

def forward(x,ain,aout,w,cache=False):
    z0=np.concatenate([x,ain@x,aout@x],axis=1)
    h1=np.maximum(z0@w['w1']+w['b1'],0)
    z1=np.concatenate([h1,ain@h1,aout@h1],axis=1)
    h2=np.maximum(z1@w['w2']+w['b2'],0)
    logits=h2@w['w3']+w['b3'];logits-=logits.max(axis=1,keepdims=True) if len(x) else 0
    p=np.exp(logits);p/=p.sum(axis=1,keepdims=True) if len(x) else 1
    return (p,h2,(z0,h1,z1,h2)) if cache else (p,h2)

class GraphCorrelation:
    def __init__(self,artifact=None,enabled=None):
        self.enabled=os.getenv('VEIL_GNN','1')!='0' if enabled is None else enabled
        self.buckets={};self.last_ts=0.;self.next_prune=0.;self.dropped_until=0.;self.drops=0
        self.cache=None;self.cache_at=-1e20;self.weights=None;self.error=None;self.report={}
        self.max_buckets=12000;self.max_edges=2048;self.max_nodes=512
        if not self.enabled:self.status='disabled';return
        path=Path(artifact) if artifact else ROOT/'models/gnn.json'
        try:
            obj=json.loads(path.read_text())
            if obj['schema']!=SCHEMA or obj['features']!=FEATURES or obj['classes']!=CLASSES or obj['window_seconds']!=WINDOW:raise ValueError('incompatible GNN schema')
            dims={'w1':(30,24),'b1':(24,),'w2':(72,16),'b2':(16,),'w3':(16,3),'b3':(3,)}
            w={k:np.asarray(obj['weights'][k],dtype=np.float32) for k in dims}
            if any(w[k].shape!=v or not np.isfinite(w[k]).all() for k,v in dims.items()):raise ValueError('invalid GNN weights')
            threshold=float(obj['threshold'])
            if not .5<=threshold<=1:raise ValueError('invalid GNN threshold')
            self.weights=w;self.threshold=threshold;self.scope=str(obj['scope']);self.report=obj.get('validation',{})
            self.status='ready: '+self.scope
        except (OSError,ValueError,KeyError,TypeError) as exc:
            self.status='unavailable';self.error=str(exc)[:180]

    def add(self,e):
        if not self.enabled:return
        from .features import is_tcp_probe
        ts=e['ts'];self.last_ts=max(self.last_ts,ts)
        if ts<self.last_ts-WINDOW:return
        if ts>=self.next_prune:
            self.buckets={k:v for k,v in self.buckets.items() if k[0]>self.last_ts-WINDOW}
            self.next_prune=ts+1
        key=(math.floor(ts),e['src'],e['dst'])
        if key not in self.buckets:
            if len(self.buckets)>=self.max_buckets:
                self.drops+=1;self.dropped_until=max(self.dropped_until,ts+WINDOW);return
            self.buckets[key]={'src':e['src'],'dst':e['dst'],'packets':0,'bytes':0,'syn':0,'ports':set()}
        b=self.buckets[key];b['packets']+=1;b['bytes']+=e.get('length',0);b['syn']+=int(is_tcp_probe(e))
        if is_tcp_probe(e) and len(b['ports'])<64:b['ports'].add(e.get('dport',0))

    def snapshot(self,now):
        if self.cache is not None and 0<=now-self.cache_at<2:return self.cache
        tick=time.perf_counter()
        out={'status':self.status,'available':False,'experimental':True,'scope':getattr(self,'scope','unavailable'),
             'window_seconds':WINDOW,'window_end':now,'threshold':getattr(self,'threshold',None),
             'nodes':{},'correlations':[],'omitted_correlations':0,'dropped_packets':self.drops,
             'reason':self.error,'inference_ms':0,'role':'supporting graph signal; does not create alerts'}
        if self.weights is None:return out
        merged={}
        for (second,s,t),b in self.buckets.items():
            # Complete one-second bins only: strictly exclude bins touching the old boundary.
            if not now-WINDOW<second<=now:continue
            d=merged.setdefault((s,t),dict(src=s,dst=t,packets=0,bytes=0,syn=0,ports=set()))
            for k in ('packets','bytes','syn'):d[k]+=b[k]
            d['ports'].update(b['ports'])
        edges=list(merged.values());ips={e[k] for e in edges for k in ('src','dst')}
        if now<self.dropped_until or len(edges)>self.max_edges or len(ips)>self.max_nodes:
            out.update(status='capacity limit',reason='GNN abstained: observation window exceeds configured capacity.')
        elif not edges:out.update(status='waiting',reason='No packet metadata in the last 30 seconds.')
        else:
            ids,x,ain,aout,raw=graph_arrays(edges)
            try:
                with threadpool_limits(limits=1):p,h=forward(x,ain,aout,self.weights)
                if not np.isfinite(p).all():raise ValueError('non-finite model output')
                out['available']=True
                for i,ip in enumerate(ids):
                    label=int(p[i].argmax());score=float(p[i,label])
                    support=(raw[i,6]>=16 or raw[i,7]>=16) if label==1 else ((raw[i,4]>=.7 and raw[i,0]>=20) or (raw[i,5]>=.5 and raw[i,9]>=4)) if label==2 else False
                    flag=label!=0 and score>=self.threshold and bool(support)
                    out['nodes'][ip]={'label':CLASSES[label],'score':round(score,5),'flagged':flag,
                        'scores':{c:round(float(p[i,j]),5) for j,c in enumerate(CLASSES)},
                        'evidence':{'sent_packets':int(raw[i,0]),'received_packets':int(raw[i,1]),'out_syn_fraction':round(float(raw[i,4]),3),
                            'in_syn_fraction':round(float(raw[i,5]),3),'probe_ports':int(raw[i,6]),'destinations':int(raw[i,8]),'sources':int(raw[i,9])}}
                # Group only observed co-sources with a shared destination and matching learned pattern.
                # Never draw correlation edges as if they were captured IP traffic.
                groups=defaultdict(list)
                for e in edges:
                    node=out['nodes'][e['src']]
                    own=node['evidence'];source_support=own['probe_ports']>=16 if node['label']=='scan_pattern' else own['out_syn_fraction']>=.7 and own['sent_packets']>=20
                    if node['flagged'] and source_support:groups[(e['dst'],node['label'])].append(e['src'])
                ix={ip:i for i,ip in enumerate(ids)}
                for (dst,label),sources in sorted(groups.items()):
                    sources=sorted(set(sources))
                    if len(sources)<2:continue
                    vectors=h[[ix[s] for s in sources]];norm=np.linalg.norm(vectors,axis=1,keepdims=True);unit=vectors/np.maximum(norm,1e-8)
                    centroid=unit.mean(axis=0);similarity=float(np.mean(unit@centroid/max(float(np.linalg.norm(centroid)),1e-8)))
                    out['correlations'].append({'destination':dst,'pattern':label,'sources':sources,'source_count':len(sources),
                        'embedding_similarity':round(similarity,4),'minimum_vote':round(min(out['nodes'][s]['score'] for s in sources),5),
                        'evidence':f'{len(sources)} observed sources share this destination and the same GNN pattern; similarity is not proof of coordination.'})
                out['omitted_correlations']=max(0,len(out['correlations'])-50);out['correlations']=out['correlations'][:50]
            except (ValueError,ArithmeticError) as exc:out.update(status='inference error',reason=str(exc),available=False,nodes={},correlations=[])
        out['inference_ms']=round((time.perf_counter()-tick)*1000,2)
        self.cache=out;self.cache_at=now
        return out
