#!/usr/bin/env python3
"""Train all layers of a directed mean GraphSAGE using explicit NumPy backprop.
Optional JSONL graphs: {scenario_id, split:train|validation|test, edges, labels}.
Edges: src,dst,packets,bytes,syn,ports (SYN destination port list).
Labels map every IP to background|scan_pattern|syn_convergence.
Use scenario-separated captures; never label data from VEIL's own predictions.
"""
import argparse,json,sys
from pathlib import Path
import numpy as np
from scipy.sparse import block_diag
from sklearn.metrics import classification_report,f1_score
from threadpoolctl import threadpool_limits
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.gnn import SCHEMA,FEATURES,CLASSES,WINDOW,graph_arrays,forward

def synthetic(seed,count,split):
    rng=np.random.default_rng(seed);graphs=[]
    for scenario in range(count):
        edges=[];labels={};n=int(rng.integers(12,36));dsts=[f'10.0.0.{i+1}' for i in range(4)]
        kind=scenario%5
        def edge(s,t,packets,syn,ports,mean):
            edges.append(dict(src=s,dst=t,packets=int(packets),bytes=int(packets*mean),syn=int(syn),ports=list(ports)))
            labels.setdefault(s,'background');labels.setdefault(t,'background')
        for i in range(n):
            s=f'192.0.2.{i+1}';t=dsts[int(rng.integers(4))];packets=int(rng.integers(4,4000));syn=int(rng.integers(0,min(30,packets)+1))
            edge(s,t,packets,syn,[443] if syn else [],int(rng.integers(300,1400)))
        if kind==1: # Multiport source scans, including several coordinated sources.
            for i in range(int(rng.integers(1,6))):
                s=f'198.51.100.{i+1}';t=dsts[0];ports=list(range(8000,8000+int(rng.integers(18,65))))
                packets=len(ports)*int(rng.integers(1,5));edge(s,t,packets,packets,ports,60)
                labels[s]='scan_pattern';labels[t]='scan_pattern'
        elif kind==2: # Distributed SYN convergence.
            for i in range(int(rng.integers(5,25))):
                s=f'198.51.100.{i+1}';t=dsts[0];packets=int(rng.integers(150,2200));syn=int(packets*rng.uniform(.8,1))
                edge(s,t,packets,syn,[443],int(rng.integers(40,100)))
                labels[s]='syn_convergence';labels[t]='syn_convergence'
        elif kind==3: # Benign shared service / connection surge hard negatives.
            for i in range(int(rng.integers(5,25))):
                packets=int(rng.integers(20,150));edge(f'203.0.113.{i+1}',dsts[0],packets,int(packets*rng.uniform(.1,.65)),[443],600)
        elif kind==4: # Isolated SYN-heavy contact is not coordinated convergence.
            edge('203.0.113.90',dsts[3],int(rng.integers(2,40)),2,[22],60)
        graphs.append(dict(scenario_id=f'{split}-{scenario}',split=split,edges=edges,labels=labels))
    return graphs

def validate_graphs(graphs):
    seen={};counts={s:0 for s in ('train','validation','test')}
    import ipaddress,math
    for g in graphs:
        split=g['split'];sid=g['scenario_id']
        if split not in counts:raise ValueError('Unknown split')
        if not isinstance(sid,str) or not sid:raise ValueError('Scenario ID required')
        if sid in seen and seen[sid]!=split:raise ValueError('Scenario leakage across splits')
        seen[sid]=split;counts[split]+=1
        if not 1<=len(g['edges'])<=2048:raise ValueError('Graph must contain 1–2048 edges')
        pairs=set()
        for e in g['edges']:
            for k in ('src','dst'):ipaddress.ip_address(e[k])
            pair=(e['src'],e['dst'])
            if pair in pairs:raise ValueError('Aggregate each directed IP pair once')
            pairs.add(pair)
            for k in ('packets','bytes','syn'):
                if type(e[k]) is not int or e[k]<0:raise ValueError('Counts must be nonnegative integers')
            if not 1<=e['packets'] or e['syn']>e['packets']:raise ValueError('Invalid SYN count')
            if any(type(p) is not int or not 0<=p<=65535 for p in e['ports']):raise ValueError('Invalid port')
        ids={e[k] for e in g['edges'] for k in ('src','dst')}
        if len(ids)>512 or set(g['labels'])!=ids or any(v not in CLASSES for v in g['labels'].values()):raise ValueError('Every observed IP requires a supported label; max 512 nodes')
    if min(counts.values())<5:raise ValueError('At least five independent graphs required in each split')

def batch(graphs):
    xs=[];ais=[];aos=[];ys=[]
    for g in graphs:
        ids,x,ai,ao,_=graph_arrays(g['edges']);xs.append(x);ais.append(ai);aos.append(ao);ys.extend(CLASSES.index(g['labels'][i]) for i in ids)
    return np.concatenate(xs),block_diag(ais,format='csr'),block_diag(aos,format='csr'),np.array(ys)

def train(train_data,epochs=240):
    x,ai,ao,y=train_data;rng=np.random.default_rng(26145)
    w={k:rng.normal(0,np.sqrt(2/shape[0]),shape).astype(np.float32) if k.startswith('w') else np.zeros(shape,np.float32) for k,shape in {'w1':(30,24),'b1':(24,),'w2':(72,16),'b2':(16,),'w3':(16,3),'b3':(3,)}.items()}
    m={k:np.zeros_like(v) for k,v in w.items()};v={k:np.zeros_like(a) for k,a in w.items()}
    cw=len(y)/(3*np.maximum(np.bincount(y,minlength=3),1));sw=cw[y];sw/=sw.sum()
    for epoch in range(1,epochs+1):
        p,_,(z0,h1,z1,h2)=forward(x,ai,ao,w,True);delta=p.copy();delta[np.arange(len(y)),y]-=1;delta*=sw[:,None]
        grad={'w3':h2.T@delta,'b3':delta.sum(0)}
        d2=(delta@w['w3'].T)*(h2>0);grad.update(w2=z1.T@d2,b2=d2.sum(0))
        dz=d2@w['w2'].T;a,b,c=np.split(dz,3,axis=1)
        d1=(a+ai.T@b+ao.T@c)*(h1>0);grad.update(w1=z0.T@d1,b1=d1.sum(0))
        for k in w:
            g=grad[k]+(1e-4*w[k] if k.startswith('w') else 0)
            m[k]=.9*m[k]+.1*g;v[k]=.999*v[k]+.001*g*g
            w[k]-=.008*(m[k]/(1-.9**epoch))/(np.sqrt(v[k]/(1-.999**epoch))+1e-8)
    return w

def metrics(data,w,threshold):
    x,ai,ao,y=data;p,_=forward(x,ai,ao,w);pred=p.argmax(1);flag=(pred!=0)&(p.max(1)>=threshold)
    return dict(nodes=len(y),macro_f1=float(f1_score(y,pred,average='macro')),background_false_flag_rate=float(flag[y==0].mean()),
        pattern_recall_at_threshold=float(flag[y!=0].mean()),report=classification_report(y,pred,labels=[0,1,2],target_names=CLASSES,output_dict=True,zero_division=0))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',type=Path);parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'models/gnn.json');parser.add_argument('--epochs',type=int,default=240);args=parser.parse_args()
    graphs=[json.loads(line) for line in args.dataset.read_text().splitlines() if line.strip()] if args.dataset else synthetic(10,120,'train')+synthetic(20,30,'validation')+synthetic(30,30,'test')
    validate_graphs(graphs);datasets={s:batch([g for g in graphs if g['split']==s]) for s in ('train','validation','test')}
    with threadpool_limits(limits=1):
        w=train(datasets['train'],args.epochs)
        # Select a conservative threshold from validation only; never tune on test.
        candidates=[t for t in (.8,.85,.9,.95,.98,.995) if metrics(datasets['validation'],w,t)['background_false_flag_rate']<=.01]
        threshold=candidates[0] if candidates else 1.
        val=metrics(datasets['validation'],w,threshold);test=metrics(datasets['test'],w,threshold)
        x,ai,ao,y=datasets['test'];zero=ai*0
        ablation=metrics((x,zero,zero,y),w,threshold)
    obj=dict(schema=SCHEMA,features=FEATURES,classes=CLASSES,window_seconds=WINDOW,threshold=threshold,
      scope='supplied labeled graph dataset; external validity unverified' if args.dataset else 'synthetic demonstration only; real-network accuracy unverified',
      architecture='two-layer directed mean GraphSAGE; 24/16 hidden units; learned softmax head',
      weights={k:v.tolist() for k,v in w.items()},validation=val)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(obj,separators=(',',':')))
    report=dict(scope=obj['scope'],threshold=threshold,split_graphs={s:sum(g['split']==s for g in graphs) for s in datasets},validation=val,test=test,
        no_neighbor_ablation=ablation,notes=['Entire scenarios separated across splits.','Synthetic labels are generator labels, not proof of attacks.','Ablation removes neighbor messages at inference; it is not a separately retrained baseline.','No claim of improvement over RF/IF or production accuracy.'])
    args.output.with_name('gnn-report.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:report[k] for k in ('scope','threshold','split_graphs')}));print('Test macro F1:',test['macro_f1'],'Ablation:',ablation['macro_f1'])
if __name__=='__main__':main()
