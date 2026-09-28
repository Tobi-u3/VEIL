import time,uuid,json,os
from pathlib import Path
from collections import deque,Counter
import networkx as nx
from .features import Windows,entropy
from .ml import Models
from .traffic import Traffic

class Engine:
    def __init__(self,store=None):
        self.windows=Windows();self.models=Models();self.store=store
        self.alerts=deque(maxlen=100);self.history=deque(maxlen=60);self.graph=nx.DiGraph()
        self.events=0;self.window_count=0;self.errors=0;self.started=time.monotonic()
        self.cooldown={};self.latencies=deque(maxlen=2000)
        self.status={'mode':'idle','input':'waiting','last_error':None,'last_event':None}
        path=Path('data/ja4-watchlist.json')
        self.watchlist=set(json.loads(path.read_text())) if path.exists() else set()
        self.last_ts=0;self.drift_events=0;self.destinations={};self.traffic=Traffic();self.next_flush=0

    def ingest(self,e):
        if e.get('kind') not in ('packet','dns','tls'): return
        for k in ('src','dst','ts','uid'):
            if k not in e: raise ValueError('Missing event field '+k)
        import math,ipaddress
        ipaddress.ip_address(e['src']);ipaddress.ip_address(e['dst'])
        e['ts']=float(e['ts'])
        if not math.isfinite(e['ts']) or e['ts']<0: raise ValueError('Invalid timestamp')
        if not 0 <= e.get('length',0) <= 1_000_000: raise ValueError('Invalid packet length')
        # Flush before adding boundary events. Packet-time replay and live use the same engine.
        if e['ts']>=self.next_flush:
            self.flush(e['ts']);self.next_flush=e['ts']+.1
        self.windows.add(e)
        if e['kind']=='packet':
            self.traffic.add(e,self.graph)
            dst=e['dst']
            if dst in self.destinations or len(self.destinations)<1000:
                d=self.destinations.setdefault(dst,{'start':e['ts'],'last':e['ts'],'packets':0,'bytes':0,'syn':0,'sizes2':0,'sources':Counter(),'uids':set(),'source':e.get('source','live'),'ports':set()})
                d['last']=e['ts'];d['packets']+=1;d['bytes']+=e.get('length',0);d['sizes2']+=e.get('length',0)**2;d['syn']+=bool(e.get('syn'))
                if len(d['ports'])<65536:d['ports'].add(e.get('dport',0))
                if e['src'] in d['sources'] or len(d['sources'])<1024:d['sources'][e['src']]+=1
                if len(d['uids'])<64:d['uids'].add(e['uid'])
        self.events+=1;self.last_ts=max(self.last_ts,e['ts'])
        self.status['last_event']=time.time()

    def flush(self,now,force=False):
        self.flush_destinations(now,force)
        for b,beacons in self.windows.flush(now,force):
            tick=time.perf_counter()
            f=b.vector(self.windows.period,beacons,self.watchlist)
            result=self.models.predict(f)
            if result['drift']: self.drift_events+=1
            self.window_count+=1
            wid=str(uuid.uuid4())
            rec={'id':wid,'timestamp':b.last,'source':b.source,'src':b.src,'dst':b.dst,'features':f}
            if self.store:self.store.save('windows',rec)
            self.history.append({'time':b.last,'pps':f['pps'],'bps':f['bps']})
            evidence=[];candidate=None;severity='medium'
            if f['pps']>=250 and (f['syn_fraction']>.7 or f['mean_size']>500):
                candidate='ddos';severity='high';evidence=['High sender packet rate', 'Observed SYN fraction / packet size pattern']
            if f['unique_ports']>=16:
                candidate='scan';severity='high';evidence=['Many destination ports from one source within 2 seconds']
            if f['dns_entropy']>=3.8 and f['dns_length']>=28:
                candidate='dns_anomaly';evidence=['Long, high-entropy DNS label', 'DGA or tunnelling suspicion; not proof']
            if candidate is None and f['pps'] < 10 and f['beacon_count']>=6 and f['beacon_cv']<.15:
                candidate='beaconing';evidence=['Low variation in connection-start intervals','Periodic benign services can look similar']
            if f['ja4_watchlist']:
                candidate='encrypted_suspicion';severity='high';evidence=['Observed JA4 matches local analyst watchlist','Fingerprint match alone does not prove malware']
            if f['bps']>=2e6 and f['syn_fraction']<.1:
                candidate='large_transfer';evidence=['High observed sender-to-server byte rate','Reverse direction unavailable: exfiltration not confirmed']
            if candidate is None and result['kitnet_anomaly']:
                candidate='unknown_anomaly';evidence=['KitNET reconstruction error exceeds clean-baseline threshold']
            key=(b.src,b.dst,candidate)
            if candidate and b.last-self.cooldown.get(key,-1e20)>=10:
                self.cooldown[key]=b.last
                if len(self.cooldown)>5000:self.cooldown.pop(next(iter(self.cooldown)))
                agrees=result['label']==candidate
                confidence=result['confidence'] if agrees else None
                explanation=self.models.explain_details(f,result['label'])
                shap=explanation['features']
                alert={'id':str(uuid.uuid4()),'timestamp':b.last,'flow_identifier':sorted(b.uids),
                    'src':b.src,'dst':b.dst,'threat_class':candidate,'severity':severity,
                    'confidence':confidence,'confidence_type':result['confidence_type'] if agrees else 'heuristic: not calibrated',
                    'source':b.source,'evidence':evidence,'features':f,'shap':shap,'shap_explanation':explanation,
                    'shap_explains_class':result['label'], 'model_vote':result,
                    'window_seconds':2,'reverse_bytes':None,'outbound_inbound_ratio':None,
                    'ja4':sorted(b.ja4),'dns_samples':b.dns[:3],
                    'limitations':['One-way observation','No payload decryption','Synthetic-trained classifier'],
                    'created_at':time.time()}
                self.alerts.appendleft(alert)
                if self.store:self.store.save('alerts',alert)
            self.latencies.append((time.perf_counter()-tick)*1000)

    def flush_destinations(self,now,force=False):
        import math
        for dst,d in list(self.destinations.items()):
            if not force and now-d['start']<2:continue
            del self.destinations[dst]
            if d['packets']<500 or len(d['sources'])<4:continue
            key=('multiple sources',dst,'ddos')
            if d['last']-self.cooldown.get(key,-1e20)<10:continue
            self.cooldown[key]=d['last']
            total=sum(d['sources'].values())
            ent=-sum((n/total)*math.log2(n/total) for n in d['sources'].values())
            size=d['bytes']/d['packets']
            f={'pps':d['packets']/2,'bps':d['bytes']/2,'syn_fraction':d['syn']/d['packets'],
               'unique_ports':len(d['ports']),'mean_size':size,'size_std':math.sqrt(max(0,d['sizes2']/d['packets']-size*size)),
               'dns_entropy':0,'dns_length':0,'dns_txt_fraction':0,'beacon_cv':1,'beacon_count':0,'ja4_watchlist':0,
               'source_ip_entropy':ent,'distinct_sources':len(d['sources'])}
            vote=self.models.predict(f)
            explanation=self.models.explain_details(f,vote['label'])
            alert={'id':str(uuid.uuid4()),'timestamp':d['last'],'flow_identifier':sorted(d['uids']),
              'src':'multiple sources','related_sources':sorted(d['sources']),'dst':dst,'threat_class':'ddos','severity':'high','confidence':None,
              'confidence_type':'aggregate rate heuristic: not calibrated','source':d['source'],
              'evidence':['High aggregate rate from multiple source addresses',
                          'Source-IP entropy measures distribution, not proof of spoofing'],
              'features':f,'shap':explanation['features'],'shap_explanation':explanation,
              'shap_explains_class':vote['label'],'model_vote':vote,'window_seconds':2,
              'reverse_bytes':None,'outbound_inbound_ratio':None,'ja4':[],'dns_samples':[],
              'limitations':['Rate suspicion, not proof of DDoS','Source distribution capped at 1024 addresses'],
              'created_at':time.time()}
            self.alerts.appendleft(alert)
            if self.store:self.store.save('alerts',alert)

    def snapshot(self,view="all"):
        import numpy as np
        rates=list(self.history)
        alerts=list(self.alerts)
        now=time.time() if self.status['mode']=='live' else self.last_ts
        return {'status':self.status,'models':self.models.status,
            'metrics':{'packets':self.traffic.count,'captured_bytes':self.traffic.bytes,'retained_packets':len(self.traffic.packets),'events':self.events,'windows':self.window_count,'alerts':len(self.alerts),
                'processing_p95_ms':round(float(np.percentile(self.latencies,95)),2) if self.latencies else 0,
                'state_drops':self.windows.dropped,'late_events':self.windows.late,'parse_errors':self.errors,
                'drift_events':self.drift_events,'uptime_seconds':int(time.monotonic()-self.started)},
            'alerts':alerts if view in ('all','graph','detections') else [],'history':rates,
            'packets':self.traffic.page() if view in ('all','packets') else None,
            'graph':self.traffic.topology(self.graph,alerts,now) if view in ('all','graph') else None,
            'capabilities':{'reverse_traffic':'not observed','JA4':'watchlist loaded' if self.watchlist else 'no watchlist; plugin required for live fingerprints',
            'capture_isolation':'verify on capture host; application cannot certify wiring',
            'database':'PostgreSQL' if self.store and self.store.pg else 'SQLite demo fallback'}}
