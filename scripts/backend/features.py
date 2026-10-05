"""Bounded event-time aggregation; no return-direction values are invented."""
from collections import Counter, deque
from dataclasses import dataclass, field
import math
import numpy as np

FEATURES = ['pps', 'bps', 'syn_fraction', 'unique_ports', 'mean_size',
            'size_std', 'dns_entropy', 'dns_length', 'dns_txt_fraction',
            'beacon_cv', 'beacon_count', 'ja4_watchlist']
FEATURE_SCHEMA = 'veil-v2-tcp-probe-ports'

def is_tcp_probe(e):
    """Only client SYN without ACK is an initial TCP connection probe."""
    if e.get('proto', 'tcp' if e.get('syn') else 'other') != 'tcp':
        return False
    flags = e.get('tcp_flags')
    return bool(flags & 2 and not flags & 16) if flags is not None else bool(e.get('syn'))

def entropy(s):
    c = Counter(s)
    n = sum(c.values())
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0.0

@dataclass
class Bucket:
    src: str
    dst: str
    start: float
    last: float
    packets: int = 0
    bytes: int = 0
    syn: int = 0
    size2: int = 0
    ports: set = field(default_factory=set)
    probe_ports: set = field(default_factory=set)
    scan_port_count: int = -1
    uids: set = field(default_factory=set)
    dns: list = field(default_factory=list)
    ja4: set = field(default_factory=set)
    query_count: int = 0
    txt_count: int = 0
    source: str = 'live'

    def add(self, e):
        self.last = max(self.last, e['ts'])
        self.source = e.get('source', 'live')
        if e['kind'] == 'packet':
            size = e.get('length', 0)
            self.packets += 1
            self.bytes += size
            self.size2 += size*size
            probe = is_tcp_probe(e)
            self.syn += probe
            if probe and 0 < e.get('dport', 0) <= 65535:
                self.probe_ports.add(e['dport'])
            if len(self.ports) < 65536:
                self.ports.add(e.get('dport', 0))
        if len(self.uids) < 64:
            self.uids.add(e.get('uid', 'unknown'))
        if e.get('query'):
            self.query_count += 1
            self.txt_count += e.get('qtype', 0) == 16
            if len(self.dns) < 128:
                self.dns.append(e['query'][:253])
        if e.get('ja4') and len(self.ja4) < 32:
            self.ja4.add(e['ja4'])

    def vector(self, period, beacon, watchlist):
        sizes = self.bytes/max(self.packets, 1)
        std = math.sqrt(max(0, self.size2/max(self.packets,1)-sizes*sizes))
        labels = [s.split('.')[0] for s in self.dns]
        gaps = np.diff(list(beacon))
        cv = float(np.std(gaps)/np.mean(gaps)) if len(gaps)>=4 and np.mean(gaps)>0 else 1.0
        return dict(zip(FEATURES, [self.packets/period, self.bytes/period,
            self.syn/max(self.packets,1), self.scan_port_count if self.scan_port_count>=0 else len(self.probe_ports), sizes, std,
            max((entropy(s) for s in labels), default=0),
            max(map(len, labels), default=0), self.txt_count/max(self.query_count,1),
            cv, len(beacon), int(bool(self.ja4 & watchlist))]))

class Windows:
    def __init__(self, period=2.0, capacity=5000, scan_period=10.0):
        self.period, self.capacity = period, capacity
        self.scan_period = scan_period
        self.probes = {}
        self.buckets = {}
        self.beacons = {}
        self.seen = {}
        self.dropped = 0
        self.watermark = 0.0
        self.late = 0

    def add(self, e):
        ts = e['ts']
        if ts < self.watermark - self.period:
            self.late += 1
            return
        self.watermark = max(ts, self.watermark)
        key = (e['src'], e['dst'])
        if key not in self.buckets:
            if len(self.buckets) >= self.capacity:
                self.dropped += 1
                return
            self.buckets[key] = Bucket(*key, start=ts, last=ts)
        b = self.buckets[key]
        b.add(e)
        if e['kind']=='packet' and is_tcp_probe(e) and e.get('dport',0)>0:
            if key not in self.probes and len(self.probes)>=self.capacity:
                self.probes.pop(next(iter(self.probes)))
            ports=self.probes.setdefault(key,{})
            for port,last in list(ports.items()):
                if ts-last>self.scan_period:del ports[port]
            if e['dport'] not in ports and len(ports)>=256:
                ports.pop(next(iter(ports)))
            ports[e['dport']]=ts
        # Only connection starts, not every packet, contribute to beacon timing.
        if e.get('start'):
            uid = e.get('uid')
            if uid not in self.seen:
                if len(self.seen) >= self.capacity*4:
                    self.seen.pop(next(iter(self.seen)))
                self.seen[uid] = ts
                bk = (e['src'], e['dst'], e.get('dport',0))
                if bk not in self.beacons and len(self.beacons)>=self.capacity:
                    self.beacons.pop(next(iter(self.beacons)))
                q = self.beacons.setdefault(bk, deque(maxlen=32))
                q.append(ts)
        # Age state incrementally; bounded capacities cover worst-case cardinality.
        if len(self.seen) and next(iter(self.seen.values())) < ts-120:
            self.seen.pop(next(iter(self.seen)))

    def flush(self, now, force=False):
        out=[]
        for key,b in list(self.buckets.items()):
            if force or now-b.start >= self.period:
                # Use the last event time: a delayed flush must not erase observed probes.
                ports=self.probes.get(key,{})
                b.scan_port_count=sum(b.last-ts<=self.scan_period for ts in ports.values())
                candidates=[v for k,v in self.beacons.items() if k[:2]==key and len(v)>1 and (v[-1]-v[0])/(len(v)-1)>=1]
                for q in candidates:
                    while q and q[0]<now-120: q.popleft()
                q=max(candidates,key=len,default=[])
                out.append((b,q))
                del self.buckets[key]
        for key,ports in list(self.probes.items()):
            if ports and now-max(ports.values())>self.scan_period+self.period:
                del self.probes[key]
        return out
