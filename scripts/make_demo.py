"""Deterministic, multi-network metadata demonstration. No network transmissions."""
import json,random
from pathlib import Path
rng=random.Random(26145)
ROOT=Path(__file__).resolve().parents[1]
rows=[];base=1700000000.
services=[('10.77.0.20',443,'tcp'),('10.77.0.20',80,'tcp'),('10.77.0.21',8080,'tcp'),
          ('10.77.0.21',8443,'tcp'),('10.77.0.22',53,'udp'),('10.77.0.22',123,'udp'),
          ('10.77.0.23',22,'tcp'),('10.77.0.23',5432,'tcp'),('10.77.0.24',1883,'tcp'),
          ('10.77.0.24',8883,'tcp'),('10.77.0.25',443,'udp'),('10.77.0.25',3389,'tcp')]
def packet(t,src='10.77.0.30',port=8000,size=600,syn=False,uid=None,start=False,dst='10.77.0.20',sport=None,proto=None):
    protocol=proto or ('udp' if port in (53,123) else 'tcp')
    rows.append({'kind':'packet','ts':base+t,'src':src,'dst':dst,'sport':sport or rng.randrange(32768,60999),
                 'proto':protocol,'tcp_flags':(2 if syn else 24) if protocol=='tcp' else None,'dport':port,
                 'length':size,'syn':syn and protocol=='tcp','start':start,'uid':uid or f'{src}-{dst}-{t}', 'source':'replay'})
# Familiar local client plus 160 clients across eight prefixes.
for i in range(600):packet(i*.05,sport=41820)
networks=['10.80.1','10.80.2','10.80.3','10.80.4','172.20.1','192.0.2','198.51.100','203.0.113']
for ni,network in enumerate(networks):
    for hi in range(20):
        src=f'{network}.{100+hi}';dst,port,proto=services[(ni*20+hi)%len(services)];sport=33000+ni*1000+hi*17
        for j in range(18):
            packet(j*1.8+rng.random()*.8,src,port,rng.randrange(80,1200),dst=dst,sport=sport,proto=proto,uid=f'normal-{ni}-{hi}')
# External office service traffic.
for i in range(100):packet(i*.3,src='198.51.100.23',port=8443,size=800,dst='10.77.0.21',sport=52419)
# Port scan, concentrated SYN-rate burst, and distributed source convergence.
for i in range(48):packet(3+i*.02,'203.0.113.45',1000+i,60,True,start=True)
for i in range(2400):packet(8+i*.0015,'203.0.113.45',443,60,True,start=True)
for i in range(1440):
    n=i%48;src=f'{["192.0.2","198.51.100","203.0.113"][n//16]}.{150+n%16}'
    packet(18+i*.001,src,443,60,True,start=True,sport=41000+i,dst='10.77.0.21')
# DNS anomaly records plus their synthetic packet observations.
for i in range(20):
    t=14+i*.1;src='203.0.113.45';packet(t,src,53,150,False,dst='10.77.0.22',sport=54821)
    rows.append({'kind':'dns','ts':base+t+.0001,'src':src,'dst':'10.77.0.22','uid':f'dns-{i}',
                 'query':''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=48))+'.lab.test','qtype':16,'source':'replay'})
# Distinct recurring connection-start patterns; periodicity alone is only suspicious.
for host,port,dst in [('192.0.2.40',443,'10.77.0.20'),('198.51.100.41',8443,'10.77.0.21'),('203.0.113.42',8080,'10.77.0.21')]:
    for i in range(10):packet(1+i*3,host,port,90,True,uid=f'beacon-{host}-{i}',start=True,dst=dst)
rows.sort(key=lambda e:e['ts'])
(ROOT/'data').mkdir(exist_ok=True)
(ROOT/'data/demo.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows))
packets=[e for e in rows if e['kind']=='packet']
summary={'synthetic':True,'network_transmissions':0,'events':len(rows),'packets':len(packets),
         'source_hosts':len({e['src'] for e in packets}),'destination_hosts':len({e['dst'] for e in packets}),
         'source_ports':len({e['sport'] for e in packets}),'destination_ports':sorted({e['dport'] for e in packets}),
         'duration_seconds':round(rows[-1]['ts']-rows[0]['ts'],2),
         'scenarios':['diverse service traffic','port scanning','SYN-rate burst','48-source rate convergence','DNS anomaly','three periodic connection patterns']}
(ROOT/'data/demo-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
