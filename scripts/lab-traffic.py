"""Fixed-target, short, rate-limited lab patterns. Run inside veil-client/veil-attacker."""
import argparse,socket,time,random,urllib.request,os
p=argparse.ArgumentParser();p.add_argument('scenario',choices=['normal','scan','syn','dns','beacon']);a=p.parse_args()
# Require our isolated namespace, not just a private target.
if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
    raise SystemExit('Run inside the VEIL lab namespace with ip netns exec.')
TARGET='10.77.0.20'
if a.scenario=='normal':
    for _ in range(20):
        print(urllib.request.urlopen('http://'+TARGET+':8000',timeout=2).status);time.sleep(.3)
elif a.scenario=='scan':
    for port in range(8100,8148):
        s=socket.socket();s.settimeout(.02);s.connect_ex((TARGET,port));s.close();time.sleep(.01)
elif a.scenario=='beacon':
    for _ in range(9):
        s=socket.socket();s.settimeout(.3);s.connect_ex((TARGET,8000));s.close();time.sleep(3)
elif a.scenario=='dns':
    from scapy.all import IP,UDP,DNS,DNSQR,send
    random.seed(26145)
    for i in range(25):
        name=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789',k=48))+'.lab.test'
        send(IP(dst=TARGET)/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=name,qtype=16)),verbose=False);time.sleep(.05)
elif a.scenario=='syn':
    from scapy.all import IP,TCP,send
    # Capped 1800 packets at approximately 600pps; only the disposable server.
    send([IP(dst=TARGET)/TCP(sport=20000+i,dport=8000,flags='S',seq=i) for i in range(1800)],inter=1/600,verbose=False)
