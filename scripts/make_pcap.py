"""Write synthetic Ethernet/IPv4 PCAP using only stdlib; never opens a raw socket."""
import json,struct,socket
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def checksum(data):
    if len(data)%2:data+=b'\0'
    n=sum(struct.unpack('!'+str(len(data)//2)+'H',data));n=(n>>16)+(n&65535);n+=(n>>16)
    return (~n)&65535
packets=[]
for line in (ROOT/'data/demo.jsonl').read_text().splitlines():
    e=json.loads(line);src=socket.inet_aton(e['src']);dst=socket.inet_aton(e['dst'])
    if e['kind']=='dns':
        name=b''.join(bytes([len(x)])+x.encode() for x in e['query'].split('.'))+b'\0'
        dns=struct.pack('!6H',len(packets)%65535,0x100,1,0,0,0)+name+struct.pack('!HH',e['qtype'],1)
        segment=struct.pack('!HHHH',45000,53,8+len(dns),0)+dns;proto=17
    elif e['kind']=='packet':
        sp=e.get('sport',40000)
        if e.get('proto')=='udp':
            payload=b'x'*max(0,e['length']-28)
            segment=struct.pack('!HHHH',sp,e['dport'],8+len(payload),0)+payload;proto=17
        else:
            flags=2 if e.get('syn') else 24
            payload=b'x'*max(0,e['length']-40)
            segment=struct.pack('!HHIIBBHHH',sp,e['dport'],len(packets),0,80,flags,8192,0,0)+payload;proto=6
            ck=checksum(src+dst+struct.pack('!BBH',0,proto,len(segment))+segment)
            segment=segment[:16]+struct.pack('!H',ck)+segment[18:]
    else:continue
    hdr=struct.pack('!BBHHHBBH4s4s',69,0,20+len(segment),len(packets)%65535,0,64,proto,0,src,dst)
    hdr=hdr[:10]+struct.pack('!H',checksum(hdr))+hdr[12:]
    eth=bytes.fromhex('0200000000200200000000100800')+hdr+segment
    packets.append((e['ts'],eth))
with (ROOT/'data/demo.pcap').open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for ts,data in packets:
        seconds=int(ts);f.write(struct.pack('<IIII',seconds,int((ts-seconds)*1e6),len(data),len(data)));f.write(data)
print(f'Wrote {len(packets)} synthetic packets to disk. No packets transmitted.')
