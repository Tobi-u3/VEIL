#!/usr/bin/env bash
# Verifies the software mirror, not a physical data diode. Requires a running lab.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo 'Run install.sh first'; exit 1; }
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
ip -n veil-monitor addr show capture0
[[ -z $(ip -n veil-monitor -o addr show capture0 | awk '$3=="inet" || $3=="inet6"') ]]
[[ -z $(ip -n veil-monitor route show) ]]
ip netns exec veil-monitor tc filter show dev capture0 egress | grep -q drop
tc filter show dev vl-mon ingress | grep -q drop
# Capture packets copied BEFORE server veth delivery. Ping both endpoints to generate replies.
ip netns exec veil-monitor "$PY" -c 'from scapy.all import sniff,wrpcap; import sys; wrpcap(sys.argv[1],sniff(iface="capture0",timeout=4))' "$WORK/mirror.pcap" &
CAP=$!
sleep .5
ip netns exec veil-client ping -n -c 2 -W 1 10.77.0.20
ip netns exec veil-attacker ping -n -c 2 -W 1 10.77.0.20
wait "$CAP"
"$PY" - "$WORK/mirror.pcap" <<'PY'
from scapy.all import rdpcap,IP
import sys
p=[x[IP] for x in rdpcap(sys.argv[1]) if IP in x]
assert p,'No mirrored IPv4 packets'
assert all(x.dst=='10.77.0.20' for x in p),'Wrong mirror direction'
assert not any(x.src=='10.77.0.20' for x in p),'Server replies leaked into capture'
assert {'10.77.0.10','10.77.0.30'} <= {x.src for x in p},'Missing sender'
print('PASS: both senders reached server; only sender-to-server copies observed.')
PY
# Test egress drop with a distinctive Ethernet frame, while sniffing server.
ip netns exec veil-server "$PY" -c 'from scapy.all import sniff,wrpcap; import sys; wrpcap(sys.argv[1],sniff(iface="eth0",timeout=3))' "$WORK/server.pcap" &
CAP=$!
sleep .5
ip netns exec veil-monitor "$PY" -c 'from scapy.all import Ether,Raw,sendp; sendp(Ether(dst="ff:ff:ff:ff:ff:ff",type=0x88b5)/Raw(b"VEIL_RETURN_PATH_TEST"),iface="capture0",count=3,verbose=False)'
wait "$CAP"
"$PY" - "$WORK/server.pcap" <<'PY'
from scapy.all import rdpcap
import sys
assert not any(b'VEIL_RETURN_PATH_TEST' in bytes(p) for p in rdpcap(sys.argv[1])), 'Observer frame reached server'
print('PASS: observer test frames did not reach server.')
PY
ip netns exec veil-monitor tc -s filter show dev capture0 egress
tc -s filter show dev vl-srv egress
echo 'Save this output as live capture evidence. Also run the latency benchmark in docs/DEMO.md.'
