#!/usr/bin/env bash
# Replays ONLY onto a private virtual link with no production attachment.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
[[ $# == 1 && -f $1 ]] || { echo 'Usage: sudo bash scripts/replay-pcap.sh FILE.pcap'; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PCAP=$(realpath "$1")
command -v tcpreplay >/dev/null
ZEEK=${ZEEK_BIN:-$(command -v zeek)}
for n in veil-replay-src veil-replay-mon; do
 if ip netns list | awk '{print $1}' | grep -qx "$n"; then echo "$n already exists"; exit 1; fi
done
cleanup(){
 [[ -z ${ZPID:-} ]] || kill "$ZPID" 2>/dev/null || true
 ip netns del veil-replay-src 2>/dev/null || true
 ip netns del veil-replay-mon 2>/dev/null || true
}
trap cleanup EXIT INT TERM
ip netns add veil-replay-src
ip netns add veil-replay-mon
ip link add vr-src type veth peer name vr-mon
ip link set vr-src netns veil-replay-src
ip link set vr-mon netns veil-replay-mon
for spec in 'src vr-src' 'mon vr-mon'; do
 read -r n d <<< "$spec"
 ip netns exec "veil-replay-$n" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
 ip -n "veil-replay-$n" link set "$d" up
done
ip netns exec veil-replay-mon tc qdisc add dev vr-mon clsact
ip netns exec veil-replay-mon tc filter add dev vr-mon egress protocol all matchall action drop
mkdir -p "$ROOT/data/pcap-replay"
cd "$ROOT/data/pcap-replay"
ip netns exec veil-replay-mon "$ZEEK" -C -i vr-mon "$ROOT/zeek/veil.zeek" &
ZPID=$!
sleep 1
# Packet rate cap; no target rewriting. All mirrored destination addresses are accepted by default.
ip netns exec veil-replay-src tcpreplay --intf1=vr-src --pps=500 "$PCAP"
sleep 2
