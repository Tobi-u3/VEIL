#!/usr/bin/env bash
# Private namespace demo. Never attaches to or reconfigures physical interfaces.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run sudo bash scripts/lab-up.sh'; exit 1; }
for x in ip tc sysctl; do command -v "$x" >/dev/null; done
for n in veil-server veil-client veil-attacker veil-monitor; do
  if ip netns list | awk '{print $1}' | grep -qx "$n"; then echo "$n already exists; use lab-down.sh first"; exit 1; fi
done
for d in vl-br vl-srv vl-cli vl-atk vl-mon; do
  if ip link show "$d" >/dev/null 2>&1; then echo "Interface $d exists; refusing to modify it"; exit 1; fi
done
# Roll back only resources whose names were verified absent above.
cleanup_failure(){ bash "$(dirname "$0")/lab-down.sh"; }
trap cleanup_failure ERR
ip link add vl-br type bridge
ip link set vl-br up
for spec in 'server srv 20' 'client cli 30' 'attacker atk 10'; do
  read -r name port octet <<< "$spec"
  ip netns add "veil-$name"
  ip link add "vl-$port" type veth peer name "vp-$port"
  ip link set "vp-$port" netns "veil-$name"
  ip link set "vl-$port" master vl-br
  ip link set "vl-$port" up
  ip -n "veil-$name" link set "vp-$port" name eth0
  ip -n "veil-$name" addr add "10.77.0.$octet/24" dev eth0
  ip -n "veil-$name" link set lo up
  ip -n "veil-$name" link set eth0 up
done
ip netns add veil-monitor
ip link add vl-mon type veth peer name vp-mon
ip link set vp-mon netns veil-monitor
ip -n veil-monitor link set vp-mon name capture0
ip netns exec veil-monitor sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip netns exec veil-monitor sysctl -qw net.ipv6.conf.default.disable_ipv6=1
ip link set vl-mon up
ip -n veil-monitor link set capture0 up
ip -n veil-monitor link set capture0 promisc on
# No address, route, bridge membership, or management NIC inside this namespace.
# Defence in depth: drop observer-originated frames at both ends.
ip netns exec veil-monitor tc qdisc add dev capture0 clsact
ip netns exec veil-monitor tc filter add dev capture0 egress protocol all pref 1 matchall action drop
tc qdisc add dev vl-mon clsact
tc filter add dev vl-mon ingress protocol all pref 1 matchall action drop
# Egress on server-facing bridge port copies only frames travelling TO server.
tc qdisc add dev vl-srv clsact
tc filter add dev vl-srv egress protocol all pref 10 matchall action mirred egress mirror dev vl-mon
trap - ERR
printf '%s\n' 'Lab ready: server 10.77.0.20, normal client .30, attacker .10.' 'Observer: veil-monitor/capture0. Copy point: vl-srv egress.' 'Original forwarding does not wait for analytics. Software isolation is not a hardware diode.'
