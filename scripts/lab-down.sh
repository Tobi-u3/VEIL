#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
for n in veil-monitor veil-server veil-client veil-attacker; do
  if ip netns list | awk '{print $1}' | grep -qx "$n"; then
    for pid in $(ip netns pids "$n"); do kill "$pid" 2>/dev/null || true; done
    ip netns del "$n"
  fi
done
for d in vl-mon vl-srv vl-cli vl-atk vl-br; do ip link del "$d" 2>/dev/null || true; done
echo 'Removed VEIL lab namespaces and VEIL virtual interfaces only.'
