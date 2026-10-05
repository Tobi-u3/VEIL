#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $EUID == 0 ]] || { echo 'Run sudo env PATH="$PATH" bash scripts/capture.sh'; exit 1; }
ZEEK=${ZEEK_BIN:-$(command -v zeek || true)}
[[ -x "$ZEEK" ]] || { echo 'Set ZEEK_BIN to the installed Zeek executable'; exit 1; }
mkdir -p "$ROOT/data/live"
cd "$ROOT/data/live"
EXTRA=()
if [[ ${VEIL_JA4:-0} == 1 ]]; then EXTRA+=(packages "$ROOT/zeek/ja4.zeek"); fi
FILTER_ARGS=()
if [[ -n ${VEIL_PROTECTED_SERVERS:-} ]]; then
  ADDRS=$(python3 -c 'import ipaddress,sys;print(",".join(str(ipaddress.ip_address(s.strip())) for s in sys.argv[1].split(",")))' "$VEIL_PROTECTED_SERVERS")
  FILTER_ARGS+=("VEIL::protected_servers={$ADDRS}")
fi
# An empty destination set accepts every observed IPv4/IPv6 destination. Never filter source subnets.
# -C is explicit for this veth lab with possible checksum offload artefacts.
# For physical taps validate checksums first rather than blindly ignoring them.
exec ip netns exec veil-monitor "$ZEEK" -C -i capture0 "$ROOT/zeek/veil.zeek" "${EXTRA[@]}" "${FILTER_ARGS[@]}"
