# Demonstration guide (three days remaining)

## Day 1: prove the observation boundary

1. Follow README quick start and run the synthetic replay. This establishes that the application works independently of packet capture.
2. Run the isolated namespace setup and `verify-lab.sh`. Save its output. Both attacker and client must reach the server; the observer must see only destination 10.77.0.20; injected observer test frames must not arrive at the server.
3. Run the HTTP server and normal client from README. A returned HTTP 200 proves the original request and response still work. Stop Zeek and repeat the normal request: service must continue. Restart Zeek and confirm `data/live/veil_events.log` grows while traffic runs.
4. Start the API with `VEIL_LOG` set and check that the UI shows LIVE mode. Replay controls are disabled in live mode. Inspect `tc -s filter show dev vl-srv egress` and capture counters; recording zeros without producing traffic is not a valid test.

## Day 2: demonstrate detection and evidence

Use a separate terminal for each logical role. Start normal client traffic, run the scan pattern, then the bounded SYN pattern, DNS pattern and beacon pattern. Wait at least 30 seconds for the beacon sequence. Inspect an alert's actual feature values and the separate heuristic/SHAP explanations. Do not promise an alert for every lab pattern without verifying the capture and thresholds on your machine.

You can run the normal client repeatedly while generating a lab pattern. All traffic generators target only the disposable lab server. The lab has no default Internet route.

### JA4 integration

Your existing Zeek installation needs `zkg` and the official FoxIO compiled JA4 package. Its current documented requirements include Zeek 7+, a C++20 compiler and CMake. Install it using the same Zeek prefix/user configuration used by capture:

```bash
zkg install zeek/foxio/ja4
zeek -NN | grep -i ja4
```

Then start capture with the optional JA4 policy enabled:

```bash
sudo env PATH="$PATH" ZEEK_BIN="$(command -v zeek)" VEIL_JA4=1 bash scripts/capture.sh
```

The package must be visible to the root-run Zeek process too; a package installed only in a different user's search path may be missing. Check `zeek-config --zeekpath` / installed plugin paths instead of inventing a fingerprint when loading fails.

The adapter uses the official `JA4::calculate_ja4` function and the `FINGERPRINT` connection metadata from the current plugin source. This adapter is version-sensitive: if it does not parse, use the base capture policy while reporting JA4 as unavailable and share the exact error for adjustment.

To produce TLS traffic in the isolated lab, create a short-lived self-signed certificate and a local TLS test server; the client can use `curl -k` for this self-signed demo only:

```bash
mkdir -p data/tls
openssl req -x509 -newkey rsa:2048 -nodes -keyout data/tls/key.pem -out data/tls/cert.pem -days 2 -subj '/CN=veil.lab'
sudo ip netns exec veil-server openssl s_server -accept 8443 -cert data/tls/cert.pem -key data/tls/key.pem -www
# Another terminal:
sudo ip netns exec veil-client curl -k https://10.77.0.20:8443/
```

Inspect `veil_events.log` for a `kind:"tls"` record and an actual JA4 value. The observer does not possess or use the TLS private key; the key exists only at the test server. Keep the test session open/repeat requests if a very short session ends before the scheduled JA4 check. No fingerprint match alert is expected with the default empty watchlist. To show a clearly labelled **test watchlist match**, copy the observed fingerprint into `data/ja4-watchlist.json` as a JSON array and restart the API. State explicitly that the fingerprint is a lab test indicator, not known malware. Remove it after the demo. QUIC requires a real QUIC fixture/server and separate verification; the supplied TLS test does not validate QUIC.

### PCAP replay

`data/demo.pcap` is a synthetic fixture. Offline Zeek processing can validate parsing without sending packets:

```bash
mkdir -p data/offline
cd data/offline
zeek -C -r ../demo.pcap ../../zeek/veil.zeek
```

This offline command is a parser validation, not the live streaming demo. For real-time packet replay on a **separate isolated link**:

```bash
sudo env PATH="$PATH" ZEEK_BIN="$(command -v zeek)" bash scripts/replay-pcap.sh data/demo.pcap
```

The replay script creates `veil-replay-src` and `veil-replay-mon`, with no connection to production or the live server. It rate-caps playback at 500 packets/sec. Point a separately restarted backend at `data/pcap-replay/veil_events.log` and clearly label this as packet replay in your presentation. Existing trace IPs are not rewritten; all observed destinations are accepted by default; an optional `VEIL::protected_servers` set can narrow the scope.

## Day 3: validation and recording

1. Record a 60–90 second demo: show HTTP service working, one-way mirror verification, live detection, evidence drawer, graph, readiness tab and exported JSON alert.
2. Run `python scripts/benchmark.py` and include the actual result from your laptop. This measures metadata processing, not physical link throughput.
3. Measure capture: count sent packets vs mirrored packets with an independent sniffer; review Zeek `capture_loss.log` if enabled and kernel drop counters. State packet size, offered packets/s, duration, CPU/RAM and capture loss. Do not reuse metadata events/s as Mbps.
4. Compare client request latency with the mirror disabled/enabled, not merely Zeek stopped. In this disposable lab, temporarily delete only the known mirror rule with `sudo tc filter del dev vl-srv egress pref 10`, measure at least 100 normal requests, then restore it with `sudo tc filter add dev vl-srv egress protocol all pref 10 matchall action mirred egress mirror dev vl-mon`. Report both distributions and workload. This does not touch wlan0 or physical interfaces.
5. Keep claims aligned with `MODEL_CARD.md`. Full exfiltration, reliable encrypted-malware attribution, host scanning outside this server, distributed spoofed-source flood validation and hardware diode enforcement are not established by this demonstration.
6. Remove the final instruction slide from your supplied PDF; its own instructions specify at most six slides.

## Troubleshooting

- `Cannot open netlink socket / Operation not permitted`: namespaces require a native Linux host or a VM with suitable privileges. Docker/container restrictions may prevent them. Use replay until running the lab on Kali.
- Zeek not found under sudo: pass the full executable using `ZEEK_BIN=/absolute/path/to/zeek`.
- HTTP works but no capture: inspect mirror rule/counters, ensure capture runs inside `veil-monitor`, and verify the target IP. Capturing wlan0 does not substitute for the explicit mirror.
- Empty DNS data: ordinary web traffic may use encrypted DNS, or queries may go to a different resolver outside this server tap. Use the controlled DNS lab pattern.
- No beacon alert: wait for six or more separate sessions. Packets inside one connection are not treated as separate beacons.
- API fails with PostgreSQL configured: check container health and password. Remove `DATABASE_URL` only if intentionally choosing the labelled SQLite demo fallback.
- Model predictions seem wrong: synthetic training is not representative of your network. Trust observable evidence and collect a verified baseline; do not advertise the toy model's validation accuracy.
- No live event counter movement: the WebSocket is only a UI transport; its connection indicator is not capture health.
