# GNN extension — original UI

This build adds trained, experimental IP correlation to the selected Detection Fix prototype. See [GNN setup and model limits](docs/GNN.md). The original dashboard layout is retained.

# VEIL — working passive threat-detection prototype

Team Blue Lock · SIH26145. Start with the replay, then validate the live namespace lab on Kali. This version uses **RandomForest + IsolationForest + SHAP**, FastAPI/WebSockets, React/TypeScript/Tailwind/React Flow, and SQLite (optional PostgreSQL through psycopg). JA4 is optional and must come from the installed Zeek plugin. No SQLAlchemy, KitNET, River, payload storage, active production queries or inline blocking.

## 1. Install and start

Extract into a **new folder** so your previous project remains available:

```bash
unzip ~/Downloads/VEIL_Detection_Fix.zip -d ~/Downloads/VEIL_Updated
cd ~/Downloads/VEIL_Updated/veil
bash scripts/install.sh
.venv/bin/python scripts/create_user.py
bash scripts/start.sh
```

Open **http://127.0.0.1:8000**. Use the account you just created; its password must contain 15–128 characters. Click **Run demo replay**. Packet metadata, detections, SHAP evidence and the IP graph update through the actual pipeline. The built frontend is included, so Node/npm is only needed if editing/rebuilding the UI.

The replay contains synthetic metadata. It sends no packets and does not validate network capture or real-world detection accuracy.

Python **3.12–3.14** is supported by the selected dependency versions; execution was tested with Python 3.12. Python 3.14 wheel resolution was checked, but execution on your Kali installation still needs verification. The installer uses a compatible installed Python and creates `.venv`; it does not alter your system Python. Select a specific interpreter if necessary:

```bash
PYTHON=python3.13 bash scripts/install.sh
```

For a UI rebuild, use Node 20.19+ or 22+ and `REBUILD_UI=1 bash scripts/install.sh`.

## 2. Verify live passive capture on Kali

Keep your existing compiled Zeek. Check:

```bash
zeek --version
```

Install lab prerequisites if missing:

```bash
sudo apt update
sudo apt install -y iproute2 iputils-ping tcpdump tcpreplay
```

From the project directory:

```bash
sudo bash scripts/lab-up.sh
sudo bash scripts/verify-lab.sh
```

Both checks must pass: server replies stay out of the observer, and test frames sent by the observer cannot reach the server. The script creates server `.20`, client `.30`, attacker `.10` and a monitor namespace. It does not attach to wlan0. A software namespace/drop-rule test is not certification of a hardware data diode.

Run these in **four separate terminals**, each starting with:

```bash
cd ~/Downloads/VEIL_Updated/veil
```

**Terminal 1 — test server**

```bash
mkdir -p data/server-public
sudo ip netns exec veil-server python3 -m http.server 8000 --bind 10.77.0.20 --directory "$PWD/data/server-public"
```

**Terminal 2 — capture the mirrored copy**

```bash
sudo env PATH="$PATH" ZEEK_BIN="$(command -v zeek)" bash scripts/capture.sh
```

If Zeek is not on PATH, set `ZEEK_BIN` to its actual executable path. This terminal must stay running.

**Terminal 3 — live backend**

Stop the replay backend with Ctrl+C first, then:

```bash
VEIL_LOG="$PWD/data/live/veil_events.log" bash scripts/start.sh
```

Sign in again. The system page should show live mode; packet counts should move when Terminal 4 generates traffic. A WebSocket connection alone does not prove capture. An idle server legitimately produces no new packets.

**Terminal 4 — normal traffic, then controlled test patterns**

```bash
sudo ip netns exec veil-client "$PWD/.venv/bin/python" scripts/lab-traffic.py normal
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py scan
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py syn
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py dns
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py beacon
```

These finite test patterns target only the disposable lab server. Inspect Detections, evidence, the graph and alert export. Beacon detection needs several separate connections and takes about 27 seconds. SYN-rate results depend on actual generator throughput; record observed rates rather than assuming an alert.

After stopping the server, capture and backend:

```bash
sudo bash scripts/lab-down.sh
```

## 3. Detection and evidence

Twelve metadata features are analysed by RandomForest and IsolationForest for each completed two-second source/destination window. The `unique_ports` feature now counts **TCP SYN-without-ACK destination ports over a rolling ten-second window**, so normal ACK/data packets and SYN-ACK replies to client ports cannot inflate the scan signal. TCP port-scan suspicion requires at least sixteen distinct probed ports. A normal ping to one destination is captured and analysed, but is not a port scan.

A SYN-rate alert requires high rate **and** a predominantly SYN-probe pattern. Ordinary download rate and packet size alone no longer create a named DDoS/large-transfer alert. Aggregate DDoS suspicion likewise requires predominantly SYN probes, rather than simply several busy source addresses. This narrower signature reduces false positives; it does not provide comprehensive UDP/ICMP/HTTP flood detection.

RandomForest votes support and explain behavioural suspicions. An unsupported classifier vote alone does not create a named attack alert. IsolationForest can raise an unknown anomaly after three consecutive populated outlier windows (at least four packets per window; gaps no greater than five seconds). This persistence requirement reduces isolated false alerts but delays anomaly alerts and may miss short bursts. DNS, periodic connections and JA4 matches remain suspicious evidence requiring review.

SHAP explains the RandomForest vote; the UI separates rule/anomaly triggers from classifier evidence. Scores are not calibrated attack probabilities. Both bundled models use **synthetic training data**, with normal high-throughput transfers and ping-like traffic included in the demonstration baseline. Test scenario success does not establish real-network accuracy.

Export captured live feature windows from the SQLite store for review:

```bash
.venv/bin/python scripts/export_features.py --output unreviewed_live_features.csv
```

Add independently verified `label` values to reviewed feature CSVs. Use separate, later validation windows rather than the same captured sessions. The current schema is `veil-v2-tcp-probe-ports`; export new windows after this update. Legacy models/baselines with different port semantics must be retrained.

Train RandomForest from the reviewed data:

```bash
.venv/bin/python scripts/train.py --train-csv reviewed_training.csv --validation-csv reviewed_validation.csv
```

Both files need all feature columns and `label`; at least 100 training and 20 validation rows are required, with benign and at least one attack class in training. These are input minimums, not sufficient evidence of model quality. Accepted labels: `benign`, `ddos`, `scan`, `dns_anomaly`, `beaconing`, `encrypted_suspicion`, `large_transfer`. Timestamp columns, when present, must establish later validation data. High transfers should be labelled by independently known context, not automatically treated as attacks. The reported metrics apply only to your supplied validation set.

Replace only the anomaly baseline using at least 1,200 reviewed benign feature windows:

```bash
.venv/bin/python scripts/train_isolation.py --benign-csv /absolute/path/reviewed_benign.csv
```

Restart the backend afterward. CSV columns must match `backend/features.py::FEATURES`. Do not treat generated labels or the detector's own predictions as ground truth. `scripts/train.py` without CSV arguments regenerates the synthetic demonstration classifier. Restart VEIL after any model replacement.

## 4. Persistence and limits

Alerts and feature windows are persisted locally in `data/veil.sqlite`; the latest 100 alerts return to the dashboard after restart. The database retains at most 10,000 rows per table when periodic cleanup runs. Packet browsing retains the latest 10,000 metadata records in memory; these packet counts and model windows reset on restart. Login sessions reset too.

The live follower tolerates partial lines, malformed records, log truncation and rotation. It reads an existing log from the beginning after restart; this prototype does **not** implement exactly-once ingestion, so restarting against an old log may reproduce alerts. For a clean demonstration, stop Zeek/backend, move old capture logs aside, then start capture and the backend with a fresh log. Preserve logs required as evidence.

No outgoing production traffic is observed in this lab's strict incoming-only scope. Exfiltration, reverse traffic ratios and attack success cannot be confirmed. The graph shows observed IP relationships, alert links, and experimental trained GNN correlation. None of these proves that an address is malicious. Network mirroring and monitor isolation require verification at deployment.

## 5. JA4, optional PostgreSQL and packet replay

See `docs/DEMO.md` for the retained Zeek JA4/TLS test and isolated tcpreplay instructions. Base capture works without JA4. The default watchlist is empty. TLS/QUIC fingerprint integration depends on the installed FoxIO plugin and has not been rerun in this build environment.

SQLite requires no database service. To use an existing PostgreSQL instance, supply `DATABASE_URL` as in `compose.yml` and pass it together with `VEIL_LOG` for live operation. A PostgreSQL connection failure stops startup. PostgreSQL was not exercised in this validation run.

## 6. Check your installation

```bash
.venv/bin/python scripts/doctor.py --require-account
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/benchmark.py
```

The package includes the current 40-test log in `docs/test-results.txt`, build verification in `docs/VALIDATION.md`, and a measured metadata benchmark in `docs/benchmark.json`. This is not a packet-capture throughput benchmark. See `docs/SECURITY.md` before any remote analyst access; startup binds only to loopback.

If installation fails, share the final error output and `python3 --version`. Do not reinstall or replace Kali's system Python to troubleshoot this project.

## 7. RHEL VirtualBox test: ping versus port scan

Your RHEL VM sending `ping` to the Kali destination should create ICMP packet records and **no port-scan alert**. Ping checks reachability; it does not probe TCP ports. To test a port scan, leave Zeek and the live backend running, and run this from your own RHEL VM:

```bash
VEIL_IP=YOUR_KALI_WIFI_IPV4_ADDRESS
sudo nmap -sS -Pn -n -p 8100-8147 --min-rate 20 --max-rate 30 --max-retries 0 "$VEIL_IP"
```

Replace the placeholder with the current destination IP. This finite test probes 48 TCP ports on your own lab host. Check that VEIL captures packets with `proto: tcp`, `syn: true` and different `dport` values. When at least 16 distinct ports are seen in ten seconds, a scan suspicion should appear after the feature window completes. If the probes are not seen, detection cannot infer the missing packets. Send an alert export plus a short metadata sample for diagnosis; a ping alone does not validate attack detection.

The backend retains historical alerts if you reuse an existing database. Use a fresh extraction directory/database to distinguish this version's output from old false alerts. Keep earlier captures if needed as evidence.

## 8. Continue real wlan0 capture

The following captures incoming IPv4 packets addressed to this Kali laptop; it is not a receive-only mirror/diode boundary. It does not capture arbitrary traffic elsewhere on Wi-Fi. Use a separate, isolated mirror interface for the final deployment.

Terminal 1:

```bash
cd ~/Downloads/VEIL_Updated/veil
PROJECT_ROOT="$PWD"
ZEEK_BIN="$(command -v zeek)"
LOCAL_IP=$(ip -4 -o addr show wlan0 scope global | awk '{split($4,a,"/");print a[1];exit}')
echo "$LOCAL_IP"
mkdir -p data/wifi-live
cd data/wifi-live
sudo "$ZEEK_BIN" -C -i wlan0 -f "ip and dst host $LOCAL_IP" "$PROJECT_ROOT/zeek/veil.zeek"
```

Continue only if LOCAL_IP printed the expected current destination address. Keep capture running, then in Terminal 2:

```bash
cd ~/Downloads/VEIL_Updated/veil
VEIL_LOG="$PWD/data/wifi-live/veil_events.log" bash scripts/start.sh
```

Keep only one backend on port 8000; stop the earlier version before starting this one. New captures use the new folder, so previous alerts are not mixed into this verification.
