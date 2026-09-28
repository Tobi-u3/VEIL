# VEIL — Passive Threat Intelligence

Working SIH prototype source for Team BlueLock · PS 26145.

**Start with the local replay demo, then verify the live lab on Kali.** This package includes the built React dashboard, streaming Python backend, trained synthetic demonstration models, isolated network lab scripts, Zeek policies, upstream KitNET, tests and measured benchmark results. Read `docs/ARCHITECTURE.md` for the exact boundary and detection limits.

## 1. Quick start on Kali

Use Python **3.11–3.13** (3.12 tested), Node **20.19+ or 22+**, npm, and a terminal in this folder. Avoid Python 3.14 for this pinned scientific stack unless all dependencies install successfully. Do not replace Kali's system Python.

```bash
# Install prerequisites if missing:
sudo apt update
sudo apt install -y python3-venv python3-pip nodejs npm iproute2 iputils-ping tcpdump tcpreplay

# Creates a project virtual environment and rebuilds models/UI:
bash scripts/install.sh

# Create your analyst account (no default password):
.venv/bin/python scripts/create_user.py

# Starts the analyst UI and API; keep this terminal open:
bash scripts/start.sh
```

Open **http://127.0.0.1:8000** and sign in, then click **Run demo replay**. Watch for scan, SYN-rate, DNS and beaconing suspicions over about 30 seconds. Open Detections to inspect evidence, feature values and SHAP. Captured packets is the first page; Traffic graph is a separate page with small IP circles and a right-side information panel. Use the top-right theme switch for pastel light or navy/lavender dark mode. The System readiness tab reports which components are active. Export alerts downloads structured JSONL.

This demo replays synthetic metadata through actual detection code. It sends no packets, does not prove live capture, and is not a real-world accuracy evaluation.

If frontend dependencies are unavailable, the prebuilt `frontend/dist` works immediately after Python dependencies are installed:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/create_user.py
bash scripts/start.sh
```

If loading a bundled model reports a package-version error, regenerate it with `.venv/bin/python scripts/train.py` and `.venv/bin/python scripts/train_kitnet.py --synthetic-demo`.

## Login and grouped graph update

Run `.venv/bin/python scripts/create_user.py` once, then `bash scripts/start.sh`. The prompt creates one local analyst account with a 15–128 character password. No account or password is shipped. Restart VEIL after replacing the account. Credentials are in `data/credentials.json` with owner-only file permissions; keep this file private and out of shared ZIPs.

Authentication covers the data APIs, exports, replay control and WebSocket. Passwords use salted scrypt; sessions use HttpOnly, SameSite=Strict cookies, CSRF validation, 8-hour maximum lifetime and 30-minute inactivity expiry. Sign-out revokes the server session and closes its live stream. Ten login attempts within 15 minutes temporarily block further attempts. This is a single-process prototype; see `docs/SECURITY.md` before remote deployment.

The graph opens as clusters of small IP dots grouped by IPv4 /24 or IPv6 /64 prefix. Select a cluster for member IPs and shared destinations. Select an IP and choose Explore connections to see its peers, direction arrows and observed TCP/UDP destination ports. Motion can be paused; reduced-motion settings are respected. Large views use 12 prefixes/page, up to 96 representative real IP dots per cluster, and 24 peers/page. Search and member lists retain access to every observed IP. Grouping is a visual aid, not a DDoS classifier or proof that IPs belong to one organization. A server node's peers can span many groups.

To change grouping, start with `VEIL_IPV4_PREFIX=24 VEIL_IPV6_PREFIX=64 bash scripts/start.sh` (IPv4 range 0–32, IPv6 0–128). Use prefix lengths matching your lab. These settings only change grouping; they do not filter traffic or change detections. NAT may combine many devices into one visible address.

## Reference-inspired graph and evidence update

See `docs/UPDATE.md` for the exact changes. The replay now contains **214 source hosts, 6 destination hosts, 7,518 packet records and 60 destination ports**, with diverse TCP/UDP service traffic and synthetic scan, flood, DNS and periodic-connection scenarios. All traffic remains synthetic metadata; running the dashboard replay sends no packets.

SHAP now displays signed feature contributions, baseline, remaining-feature contribution and reconstructed model vote. Model/behavioral disagreements are explicit. KitNET anomaly alerts show reconstruction error and threshold; classifier SHAP does not explain KitNET. The aggregate detector now supplies the actual observed destination-port count instead of a constant to the classifier.

The KitNET synthetic baseline was broadened using independent benign packet windows (seed 173), without attack data or automatic learning from alerts. Independent synthetic validation uses seed 9881. These results are not operational accuracy claims.

## Dashboard update

The packet page refreshes every 500ms and browses the latest 10,000 packet metadata records, 100 at a time. Pause, resume, search, filter address scope, and browse older pages. The full Zeek metadata log stays on the capture host. No source subnet is filtered. Graph colours and node details reference the exact retained detection IDs; normal traffic cannot silently clear a retained warning.

Sources from other networks are displayed if their packets reach the mirrored link. NAT can change visible source addresses; VEIL cannot recover an address hidden upstream. The default capture policy accepts every observed IPv4/IPv6 destination instead of hard-coding 10.77.0.20. The mirror placement, not a source subnet filter, establishes direction. Optional destination allowlist: `VEIL_PROTECTED_SERVERS=10.77.0.20,2001:db8::20` when starting capture.

The mirror copies traffic before server delivery. The UI and inference update asynchronously; alerts do not have to precede server receipt.

## 2. Live passive capture lab

Use your existing working **Zeek 9** executable. This avoids replacing your Kali libraries or mixing Debian repositories. Confirm `zeek --version`; set `ZEEK_BIN` explicitly if needed. Detailed commands and explanation are in `docs/DEMO.md`.

```bash
sudo bash scripts/lab-up.sh
sudo bash scripts/verify-lab.sh
```

The script creates four logical systems entirely on your laptop: server `.20`, normal client `.30`, attacker `.10`, and an unnumbered receive-only observer. It does not modify wlan0 or your physical network.

In separate terminals:

```bash
# A — isolated server; serve a temporary empty folder, not your home directory
mkdir -p data/server-public
sudo ip netns exec veil-server python3 -m http.server 8000 --bind 10.77.0.20 --directory "$PWD/data/server-public"
```

```bash
# B — Zeek sees only the mirrored copy
sudo env PATH="$PATH" ZEEK_BIN="$(command -v zeek)" bash scripts/capture.sh
```

```bash
# C — stop the previous demo backend, then start LIVE mode
VEIL_LOG="$PWD/data/live/veil_events.log" bash scripts/start.sh
```

```bash
# D — normal traffic, then controlled attack-like lab patterns
sudo ip netns exec veil-client "$PWD/.venv/bin/python" scripts/lab-traffic.py normal
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py scan
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py syn
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py dns
sudo ip netns exec veil-attacker "$PWD/.venv/bin/python" scripts/lab-traffic.py beacon
```

The pattern generator has a fixed lab destination and finite workloads. It is not an Internet attack tool. Normal server replies still reach the normal client; they are simply absent from the observer feed.

Cleanup after stopping capture/backend:

```bash
sudo bash scripts/lab-down.sh
```

## 3. Enable PostgreSQL

The zero-setup demo uses SQLite and labels it. To use the PPT's PostgreSQL stack, install Docker/Compose or use an existing PostgreSQL server, then:

```bash
# Choose a local development password (URL-safe characters).
printf 'VEIL_DB_PASSWORD=replace_this_with_your_own_password\n' > .env
chmod 600 .env
docker compose -f compose.yml up -d
DATABASE_URL='postgresql://veil:replace_this_with_your_own_password@127.0.0.1:5432/veil' bash scripts/start.sh
```

For live mode, pass **both** `DATABASE_URL` and `VEIL_LOG`. PostgreSQL connection failures stop startup; the app does not silently fall back.

## 4. JA4 and model baseline

See `docs/DEMO.md` for the official JA4 plugin installation and TLS validation. The default watchlist is empty. Add only fingerprints you have independently labelled; a match alone is not proof of malware.

KitNET is included from the actual upstream MIT implementation, with a small NumPy compatibility patch. Both bundled ML artifacts are trained on synthetic demonstration data. Replace the baseline with verified benign feature windows before treating anomaly scores as useful for your network. River/ADWIN flags drift; it does not magically know that a prediction was wrong or automatically retrain from mistakes.

## 5. Tests and benchmark

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/benchmark.py
```

`docs/VALIDATION.md` distinguishes tests run in the build environment from hardware/live checks still required on your machine. `docs/benchmark.json` records the measured **metadata pipeline** throughput. It is not a Zeek packet-capture Mbps measurement.

## Project map

- `backend/`: event tail, bounded feature windows, models, evidence, FastAPI, persistence.
- `frontend/`: React/TypeScript/Tailwind/React Flow source and built UI.
- `zeek/`: immediate packet/DNS metadata and optional JA4 event integration.
- `scripts/`: setup, private live lab, replay, training and verification.
- `tests/`: functional pipeline/API tests.
- `models/`: synthetic model artifacts and model reports.
- `data/demo.jsonl`, `data/demo.pcap`: clearly labelled synthetic fixtures.
- `docs/`: architecture, walkthrough, model card, validation and benchmarks.

## What you should say in the presentation

“VEIL passively analyses a one-way mirrored traffic feed and raises evidence-backed suspicions. Our prototype demonstrates streaming acquisition, feature extraction, layered ML inference and a live dashboard. We report measured throughput and explicitly mark missing evidence.”

Do not claim prevention before arrival, zero mirroring overhead, guaranteed accuracy, confirmed encrypted malware, a trained GNN, or full exfiltration visibility from incoming-only packets. Your supplied PDF also contains a seventh instruction slide; remove it before a six-slide submission.
