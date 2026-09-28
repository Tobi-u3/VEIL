# Validation record

## Completed in the build environment

- 18 automated tests passed: aggregation, resource bounds, DNS entropy, partial/rotated/malformed logs, replay detections, distributed-source rate/entropy, missing reverse metrics, JA4 watchlist evidence, SQLite persistence, HTTP API and WebSocket transport.
- TypeScript checking and Vite production build passed.
- Browser interaction test: backend connection, start replay, scan appears, click alert, evidence drawer opens; zero uncaught browser JavaScript errors. Screenshots are included in this folder.
- Zeek **9.0.0** parsed the base capture policy successfully and processed `data/demo.pcap` offline. Its actual output was fed through the detection engine. See `zeek-validation.json` for record counts and resulting detections.
- Actual upstream KitNET code loaded, trained and performed inference, using the explicitly synthetic benign baseline. RF, River/ADWIN, SHAP and NetworkX ran in the tests.
- Measured metadata-processing benchmark: **63,940 events in 6.006 seconds, approximately 10,645 events/second**, against a stated target of 1,000 metadata events/second. Completed-window processing p95 was **6.2ms**. Hardware/runtime and scope are recorded in `benchmark.json`. This short benchmark includes SQLite writes and does not establish sustained wire-speed capture or end-to-end alert latency.
- Shell scripts pass `bash -n`. Python source compiles.

## Not verified here — required on your Kali/VM lab

- Live kernel mirroring, original-packet forwarding, observer transmit blocking, actual packet loss and physical three-machine setup. Network namespace creation was denied by the build environment. Run `scripts/verify-lab.sh`; no passing result is implied by the included script.
- JA4 plugin installation and its version-sensitive live adapter, actual TLS/QUIC fingerprints, complete encrypted-malware detection.
- PostgreSQL connection/integration. The implementation and Compose configuration are included; functional persistence testing used SQLite.
- Hardware data diode isolation, forensic tamper resistance, production deployment, representative real attack accuracy and full exfiltration analysis.

## Meaning of “working”

The packaged dashboard, metadata streaming/replay, feature extraction, model inference, graph, alert evidence, export and local persistence were executed. The base Zeek policy was additionally run against packet data. The provided live lab requires the host-side verification above before it can be described as a verified live demonstration.

The system produces suspicions and evidence. It does not block attacks, guarantee pre-arrival detection, assert that every anomaly is malicious, or substitute synthetic classification scores for real evaluation.

## Dashboard revision checks

- Captured-packet overview contains no detection feed; graph and detections have separate pages.
- Browser checks passed for packet pause/resume, several observed source prefixes, both themes, theme persistence, node details and alert-to-graph navigation, with zero uncaught JavaScript errors.
- Backend tests verify a thousand-plus requests reuse IP nodes, public IPv4/IPv6 addresses are not filtered, packet count excludes DNS/TLS metadata, cursor pages do not overlap, and retained warnings survive later normal traffic and graph expiry.
- Offline Zeek revision fixture: 3,197 packets and 3,217 metadata records; graph alert IDs match the retained feed. See zeek-validation.json.
- Topology-only load fixture: 10,000 packets from 1,000 source IPs produces 1,001 nodes and 1,000 relationships. This does not validate 1,000-source ML inference or live capture throughput.

## Login and network grouping revision

- 22 Python tests passed: pipeline and topology checks plus unauthorized HTTP/WebSocket access, valid/invalid login, throttling, CSRF/origin checks, logout revocation of an open socket, session expiry, Host validation and missing-account failure.
- TypeScript checking and Vite production build passed.
- Chromium checks passed for login/logout, packet browsing, theme persistence, prefix-group selection, IP selection and detection-to-graph navigation. No page JavaScript errors observed.
- Browser fixture with 1,000 sources and one server passed rendering and IP search with the grouped layout. This is a UI fixture, not a live wire-rate benchmark.
- Screenshots were regenerated for the authenticated dashboard and login page. TLS proxy deployment, physical mirroring and independent security assessment remain unverified.
