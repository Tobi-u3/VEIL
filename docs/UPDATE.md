# Targeted VEIL update

## Graph and interface

- Reference-inspired clusters of small IP circles, grouped by address prefix.
- Animated arrows indicate direction on recent relationships. They are a visual guide, not packet-by-packet timing. Historical edges remain still and dashed.
- Select a cluster for members/shared destinations; select an IP and explore connections for individual peers and observed protocol/port labels.
- Up to 12 prefixes per page, 96 actual member dots per prefix, 40 bundled links, and 24 peers per detailed page. These are declared display limits, not capture filters. Search includes every retained IP. Cluster member lists expose IPs omitted from the dot sample.
- Cross-prefix edges are bundled. Within-prefix relationships appear in the detailed connection view. Port lists retain up to 64 distinct protocol/port combinations per IP pair and display a truncation notice if exceeded.
- Large readable text, navy/lavender and pastel themes, keyboard-accessible IP dots, pause animation, reduced-motion support, and original SVG illustrations for passive mirroring and secure analyst access.

## Replay

214 source hosts, six destinations, nine prefixes, 7,518 packets plus 20 DNS records over 31.39 seconds of event time. Source ports vary. Services include TCP/UDP 443, 80, 22, 53, 123, 1883, 3389, 5432, 8000, 8080, 8443 and 8883; a synthetic scan uses ports 1000–1047. The graph does not classify service applications solely from port numbers.

The replay emits no network traffic. `make_pcap.py` writes the same expanded fixture to disk, preserving source ports and TCP/UDP distinctions. A DNS metadata event becomes a separate synthetic DNS packet in that PCAP, so its packet count differs from the JSONL packet-record count.

## SHAP review

All 65 explanations emitted by the expanded replay reconstructed the explained RF class score, with maximum absolute error about 2.22e-16. Signed bars show percentage-point changes to that class's synthetic model vote. The remaining contributions are included explicitly in the calculation.

54 alerts originate from KitNET anomaly signals whose class labels differ from the RF vote. The interface explicitly separates their reconstruction-error trigger from the RF SHAP explanation. This is not presented as model agreement. The aggregate DDoS feature vector now counts actual destination ports instead of using a constant one.

The previous synthetic KitNET baseline produced 143 alerts on this expanded replay, including ordinary service-flow anomalies. An independent packet-derived benign baseline reduced this to 65. None had a designated benign source as the individually flagged sender. Aggregate rate alerts can also link benign sources present in the same destination window; a red node means linked evidence, not a verdict against that device. A separate seed produced zero flagged windows out of 1,200 synthetic benign windows. This is a controlled demonstration result, not measured real-network false-positive performance. A verified benign operational baseline is still required for a real deployment.

## Verification

- 26 Python tests: detection pipeline, authentication, graph data, port counts, expanded demo diversity, SHAP score reconstruction and actual aggregate-port inputs.
- TypeScript and production frontend build.
- Browser scale fixture: 1,001 represented IPs compressed into five network clusters; searching omitted dots, 1,000-peer pagination, animated edges, pause, reduced motion, and both themes.
- End-to-end authenticated replay and visual checks recorded in `browser-test.json`.

Model artifacts, generated replay data and the affected frontend/backend modules are the intended changes. User credentials, login implementation, database schema, physical capture scripts and production-network configuration are not part of this update. No live physical mirror or hardware-diode validation was performed here.
