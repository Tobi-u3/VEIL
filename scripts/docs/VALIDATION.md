# Validation — 2026-10-03 detection update

## Completed

- All **40 tests passed** in 31.103 seconds. The suite includes actual model inference and SHAP additivity, ping-versus-scan distinction, normal bulk transfers, SYN-ACK replies, fast scans, probes across multiple windows, repeated single-port SYN bursts, probe-history expiry and legacy feature-schema rejection.
- The authenticated live-file integration test passed: partial/malformed log handling, packet counting, scan evidence, SHAP, WebSocket delivery and JSON alert export.
- The original incorrect scan on ordinary download metadata was reproduced before the fix. The new regression case does not raise a scan or DDoS alert for that traffic.
- Both model artifacts were regenerated with the veil-v2-tcp-probe-ports schema. Doctor checks passed. The CSV training CLI was tested with synthetic fixtures in a temporary project, and same-file training/validation was rejected. See training-cli-check.json.
- TypeScript checking and the Vite frontend build passed; the regenerated assets are included.
- Actual local Uvicorn startup, HTML/assets, authenticated replay, access blocking before login and logout revocation passed. See startup-smoke.json.
- Light-theme text/accent token contrasts against pastel surfaces met 4.5:1, with a minimum checked ratio of 6.61:1. See light-contrast.json. This checks CSS token colours, not every rendered pixel.
- pip check found no broken requirements; all shell scripts passed bash -n.

## Measured metadata performance

The final one-pass synthetic metadata benchmark processed 7538 events in 17.653 seconds: 427 events/second. It did not meet the retained 1,000 events/second target. This is feature/model/SQLite processing, not wire-speed capture, end-to-end alert latency or real-network accuracy. See benchmark.json and rerun on the actual host.

## Still requires verification on the user's laptop

Zeek, actual RHEL-to-Kali packets, mirror/drop enforcement, live JA4 and capture loss were not exercised in this build environment. The user's ping capture was reported by the user, not independently observed here. A browser screenshot was unavailable because the browser download failed; inspect the rebuilt light-theme dashboard on the laptop.

Normal ping to one destination is correctly not a TCP port scan. Run README section 7's finite 48-port test and check that incoming TCP SYN probes reach VEIL. Tests establish behaviour on controlled fixtures and selected normal cases, not comprehensive attack coverage.

Both bundled models remain synthetic-trained. Real labelled training and time-separated validation are needed to measure precision, recall, false-positive rate and operational performance. Persistent anomaly gating delays alerts and may miss brief events. The narrower SYN-based flood signature does not provide UDP/ICMP/HTTP flood detection. Perfect detection is not claimed.
