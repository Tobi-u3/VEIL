# GNN extension

This build starts from VEIL_Detection_Fix, preserves the original UI, and adds GraphSAGE IP correlation. See GNN.md for installation, validation, and limits.

# Detection and contrast corrections — 2026-10-03

The user's ICMP ping from a RHEL VirtualBox guest was successfully captured. No port-scan alert for that test is expected: ordinary ping is reachability traffic, not TCP port probing.

A separate code defect was reproduced with controlled metadata: normal download data across multiple client destination ports incorrectly raised a scan alert in the previous version. The new version counts only TCP SYN without ACK as a probe and uses a rolling ten-second port history. Normal downloads and SYN-ACK replies no longer satisfy that scan condition. Scan tests spanning several two-second analysis windows now pass.

Both ML models continue to evaluate each completed window. The demonstration baseline now includes normal high-throughput transfers and sparse ping-like traffic. Unsupported model-only attack labels and rate-only DDoS labels were removed. Persistent unknown ML anomalies require three populated outlier windows. Real labelled training/validation CSV support was added; synthetic metrics do not establish real-world accuracy.

Light-mode primary, secondary, muted and accent text colours were darkened. Contrast checks against pastel surfaces passed with a minimum token ratio of 6.61:1. The frontend was rebuilt. A browser screenshot could not be produced because the browser download failed in this environment; visual inspection on the user's laptop remains needed.

The current feature schema is veil-v2-tcp-probe-ports, and both included model artifacts were regenerated to match it. Old locally retrained models/baselines must be regenerated with the new semantics. Do not reuse historical false alerts as validation of this version.

See README section 7 for a finite 48-port Nmap test from the user's RHEL VM to their own Kali destination.
