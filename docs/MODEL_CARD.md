# Model card

## Random forest

Implementation: scikit-learn RandomForestClassifier, 80 trees, maximum depth 10, fixed seed 26145. Twelve features: packet rate, byte rate, SYN fraction, unique destination ports, mean packet size, size standard deviation, DNS first-label entropy, DNS label length, TXT fraction, connection-interval coefficient of variation, connection count, local JA4-watchlist flag.

The included model is trained on generated feature vectors covering benign and six demonstration categories. The validation generator uses another seed. This is an independent draw from the same simplistic synthetic generator, NOT separation by real capture/session/campaign and NOT validation on real attacks. `models/training-report.json` is a smoke-test result only. A high synthetic score must not be presented as attack-detection accuracy.

`confidence` is the uncalibrated classifier vote for a heuristic-supported class, or null when the classifier disagrees / no named class exists. Severity is an explicit triage mapping, not a probability. Unknown KitNET alerts have null class confidence. SHAP contributions explain the model's selected class; they do not establish causation or explain a different heuristic class.

## KitNET

The bundled implementation is upstream ymirsky/KitNET-py, commit `02eb5e804568ee9f3968d4fc5bdfd37a9c0bc190`, MIT licence retained. Compatibility patches: replace `numpy.Inf` with `numpy.inf` in dA.py; clip the sigmoid exponent in utils.py to [-700,700] to avoid overflow. Feature mapper grace period 100, autoencoder training grace period 500. Only the first 601 trusted baseline rows train it. Remaining rows set a 99.5th-percentile reconstruction-error threshold, multiplied by 1.2. The supplied artifact uses synthetic benign data and is labelled accordingly.

Use `python scripts/train_kitnet.py --benign-csv YOUR_VERIFIED_BENIGN_FEATURES.csv` to replace the baseline after collecting at least 1,200 representative clean windows. The CSV must have the twelve named feature columns. Live observations never automatically train KitNET. Do not train from its own predictions.

## River / ADWIN

ADWIN receives log(1 + packet rate) for each completed window. It identifies a shift in that sequence, which can also reflect changing mixtures of hosts. It is not supervised error feedback. Its state resets at process start. A deployment should use per-host or per-service baselines and validate drift decisions. Retraining is deliberately offline/explicit in this prototype.

## Required real-data validation before accuracy claims

Collect labelled normal and isolated lab traces separately. Split by session/time/scenario, not random packet rows. Include normal high-volume backups, browsers with long DNS names, update checks and monitoring agents. Freeze the training set, tune thresholds on validation captures, then evaluate previously unseen captures. Report per-class precision/recall/F1, false alerts per hour, confusion matrix, capture losses, CPU/RAM, event throughput and observation-to-alert p50/p95/p99. Calibrate class probabilities on a separate set if displaying them as probabilities. Measure each of the six categories only when its required evidence is visible.

This prototype does not claim to detect every attack, to have production-grade accuracy, or to confirm malware by JA4 alone.
