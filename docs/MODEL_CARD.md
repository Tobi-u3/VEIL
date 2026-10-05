# Current model card

RandomForestClassifier: 80 trees, depth 10, seed 26145; twelve features in `backend/features.py`. Its training and generator-based validation data are synthetic. Model votes are computed for every completed window and compared with observed evidence. A vote without supporting evidence cannot create a named attack alert; behavioural suspicion can still be shown when the classifier disagrees. This threshold is a prototype choice, not a validated operating point. Confidence means the selected class vote, not a calibrated probability of an attack. `models/training-report.json` reports only synthetic generator validation.

IsolationForest: 100 trees, maximum 256 samples/tree, seed 26145. A fixed 70/30 shuffled split separates fitting from baseline calibration. The score is `-score_samples`; higher means more unusual. The threshold is the 99.5th percentile of calibration scores plus .02. The default 3,000-row baseline contains independent synthetic benign packet windows and broadened synthetic benign classifier rows, including high-throughput transfers and ping-like traffic. See `models/isolation-report.json`. The training/calibration seed and the demo baseline are fixed for reproducibility; these are not operational performance claims.

`train_isolation.py --benign-csv PATH` accepts reviewed benign rows with all feature columns and requires >=1,200 finite rows. It never learns automatically from alerts. Representative time-separated benign validation and labelled attack evaluation are still needed. The random calibration split used for the prototype does not replace time-separated operational testing.

SHAP explains only RandomForest class probabilities. Signed contributions plus the baseline reconstruct the selected class vote; the tests check additivity. An unknown-anomaly alert retains its IsolationForest score and threshold separately. Its RandomForest SHAP bars can legitimately explain a benign classifier vote.

JA4 matches are only local watchlist evidence. An empty watchlist creates no match alert. TLS fingerprints, long DNS labels, periodic traffic, high rates and port diversity all have benign explanations. Incoming-only observation cannot prove attack success or exfiltration. Neither detector guarantees detection of previously unseen threats.


## October 3 corrections

Feature schema: `veil-v2-tcp-probe-ports`. TCP flags take precedence over the synthetic `syn` hint, so SYN-ACK/data replies do not count as connection probes. Sixteen distinct probed ports over ten seconds create scan suspicion. ICMP ping to one destination is not a port scan. Older model artifacts and labelled baselines require re-export/retraining to use these feature semantics.

Normal high-rate transfers and sparse ping-like traffic were added to the synthetic benign training/baseline data. High packet/byte rate alone no longer becomes a DDoS or exfiltration label. DDoS suspicion here is restricted to predominantly SYN probes at high rate; UDP/ICMP/HTTP flood coverage is not claimed.

IsolationForest alerts require three consecutive populated outlier windows, each with >=4 packets and gaps <=5 seconds. This reduces transient false alarms but increases alert delay and can miss short-lived anomalies. A persistent outlier is still a suspicion, not proof of malicious traffic.

`train.py --train-csv TRAIN --validation-csv VALIDATION` fits the classifier on independently labelled metadata windows and reports metrics on a separate validation file. It rejects the same file for both roles and requires later validation timestamps when timestamp columns exist. The operator must ensure label validity and separation of related sessions; this utility does not establish ground truth or automatically eliminate leakage.


## Graph neural network extension
See GNN.md and models/gnn-report.json for architecture, synthetic training scope, raw evaluation, evidence gates, and capacity limits. GNN predictions support graph review only; they do not create alerts.
