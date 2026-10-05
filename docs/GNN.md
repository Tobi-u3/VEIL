# GNN IP correlation

This extension is based on VEIL_Detection_Fix.zip and retains that version's UI. Open Traffic graph to use the new GNN IP correlation panel.

## What is implemented

A trained, two-layer directed mean GraphSAGE variant with 24 and 16 hidden units and a three-class softmax output. Both message-passing layers and the classifier head are trained using class-weighted cross entropy and Adam. Each layer concatenates a node's representation with the mean of its incoming neighbors and the mean of its outgoing neighbors. Incoming and outgoing here refer to edges in the observed copied traffic, not a second capture direction.

NumPy and SciPy implement training and inference. No GPU, PyTorch, or PyTorch Geometric installation is required. Weights are stored in a schema-validated JSON artifact, models/gnn.json. The model is a real learned graph neural network; it is not a renamed graph layout or a scikit-learn model.

Features are sent/received packet and byte totals, sent/received SYN-without-ACK fractions, source/destination TCP probe-port diversity, and distinct incoming/outgoing neighbor counts. Counts are log transformed. IP strings identify nodes only; they are not model features. Existing detection labels are not model inputs. JA4, DNS payloads, decrypted content, and active network queries are not used by this GNN.

## Reading the graph

- Background, scan pattern, and SYN convergence are learned pattern classes. Scores are uncalibrated model votes, not attack probabilities.
- A gold dashed ring marks an IP meeting the model threshold and observed-evidence review criteria. Red fills still mean an existing detection is linked. A target can receive a pattern label; this does not label it as an attacker.
- Click a candidate IP, graph node, or a source inside a correlation group to view its score, measured features, and captured connections.
- Shared-destination groups require at least two observed source IPs, the same selected model class, and supporting source behavior. Sources sharing a destination alone are not enough.
- Embedding similarity is the mean cosine similarity to the group's normalized embedding centroid. It is a descriptive similarity score, not proof of coordination, common ownership, or malicious intent.
- Graph arrows always represent observed traffic. GNN groups do not invent captured connections.
- SHAP continues to explain Random Forest only. The GNN's observed-feature panel is evidence for analyst review, not a causal attribution method.

The review criteria supplement the GNN: scan candidates need at least 16 outgoing or incoming probe ports; SYN-convergence candidates need outgoing SYN fraction >= 0.7 with >= 20 sent packets, or incoming SYN fraction >= 0.5 with >= 4 sources. Group members must satisfy the outgoing/source-side condition. High model votes without these conditions remain inspectable but receive no review ring.

## Timing and limits

The GNN collects a rolling 30-second window using one-second bins and runs on graph/all snapshots, at most once per two seconds of observation time. Bins touching the old boundary are excluded; effective coverage can be up to one second shorter. Replay uses event time, so its final state remains inspectable. Live mode uses current time, so old results expire when traffic stops. Historical detection edges are not fed back into the GNN.

Limits: 512 IP nodes, 2,048 directed edges, 12,000 per-edge time bins, and 64 retained probe ports per edge per bin. There are at most 50 displayed correlation groups. Exceeding node/edge/bin capacity causes the GNN to abstain and show a capacity message; the existing capture and detectors continue. Port diversity beyond the retained sample is approximate. The graph's existing 120-second view and the GNN's 30-second view intentionally differ.

GNN scores are supporting graph signals and do not generate, suppress, or upgrade existing alerts. They are ephemeral and are not persisted as detection records. Restart clears their window. Set VEIL_GNN=0 before startup to disable the collector/model. Missing or incompatible weights show an unavailable state while existing detection continues.

## Start on Kali

Extract VEIL_GNN.zip into a new directory so your existing installation remains available:

```bash
unzip ~/Downloads/VEIL_GNN.zip -d ~/Downloads/VEIL_GNN
cd ~/Downloads/VEIL_GNN/veil
bash scripts/install.sh
.venv/bin/python scripts/create_user.py
bash scripts/start.sh
```

Open http://127.0.0.1:8000, sign in, run demo replay, and open Traffic graph. The bundled trained model and built frontend are included. The demo contains SYN convergence from multiple IPs and a port scan; a correlation group needs multiple sources, while a single-source scan can still produce a node pattern.

For live capture, keep your existing Zeek capture process running and start this backend with its actual absolute log path:

```bash
VEIL_LOG=/absolute/path/to/veil_events.log bash scripts/start.sh
```

Stop the old backend before starting this one on port 8000. Do not run the replay while live ingest is selected. A same-host scan must be captured on the interface carrying that traffic (often loopback); GNN availability does not prove capture wiring or one-way enforcement.

## Retraining

Regenerate the demonstration weights:

```bash
.venv/bin/python scripts/train_gnn.py
```

Train with externally labeled graph snapshots:

```bash
.venv/bin/python scripts/train_gnn.py --dataset reviewed-graphs.jsonl
```

Each JSONL record contains scenario_id, split (train, validation, or test), edges, and labels. Aggregate each directed pair once per snapshot. Example record shape (not a sufficient training dataset):

```json
{"scenario_id":"capture-01","split":"train","edges":[{"src":"192.0.2.1","dst":"10.0.0.1","packets":50,"bytes":3000,"syn":48,"ports":[443]}],"labels":{"192.0.2.1":"background","10.0.0.1":"background"}}
```

The ports list contains only distinct SYN-without-ACK TCP destination ports. Supply a supported label for every observed IP, including targets. Use at least five independent graphs in each split, and keep entire capture scenarios separated. The trainer rejects a scenario ID crossing split boundaries; the operator must also keep overlapping windows and related captures in the same split. Labels require independent review; never use VEIL predictions as ground truth. Restart after replacing the model file.

## Validation and claims

The bundled weights were trained on 120 synthetic scenarios, with 30 independent validation scenarios and 30 test scenarios. The raw classifier's synthetic test macro F1 is approximately 0.9933. Removing neighbor messages at inference reduced it to approximately 0.8952. This ablation uses the same trained weights, not a separately trained baseline. Detailed class metrics and threshold selection are in models/gnn-report.json. Those metrics precede the additional observed-evidence review gates.

These synthetic results do not establish live-network accuracy, generalization, calibrated attack probability, or an improvement over the existing RF/IF system. Shared services, NAT, unusual benign scans, and coordinated legitimate administration can still produce false positives. The model needs reviewed real-network graphs and independent evaluation before operational reliance.

Reference: Hamilton, Ying, Leskovec, Inductive Representation Learning on Large Graphs (GraphSAGE), NeurIPS 2017: https://arxiv.org/abs/1706.02216. This implementation uses separate directed-neighbor means and no neighborhood sampling within its explicit capacity limits.
