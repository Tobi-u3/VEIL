"""Measured metadata pipeline throughput, explicitly NOT wire-speed capture throughput."""
import sys,time,json,platform
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.engine import Engine
from backend.store import Store
engine=Engine(Store());records=[json.loads(x) for x in (ROOT/'data/demo.jsonl').read_text().splitlines()]
start=time.perf_counter();loops=20
for k in range(loops):
    for r in records:
        e=dict(r);e['ts']+=k*35;e['uid']=f'{k}-{e["uid"]}';engine.ingest(e)
engine.flush(engine.last_ts+2,True)
elapsed=time.perf_counter()-start
report={'scope':'Synthetic JSON metadata ingestion, feature extraction, RF, KitNET, SHAP on alerts, ADWIN, NetworkX and SQLite persistence; NOT Zeek packet capture throughput',
        'events':len(records)*loops,'elapsed_seconds':round(elapsed,3),'events_per_second':round(len(records)*loops/elapsed),
        'target_events_per_second':1000,'target_met':len(records)*loops/elapsed>=1000,
        'python':platform.python_version(),'platform':platform.platform(),'metrics':engine.snapshot()['metrics'],
        'latency_definition':'processing_p95_ms covers a completed feature window and persistence; excludes 2s accumulation, log lag and UI delay'}
(ROOT/'docs/benchmark.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));engine.store.close()
