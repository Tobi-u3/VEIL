import json,unittest
from pathlib import Path
from backend.engine import Engine
from backend.features import FEATURES
from backend.ml import Models
import networkx as nx
from backend.traffic import Traffic

class ExplanationTests(unittest.TestCase):
    def test_shap_reconstructs_scores(self):
        m=Models();self.assertIsNotNone(m.explainer)
        vectors=[dict(zip(FEATURES,[2,1200,0,1,600,50,0,0,0,1,0,0])),
                 dict(zip(FEATURES,[700,42000,1,1,60,0,0,0,0,1,0,0])),
                 dict(zip(FEATURES,[24,1440,1,48,60,0,0,0,0,1,0,0]))]
        for f in vectors:
            for label in m.rf.classes_:
                x=m.explain_details(f,label)
                self.assertTrue(x['additivity_verified'],x)
                self.assertAlmostEqual(x['base_value']+x['contribution_sum'],x['model_score'],places=6)
                self.assertAlmostEqual(sum(v['contribution'] for v in x['features'])+x['other_contribution'],x['contribution_sum'],places=6)
    def test_aggregate_uses_actual_port_count(self):
        e=Engine();e.models.kit_threshold=None
        for i in range(800):e.ingest({'kind':'packet','ts':1+i*.001,'uid':str(i),'src':f'192.0.2.{1+i%8}','dst':'10.77.0.20','sport':42000+i,'dport':[80,443,8080,8443][i%4],'length':60,'syn':True})
        e.flush(4,True)
        a=next(a for a in e.alerts if a['src']=='multiple sources')
        self.assertEqual(a['features']['unique_ports'],4)
        self.assertEqual(a['shap_explanation']['class'],a['shap_explains_class'])
    def test_observed_ports_and_transport_counts(self):
        t=Traffic();g=nx.DiGraph()
        for i,(port,proto) in enumerate([(443,'tcp'),(443,'udp'),(443,'tcp'),(53,'udp')]):
            t.add({'ts':i+1,'src':'192.0.2.1','dst':'10.77.0.20','uid':str(i),'length':60,'dport':port,'proto':proto},g)
        edge=t.topology(g,[],4)['edges'][0]
        self.assertEqual(sum(p['packets'] for p in edge['ports']),4)
        self.assertEqual({(p['protocol'],p['port']):p['packets'] for p in edge['ports']},{('tcp',443):2,('udp',443):1,('udp',53):1})
        self.assertIn('port_counts',g['192.0.2.1']['10.77.0.20'])
    def test_demo_diversity(self):
        packets=[e for e in map(json.loads,Path('data/demo.jsonl').read_text().splitlines()) if e['kind']=='packet']
        self.assertGreaterEqual(len({e['src'] for e in packets}),200)
        self.assertGreaterEqual(len({e['dst'] for e in packets}),6)
        self.assertGreater(len({e['sport'] for e in packets}),100)
        self.assertTrue({22,53,80,123,443,1883,3389,5432,8080,8443,8883}<={e['dport'] for e in packets})
