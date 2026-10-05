import json,tempfile,unittest
from pathlib import Path
import numpy as np
from backend.gnn import GraphCorrelation,graph_arrays,forward,ROOT
from scripts.train_gnn import synthetic,validate_graphs

class GNNTests(unittest.TestCase):
 def packet(self,ts=100,src='192.0.2.1',dst='10.0.0.1',port=443,flags=2):
  return dict(ts=ts,src=src,dst=dst,dport=port,length=60,proto='tcp',tcp_flags=flags)
 def test_probe_flags_and_window_expiry(self):
  g=GraphCorrelation();g.add(self.packet(flags=18));r=g.snapshot(101)
  self.assertEqual(r['nodes']['192.0.2.1']['evidence']['probe_ports'],0)
  self.assertFalse(g.snapshot(132)['available']);self.assertFalse(g.snapshot(132)['nodes'])
 def test_missing_corrupt_disabled_models(self):
  g=GraphCorrelation('/nonexistent');self.assertFalse(g.snapshot(10)['available'])
  self.assertFalse(GraphCorrelation(enabled=False).snapshot(10)['available'])
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'bad.json';p.write_text('{"schema":"old"}')
   self.assertEqual(GraphCorrelation(p).status,'unavailable')
 def test_capacity_abstains(self):
  g=GraphCorrelation();g.max_buckets=1;g.add(self.packet());g.add(self.packet(src='192.0.2.2'))
  self.assertFalse(g.snapshot(101)['available']);self.assertEqual(g.snapshot(101)['status'],'capacity limit')
 def test_node_capacity_abstains(self):
  g=GraphCorrelation();g.max_nodes=1;g.add(self.packet());self.assertEqual(g.snapshot(101)['status'],'capacity limit')
 def test_late_packets_do_not_resurrect_expired_window(self):
  g=GraphCorrelation();g.add(self.packet(ts=150));g.add(self.packet(ts=100,src='192.0.2.2'))
  self.assertNotIn('192.0.2.2',g.snapshot(151)['nodes'])
 def test_cache_and_finite_probabilities(self):
  g=GraphCorrelation();g.add(self.packet());r=g.snapshot(101)
  self.assertIs(r,g.snapshot(102));self.assertIsNot(r,g.snapshot(104))
  for n in r['nodes'].values():self.assertAlmostEqual(sum(n['scores'].values()),1,places=4)
 def test_ip_rename_equivariance_and_neighbor_influence(self):
  g=GraphCorrelation();scene=synthetic(91,3,'test')[2];edges=scene['edges']
  ids,x,ai,ao,_=graph_arrays(edges);p,_=forward(x,ai,ao,g.weights)
  changed,_=forward(x,ai*0,ao*0,g.weights)
  self.assertGreater(np.max(abs(p-changed)),.01)
  mapping={ip:f'2001:db8::{i+1:x}' for i,ip in enumerate(reversed(ids))}
  remapped=[{**e,'src':mapping[e['src']],'dst':mapping[e['dst']]} for e in edges]
  renamed,xx,a,b,_=graph_arrays(remapped);q,_=forward(xx,a,b,g.weights)
  for i,ip in enumerate(ids):np.testing.assert_allclose(p[i],q[renamed.index(mapping[ip])],atol=1e-5)
 def test_synthetic_scan_pattern_and_correlations(self):
  g=GraphCorrelation()
  for source in ('192.0.2.1','192.0.2.2'):
   for port in range(8000,8048):g.add(self.packet(src=source,port=port))
  r=g.snapshot(101)
  self.assertTrue(r['nodes']['192.0.2.1']['flagged']);self.assertEqual(r['nodes']['192.0.2.1']['label'],'scan_pattern')
  self.assertTrue(r['correlations']);self.assertEqual(r['correlations'][0]['source_count'],2)
 def test_benign_cosource_not_correlated_by_neighbor_alone(self):
  g=GraphCorrelation()
  for source in ('192.0.2.1','192.0.2.2'):
   for port in range(8000,8048):g.add(self.packet(src=source,port=port))
  for i in range(100):g.add(self.packet(src='192.0.2.3',flags=24))
  r=g.snapshot(101)
  self.assertFalse(r['nodes']['192.0.2.3']['flagged'])
  self.assertNotIn('192.0.2.3',r['correlations'][0]['sources'])
 def test_normal_ping_not_flagged(self):
  g=GraphCorrelation()
  for i in range(10):g.add({**self.packet(ts=100+i,port=0,flags=0),'proto':'icmp','length':84})
  self.assertFalse(any(n['flagged'] for n in g.snapshot(110)['nodes'].values()))
 def test_scenario_leakage_rejected(self):
  graphs=synthetic(1,5,'train')+synthetic(2,5,'validation')+synthetic(3,5,'test')
  graphs[-1]['scenario_id']=graphs[0]['scenario_id']
  with self.assertRaisesRegex(ValueError,'leakage'):validate_graphs(graphs)
if __name__=='__main__':unittest.main()
