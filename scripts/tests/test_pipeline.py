import unittest,tempfile,json,os
from pathlib import Path
from backend.features import Windows,entropy
from backend.ingest import Tail
from backend.engine import Engine
from backend.store import Store

class PipelineTests(unittest.TestCase):
    def packet(self,t=1,**kw):
        return {'kind':'packet','ts':t,'uid':str(t),'src':'10.77.0.10','dst':'10.77.0.20','dport':80,'length':60,**kw}
    def test_entropy(self):self.assertEqual(entropy('aaaa'),0);self.assertAlmostEqual(entropy('abcd'),2)
    def test_window_and_reverse_missing(self):
        w=Windows();w.add(self.packet());w.add(self.packet(1.5));self.assertFalse(w.flush(2))
        b,q=w.flush(3)[0];f=b.vector(2,q,set());self.assertEqual(f['pps'],1);self.assertNotIn('reverse_bytes',f)
    def test_capacity(self):
        w=Windows(capacity=1);w.add(self.packet());w.add(self.packet(src='10.77.0.11'));self.assertEqual(w.dropped,1)
    def test_tail_partial_rotation_and_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.log';p.write_text('{"a":');t=Tail(p);self.assertEqual(t.read(),[])
            with p.open('a') as f:f.write('1}\nbad json\n{"a":2}\n')
            self.assertEqual(t.read(),[{'a':1},{'a':2}]);self.assertEqual(t.errors,1)
            p.rename(Path(d)/'old');p.write_text('{"a":3}\n');self.assertEqual(t.read(),[{'a':3}])
    def test_packet_sequence_not_beacon(self):
        w=Windows()
        for i in range(20):w.add(self.packet(i*.01,start=True))
        b,q=w.flush(3)[0];self.assertEqual(len(q),0)
    def test_store(self):
        with tempfile.TemporaryDirectory() as d:
            old=os.environ.get('VEIL_DB');os.environ['VEIL_DB']=str(Path(d)/'test.db')
            s=Store();s.save('alerts',{'id':'1','timestamp':1,'threat_class':'scan'});s.save('alerts',{'id':'1','timestamp':1})
            self.assertEqual(len(s.alerts()),1);s.close()
            if old:os.environ['VEIL_DB']=old
            else:del os.environ['VEIL_DB']
    def test_demo_detections_and_no_fabricated_ratios(self):
        e=Engine()
        classes=set()
        for line in Path('data/demo.jsonl').read_text().splitlines():
            e.ingest(json.loads(line));classes.update(a['threat_class'] for a in e.alerts)
        e.flush(e.last_ts+2,True)
        classes.update(a['threat_class'] for a in e.alerts)
        # Expanded replay can exceed the bounded 100-record UI feed.
        self.assertLessEqual(len(e.alerts),100)
        self.assertTrue({'scan','ddos','dns_anomaly','beaconing'} <= classes,classes)
        for a in e.alerts:
            self.assertIsNone(a['outbound_inbound_ratio']);self.assertIsNone(a['reverse_bytes'])
            json.dumps(a,allow_nan=False)
        self.assertGreater(e.window_count,0)
    def test_normal_no_rule_alert(self):
        e=Engine();e.models.isolation_threshold=None
        for i in range(30):e.ingest(self.packet(1+i*.05,src='10.77.0.30'))
        e.flush(4,True);self.assertFalse(e.alerts)
    def test_distributed_rate(self):
        e=Engine();e.models.isolation_threshold=None
        for i in range(800):e.ingest(self.packet(1+i*.001,src=f'10.77.0.{40+i%8}',syn=True))
        e.flush(4,True)
        a=next(a for a in e.alerts if a['src']=='multiple sources')
        self.assertEqual(a['threat_class'],'ddos');self.assertAlmostEqual(a['features']['source_ip_entropy'],3)
    def test_bad_timestamp(self):
        e=Engine()
        with self.assertRaises(ValueError):e.ingest(self.packet(float('nan')))
    def test_ja4_observed_only(self):
        e=Engine();e.watchlist={'test-fingerprint'}
        e.ingest(self.packet(kind='tls',ja4='test-fingerprint'));e.flush(4,True)
        self.assertEqual(e.alerts[0]['threat_class'],'encrypted_suspicion')
        self.assertEqual(e.alerts[0]['ja4'],['test-fingerprint'])
if __name__=='__main__':unittest.main()
