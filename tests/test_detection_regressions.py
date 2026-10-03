import unittest
from unittest.mock import patch
from backend.engine import Engine
from backend.features import FEATURES, FEATURE_SCHEMA
from backend.ml import Models


def packet(i, ts, **fields):
    return {'kind': 'packet', 'ts': ts, 'uid': str(i), 'src': '192.0.2.10',
            'dst': '10.77.0.20', 'proto': 'tcp', 'length': 60,
            'sport': 40000, 'dport': 8100+i, 'tcp_flags': 2, 'syn': True, **fields}


class DetectionRegressions(unittest.TestCase):
    def test_ping_is_captured_but_is_not_a_scan(self):
        e=Engine()
        for i in range(10):e.ingest(packet(i,100+i*.5,proto='icmp',dport=0,sport=0,tcp_flags=0,syn=False,length=84))
        e.flush(108,True)
        self.assertEqual(e.traffic.count,10)
        self.assertGreater(e.window_count,0)
        self.assertFalse(e.alerts)

    def test_bulk_download_is_not_scan_or_ddos(self):
        e=Engine()
        for i in range(1800):
            e.ingest(packet(i,100+i*.001,src=f'192.0.2.{10+i%6}',dport=40000+i%30,
                            tcp_flags=24,syn=False,length=1400))
        e.flush(104,True)
        self.assertFalse(e.alerts)
        self.assertEqual(e.traffic.count,1800)

    def test_synack_replies_are_not_port_probes(self):
        e=Engine()
        for i in range(48):e.ingest(packet(i,100+i*.01,tcp_flags=18,syn=True))
        e.flush(104,True)
        self.assertFalse(any(a['threat_class']=='scan' for a in e.alerts))
        self.assertTrue(all(b.scan_port_count==0 for b in e.windows.buckets.values()))

    def test_fast_tcp_port_scan_has_model_and_probe_evidence(self):
        e=Engine()
        for i in range(48):e.ingest(packet(i,100+i*.01))
        e.flush(104,True)
        alert=next(a for a in e.alerts if a['threat_class']=='scan')
        self.assertEqual(alert['features']['unique_ports'],48)
        self.assertEqual(alert['model_vote']['label'],'scan')
        self.assertTrue(alert['shap_explanation']['additivity_verified'])
        self.assertIn('TCP SYN',alert['evidence'][0])

    def test_scan_spanning_several_windows_is_detected(self):
        e=Engine()
        for i in range(24):e.ingest(packet(i,100+i*.35))
        e.flush(112,True)
        self.assertTrue(any(a['threat_class']=='scan' for a in e.alerts))
        self.assertTrue(all(a['scan_window_seconds']==10 for a in e.alerts))

    def test_single_port_syn_burst_is_not_port_scan(self):
        e=Engine()
        for i in range(600):e.ingest(packet(i,100+i*.001,dport=8000))
        e.flush(104,True)
        self.assertTrue(any(a['threat_class']=='ddos' for a in e.alerts))
        self.assertFalse(any(a['threat_class']=='scan' for a in e.alerts))

    def test_probe_history_expires(self):
        e=Engine()
        for i in range(10):e.ingest(packet(i,100+i*.01))
        e.flush(103,True)
        for i in range(10,20):e.ingest(packet(i,120+(i-10)*.01))
        e.flush(124,True)
        self.assertFalse(any(a['threat_class']=='scan' for a in e.alerts))

    def test_legacy_feature_artifact_is_rejected(self):
        with patch('backend.ml.joblib.load',return_value={'features':FEATURES, 'feature_schema':'legacy'}):
            with self.assertRaisesRegex(ValueError,'schema mismatch'):Models()


if __name__=='__main__':unittest.main()
