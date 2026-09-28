import unittest,json
import networkx as nx
from backend.traffic import Traffic,address_info
from backend.engine import Engine

class TrafficTests(unittest.TestCase):
    def packet(self,ts=1,src='198.51.100.23',dst='10.77.0.20',**kw):
        return {'kind':'packet','ts':ts,'src':src,'dst':dst,'uid':f'{src}-{ts}',
                'sport':50000,'dport':80,'length':80,'proto':'tcp',**kw}
    def test_every_packet_not_protocol_events(self):
        e=Engine();e.models.kit_threshold=None
        for i in range(1200):e.ingest(self.packet(1+i*.001))
        e.ingest(self.packet(2.2,kind='dns',query='example.test',qtype=1))
        s=e.snapshot()
        self.assertEqual(s['metrics']['packets'],1200)
        self.assertEqual(s['metrics']['events'],1201)
        self.assertEqual(len(s['graph']['nodes']),2)
        self.assertEqual(s['graph']['edges'][0]['packets'],1200)
        self.assertEqual(s['packets']['items'][0]['sequence'],1200)
    def test_buffer_and_cursor_no_duplicates(self):
        t=Traffic(capacity=250);g=nx.DiGraph()
        for i in range(300):t.add(self.packet(i),g)
        first=t.page();second=t.page(before=first['next_before']);third=t.page(before=second['next_before'])
        seq=[p['sequence'] for page in (first,second,third) for p in page['items']]
        self.assertEqual(seq,list(range(300,50,-1)))
        self.assertEqual(first['expired'],50);self.assertIsNone(third['next_before'])
    def test_external_and_ipv6_not_filtered(self):
        t=Traffic();g=nx.DiGraph()
        for i,src in enumerate(('10.77.0.30','1.1.1.1','2001:4860:4860::8888','203.0.113.3')):
            t.add(self.packet(i,src=src),g)
        self.assertEqual(t.count,4)
        self.assertEqual(len(t.page(scope='public')['items']),2)
        self.assertEqual(len(t.page(query='2001:4860')['items']),1)
        self.assertEqual(address_info('203.0.113.3')['scope'],'documentation')
        self.assertEqual(address_info('2001:4860:4860::8888')['ip_version'],6)
    def test_warning_persists_after_normal_and_expiry(self):
        e=Engine();e.models.kit_threshold=None
        for i in range(30):e.ingest(self.packet(1+i*.01,dport=1000+i,syn=True))
        e.flush(4,True)
        alert=e.alerts[0]
        e.ingest(self.packet(5));e.flush(8,True)
        g=e.snapshot()['graph'];edge=next(x for x in g['edges'] if x['source']==alert['src'])
        self.assertTrue(edge['suspicious']);self.assertIn(alert['id'],edge['alert_ids'])
        e.last_ts=200;g=e.snapshot()['graph']
        self.assertTrue(g['edges'][0]['suspicious']);self.assertFalse(g['edges'][0]['recent'])
        self.assertIn(alert['id'],g['nodes'][0]['alert_ids'])
        e.alerts.clear();self.assertFalse(e.snapshot()['graph']['nodes'])
    def test_aggregate_alert_links_actual_sources(self):
        e=Engine();e.models.kit_threshold=None
        for i in range(800):e.ingest(self.packet(1+i*.001,src=f'203.0.113.{1+i%8}',syn=True))
        e.flush(4,True)
        a=next(a for a in e.alerts if a['src']=='multiple sources')
        self.assertEqual(len(a['related_sources']),8)
        g=e.snapshot()['graph']
        self.assertNotIn('multiple sources',{n['id'] for n in g['nodes']})
        self.assertEqual(sum(a['id'] in edge['alert_ids'] for edge in g['edges']),8)
        self.assertEqual({i for x in g['edges'] for i in x['alert_ids']},{a['id'] for a in e.alerts})
    def test_websocket_views_bounded(self):
        e=Engine();e.ingest(self.packet())
        s=e.snapshot('packets');self.assertIsNone(s['graph']);self.assertFalse(s['alerts']);self.assertEqual(len(s['packets']['items']),1)
        s=e.snapshot('graph');self.assertIsNone(s['packets']);self.assertEqual(len(s['graph']['nodes']),2)
if __name__=='__main__':unittest.main()
