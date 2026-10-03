import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient
from backend.app import app
from backend.auth import make_credentials
from backend.engine import Engine
from backend.features import FEATURES
from backend.ml import Models
from backend.store import Store


class WorkingModelTests(unittest.TestCase):
    def test_isolation_score_matches_estimator(self):
        models = Models()
        f = dict(zip(FEATURES, [2, 1200, 0, 1, 600, 50, 0, 0, 0, 1, 0, 0]))
        result = models.predict(f)
        self.assertAlmostEqual(result['isolation_score'],
                               -models.isolation.score_samples(np.array([list(f.values())]))[0])
        models.isolation_threshold = result['isolation_score'] - .001
        self.assertTrue(models.predict(f)['isolation_anomaly'])
        models.isolation_threshold = result['isolation_score'] + .001
        self.assertFalse(models.predict(f)['isolation_anomaly'])

    def test_unsupported_classifier_vote_does_not_invent_scan(self):
        engine = Engine()
        original = engine.models.predict
        engine.models.predict = lambda f: {**original(f), 'label': 'scan',
                                           'confidence': .95, 'isolation_anomaly': False}
        engine.ingest({'kind': 'packet', 'ts': 1, 'uid': 'u', 'src': '192.0.2.1',
                       'dst': '10.77.0.20', 'length': 60, 'dport': 80})
        engine.flush(4, True)
        self.assertFalse(engine.alerts, 'A classifier vote without TCP probes must not invent a scan')

    def test_unknown_anomaly_preserves_detector_evidence(self):
        engine = Engine()
        original = engine.models.predict
        engine.models.predict = lambda f: {**original(f), 'label': 'benign',
                                           'isolation_anomaly': True, 'isolation_score': .8}
        for start in (1,4,7):
            for i in range(4):
                engine.ingest({'kind': 'packet', 'ts': start+i*.1, 'uid': str(start)+'-'+str(i), 'src': '192.0.2.1',
                               'dst': '10.77.0.20', 'length': 60, 'dport': 80})
            engine.flush(start+2, True)
            if start<7:self.assertFalse(engine.alerts, 'One or two outlier windows are insufficient')
        alert = engine.alerts[0]
        self.assertEqual(alert['threat_class'], 'unknown_anomaly')
        self.assertIsNone(alert['confidence'])
        self.assertEqual(alert['model_vote']['isolation_score'], .8)
        self.assertEqual(alert['shap_explains_class'], 'benign')

    def test_invalid_events_do_not_pollute_state(self):
        engine = Engine()
        base = {'kind': 'packet', 'ts': 1, 'uid': 'u', 'src': '192.0.2.1',
                'dst': '10.77.0.20', 'length': 60, 'dport': 80}
        for record in ([], {**base, 'dport': 65536}, {**base, 'length': float('nan')},
                       {**base, 'uid': []}, {**base, 'query': {}}):
            with self.assertRaises(ValueError):
                engine.ingest(record)
        self.assertEqual(engine.events, 0)
        self.assertEqual(engine.traffic.count, 0)

    def test_saved_alerts_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'VEIL_DB': str(Path(directory)/'test.sqlite'),
                                         'DATABASE_URL': ''}):
                first = Store()
                record = {'id': 'persisted', 'timestamp': 1, 'threat_class': 'scan'}
                first.save('alerts', record)
                first.close()
                second = Store()
                engine = Engine(second)
                self.assertEqual(list(engine.alerts), [record])
                second.close()

    def test_live_log_to_authenticated_api_and_websocket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root/'credentials.json'
            credentials.write_text(json.dumps(make_credentials('analyst', 'test-only-long-passphrase')))
            log = root/'events.log'
            env = {'VEIL_DB': str(root/'live.sqlite'), 'VEIL_AUTH_FILE': str(credentials),
                   'VEIL_LOG': str(log), 'DATABASE_URL': ''}
            with patch.dict(os.environ, env), TestClient(app, base_url='http://127.0.0.1:8000') as client:
                headers = {'origin': 'http://127.0.0.1:8000'}
                login = client.post('/api/auth/login', json={'username': 'analyst',
                                    'password': 'test-only-long-passphrase'}, headers=headers)
                self.assertEqual(login.status_code, 200)
                headers['x-csrf-token'] = login.json()['csrf']
                self.assertEqual(client.post('/api/replay', headers=headers).status_code, 409)
                ts = time.time()
                events = [{'kind': 'packet', 'ts': ts+i*.001, 'uid': str(i),
                           'src': '192.0.2.1', 'dst': '10.77.0.20', 'length': 60,
                           'dport': 8100+i, 'sport': 42000+i, 'syn': True, 'proto': 'tcp'}
                          for i in range(40)]
                # Invalid records must not kill the follower. Last valid row is partial.
                text = '\n'.join(json.dumps(e) for e in events)
                log.write_text('not-json\n[]\n'+text[:-3])
                deadline = time.monotonic()+8
                while time.monotonic()<deadline:
                    state=client.get('/api/state').json()
                    if state['metrics']['packets']==39: break
                    time.sleep(.05)
                self.assertEqual(state['metrics']['packets'],39)
                with log.open('a') as stream: stream.write(text[-3:]+'\n')
                while time.monotonic()<deadline:
                    state=client.get('/api/state').json()
                    if state['alerts']: break
                    time.sleep(.05)
                self.assertEqual(state['metrics']['packets'],40)
                self.assertGreaterEqual(state['metrics']['parse_errors'],2)
                alert=next(a for a in state['alerts'] if a['threat_class']=='scan')
                self.assertEqual(alert['source'],'live')
                self.assertTrue(alert['shap_explanation']['additivity_verified'])
                with client.websocket_connect('ws://127.0.0.1:8000/ws?view=detections', headers=headers) as ws:
                    self.assertEqual(ws.receive_json()['alerts'][0]['id'],alert['id'])
                exported=client.get('/api/alerts/export').text
                self.assertIn(alert['id'],exported)
