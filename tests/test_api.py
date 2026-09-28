import unittest,tempfile,os,json,time
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from backend.app import app
from backend.auth import make_credentials,Auth

class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.credential=make_credentials('analyst','test-only-long-passphrase')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();d=Path(self.tmp.name)
        (d/'credentials.json').write_text(json.dumps(self.credential))
        self.env=patch.dict(os.environ,{'VEIL_DB':str(d/'api.sqlite'),'VEIL_AUTH_FILE':str(d/'credentials.json')});self.env.start()
        self.c=TestClient(app,base_url='http://127.0.0.1:8000');self.c.__enter__()
        self.headers={'origin':'http://127.0.0.1:8000'}
    def tearDown(self):self.c.__exit__(None,None,None);self.env.stop();self.tmp.cleanup()
    def login(self):
        r=self.c.post('/api/auth/login',json={'username':'analyst','password':'test-only-long-passphrase'},headers=self.headers)
        self.assertEqual(r.status_code,200);self.headers['x-csrf-token']=r.json()['csrf'];return r
    def test_private_endpoints_and_socket(self):
        for path in ('/api/state','/api/packets','/api/packets/export','/api/alerts/export','/api/auth/me'):
            self.assertEqual(self.c.get(path).status_code,401,path)
        self.assertEqual(self.c.post('/api/replay',headers=self.headers).status_code,401)
        with self.assertRaises(WebSocketDisconnect):
            with self.c.websocket_connect('ws://127.0.0.1:8000/ws',headers=self.headers):pass
        self.assertEqual(self.c.get('/api/health').json(),{'ok':True})
        self.assertEqual(self.c.get('/docs').status_code,404)
    def test_login_csrf_logout_and_replay(self):
        r=self.login();cookie=r.headers['set-cookie'];self.assertIn('HttpOnly',cookie);self.assertIn('SameSite=strict',cookie)
        self.assertEqual(self.c.get('/api/auth/me').json()['username'],'analyst')
        self.assertEqual(self.c.get('/api/packets?limit=201').status_code,422)
        self.assertEqual(self.c.get('/api/packets/export').status_code,200)
        self.assertEqual(self.c.post('/api/replay',headers={'origin':self.headers['origin']}).status_code,403)
        self.assertEqual(self.c.post('/api/replay',headers={**self.headers,'origin':'https://evil.example'}).status_code,403)
        with self.c.websocket_connect('ws://127.0.0.1:8000/ws',headers=self.headers) as ws:
            self.assertEqual(ws.receive_json()['status']['mode'],'idle')
            self.assertEqual(self.c.post('/api/auth/logout',headers=self.headers).status_code,200)
            with self.assertRaises(WebSocketDisconnect):ws.receive_json()
        self.assertEqual(self.c.get('/api/state').status_code,401)
        self.login();self.assertEqual(self.c.post('/api/replay',headers=self.headers).status_code,200)
        self.assertEqual(self.c.post('/api/replay',headers=self.headers).status_code,409)
    def test_expiry_and_host(self):
        self.login()
        for session in app.state.auth.sessions.values():session['expires']=time.monotonic()-1
        self.assertEqual(self.c.get('/api/state').status_code,401)
        self.assertEqual(self.c.get('/api/state',headers={'host':'evil.example'}).status_code,400)
    def test_invalid_and_throttle(self):
        for _ in range(10):
            r=self.c.post('/api/auth/login',json={'username':'unknown','password':'wrong'},headers=self.headers)
            self.assertEqual(r.status_code,401)
        self.assertEqual(self.c.post('/api/auth/login',json={'username':'analyst','password':'test-only-long-passphrase'},headers=self.headers).status_code,429)
    def test_https_and_fail_closed(self):
        with patch.dict(os.environ,{'VEIL_PUBLIC_ORIGIN':'http://remote.example'}):
            with self.assertRaises(ValueError):Auth()
        with patch.dict(os.environ,{'VEIL_PUBLIC_ORIGIN':'https://veil.example'}):
            auth=Auth();self.assertTrue(auth.secure)
        app.state.auth.credentials=None
        self.assertEqual(self.c.post('/api/auth/login',json={'username':'analyst','password':'anything'},headers=self.headers).status_code,503)
