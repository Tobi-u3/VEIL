"""Single-operator authentication. Credentials on disk; revocable sessions in memory."""
import hashlib,hmac,json,os,secrets,time
from pathlib import Path
from threading import RLock

ROOT=Path(__file__).resolve().parents[1]
def credential_path():return Path(os.getenv('VEIL_AUTH_FILE',str(ROOT/'data/credentials.json')))
def password_hash(password,salt):
    return hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=131072,r=8,p=1,maxmem=256*1024*1024).hex()
def make_credentials(username,password):
    if not 1<=len(username)<=64 or not username.strip():raise ValueError('Username must contain 1–64 characters')
    if not 15<=len(password)<=128:raise ValueError('Use a password of 15–128 characters')
    salt=secrets.token_hex(16)
    return dict(username=username.strip(),salt=salt,password_hash=password_hash(password,salt))

class Auth:
    def __init__(self):
        path=credential_path()
        self.credentials=json.loads(path.read_text()) if path.exists() else None
        self.sessions={};self.attempts={};self.lock=RLock()
        self.origin=os.getenv('VEIL_PUBLIC_ORIGIN','http://127.0.0.1:8000').rstrip('/')
        from urllib.parse import urlsplit
        parsed=urlsplit(self.origin)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:raise ValueError('VEIL_PUBLIC_ORIGIN must be an origin')
        if parsed.scheme!='https' and parsed.hostname not in ('127.0.0.1','localhost','[::1]','::1'):raise ValueError('Remote analyst access requires HTTPS')
        self.secure=parsed.scheme=='https'
        self.origins={self.origin}
        if not self.secure:self.origins|={'http://localhost:8000','http://127.0.0.1:8000','http://localhost:5173','http://127.0.0.1:5173'}
        self.hosts={urlsplit(o).netloc for o in self.origins}
    def login(self,username,password,peer):
        now=time.monotonic()
        with self.lock:
            self.attempts={k:v for k,v in self.attempts.items() if now-v[0]<900}
            keys=['peer:'+peer,'account'] # One local operator account; bounded state.
            if any(self.attempts.get(k,(0,0))[1]>=10 for k in keys):return None,429
            if len(self.attempts)>2048:return None,429
            for k in keys:
                first,n=self.attempts.get(k,(now,0));self.attempts[k]=(first,n+1)
        if not self.credentials:return None,503
        c=self.credentials
        valid=hmac.compare_digest(password_hash(password,c['salt']),c['password_hash'])
        valid &= hmac.compare_digest(username.encode(),c['username'].encode())
        if not valid:return None,401
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
        with self.lock:
            self.sessions={k:v for k,v in self.sessions.items() if now-v['last']<1800 and now<v['expires']}
            if len(self.sessions)>=32:self.sessions.pop(next(iter(self.sessions)))
            self.sessions[self.key(token)]={'username':c['username'],'csrf':csrf,'last':now,'expires':now+8*3600}
        return (token,{'username':c['username'],'csrf':csrf}),200
    @staticmethod
    def key(token):return hashlib.sha256(token.encode()).hexdigest()
    def session(self,token,touch=True):
        if not token:return None
        now=time.monotonic()
        with self.lock:
            key=self.key(token);s=self.sessions.get(key)
            if not s:return None
            if now>=s['expires'] or now-s['last']>=1800:
                self.sessions.pop(key,None);return None
            if touch:s['last']=now
            return s.copy()
    def revoke(self,token):
        with self.lock:self.sessions.pop(self.key(token or ''),None)
