import asyncio,os,json,hmac
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI,WebSocket,WebSocketDisconnect,HTTPException,Request,Query
from fastapi.responses import FileResponse,Response,JSONResponse
from pydantic import BaseModel,Field
from .auth import Auth
from fastapi.staticfiles import StaticFiles
from .engine import Engine
from .store import Store
from .ingest import follow,replay
ROOT=Path(__file__).resolve().parents[1]
engine=None;task=None
@asynccontextmanager
async def lifespan(app):
    global engine,task
    task=None
    app.state.auth=Auth()
    app.state.login_lock=asyncio.Lock()
    store=Store();engine=Engine(store)
    logfile=os.getenv('VEIL_LOG')
    if logfile:task=asyncio.create_task(follow(engine,logfile))
    yield
    if task:
        task.cancel()
        try:await task
        except asyncio.CancelledError:pass
    store.close()
app=FastAPI(title='VEIL passive threat intelligence',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)

@app.middleware('http')
async def protect(request:Request,call_next):
    auth=app.state.auth
    if request.headers.get('host') not in auth.hosts:
        return JSONResponse({'detail':'Untrusted host'},status_code=400)
    session=auth.session(request.cookies.get('veil_session'),touch=request.url.path!='/api/auth/me')
    if request.url.path.startswith('/api/') and request.url.path not in ('/api/auth/login','/api/health'):
        if not session:return JSONResponse({'detail':'Sign in required'},status_code=401,headers={'Cache-Control':'no-store'})
    if request.method not in ('GET','HEAD','OPTIONS'):
        if request.headers.get('origin') not in auth.origins:
            return JSONResponse({'detail':'Untrusted origin'},status_code=403)
        if request.url.path!='/api/auth/login' and (not session or not hmac.compare_digest(request.headers.get('x-csrf-token',''),session['csrf'])):
            return JSONResponse({'detail':'Invalid CSRF token'},status_code=403)
    request.state.session=session
    response=await call_next(request)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
      'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"})
    if auth.secure:response.headers['Strict-Transport-Security']='max-age=31536000'
    return response

class Login(BaseModel):
    username:str=Field(min_length=1,max_length=64)
    password:str=Field(min_length=1,max_length=128)

@app.post('/api/auth/login')
async def login(body:Login,request:Request):
    # Serialize memory-hard password verification; never block the event loop.
    if app.state.login_lock.locked():raise HTTPException(429,'Please retry shortly')
    async with app.state.login_lock:
        result,status=await asyncio.to_thread(app.state.auth.login,body.username,body.password,request.client.host)
    if status!=200:raise HTTPException(status,{401:'Invalid username or password',429:'Too many attempts. Try again in 15 minutes.',503:'Operator account is not configured. Run scripts/create_user.py locally.'}[status])
    token,public=result
    app.state.auth.revoke(request.cookies.get('veil_session'))
    response=JSONResponse(public)
    response.set_cookie('veil_session',token,httponly=True,secure=app.state.auth.secure,samesite='strict',max_age=8*3600,path='/')
    return response

@app.get('/api/auth/me')
def me(request:Request):
    return {k:request.state.session[k] for k in ('username','csrf')}

@app.post('/api/auth/logout')
def logout(request:Request):
    app.state.auth.revoke(request.cookies.get('veil_session'))
    response=JSONResponse({'ok':True});response.delete_cookie('veil_session',path='/');return response

@app.get('/api/state')
def state():return engine.snapshot()
@app.get('/api/packets')
def packets(before:int|None=None,limit:int=Query(100,ge=1,le=200),q:str=Query('',max_length=200),scope:str='all'):
    return engine.traffic.page(before,limit,q,scope)
@app.get('/api/packets/export')
def packet_export():
    return Response('\n'.join(json.dumps(x) for x in engine.traffic.packets),media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="veil-recent-packets.jsonl"'})
@app.get('/api/health')
def health():return {'ok':True}
@app.get('/api/alerts/export')
def export():
    return Response('\n'.join(json.dumps(x) for x in engine.store.alerts()),media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="veil-alerts.jsonl"'})
@app.post('/api/replay')
async def start_replay(request:Request):
    global task,engine
    if os.getenv('VEIL_LOG'):raise HTTPException(409,'Replay disabled while live ingest is configured')
    if task and not task.done():raise HTTPException(409,'Replay already running')
    path=ROOT/'data/demo.jsonl'
    if not path.exists():raise HTTPException(409,'Generate demo first: python scripts/make_demo.py')
    engine=Engine(engine.store)
    task=asyncio.create_task(replay(engine,path,1))
    return {'started':True,'source':'synthetic metadata replay; no packets sent'}
@app.websocket('/ws')
async def websocket(ws:WebSocket):
    auth=app.state.auth
    if ws.headers.get('host') not in auth.hosts or ws.headers.get('origin') not in auth.origins or not auth.session(ws.cookies.get('veil_session'),touch=False):
        await ws.close(code=1008);return
    view=ws.query_params.get("view","all")
    if view not in ("all","packets","graph","detections","system"):view="packets"
    await ws.accept()
    try:
        while True:
            if not auth.session(ws.cookies.get('veil_session'),touch=False):
                await ws.close(code=1008);return
            await ws.send_json(engine.snapshot(view));await asyncio.sleep(.5)
    except (WebSocketDisconnect,RuntimeError):pass
if (ROOT/'frontend/dist/assets').exists():
    app.mount('/assets',StaticFiles(directory=ROOT/'frontend/dist/assets'),name='assets')
@app.get('/')
def index():
    path=ROOT/'frontend/dist/index.html'
    if path.exists():return FileResponse(path)
    return {'message':'Build frontend: cd frontend && npm ci && npm run build','api':'/docs'}
