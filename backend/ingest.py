"""JSON-lines tail handles rotation, partial lines, and truncation."""
import asyncio,json,os,time
from pathlib import Path

class Tail:
    def __init__(self,path):self.path=Path(path);self.inode=None;self.offset=0;self.partial=b'';self.errors=0
    def read(self):
        try:st=self.path.stat()
        except FileNotFoundError:return []
        if st.st_ino!=self.inode or st.st_size<self.offset:
            self.inode=st.st_ino;self.offset=0;self.partial=b''
        with self.path.open('rb') as f:
            f.seek(self.offset);data=f.read(2*1024*1024);self.offset=f.tell()
        lines=(self.partial+data).split(b'\n');self.partial=lines.pop()
        if len(self.partial)>1024*1024:raise ValueError('Oversized incomplete log record')
        out=[]
        for line in lines:
            if not line.strip() or line.startswith(b'#'):continue
            try:out.append(json.loads(line))
            except (ValueError,UnicodeDecodeError):self.errors+=1
        return out

async def follow(engine,path):
    tail=Tail(path);engine.status.update(mode='live',input=str(path))
    while True:
        try:
            for e in tail.read():
                try:
                    e['source']='live';engine.ingest(e)
                except (ValueError,TypeError,KeyError):engine.errors+=1
            engine.errors+=tail.errors;tail.errors=0
            engine.flush(time.time())
        except (ValueError,OSError) as ex:
            engine.errors+=1;engine.status['last_error']=str(ex)
        await asyncio.sleep(.1)

async def replay(engine,path,speed=1):
    engine.status.update(mode='replay',input=Path(path).name)
    previous=None
    with open(path) as f:
        for line in f:
            if not line.strip():continue
            e=json.loads(line)
            if previous is not None:await asyncio.sleep(max(0,(e['ts']-previous)/speed))
            previous=e['ts'];e['source']='replay';engine.ingest(e)
    engine.flush(engine.last_ts+2,force=True)
    engine.status['mode']='replay complete'
