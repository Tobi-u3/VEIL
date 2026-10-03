import os,json,sqlite3
from pathlib import Path
class Store:
    def __init__(self):
        url=os.getenv('DATABASE_URL')
        self.pg=bool(url)
        if self.pg:
            import psycopg
            self.db=psycopg.connect(url,autocommit=True)
        else:
            p=Path(os.getenv('VEIL_DB','data/veil.sqlite'));p.parent.mkdir(parents=True,exist_ok=True)
            self.db=sqlite3.connect(p,check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, ts DOUBLE PRECISION, body TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS windows (id TEXT PRIMARY KEY, ts DOUBLE PRECISION, body TEXT)')
        self.db.commit()
        self.count=0
    def save(self,table,record):
        assert table in ('alerts','windows')
        ph='%s' if self.pg else '?'
        self.db.execute(f'INSERT INTO {table} (id,ts,body) VALUES ({ph},{ph},{ph}) ON CONFLICT (id) DO NOTHING',
                        (record['id'],record['timestamp'],json.dumps(record,allow_nan=False)))
        self.count+=1
        if self.count%100==0:
            # Bounded local history: keep latest 10,000 records per table.
            for t in ('alerts','windows'):
                self.db.execute(f'DELETE FROM {t} WHERE id NOT IN (SELECT id FROM {t} ORDER BY ts DESC LIMIT 10000)')
        self.db.commit()
    def alerts(self):
        return [json.loads(r[0]) for r in self.db.execute('SELECT body FROM alerts ORDER BY ts DESC LIMIT 100').fetchall()]
    def close(self): self.db.close()
