"""Export unreviewed SQLite feature windows for offline analyst labelling."""
import argparse
import csv
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.features import FEATURES,FEATURE_SCHEMA

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=ROOT/'data/veil.sqlite')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', choices=['live','replay','all'], default='live')
    args = parser.parse_args()
    if args.output.resolve()==args.db.resolve(): parser.error('Output must not overwrite the database')
    if args.output.exists(): parser.error('Output already exists; choose a new filename')
    count=0
    with sqlite3.connect(args.db.resolve().as_uri()+'?mode=ro',uri=True) as database:
        with args.output.open('x',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['timestamp','src','dst','source','feature_schema']+FEATURES)
            writer.writeheader()
            for body, in database.execute('SELECT body FROM windows ORDER BY ts'):
                record=json.loads(body)
                if args.source!='all' and record.get('source')!=args.source:continue
                writer.writerow({**{k:record.get(k,'') for k in ['timestamp','src','dst','source']},
                                 'feature_schema':record.get('feature_schema','legacy'), **{k:record['features'][k] for k in FEATURES}})
                count+=1
    print(f'Exported {count} unreviewed windows. Review and filter verified benign rows before training.')
