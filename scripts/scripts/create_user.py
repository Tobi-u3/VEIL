#!/usr/bin/env python3
"""Run locally before starting VEIL. No default password or public registration."""
import getpass,json,os,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.auth import make_credentials,credential_path
if __name__=='__main__':
    path=credential_path()
    if path.exists() and input('Replace the operator account? Restart VEIL to revoke existing sessions. Type REPLACE: ')!='REPLACE':sys.exit('Cancelled')
    username=input('Analyst username: ').strip()
    password=getpass.getpass('Password (15–128 characters): ')
    if password!=getpass.getpass('Confirm password: '):sys.exit('Passwords do not match')
    try:record=make_credentials(username,password)
    except ValueError as exc:sys.exit(str(exc))
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd,'w') as f:json.dump(record,f)
    os.chmod(temp,0o600);os.replace(temp,path)
    print('Operator account saved. Start or restart VEIL, then sign in.')
