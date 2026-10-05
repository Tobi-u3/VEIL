"""Wait for this exact analysis, verify revision, export every unresolved issue page."""
import json, os, time, urllib.parse, urllib.request
from pathlib import Path
root = Path(os.environ['BL_REPORTS'])
props = dict(line.split('=',1) for line in (root/'sonar-work/report-task.txt').read_text().splitlines() if '=' in line)
base = os.environ['SONAR_HOST_URL'].rstrip('/')
def api(path, **params):
    req = urllib.request.Request(base + path + '?' + urllib.parse.urlencode(params), headers={'Authorization':'Bearer '+os.environ['SONAR_API_TOKEN']})
    with urllib.request.urlopen(req, timeout=30) as r:return json.load(r)
deadline=time.monotonic()+600
while True:
    task=api('/api/ce/task',id=props['ceTaskId'])['task']
    if task['status']=='SUCCESS':break
    if task['status'] in ('FAILED','CANCELED'):raise SystemExit('Sonar processing failed')
    if time.monotonic()>deadline:raise SystemExit('Sonar processing timeout')
    time.sleep(3)
analysis=api('/api/project_analyses/search',project=os.environ['SONAR_PROJECT_KEY'],ps=1)['analyses']
if not analysis or analysis[0]['key']!=task['analysisId'] or analysis[0].get('revision')!=os.environ['GITHUB_SHA']:
    raise SystemExit('Sonar current analysis does not match this commit. Avoid other scans of project veil during CI.')
issues=[];page=1
while True:
    data=api('/api/issues/search',componentKeys=os.environ['SONAR_PROJECT_KEY'],resolved='false',p=page,ps=500)
    total=data.get('paging',{}).get('total',data.get('total'))
    if total is None:raise SystemExit('Missing Sonar pagination total')
    issues.extend(data['issues'])
    if len(issues)>=total:break
    if not data['issues']:raise SystemExit('Incomplete Sonar export')
    page+=1
(root/'sonar.json').write_text(json.dumps({'issues':issues,'total':total}))
print(f'Exported {len(issues)} Sonar entries for {os.environ["GITHUB_SHA"]}')
