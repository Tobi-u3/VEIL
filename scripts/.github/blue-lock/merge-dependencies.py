"""Adapt pip-audit findings into Blue Lock's existing Dependency-Check input."""
import json, sys
from pathlib import Path
def merge(frontend, python):
    if not isinstance(frontend.get('dependencies'),list):raise ValueError('Invalid Dependency-Check report')
    deps=python.get('dependencies')
    if not isinstance(deps,list) or not deps:raise ValueError('Missing or empty Python dependency audit')
    added=[]
    for d in deps:
        if d.get('skip_reason'):raise ValueError('Python audit skipped a dependency: '+d.get('name','unknown'))
        if not d.get('name') or not d.get('version') or not isinstance(d.get('vulns'),list):raise ValueError('Incomplete Python dependency audit')
        vulns=[]
        for v in d['vulns']:
            if not v.get('id'):raise ValueError('Python advisory missing ID')
            vulns.append({'name':v['id'],'severity':'HIGH','description':
                'pip-audit advisory; HIGH is a conservative local policy because this output has no CVSS severity. '+
                v.get('description','')+' Fix versions: '+', '.join(v.get('fix_versions',[]))})
        added.append({'fileName':f"requirements.txt: {d['name']}=={d['version']}",'vulnerabilities':vulns})
    return {**frontend,'dependencies':frontend['dependencies']+added,'blueLockPythonAudit':{'scanner':'pip-audit','packages':len(added),'severityPolicy':'HIGH fallback; no CVSS supplied'}}
if __name__=='__main__':
    root=Path(sys.argv[1])
    combined=merge(json.loads((root/'dependency-check-report.json').read_text()),json.loads((root/'pip-audit.json').read_text()))
    (root/'dependency-check-report.json').write_text(json.dumps(combined))
    print('Frontend and Python dependency evidence merged.')
