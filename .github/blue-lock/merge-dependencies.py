"""Merge independent npm-audit and pip-audit evidence into Dependency-Check input."""
import json, sys
from pathlib import Path

def merge(frontend, npm, python):
    if not isinstance(frontend.get('dependencies'), list):
        raise ValueError('Invalid Dependency-Check report')
    packages=npm.get('vulnerabilities')
    if not isinstance(packages,dict) or not isinstance(npm.get('metadata'),dict):
        raise ValueError('Incomplete npm audit JSON')
    pydeps=python.get('dependencies')
    if not isinstance(pydeps,list) or not pydeps:
        raise ValueError('Missing or empty Python dependency audit')
    added=[]
    severity_map={'critical':'CRITICAL','high':'HIGH','moderate':'MEDIUM','medium':'MEDIUM','low':'LOW','info':'INFO'}
    for name,v in packages.items():
        sev=severity_map.get(str(v.get('severity','')).lower())
        if not sev: raise ValueError(f'Unknown npm severity for {name}')
        advisories=[x for x in v.get('via',[]) if isinstance(x,dict)]
        ids=', '.join(str(x.get('source') or x.get('name') or 'advisory') for x in advisories)
        titles='; '.join(str(x.get('title') or x.get('name') or '') for x in advisories)
        urls=' '.join(str(x.get('url')) for x in advisories if x.get('url'))
        directness='direct' if v.get('isDirect') else 'transitive'
        detail=f"npm audit {sev}; {directness} dependency; range {v.get('range','unknown')}; advisories {ids}; {titles}; {urls}; fixAvailable={v.get('fixAvailable',False)}"
        added.append({'fileName':f'frontend/package-lock.json: {name}', 'vulnerabilities':[{'name':f'npm audit: {name}', 'severity':sev, 'description':detail}]})
    py_count=0
    for d in pydeps:
        if d.get('skip_reason'): raise ValueError('Python audit skipped a dependency: '+d.get('name','unknown'))
        if not d.get('name') or not d.get('version') or not isinstance(d.get('vulns'),list):
            raise ValueError('Incomplete Python dependency audit')
        py_count+=1; vulns=[]
        for v in d['vulns']:
            if not v.get('id'): raise ValueError('Python advisory missing ID')
            vulns.append({'name':v['id'],'severity':'HIGH','description':
                'pip-audit advisory; HIGH is a conservative local policy because this output has no CVSS severity. '+
                v.get('description','')+' Fix versions: '+', '.join(v.get('fix_versions',[]))})
        added.append({'fileName':f"requirements.txt: {d['name']}=={d['version']}",'vulnerabilities':vulns})
    metadata={**(frontend.get('blueLockAdditionalAudits') or {}),
      'npmAudit':{'packages':len(packages),'findings':sum(len(x['vulnerabilities']) for x in added[:len(packages)])},
      'pipAudit':{'packages':py_count,'severityPolicy':'HIGH fallback; pip-audit output has no CVSS severity'}}
    return {**frontend,'dependencies':frontend['dependencies']+added,'blueLockAdditionalAudits':metadata}

if __name__=='__main__':
    root=Path(sys.argv[1])
    combined=merge(json.loads((root/'dependency-check-report.json').read_text()),
      json.loads((root/'npm-audit.json').read_text()),json.loads((root/'pip-audit.json').read_text()))
    (root/'dependency-check-report.json').write_text(json.dumps(combined))
    print('Dependency-Check, npm audit and pip-audit evidence merged.')
