"""Combine TruffleHog and redacted Gitleaks findings in Blue Lock's JSONL format."""
import json,sys
from pathlib import Path

def merge(trufflehog, gitleaks):
    rows=[json.loads(line) for line in trufflehog.splitlines() if line.strip()]
    if not isinstance(gitleaks,list): raise ValueError('Invalid Gitleaks JSON report')
    for finding in gitleaks:
        if not finding.get('RuleID') or not finding.get('File') or not finding.get('StartLine'):
            raise ValueError('Incomplete Gitleaks finding')
        rows.append({'DetectorName':'Gitleaks:'+str(finding['RuleID']),
          'SourceMetadata':{'Data':{'Git':{'file':finding['File'],'line':finding['StartLine']}}}})
    # Select only safe fields. Never carry Match, Secret, or Line from Gitleaks.
    return json.dumps(rows,separators=(',',':'))

if __name__=='__main__':
    root=Path(sys.argv[1])
    (root/'trufflehog-combined.json').write_text(merge(
      (root/'trufflehog.jsonl').read_text(),json.loads((root/'gitleaks.json').read_text())))
    print('TruffleHog and redacted Gitleaks reports combined.')
