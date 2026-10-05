#!/usr/bin/env bash
set -euo pipefail
for cmd in docker node python3 git curl tar; do command -v "$cmd" >/dev/null; done
node -e 'if(Number(process.versions.node.split(".")[0])<24)throw Error("Node 24+ required in runner PATH")'
docker info >/dev/null
curl --fail --silent --show-error --max-time 10 "$BLUE_LOCK_URL/api/health" >/dev/null
python3 - <<'PY'
import json,os,urllib.request
with urllib.request.urlopen(os.environ['SONAR_HOST_URL']+'/api/system/status',timeout=10) as r:
    if json.load(r)['status']!='UP':raise SystemExit('SonarQube is not ready')
PY
[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || { echo 'Checkout SHA mismatch'; exit 1; }
echo 'Runner, Docker, Blue Lock and SonarQube are ready.'
