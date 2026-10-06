#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?Runner temp directory missing}"
: "${GITHUB_RUN_ID:?GitHub run ID missing}"
: "${GITHUB_SHA:?Commit missing}"
: "${SONAR_TOKEN:?Set SONAR_TOKEN in GitHub Actions secrets}"
: "${SONAR_API_TOKEN:?Set a Sonar user token with Browse permission in SONAR_API_TOKEN}"
export BL_REPORTS="$RUNNER_TEMP/blue-lock-$GITHUB_RUN_ID"
rm -rf -- "$BL_REPORTS"
mkdir -p "$BL_REPORTS/source" "$BL_REPORTS/sonar-work" "$BL_REPORTS/sonar-cache"
git archive "$GITHUB_SHA" | tar -x -C "$BL_REPORTS/source"
# Never persist detected credential values in uploaded GitHub artifacts.
docker run --rm -v "$PWD:/repo:ro" \
  trufflesecurity/trufflehog:3.97.9 git file:///repo \
  --branch "$GITHUB_SHA" --json --no-verification > "$BL_REPORTS/trufflehog.jsonl"
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -e SONAR_TOKEN -e SONAR_HOST_URL -e SONAR_USER_HOME=/sonar-cache \
  -v "$BL_REPORTS/source:/usr/src:ro" -v "$BL_REPORTS/sonar-work:/work" \
  -v "$BL_REPORTS/sonar-cache:/sonar-cache" \
  sonarsource/sonar-scanner-cli:latest \
  "-Dsonar.projectKey=$SONAR_PROJECT_KEY" -Dsonar.sources=. \
  -Dsonar.working.directory=/work -Dsonar.scm.disabled=true \
  "-Dsonar.scm.revision=$GITHUB_SHA" \
  '-Dsonar.exclusions=**/node_modules/**,**/.venv/**,**/venv/**,**/dist/**,**/__pycache__/**'
python3 .github/blue-lock/export-sonar.py
# Install the frontend lockfile without running lifecycle scripts.
docker run --rm --user "$(id -u):$(id -g)" -e npm_config_cache=/tmp/npm \
  -v "$BL_REPORTS/source/frontend:/app" -w /app node:24-bookworm-slim \
  npm ci --ignore-scripts --no-audit --no-fund
nvd_args=(--nvdDatafeed 'https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz')
if [[ -n "${NVD_API_KEY:-}" ]]; then nvd_args=(--nvdApiKeyEnvironmentVariable NVD_API_KEY); fi
docker run --rm -e NVD_API_KEY \
  -v "$BL_REPORTS/source:/src:ro" -v "$BL_REPORTS:/report" \
  -v blue-lock-dependency-data:/usr/share/dependency-check/data \
  owasp/dependency-check:latest --project VEIL-frontend --scan /src/frontend \
  --format JSON --out /report "${nvd_args[@]}"
# Resolve and audit Python direct and transitive dependencies in an isolated container.
# A finding exit (1) is accepted only if a complete valid report exists; errors block.
docker run --rm --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/cache -e PIP_ONLY_BINARY=:all: -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
  -v "$BL_REPORTS/source/requirements.txt:/requirements.txt:ro" \
  -v "$BL_REPORTS:/report" python:3.14-slim sh -c '
    python -m venv /tmp/audit && /tmp/audit/bin/pip install --quiet pip-audit &&
    { /tmp/audit/bin/pip-audit -r /requirements.txt --format json --desc on \
        --progress-spinner off --output /report/pip-audit.json; rc=$?;
      [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; }
  '
python3 .github/blue-lock/merge-dependencies.py "$BL_REPORTS"
