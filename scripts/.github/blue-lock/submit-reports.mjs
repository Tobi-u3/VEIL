// Run on a trusted CI runner after all scanners complete successfully.
import { readFileSync } from "node:fs";
const [repoId, commit, branch, sonarPath, secretsPath, dependenciesPath] =
  process.argv.slice(2);
if (!repoId || !/^[a-f0-9]{40}$/i.test(commit || "") || !dependenciesPath)
  throw Error(
    "Usage: node scripts/submit-reports.mjs REPO_ID COMMIT BRANCH sonar.json trufflehog.jsonl dependency-check-report.json",
  );
const base = process.env.BLUE_LOCK_URL || "http://127.0.0.1:3000";
async function api(path, body) {
  const r = await fetch(base + "/api" + path, {
    signal: AbortSignal.timeout(30000),
    method: body ? "POST" : "GET",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const d = await r.json();
  if (!r.ok) throw Error(d.error);
  return d;
}
let token = process.env.BLUE_LOCK_TOKEN;
if (!token) {
  if (!process.env.BLUE_LOCK_EMAIL || !process.env.BLUE_LOCK_PASSWORD)
    throw Error(
      "Set BLUE_LOCK_TOKEN or BLUE_LOCK_EMAIL and BLUE_LOCK_PASSWORD in your CI secret store",
    );
  token = (
    await api("/auth/login", {
      email: process.env.BLUE_LOCK_EMAIL,
      password: process.env.BLUE_LOCK_PASSWORD,
    })
  ).token;
}
const session = await api("/sessions", { repoId, commit, branch });
for (const [tool, path] of [
  ["sonar", sonarPath],
  ["trufflehog", secretsPath],
  ["dependency-check", dependenciesPath],
])
  await api(`/sessions/${session.id}/reports/${tool}`, {
    report: readFileSync(path, "utf8"),
  });
const deadline = Date.now() + 120000;
while (Date.now() < deadline) {
  const gate = await api(`/sessions/${session.id}/gate`);
  if (gate.status === "completed") {
    console.log(JSON.stringify(gate, null, 2));
    process.exit(gate.allowed ? 0 : 1);
  }
  await new Promise((r) => setTimeout(r, 1000));
}
throw Error("Timed out waiting for gate. Deployment must stay blocked.");
