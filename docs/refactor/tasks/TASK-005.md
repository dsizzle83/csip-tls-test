# TASK-005 — `govulncheck` + dependency audit in CI

*Status: TODO · Phase: P0 · Effort: S (≈2–3 h) · Difficulty: low · Risk: low*

## Objective
Both repos run a pinned `govulncheck` in CI on every PR plus a nightly schedule, with a
triage allowlist for accepted findings; the first run's findings are triaged and recorded
so TASK-006 (dependency refresh) has an authoritative worklist.

## Background
Verified dependency state (go.mod, both repos):
- `lexa-hub`: `go 1.21`; `golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550`
  (October **2019**), `golang.org/x/net v0.8.0`, `golang.org/x/sys v0.6.0`,
  `github.com/eclipse/paho.mqtt.golang v1.4.3`, `github.com/lorenzodonini/ocpp-go v0.19.0`,
  `github.com/simonvetter/modbus v1.6.4`, `github.com/grandcat/zeroconf v1.0.0`.
- `csip-tls-test`: `go 1.21`; same 2019 `x/crypto`,
  `x/net v0.0.0-20200114155413-6afb5195e5aa` (January **2020**),
  `x/sys v0.0.0-20220804214406-8e32c043e418`; **no paho** (the bench repo does not use
  MQTT client libraries; `cmd/mqttproxy` is a raw TCP proxy).
- Desktop toolchain: `go1.26.4` installed; `govulncheck` is NOT installed
  (`~/go/bin` has only `gopls`).

`govulncheck` reports only vulnerabilities in *reachable* code (call-graph analysis), so
expect a short list despite the ancient `x/crypto`. It has no built-in allowlist, so the
standard pattern is a wrapper script that runs `govulncheck -format json`, extracts
finding OSV IDs, and filters against a committed allowlist file.

This task does **not** upgrade anything — that is TASK-006. Ordering matters: scan first
(worklist), refresh second, then the scan turns blocking.

## Why this task exists
Review §10.4 / D7: "no CI/scanning … reads as 'no vulnerability management process'" in
due diligence. Cheap to fix; must exist before the dependency refresh so improvement is
measurable.

## Architecture review sections
D7, §10.4, §14 item 8 (shared with TASK-006). Roadmap: 03 P0; 05 §7.

## Prerequisites
TASK-002, TASK-003 (workflows exist to extend).

## Files
- **Read first:** both `go.mod`/`go.sum`; both `.github/workflows/ci.yml`.
- **Modify:** both workflows (new job `vulncheck`).
- **Create:** `scripts/ci/govulncheck.sh` + `scripts/ci/vuln-allowlist.txt` in **each**
  repo (csip-tls-test path `scripts/ci/`; lexa-hub create the same layout —
  `scripts/ci/` there too).

## Blast radius
None at runtime. CI + scripts.

## Implementation strategy
One wrapper script per repo (identical content): install a **pinned** govulncheck
(`go install golang.org/x/vuln/cmd/govulncheck@v1.1.4` — check for the latest tag when
implementing and pin that; never `@latest` in CI), run it in JSON mode over `./...`,
filter OSV IDs against the allowlist, exit 1 on any un-allowlisted finding. Start
**non-blocking** (job runs, failures reported but not required) until TASK-006 lands;
then flip to required.

## Detailed steps
1. Write `scripts/ci/govulncheck.sh` (csip-tls-test first):
   - Pins the version in a `GOVULNCHECK_VERSION` variable at the top.
   - Runs `govulncheck -format json ./...`, collects `.osv.id` of findings with
     call-stack evidence (`finding.trace` non-empty ⇒ reachable), dedupes.
   - Reads `scripts/ci/vuln-allowlist.txt` (format: `GO-YYYY-NNNN  <one-line reason>
     <date> <owner>`; `#` comments).
   - Prints a table: ID, module, allowlisted?, reason. Exits 1 iff any reachable finding
     is not allowlisted.
   - cgo note: govulncheck needs the package to *build*; run it with the same env as the
     repo's cgo CI job (wolfSSL sysroot) OR restrict to the pure-Go package list from
     TASK-002/003 and scan the cgo pair in the cgo job. Prefer scanning everything in the
     cgo job — one env, whole module.
2. Copy the script + empty allowlist into lexa-hub (`scripts/ci/` — new directory there).
3. Add job `vulncheck` to both workflows: reuse the wolfSSL cache steps, run the script.
   `continue-on-error: true` for now, with a loud step summary. Also add
   `on: schedule: cron: '17 4 * * *'` (nightly — new CVEs appear without code changes).
4. Run both scans locally (desktop has the sysroot):
   `~/go/bin/govulncheck -format json ./...` after `go install ...@<pinned>`.
5. Triage every reachable finding: for each, either (a) note it as "fixed by TASK-006
   upgrade of <module>" in the TASK-006 worklist (do NOT allowlist), or (b) if truly
   unfixable-now, add an allowlist line with reason/date. Expected: findings cluster in
   `x/crypto`/`x/net` — category (a).
6. Record the baseline: commit the scan summary as
   `docs/refactor/VULN_BASELINE_<date>.md` (raw counts + IDs + disposition table).
7. After TASK-006 merges (not this task): remove `continue-on-error`, mark required.
   Leave a TODO in the workflow referencing TASK-006 so the flip isn't forgotten.

## Testing changes
Script sanity: seed the allowlist with a fake ID and confirm filtering works; remove it.
No Go tests.

## Documentation changes
- `docs/refactor/VULN_BASELINE_<date>.md` (new, bench repo).
- 00_MASTER_INDEX status table. One line in each CLAUDE.md Commands section is optional;
  skip if noisy.

## Common mistakes to avoid
- `@latest` in CI — scanner behavior changes under you; pin and bump deliberately.
- Failing the build on *unreachable* (module-level-only) findings — use finding traces;
  otherwise the 2019 `x/crypto` drowns the signal.
- Allowlisting findings that TASK-006 will fix — that hides the refresh's motivation;
  allowlist is for genuinely-stuck items only.
- Running govulncheck without the wolfSSL env on the full module — it fails to load
  cgo packages and silently scans less than you think. Check its "packages loaded"
  output.

## Things that must NOT change
- `go.mod`/`go.sum` in both repos — zero upgrades here (RSK-04 says paho moves alone, in
  TASK-006, campaign-gated).
- CI jobs from TASK-002/003 stay required and green.

## Acceptance criteria
- [ ] `bash scripts/ci/govulncheck.sh` runs in both repos locally and in CI.
- [ ] Version pinned; nightly schedule active.
- [ ] Every reachable finding dispositioned (TASK-006 worklist or allowlist-with-reason).
- [ ] `docs/refactor/VULN_BASELINE_<date>.md` committed.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: none
- [ ] CI wall time increase <5 min per repo

## Mayhem scenarios affected
None.

## Conformance implications
None.

## Suggested commit message
`ci(security): pinned govulncheck job + triage allowlist + vuln baseline (D7)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** govulncheck in CI (both repos) + first triage baseline
**Description:** Pinned scanner, reachable-findings-only gate, allowlist for accepted
items, nightly cron. Non-blocking until TASK-006 clears the x/crypto|x/net debt.
Paired PRs (one per repo). Rollback: delete job/scripts.

## Code review checklist
- Pin present; no `@latest`.
- Allowlist entries all have reason + date; none merely defer TASK-006 work.
- Scanner sees the whole module (cgo env) — check the run log.

## Definition of done
Acceptance criteria + regression checklist + baseline doc + status headers updated.

## Possible follow-up tasks
TASK-006 (executes the worklist; flips this job to required), TASK-047/048 (fuzzers join
the nightly security lane).
