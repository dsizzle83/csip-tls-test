# TASK-073 — Cert rotation without control interruption + reconnect-churn soak

*Status: TODO · Phase: P6 · Effort: L (≈8 h) · Difficulty: high · Risk: high*

## Objective
A staged certificate-rotation procedure exists and is exercised on the
bench: a new client cert is installed alongside the old, lexa-northbound
reconnects its TLS sessions OFF-TICK onto the new cert, verifies a clean
walk, and commits — with zero loss of control enforcement (the scheduler's
fail-closed hold covers the reconnect window). A reconnect-churn soak
(N rotations/hour for 24 h) passes with no segfault, no fd leak, no
watchdog fire. A written runbook ships.

## Background
Verified mechanics:
- TLS lifecycle: `tlsclient.Client` supports Close → re-Dial reuse
  (client.go:181-183); `WolfSSLFetcher` owns a wolfSSL ctx created once
  with the cert paths (`NewWolfSSLFetcher`, fetcher.go:22-30) and holds
  ONE keep-alive session (`ensureDialed`). Rotating the CERT requires a
  NEW wolfSSL ctx (cert loading is ctx-level) — i.e., build a new fetcher
  and swap, or add a `Reload()` that re-creates ctx+session safely.
  `Free()` mid-walk is forbidden (invariant) — the swap must happen
  between walks. Northbound holds THREE fetchers (discovery, responses,
  flow-reservation; cmd/northbound/main.go:150-190) — rotate all three.
- §8.6/RSK-07: "One misordered Free under a reconnect storm is a segfault
  in the service that talks to the utility… there's no soak test for
  reconnect churn (certificate rotation will churn it)." The soak is the
  point of this task as much as the rotation.
- Fail-closed cover: `scheduler.failClosed`
  (internal/northbound/scheduler/scheduler.go:178-246) holds
  last-known-good on failed/empty walks, with clock-regression and
  default-fallback guards; local expiry (ValidUntil discipline) bounds the
  hold. VERIFY and STATE in the runbook: during the reconnect window,
  enforcement continues from the retained ActiveControl + hub local
  expiry — a rotation must complete well inside the shortest control
  ValidUntil horizon.
- LFDI: derived from the client cert (cmd/northbound/main.go:640). A
  rotated cert for the SAME device must preserve the LFDI (same
  device identity per CSIP) — the runbook must call out that a CN/key
  change changes LFDI/SFDI and is RE-ENROLLMENT, not rotation; gridsim's
  EndDevice registration must match (csip-tls-test
  `make gen-client-cert CN=…` mechanics; certs/client-staging/ is what
  `deploy-hub-pi.sh` stages).
- Watchdogs (TASK-007/008) + cert monitor (TASK-072) provide the
  detection surface for the soak.

## Why this task exists
§8.6 / RSK-07 / 09 hard gate: "Rotation procedure without control
interruption, exercised on bench incl. reconnect-churn soak." Deferred
QA gap: "TLS rotation mid-session … addressed for real in TASK-073"
(07 §deferred).

## Architecture review sections
§8.6 · §10.5 · 08 RSK-07 · 09 Certificates · 07 deferred list ·
05 §7.

## Prerequisites
TASK-072 DONE (monitor verifies the swap). TASK-069 decision landed (the
soak must exercise the SHIPPING client path; if 069 kept both paths, soak
the chosen one and then delete the loser as planned). Bench access;
schedule the 24 h soak outside campaign windows.

## Files
- **Read first:** internal/tlsclient/fetcher.go + client.go +
  internal/wolfssl (Free ordering), cmd/northbound/main.go (fetcher
  construction + run loop post-068/070), scheduler.go failClosed,
  csip-tls-test Makefile cert targets + scripts/gen-client-cert.sh +
  certs/ layout, lexa-hub scripts/deploy-hub-pi.sh (cert staging).
- **Modify:** internal/tlsclient (safe rotation seam: `Fetcher.Reload()`
  or swap-capable holder), cmd/northbound (rotation trigger: SIGHUP or a
  watched sentinel file — decide; wire to rotate all three fetchers
  off-tick), lexa-hub deploy scripts if they must stage `certs/new/`.
- **Create:** `internal/tlsclient/reload_test.go`;
  `scripts/rotate-cert.sh` (lexa-hub — the operator procedure);
  csip-tls-test `scripts/cert-churn-soak.sh` (drives N rotations/hour via
  SSH + collects evidence); runbook `docs/` entry (lexa-hub).

## Blast radius
lexa-northbound TLS lifecycle (the exact RSK-07 danger zone) + telemetry
if it shares rotation (same cert file — include it: telemetry POSTs fail
closed harmlessly, but rotate it too for consistency). Bench soak time.
No bus schema.

## Implementation strategy
Rotation = swap-at-a-safe-point: a rotation request sets a flag; the run
loop, BETWEEN walks (and responses/FR fetchers between their operations),
builds a NEW fetcher from the new paths, performs a probe walk
(DeviceCapability GET) on it, and only on success swaps the handle and
frees the old ctx (old session Close → FreeSSL → FreeCtx, in that order,
after the last in-flight use — ownership transfer, not concurrent use).
Failure = keep old, alarm, retry policy. The soak drives this repeatedly
under FAST walk cadence, watching RSS/fd counts (/proc via SSH),
journals for wolfSSL errors, and watchdog/restart counters.

## Detailed steps
1. tlsclient: implement `NewWolfSSLFetcherFrom(cfg)` reuse + a
   `SwapHandle` holder OR fetcher `Reload(cfg)`; enforce with a mutex
   that Reload never overlaps an in-flight Get/Post (the walk loop is
   single-goroutine per fetcher post-068 — assert/document rather than
   lock if true for all three). Unit tests with a fake transport where
   possible; Free-ordering covered by an integration test on the desktop
   amd64 sysroot (`make test-integration` env, csip-tls-test).
2. Rotation trigger: sentinel-file watch is deploy-friendly
   (`/etc/lexa/certs/rotate.request` containing new paths) — decide vs
   SIGHUP, record in the runbook; implement in cmd/northbound with
   probe-then-commit per fetcher; emit certstatus (072) after commit.
3. `scripts/rotate-cert.sh` (operator side): stage new cert/key (0600,
   owner lexa — `install -m 600 -o lexa` convention), write the sentinel,
   wait for certstatus to show the new NotAfter, verify a fresh walk in
   the journal, archive the old cert. Abort path documented.
4. LFDI/identity check inside the script: parse old + new cert, compare
   derived LFDI; refuse rotation on mismatch (that is re-enrollment).
5. Bench single-rotation drill: generate cert #2 for the SAME CN
   (`make gen-client-cert CN=<current>` — confirm gridsim/CA accepts a
   reissued cert and the server still maps the LFDI), run the script,
   confirm: no gap in control enforcement (run a long export cap via the
   dashboard/gridsim during rotation; meter shows continuous compliance),
   walk resumes, certstatus updated.
6. Churn soak: `cert-churn-soak.sh` — e.g. 12 rotations/hour × 24 h
   alternating cert A/B; sample every 5 min: northbound RSS + fd count
   (`ls /proc/$PID/fd | wc -l`), restart count (`systemctl show -p
   NRestarts`), journal grep for segfault/wolfSSL errors; assert flat fd
   trend, zero restarts, zero watchdog fires. Archive CSV + summary under
   csip-tls-test docs/ (QA report pattern).
7. Post-soak: full FAST campaign to confirm the bench is healthy; if 069
   kept a legacy client path, delete it now (its own commit).

## Testing changes
- reload/ordering unit + integration tests.
- Soak evidence (CSV + report).
- Run: `make test` (hub); `make test-integration` (bench repo, desktop);
  soak script; campaign after.

## Documentation changes
- Runbook: rotation procedure, abort path, LFDI caveat, re-enrollment
  pointer (gen-client-cert flow) — 09 checklist "Re-enrollment/
  commissioning runbook" feeder.
- 08 RSK-07: mark mitigated with soak evidence link.
- CLAUDE.md (lexa-hub): fetcher rotation seam note.

## Common mistakes to avoid
- Freeing the old ctx while ANY request is in flight on it (RSK-07; the
  probe-then-commit swap exists to make ownership transfer explicit).
- Rotating all three fetchers simultaneously mid-walk — each swaps at its
  own safe point.
- Testing rotation only with `systemctl restart` (that is the
  hub-restart approximation the deferred-gap note dismisses; the point is
  IN-PROCESS reconnect).
- Running the soak during QA campaigns or replay runs (bench contention).
- A new CN in the "same device" rotation — LFDI changes, gridsim sees a
  stranger, and the walk 403s: that is the re-enrollment path, not a bug.
- Forgetting `hub-replay-tune.sh fast` after any deploy involved.

## Things that must NOT change
- Control enforcement continuity: retained ActiveControl + hub local
  expiry + scheduler fail-closed hold cover the reconnect window —
  verify, don't assume (the step-5 live-cap check).
- Never `Free()` mid-walk invariant; `wolfssl.Init()` once per process.
- Cipher pinning; `RequireClientCert` posture on gridsim (server side
  untouched).
- Walk cadence and scenario timing outside rotation instants.

## Acceptance criteria
- [ ] Single-rotation drill: zero enforcement gap (meter evidence),
  walk resumes ≤1 walk period, certstatus reflects new cert.
- [ ] 24 h churn soak: flat fd/RSS, 0 segfaults, 0 restarts, 0 watchdog
  fires (report attached).
- [ ] LFDI-mismatch refusal tested.
- [ ] Runbook merged; post-soak campaign ≤ baseline.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-integration` (csip-tls-test, desktop) green
- [ ] Mayhem: full FAST campaign after the soak
- [ ] Soak evidence archived under docs/

## Mayhem scenarios affected
wan-outage-hold/expiry, northbound-hang (shared error paths) — verdicts
unchanged. Future: a rotation scenario could join the curated set
(backlog; needs SSH like hub-restart-mid-cap).

## Conformance implications
None protocol-level; supports 09 Certificates hard gates. A test lab may
ask for the rotation procedure — the runbook is the artifact.

## Suggested commit message
`feat(northbound): staged cert rotation (probe-then-commit fetcher swap) + churn-soak tooling`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Cert rotation without control interruption (RSK-07)
**Description:** Off-tick probe-then-commit swap across all three
fetchers; operator script + runbook; 24 h churn-soak evidence; live-cap
continuity proof. Risk: HIGH (wolfSSL lifecycle) — soak-gated. Rollback:
sentinel removal; old cert retained until commit.

## Code review checklist
- Free ordering (Close → FreeSSL → FreeCtx) after last use, per fetcher.
- Probe failure leaves old path fully functional.
- Soak script measures the right PID across restarts (it must FAIL the
  soak on restart, not silently re-resolve).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Mayhem rotation scenario; CSIP re-enrollment flow (backlog); TASK-081
consumes the runbook + soak evidence.
