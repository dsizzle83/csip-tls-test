# TASK-006 — Toolchain/dependency refresh (Go ≥1.22, x/crypto, x/net, paho)

*Status: DONE (2026-07-05, csip-tls-test `c7bd2fc` · lexa-hub `ae4a593`) · Phase: P0 · Effort: L (≈6–8 h focused + campaign wall-clock) · Difficulty: med · Risk: med*

**Completion note (2026-07-05):** Both repos on branch `task/006-dep-refresh`.
csip-tls-test commits: `34f9cde` (toolchain), `c7bd2fc` (x/*). lexa-hub
commits: `1983758` (toolchain), `82b387a` (x/*), `7ea23f9` (unrelated
blocking fix, see below), `ae4a593` (paho). Not pushed/merged — Principal
Engineer review pending.

**Deviation:** bench validation of commit 2 surfaced a pre-existing bug in
lexa-hub `scripts/deploy-hub-pi.sh` (from same-day commit `06931cc`,
unrelated to this task): mosquitto passwd/acl files at `root:root 0600`
are unreadable by the running `mosquitto:mosquitto`-dropped-privilege
process on this hub Pi's mosquitto build (2.0.21), verified via `strace`
(`setgid`/`setuid` happen before the file is ever opened, on every start).
This broke every `--enable-mqtt-acl` deploy, blocking this task's mandatory
bench gate. Fixed in lexa-hub `7ea23f9` (reverted to the prior working
`root:mosquitto 0640`) — out of TASK-006's charter but required to proceed;
flagged for Principal Engineer review and recommended for cherry-pick to
main independent of this task's outcome.

## Objective
Both repos build on a modern pinned Go toolchain with current `golang.org/x/*` modules;
lexa-hub's paho MQTT client is upgraded **last and alone** with a full Mayhem campaign
gate; the govulncheck baseline (TASK-005) is re-run and shrinks to zero non-allowlisted
findings.

## Background
Verified current state:
- Both `go.mod` files declare `go 1.21`. Desktop toolchain is `go1.26.4`.
- `lexa-hub`: `x/crypto` @2019-10, `x/net v0.8.0`, `x/sys v0.6.0`, `x/sync v0.1.0`,
  `paho.mqtt.golang v1.4.3`, `ocpp-go v0.19.0`, `modbus v1.6.4`, `zeroconf v1.0.0`.
- `csip-tls-test`: `x/crypto` @2019-10, `x/net` @2020-01, `x/sys` @2022-08; **no paho**
  (mqttproxy is a raw TCP proxy; sims use HTTP).
- MQTT plumbing that paho's behavior underpins (all verified in
  `lexa-hub/internal/mqttutil/mqttutil.go`): auto-reconnect + `subRegistry.replay()` on
  the OnConnect handler (resubscribe-after-reconnect — paho does not resend SUBSCRIBE),
  5 s bounded `publishTimeout` on QoS-1 PUBACK waits, 30 s connect timeout,
  `SetConnectRetry(true)`. The Mayhem scenarios that exercise exactly this:
  `mqtt-broker-restart`, `mqtt-broker-latency` (in
  `csip-tls-test/cmd/dashboard/mqtt_scenarios.go`), driven through the on-hub `mqttproxy`.
- Build surfaces that must keep working: `make build` / `make build-arm64` (lexa-hub;
  cgo pair needs the arm64 wolfSSL sysroot), csip-tls-test `make build*` targets, and
  the Pi-side native builds (`make sync-pi` builds `sim/client` + `sim/conformance` ON a
  Pi — check the Pi's installed Go version before raising the `go` directive above it,
  or the conformance runner stops building on-device).

Risk framing (RSK-04): a paho upgrade (1.4.3 → current 1.5.x) can change reconnect,
session, and inflight semantics under the very faults that protect everything else. Hence:
do it in P0 before structural work, in its own commit, gated by the mqtt scenarios and a
full campaign.

## Why this task exists
Review D7/§10.4 (dependency rot, CVE exposure), §14 item 8. Also unblocks fuzzing
(native `go test -fuzz` corpus tooling is better on modern Go) and keeps `setup-go` from
resolving stale toolchains.

## Architecture review sections
D7, §10.4, §14 item 8; 04 §4 risk 4 (RSK-04); 03 P0 risks.

## Prerequisites
TASK-002, TASK-003 (CI catches breakage), TASK-005 (baseline to shrink). Bench in FAST
mode for the campaign gate (`bash scripts/bench-up.sh --fast`).

## Files
- **Read first:** both `go.mod`/`go.sum`; `lexa-hub/internal/mqttutil/mqttutil.go`;
  TASK-005's `VULN_BASELINE_<date>.md`; paho release notes 1.4.3→target.
- **Modify:** both `go.mod` + `go.sum`; possibly small compile fixes where upgraded
  modules changed APIs (expect none for x/*; check paho option methods).
- **Create:** nothing.

## Blast radius
Whole-module compile surface in both repos; at runtime, only lexa-hub's MQTT layer
(paho) is behaviorally exposed. All six hub services link paho via `internal/mqttutil`.

## Implementation strategy
Three independently revertible commits per the RSK-04 ordering: (1) Go toolchain
directive + CI, both repos; (2) `golang.org/x/*` and other minor deps, both repos;
(3) paho alone, lexa-hub only, campaign-gated. Deploy to the bench between (2) and (3)
so any campaign delta attributes cleanly to paho.

## Detailed steps
1. **Pre-flight:** `ssh dmitri@69.0.0.1 go version || true` and check the sim Pis if any
   on-Pi build workflow is still in use (`make sync-pi` targets). Record versions. Pick
   the `go` directive: at least `1.22`; prefer the newest version available on every
   machine that compiles the repos (desktop is 1.26.4; if the Pis lack Go or only build
   via cross-compiled artifacts, the desktop bounds it).
2. **Commit 1 (both repos):** bump `go` directive (e.g. `go 1.26`); `go mod tidy`;
   `gofmt`/`go vet` sweep; run full local suites (`make test` / `make test-fast`,
   `go test ./tests/ ./internal/southbound/...`). CI green (setup-go follows
   `go-version-file`).
3. **Commit 2 (both repos):** `go get golang.org/x/crypto@latest golang.org/x/net@latest
   golang.org/x/sys@latest golang.org/x/sync@latest && go mod tidy`. Also consider
   `zeroconf`, `ocpp-go`, `modbus` patch/minor bumps ONLY if govulncheck flagged them —
   otherwise leave (each extra bump muddies campaign attribution). Full local suites +
   `make test-integration` on the desktop (real mTLS handshakes — x/crypto moved).
4. Re-run `scripts/ci/govulncheck.sh` in both repos: x/crypto|x/net findings must be gone.
5. **Bench validation of commits 1–2:** `make build-arm64` (lexa-hub; rebuild the arm64
   wolfSSL sysroot first if `/tmp` was wiped: `make wolfssl-arm64`), deploy via
   `bash scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`, **then re-run
   `scripts/hub-replay-tune.sh fast`** (the deploy resets timing to STOCK). Redeploy sims
   (`bash scripts/update-sim-pis.sh 69.0.0.1 dmitri`) in the same session (MTR-4).
   Run one full FAST campaign: `python3 scripts/mayhem.py --dashboard http://localhost:8080`.
   Must be ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND; accepted DEGRADEDs per
   `docs/QA_REPORT_V5_20260703.md` + V6 notes).
6. **Commit 3 (lexa-hub only): paho.** `go get github.com/eclipse/paho.mqtt.golang@latest
   && go mod tidy`. Read its changelog for: reconnect/backoff changes, OnConnect ordering,
   Publish token semantics, default keepalive/session flags. Confirm `mqttutil`'s
   assumptions still hold (especially: OnConnect fires on every reconnect → `replay()`
   still re-subscribes; `WaitTimeout` semantics unchanged).
7. Build, `make test`, deploy hub only (re-run `hub-replay-tune.sh fast` again), then the
   targeted gate: `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only
   mqtt-broker-restart,mqtt-broker-latency,mqtt-stale-retained,mqtt-malformed-control`
   ×10 solo runs — verdicts must match pre-upgrade. Then one full FAST campaign.
8. Flip the govulncheck job to required in both workflows (removing
   `continue-on-error`; this closes TASK-005's deferred flip).
9. Push, PR(s), update baselines: note the new dependency set in
   `docs/refactor/VULN_BASELINE_<date>.md` (append section).

## Testing changes
No new tests. Gates: full local suites both repos; `make test-integration` (desktop);
mqtt-scenario ×10 solo; two full FAST campaigns (post-commit-2, post-commit-3).

## Documentation changes
- Both CLAUDE.md "Stack" lines: `Go 1.21` → new version; lexa-hub CLAUDE.md paho version
  if named. Same-session doc updates.
- 00_MASTER_INDEX status; VULN_BASELINE append.

## Common mistakes to avoid
- Upgrading paho together with anything else — RSK-04 exists because campaign deltas
  must attribute to exactly one change.
- Forgetting `hub-replay-tune.sh fast` after **every** `deploy-hub-pi.sh` (the deploy
  overwrites `/etc/lexa/*.json` with stock-timing repo configs — verified in the script).
- `/tmp/wolfssl-arm64-sysroot` is wiped on reboot — `make build-arm64` fails obscurely;
  run `make wolfssl-arm64` first.
- Raising the `go` directive above what any still-used on-Pi build path has installed
  (step 1 pre-flight).
- `go mod tidy` in csip-tls-test pulling paho in — it shouldn't (nothing imports it);
  if it appears, something was mis-edited.
- Deploying hub without sims (or vice versa) — MTR-4 lockstep, same session.

## Things that must NOT change
- `internal/mqttutil` public behavior: bounded 5 s publish wait, resubscribe replay on
  reconnect, 30 s connect timeout. These back `mqtt-broker-restart`/`mqtt-broker-latency`
  PASSes (review §11 "broker as SPOF is handled adequately"). If the new paho breaks one,
  fix mqttutil to preserve the behavior — never relax the scenario.
- Cipher/mTLS invariants (`ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`, `RequireClientCert`,
  `wolfSSL_Init` once) — x/crypto is not used on the wolfSSL path, but the integration
  suite re-proves it.
- wolfSSL version (5.7.6-stable) — out of scope here.

## Acceptance criteria
- [x] Both go.mod: modern `go` directive; x/crypto + x/net at current releases.
- [x] lexa-hub paho at target version, in its own commit.
- [x] govulncheck: zero non-allowlisted findings; job now required in both repos.
- [x] mqtt scenarios ×10 solo: verdicts unchanged (0 FAIL/0 BLIND all 10). Full FAST campaign 32P/19D/0F/0B — 0 FAIL/BLIND, within V6/M0 baseline norms.
- [x] `make test-integration` green on the desktop.

## Regression checklist
- [x] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [x] Conformance logic tests green (`go test ./tests/`)
- [x] Mayhem: full campaign ×2 (see steps 5, 7) + targeted mqtt set ×10
- [x] Bench restored: hub FAST (this is P0 norm), all services `is-active`

## Mayhem scenarios affected
`mqtt-broker-restart`, `mqtt-broker-latency`, `mqtt-stale-retained`,
`mqtt-malformed-control` (paho reconnect surface); any scenario could shift if paho
changes delivery timing — hence the full campaigns.

## Conformance implications
x/crypto bump touches nothing on the wolfSSL path, but regenerating conformance evidence
at M0 (per 06 §2) happens after this task — sequence it so evidence reflects the shipped
dependency set.

## Suggested commit message
Three commits: `build: Go 1.2x toolchain (both repos)` ·
`build(deps): refresh golang.org/x/* (both repos)` ·
`build(deps): paho.mqtt.golang 1.4.3 → 1.5.x — campaign-gated (RSK-04)`
each `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Dependency refresh (toolchain → x/* → paho, in that order)
**Description:** Per RSK-04: three revertible commits, paho isolated and gated on the
mqtt scenario set ×10 + full FAST campaign (attach verdict tables). Rollback: revert the
offending commit; each stands alone.

## Code review checklist
- paho changelog findings enumerated in the PR; mqttutil assumptions re-verified line by
  line (OnConnect replay, WaitTimeout).
- Campaign evidence attached (both campaigns + solo runs).
- No unrelated module bumps smuggled in.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers updated +
govulncheck flipped to required.

## Possible follow-up tasks
TASK-047/048 (fuzzers on the new toolchain); backlog: evaluate ocpp-go/modbus major
upgrades separately.
