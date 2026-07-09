# TASK-074 — OCPP security profile 2 (TLS + BasicAuth); evsim counterpart

*Status: PARTIAL (2026-07-06, `task/074-ocpp-sp2` @ lexa-hub `c82b778` +
csip-tls-test `a4dcde0` — code/config/cert-tooling complete + unit-tested,
merged to main in both repos; live bench lockstep deploy + 7-scenario ×3 EV Mayhem re-run
deferred to TASK-081, see docs/BENCH.md's OCPP Security Profile 2 runbook) ·
Phase: P6 · Effort: L (≈6 h) · Difficulty: med · Risk: med*

## Objective
The lexa-ocpp CSMS and evsim run OCPP 2.0.1 Security Profile 2 on the
bench: `wss://` with a CA-signed server certificate plus HTTP Basic Auth,
enabled via config on both sides, deployed in the SAME session (lockstep),
with the seven OCPP fault scenarios re-run at their accepted verdicts over
wss. Product config documents profile 2 as the default and `ws://` as a
bench-only fallback (09 hard gate: "`ws://` disabled in product config").

## Background
IMPORTANT verified fact: **Security Profile 2 support is ALREADY
IMPLEMENTED on both sides** — this task is enablement, cert provisioning,
bench validation, and product-config policy, NOT feature development:
- CSMS: `lexa-hub/internal/ocppserver/server.go` — config has
  `CertPath`/`KeyPath` ("both must be non-empty to enable TLS (Security
  Profile 2)", :32-34) using `ws.NewTLSServer(cert, key,
  &tls.Config{MinVersion: TLS12})` (:56-59), and
  `BasicAuthUser/BasicAuthPass` enforced via `SetBasicAuthHandler` with
  constant-time compare (:64-70). `cmd/ocpp/config.go` exposes
  `cert_path`, `key_path`, `basic_auth_user`, `basic_auth_pass` (defaults
  empty = plain ws://, port 8887); `configs/ocpp.json` ships empty paths.
- evsim: `csip-tls-test/sim/evsim/main.go` — `-tls-ca` (CA PEM enabling
  verification), `-auth-user`/`-auth-pass`, wss:// URL handling via
  `ws.NewTLSClient` (:83-92, :187-215); usage header shows the SP2 form
  (:17). Library: `lorenzodonini/ocpp-go v0.19.0` in BOTH repos' go.mod
  (lockstep copy of ocppserver noted in both CLAUDE.md files — if
  TASK-022 extracted it to lexa-proto, config surface may have moved;
  verify first).
- Cert tooling: csip-tls-test `scripts/gen-server-cert.sh`,
  `scripts/gen-ev-cert.sh`, `scripts/gen-client-cert.sh`,
  `make gen-test-certs` — read gen-ev-cert.sh first; it likely already
  produces the CSMS server cert/CA pair for this exact purpose.
- The 7 OCPP fault scenarios (verified IDs in cmd/dashboard/mayhem.go):
  `ev-profile-reject`, `ev-accept-but-ignore`, `ev-min-current-floor`,
  `ev-meter-freeze`, `ev-connector-flap`, `ev-delayed-obey`,
  `ev-wrong-units`.
- Bench: lexa-ocpp on hub-pi 69.0.0.1:8887; evsim on ev-pi 69.0.0.14
  (unit ExecStart rewritten by scripts/update-sim-pis.sh — the CSMS URL
  and new flags are set there).
- OCPP-1 invariant: sessions are TransactionEvent lifecycles, never bare
  MeterValues — untouched here but the re-run guards it.

## Why this task exists
W7/§10.1: "OCPP CSMS is `ws://` (no TLS) on :8887 with no charger
authentication." AD-008 schedules profile 2 at P6 with evsim upgraded in
the same session. 09 hard gate.

## Architecture review sections
W7 · §10.1 · 02 AD-008 · 09 Security ("OCPP: security profile ≥2;
ws:// disabled in product config") · 05 §7.

## Prerequisites
TASK-022 (shared ocppserver module) DONE per the graph — verify where the
server config lives afterward. Bench access; both repos deployable in one
session.

## Files
- **Read first:** internal/ocppserver/server.go (or its lexa-proto home),
  cmd/ocpp/config.go + main.go, configs/ocpp.json;
  sim/evsim/main.go (newWSClient + flags); scripts/gen-ev-cert.sh +
  gen-server-cert.sh; scripts/update-sim-pis.sh (evsim ExecStart rewrite);
  docs/BENCH.md.
- **Modify:** configs/ocpp.json (bench + product examples: cert paths +
  basic auth), lexa-hub deploy script if certs need staging to
  /etc/lexa/certs/ (ocpp.crt is already listed in the CLAUDE.md certs
  table — verify), csip-tls-test scripts/update-sim-pis.sh (evsim flags:
  wss URL, -tls-ca, -auth-user/-auth-pass), docs/BENCH.md + both
  CLAUDE.md port/URL notes.
- **Create:** none expected (certs are generated artifacts, keys
  gitignored); possibly a `scripts/ocpp-sp2-enable.sh` helper if manual
  steps exceed ~5.

## Blast radius
lexa-ocpp ↔ evsim link (the only OCPP pair). Lockstep deploy required:
enabling TLS on the CSMS breaks a ws:// evsim instantly — same-session
rule (05 §11), same as MTR-4 discipline. Dashboard/metersim do not speak
OCPP (metersim reads hub :9100) — unaffected, but confirm nothing else
dials :8887 (`grep -rn "8887" both repos`).

## Implementation strategy
Provision a CSMS server certificate signed by the bench CA with
SAN=69.0.0.1 (IP SAN — evsim verifies against the CA; hostname/IP
mismatch is the classic failure), deploy cert+key 0600 to the hub Pi,
set ocpp.json cert/auth fields, update evsim's unit flags via
update-sim-pis.sh, restart both in one session, verify the TransactionEvent
lifecycle over wss, then re-run the 7 scenarios ×3.

## Detailed steps
1. Recon: read gen-ev-cert.sh — if it already emits a CSMS cert (CN/SAN
   for 69.0.0.1) reuse it; else extend gen-server-cert.sh usage for an
   IP-SAN cert. ECDSA P-256 to match house style (wolfSSL CSIP certs are
   ECDSA; ocpp-go/net/http supports it fine).
2. Stage to hub Pi: `install -m 600 -o lexa` cert+key under
   /etc/lexa/certs/ (extend deploy-hub-pi.sh staging if it doesn't cover
   ocpp certs — verify against its cert-staging block).
3. ocpp.json (bench): `cert_path`/`key_path` set; `basic_auth_user`:
   "evse-bench", `basic_auth_pass`: generated secret (NOT committed —
   deployed config only; repo example carries a placeholder + comment;
   05 §7 no plaintext credentials in repos).
4. evsim side: update-sim-pis.sh rewrites evsim ExecStart →
   `-csms wss://69.0.0.1:8887/ocpp -tls-ca <deployed ca path> -auth-user
   evse-bench -auth-pass <secret> -api-port 6024`; stage the CA PEM to
   ev-pi (public cert — fine to distribute).
5. Same-session restart: lexa-ocpp then evsim; verify journal handshake
   (TLS enabled log line, server.go:59; evsim "TLS enabled (CA=…)"),
   a TransactionEvent Started arrives, `lexa/evse/cs-001/state` updates,
   and a wrong-password evsim is REJECTED (auth negative check).
6. Scenario re-run: `python3 scripts/mayhem.py --dashboard
   http://69.0.0.20:8080 --only ev-profile-reject,ev-accept-but-ignore,
   ev-min-current-floor,ev-meter-freeze,ev-connector-flap,ev-delayed-obey,
   ev-wrong-units` ×3 — verdicts at their accepted ledger values.
7. Product-config policy: configs/ocpp.json example documents profile 2
   fields as REQUIRED-for-product; add the "ws:// is bench-only" line to
   lexa-hub CLAUDE.md and the 09 evidence note. (Profile 3/mTLS: record
   as backlog in 10, per AD-008 "≥2".)
8. If TASK-065's second EVSE exists: cs-002/evsim2 gets the same flags in
   the same session.

## Testing changes
- No new Go tests expected (ocppserver TLS/auth paths have existing
  simulator_test.go coverage — verify; add an auth-reject unit test if
  absent).
- Bench: step 5 handshake + negative auth + step 6 scenario ×3 evidence.
- Run: `make test` (hub), `make test-fast` (bench repo), mayhem per
  step 6.

## Documentation changes
- BENCH.md: evsim unit flags, wss URL, CA distribution.
- Both CLAUDE.md files: evsim example command gains SP2 flags; note the
  flag is still `-csms` (not `-hub`).
- 02 AD-008: profile 2 enabled date + evidence; 10_BACKLOG: profile 3.

## Common mistakes to avoid
- Restarting the CSMS with TLS while evsim still dials ws:// (instant
  BLIND EV scenarios; lockstep session or the bench looks broken).
- Cert without the 69.0.0.1 IP SAN — evsim's verified TLS client will
  refuse; a wss URL without `-tls-ca` silently falls back to system-pool
  verification (main.go:213-215) which will also refuse the bench CA.
- Committing the basic-auth secret or the server key (gitignore audit;
  placeholder in repo examples).
- Editing the evsim unit by hand instead of via update-sim-pis.sh (next
  deploy would silently revert — the config-overwrite gotcha class).
- Running the scenario set before OCPP MeterValues settle post-restart
  (let one TransactionEvent cycle complete; the harness baseline() covers
  this — don't bypass it).

## Things that must NOT change
- OCPP-1 invariant: TransactionEvent Started/Updated/Ended lifecycles —
  the plausibility gate on MeterValues current over station rating stays.
- Scenario verdict ledger for the 7 EV scenarios (transport change only).
- Port 8887, station IDs, `lexa/evse/…` topics, EVSECommand semantics.
- CSIP wolfSSL stack — completely separate TLS domain; do not share certs
  or CAs between CSIP client identity and the OCPP server cert beyond the
  bench CA if the tooling already does so (check gen-ev-cert.sh intent).

## Acceptance criteria
- [x] wss handshake + BasicAuth verified — unit-level (`TestOCPPSecurityProfile2_BasicAuth`,
  wrong password + wrong username rejected, correct credentials accepted, against
  the real `ocppserver.New`/`SetBasicAuthHandler` code path). **Bench-journal
  verification (actual wss handshake on 69.0.0.1/.14) NOT done this session —
  deferred to TASK-081.**
- [ ] TransactionEvent lifecycle + EVSE state flow intact over wss. **Bench-only —
  deferred to TASK-081** (existing `simulator_test.go` coverage is over
  plain ws://, unaffected by this task).
- [ ] 7 scenarios ×3 at accepted verdicts (evidence archived). **Deferred to
  TASK-081** (needs the live lockstep bench deploy first).
- [x] No secrets/keys committed; product-config policy documented (lexa-hub
  CLAUDE.md Critical Invariants + `cmd/ocpp/config.go` doc comments).
- [x] Deploy scripts reproduce the setup from scratch (`gen-ev-cert.sh` →
  `deploy-hub-pi.sh --enable-ocpp-sp2` → `update-sim-pis.sh --enable-ocpp-sp2`,
  documented end-to-end in csip-tls-test docs/BENCH.md).

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green
- [x] `make test-fast` (csip-tls-test) green
- [ ] Mayhem: 7-scenario EV set ×3 (full campaign optional — transport-
  only change; run full if any ocppserver code changed). **Deferred to TASK-081.**
- [ ] Lockstep deploy performed in one session (log it in the PR). **Deferred to
  TASK-081** — this session did code/config/cert-tooling only, no live SSH
  deploy (see docs/BENCH.md's OCPP Security Profile 2 runbook for the exact
  steps that session must run).

## Mayhem scenarios affected
ev-profile-reject, ev-accept-but-ignore, ev-min-current-floor,
ev-meter-freeze, ev-connector-flap, ev-delayed-obey, ev-wrong-units —
same verdicts over wss. perfect-storm's EV leg implicitly.

## Conformance implications
OCPP 2.0.1 Security Profile 2 claim becomes evidence-backed (09
Security gate). CSIP conformance unaffected.

## Suggested commit message
csip-tls-test: `ops(bench): evsim + deploy scripts on OCPP security profile 2 (wss + BasicAuth)`
lexa-hub: `ops(ocpp): enable SP2 bench config; product config policy ws:// bench-only`
(+ trailer both: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title (paired PRs):** OCPP Security Profile 2 on the bench
**Description:** Enables existing TLS+BasicAuth support end-to-end; cert
provisioning via bench CA (IP SAN); negative-auth check; 7 EV scenarios
×3 evidence. Risk: med (lockstep transport change). Rollback: clear
cert/auth fields + evsim flags, same-session restart.

## Code review checklist
- SAN correctness; key permissions; no committed secrets.
- update-sim-pis.sh idempotent for the new flags.
- Auth compare remains constant-time (untouched).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Backlog: security profile 3 (mTLS) evaluation; OCPP lifecycle-reorder
injector (07 deferred list, "revisit when evsim is next touched" — this
task touches it: file the backlog note).
