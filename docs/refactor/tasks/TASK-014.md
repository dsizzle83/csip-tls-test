# TASK-014 — lexa-api auth (bearer token) + migrate consumers (dashboard, metersim, QA drivers)

*Status: CODE COMPLETE, BENCH ROLLOUT + QA GATE PENDING (2026-07-04) · Phase: P0 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

**Status notes (2026-07-04):** Server + all five verified consumers implemented and
unit-tested on branch `task/014-api-auth` in both repos (lockstep, not yet merged).
NOT done: the bench rollout (deploy-hub-pi.sh, --enable-api-auth flip, dashboard/
metersim redeploy) and the QA gate (targeted scenarios ×5 + full FAST campaign) —
out of scope for this pass per explicit instruction (code + tests only, no bench
deploy/service restarts). **Also flagging:** this task's stated prerequisite,
TASK-013 (broker creds), is still TODO in 00_MASTER_INDEX/on `main` — not merged.
The two tasks touch disjoint subsystems (MQTT broker auth vs. lexa-api HTTP auth)
and TASK-014's own "Detailed steps" are fully self-contained (they don't call any
TASK-013 code), so the implementation proceeded without waiting; the "depends on
013" note in 04_DEPENDENCY_GRAPH appears to be about shared *review timing*
("same security wave") rather than a hard code dependency. Reviewer: please confirm
that reading before treating this as mergeable, and do not flip `--enable-api-auth`
on the bench until the QA gate in the Detailed steps §6-7 has actually run.

## Objective
`lexa-api` (:9100) requires a bearer token on `/status` and `/logs` (with `/healthz`
left open for liveness probes), the token lives in `/etc/lexa/api.json`, and every
verified consumer — the dashboard proxy, the Mayhem and bench-replay drivers (via the
dashboard), and metersim's linked mode — presents it, updated **in this same task** so
the bench never runs half-migrated.

## Background
Verified server: `lexa-hub/cmd/api/main.go` serves `GET /status` (full system snapshot),
`GET /logs` (SSE), `GET /healthz` on `listen_addr` (`configs/api.json`: `":9100"`,
plaintext, zero auth). Review W7: "exposes full system state … consumed by the
dashboard, the QA harness, *and metersim*."

Verified consumers (trace each before editing):
1. **Dashboard reverse proxy** — `csip-tls-test/cmd/dashboard/main.go`:
   `-hub http://localhost:9100` flag; `mux.Handle("/api/hub/", stripProxy("/api/hub",
   *hub))`; plus the SSE log mux (`newLogMux` with `"hub": *hub + "/logs"`).
   The browser SPA reaches lexa-api ONLY through this proxy.
2. **Mayhem driver** — `cmd/dashboard/mayhem.go` (`d.getJSON("hub", "/status", &st)`,
   line ~2087) via the driver's shared HTTP helpers over the same base-URL map.
3. **Bench-replay driver** — `cmd/dashboard/replay.go` (`d.getJSON("hub", "/status",
   &st)`, line ~745), same helpers.
4. **metersim linked mode** — `sim/metersim/main.go` `-hub-api` flag (EV power via the
   hub's `/status`); live unit rewritten by `scripts/update-sim-pis.sh` (line ~58:
   `... -hub-api http://$HUB:9100 ...`).
5. **`scripts/mayhem.py`** — verified: it talks ONLY to the dashboard (`/api/qa/*`);
   it is NOT a direct lexa-api consumer (the brief listed it — the dashboard proxy
   covers it). No change needed there beyond nothing.
6. Ad-hoc: `curl http://69.0.0.1:9100/status` sanity probes in docs/BENCH.md and
   deploy-hub-pi.sh's closing hint — update the documented commands with the header.

TLS on :9100 is explicitly deferred (AD-008: "token + TLS", air-gapped bench; implement
token now, leave a config-gated TLS listener as a follow-up backlog note) — record the
deferral in the PR and in AD-008's entry.

## Why this task exists
Review W7/§10.1 second half of §14 item 6: plaintext, unauthenticated full-state API on
the LAN. Bench-acceptable, product-indefensible; the fix must land while consumers are
few and known.

## Architecture review sections
W7, §10.1, §14 item 6; AD-008. 04 row 014 (depends on 013 — same security wave).

## Prerequisites
TASK-013 merged (broker creds; shared deploy-script patterns for secrets). Bench access.

## Files
- **Read first:** `lexa-hub/cmd/api/main.go` + `cmd/api/config.go` +
  `cmd/api/handlers.go`; `csip-tls-test/cmd/dashboard/main.go` (proxy + logmux),
  `cmd/dashboard/mayhem.go` + `replay.go` HTTP helpers (find the shared
  `getJSON`/`post` implementations), `sim/metersim/main.go` (hub-api fetch path),
  `scripts/update-sim-pis.sh`, `docs/BENCH.md`.
- **Modify (lexa-hub):** `cmd/api/config.go` (`api_token_file` field),
  `cmd/api/main.go` (auth middleware), `configs/api.json` (empty default),
  `scripts/deploy-hub-pi.sh` (token generation, like TASK-013's pass-files).
- **Modify (csip-tls-test):** `cmd/dashboard/main.go` (`-hub-token-file` flag; inject
  `Authorization: Bearer` in the /api/hub proxy director, the logmux hub stream, and
  the driver HTTP helpers for the `"hub"` target), `sim/metersim/main.go`
  (`-hub-token-file`), `scripts/update-sim-pis.sh` (pass the flag),
  `scripts/bench-up.sh` (dashboard start command gains the flag — check where the
  transient unit's ExecStart is built), `docs/BENCH.md` (probe commands).
- **Create:** nothing.

## Blast radius
Every reader of hub state on the bench. Failure mode: a missed consumer gets 401s —
dashboard KPIs blank, Mayhem diagnosis loses hub introspection (verdicts degrade to
INCONCLUSIVE-ish noise), metersim's EV term drops out of the energy balance. The staged
rollout (empty token = auth off) prevents a flag-day.

## Implementation strategy
Token support is additive and disabled-by-default (empty token ⇒ open, exactly today's
behavior). Land server + all consumers with token support; deploy everywhere; generate
the token on the Pi and enable; verify each consumer; then run the targeted QA gate.
Same introduce→flip pattern as TASK-013.

## Detailed steps
1. **Server:** `cmd/api/config.go` gains `api_token_file string` (JSON
   `"api_token_file"`). `main.go`: if the file is configured and non-empty, wrap
   `/status` and `/logs` in middleware requiring `Authorization: Bearer <token>`
   (constant-time compare, `crypto/subtle`); 401 otherwise. `/healthz` stays open
   (TASK-008's api watchdog self-probe uses it — verified dependency). SSE note: `/logs`
   auth happens at request time (header), streaming unaffected.
2. Unit tests: middleware allows/denies correctly; empty config ⇒ open.
3. **Dashboard:** add `-hub-token-file` flag; load once at startup. Inject the header:
   (a) in `stripProxy` for the hub target only — switch that one mount to a proxy whose
   `Director` sets the header; (b) in `newLogMux`'s hub stream request; (c) in the
   driver helpers (`getJSON`/`post`/whatever `d.get…` resolves to) **only for the
   `"hub"` base** — gridsim/simapi targets stay open (bench property, AD-008).
4. **metersim:** `-hub-token-file` flag; set header on its hub `/status` GETs.
5. **Scripts:** `update-sim-pis.sh` metersim ExecStart gains the flag (token file
   scp'd to the meter Pi, 0600 — generated on the hub, distributed by the script;
   document the flow); `bench-up.sh`/run-demo dashboard invocation gains
   `-hub-token-file`; `deploy-hub-pi.sh` generates `/etc/lexa/api.token`
   (`openssl rand -hex 32`, 0600 lexa-owned, only if absent) and sets
   `api_token_file` in the installed api.json (careful: the deploy overwrites
   /etc/lexa/api.json from the repo example — the script must patch the field in
   after install, like hub-replay-tune patches timing).
6. **Rollout:** deploy lexa-hub (auth still off — token file not yet configured) →
   deploy dashboard + metersim with token flags pointing at the distributed file →
   enable (`api_token_file` set, restart lexa-api) → verify:
   `curl -s http://69.0.0.1:9100/status` → 401;
   `curl -s -H "Authorization: Bearer $(ssh dmitri@69.0.0.1 sudo cat /etc/lexa/api.token)" …/status` → 200;
   dashboard KPI cards live; meter Pi's `/state` energy_balance includes EV;
   `curl 69.0.0.1:9100/healthz` → 200 unauthenticated.
7. Re-run `hub-replay-tune.sh fast` after hub deploys. QA gate:
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only
   hub-restart-mid-cap,export-cap-full-battery,ev-meter-freeze` (scenarios whose
   diagnosis reads hub `/status` through the drivers) ×5, verdict-identical; then one
   full FAST campaign (cheap insurance — the harness's hub introspection threads through
   everything).
8. Paired PRs; same-session deploy (dashboard + metersim + hub are now
   auth-lockstepped).

## Testing changes
- lexa-hub: `cmd/api` middleware tests (`go test ./cmd/api/`).
- csip-tls-test: helper-level test that the hub base gets the header and others don't
  (factor the header injection to a testable func).
- Bench evidence per step 6.

## Documentation changes
- `docs/BENCH.md`: probe commands with the token; token distribution note.
- lexa-hub CLAUDE.md: lexa-api line gains "bearer-token auth (`api_token_file`)".
- AD-008 entry: mark API-token half delivered, TLS explicitly deferred with reason.
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Locking `/healthz` — breaks TASK-008's watchdog self-probe and future LB checks.
- Forgetting the **logmux** hub stream — dashboard's merged log view silently loses hub
  lines (easy to miss because /status works).
- Injecting the header for ALL dashboard proxy targets — simapi/gridsim don't expect it
  (harmless today, but it leaks the token to every sim; scope it to the hub base).
- Editing `update-sim-pis.sh` without handling the token file's transport to the meter
  Pi — metersim on .12 can't read /etc/lexa on .1.
- Deploy-script ordering: enabling auth in api.json before the dashboard/metersim flags
  are live = blank dashboard mid-session.
- Comparing tokens with `==` — use `subtle.ConstantTimeCompare`.

## Things that must NOT change
- `/status` and `/logs` response shapes (the QA harness and dashboard SPA parse them;
  `csipReportGraceS` behavior in `cmd/api/handlers.go` untouched — it backs QA v4
  expiry-reporting discipline).
- `/healthz` semantics.
- metersim's linked-mode energy-balance math (only the transport gains a header).
- Simapi/gridsim-admin openness (documented bench property — AD-008).

## Acceptance criteria
- [ ] Tokenless `/status`/`/logs` → 401; with token → 200; `/healthz` open. (curl evidence)
- [ ] Dashboard fully functional against the locked API (KPIs, logs stream, QA tab).
- [ ] metersim linked mode shows EV power with auth on.
- [ ] Targeted scenarios ×5 verdict-identical; full FAST campaign ≤ V6 baseline.
- [ ] Token never committed; generated on-device; 0600.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: targeted set ×5 + one full FAST campaign
- [ ] Bench replay smoke: start a short replay, confirm the driver reads hub /status (then abort — driver restores the bench)

## Mayhem scenarios affected
Any scenario whose diagnosis introspects the hub (`/status` plan log — e.g.
`export-cap-full-battery`, `hub-restart-mid-cap`, EV scenarios). Expected: zero verdict
change; a 401 would surface as missing-plan diagnosis noise — that's the regression
signal to watch.

## Conformance implications
None (lexa-api is a bench/ops surface, not a CSIP surface).

## Suggested commit message
lexa-hub: `feat(api): bearer-token auth on /status,/logs; token file via deploy (W7, AD-008)`
csip-tls-test: `feat(dashboard,metersim): present lexa-api bearer token (W7 lockstep)`
both `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** lexa-api bearer-token auth + all consumers migrated (paired PRs)
**Description:** Consumer trace table (proxy/logmux/mayhem/replay/metersim; mayhem.py
needs nothing — dashboard-mediated). Empty-token = legacy-open for staged rollout.
TLS deferred per AD-008 (reason recorded). Evidence: curl matrix, dashboard screenshots,
scenario verdicts. Rollback: clear `api_token_file`, restart lexa-api.

## Code review checklist
- Every consumer in the trace table has a diff or an explicit no-change justification.
- Constant-time compare; token file perms; no token in logs (grep the middleware).
- /healthz exemption present; SSE path tested with auth.

## Definition of done
Acceptance criteria + regression checklist + docs (BENCH.md, CLAUDE.md, AD-008) +
status headers updated.

## Possible follow-up tasks
Backlog: TLS listener on :9100 (AD-008 deferred half); TASK-044 (auth-failure counter
metric); TASK-074 (OCPP security profile — the remaining W7 surface).
