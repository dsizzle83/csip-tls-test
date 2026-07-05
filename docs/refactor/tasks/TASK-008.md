# TASK-008 — Watchdogs for the other five services

*Status: DONE, code only (2026-07-04, lexa-hub@8d569eb on
`task/008-009-watchdogs-journald`) · Phase: P0 · Effort: M (≈4–6 h + staged 48 h soaks) ·
Difficulty: med · Risk: med — kick wiring + `watchdog.Ready()`/`watchdog.Kick()` landed
in all five `cmd/*/main.go` and all five unit files (`Type=notify` + per-service
`WatchdogSec` per the table below); `go build ./...` and `go test -race ./internal/...`
green; northbound/ocpp/api/modbus smoke-run locally without `NOTIFY_SOCKET` (no-op path
confirmed, including a live `GET /healthz` 200 against the api probe). The staged
one-service-per-deploy rollout, the five `kill -STOP` wedge tests, the per-service ≥24 h
soaks, and the closing full FAST Mayhem campaign are ALL deferred to the P0-exit gate per
this session's launch instructions (code + unit files + tests only this wave; no bench
deploy, no service restart). Acceptance-criteria items 1–4 and the regression-checklist
"Mayhem" and "soak evidence" rows are therefore NOT YET satisfied — do not merge until
the deploy/wedge/soak wave closes them.

## Objective
`lexa-northbound`, `lexa-modbus`, `lexa-telemetry`, `lexa-ocpp`, and `lexa-api` each gain
`Type=notify` + a service-appropriate `WatchdogSec`, kicked from that service's natural
liveness point (verified per service below), rolled out one service per deploy with soak
between.

## Background
TASK-007 created `lexa-hub/internal/watchdog` (Ready/Kick over `NOTIFY_SOCKET`) and
proved the pattern on lexa-hub. Per-service liveness points (all verified in source):

| Service | Natural liveness point | Cadence (fast/stock) | WatchdogSec |
|---|---|---|---|
| northbound | discovery walk loop, `cmd/northbound/main.go:216-228` (goroutine: `runDiscovery` then ticker `cfg.DiscoveryInterval()`) — kick once per loop iteration, after `runDiscovery` returns | 5 s / 20 s walks | 120 |
| modbus | `publishMeasurements` update-drain loop, `cmd/modbus/main.go:132` (`for upd := range updates`) — kick per update; poll errors still emit updates (`upd.Err` path), so unreachable devices don't starve the kick, but a wedged registry does | 2 s / 10 s poll × 3 devices | 60 |
| telemetry | MUP post loop, `cmd/telemetry/main.go:133-145` (`ticker := time.NewTicker(cfg.MUPPostRate())`, select loop) — add a second `kick` ticker **case inside the same select** so a wedged `postMeasurements` blocks kicks | posts every 60 s bench / 300 s default | 60 (kick ticker 10 s) |
| ocpp | none — `cmd/ocpp/main.go` main goroutine just blocks on signal (`srv.Start()` runs in a goroutine) — add a 10 s kick ticker in main that kicks **only if `mc.IsConnected()`**; weaker liveness (OCPP server health not proven) — documented | n/a | 60 |
| api | HTTP server goroutine + MQTT subs, `cmd/api/main.go` — add a 10 s ticker in main that self-probes `GET http://127.0.0.1<listen_addr>/healthz` (2 s timeout) AND checks `mc.IsConnected()` before kicking | n/a | 60 |

Notes:
- northbound: a single walk against a hung server is bounded by the tlsclient fd
  read-timeout (QA v4 fix), but chained fetch timeouts can stretch a walk — hence 120 s
  (≥4× stock 20 s walk, with headroom for a slow TLS reconnect). northbound is the
  service where a wolfSSL wedge is most plausible (§8.6) — exactly who needs this.
- modbus: `registry.Start()` runs the poll loop; updates flow to `publishMeasurements`
  via a subscription channel. Kicking per-update covers registry, channel, and MQTT
  publish path in one place. Worst case all-devices-erroring still emits updates each
  poll round.
- telemetry/ocpp/api have no tight control loop; their kick tickers live in the same
  select/goroutine as (or actively probe) the thing that matters. This is weaker than
  hub/northbound/modbus and is documented as such in each unit file comment.
- Unit files: `lexa-hub/systemd/lexa-{northbound,modbus,telemetry,ocpp,api}.service`
  currently all `Type=simple`, `Restart=on-failure`, no watchdog. Deploy path:
  `scripts/deploy-hub-pi.sh` installs `systemd/lexa-*.service` verbatim.

## Why this task exists
Review §11/§14 item 5 covers *all* services: a wedged northbound silently stops walking
(the utility-facing path!), a wedged modbus stops polling (measurement freshness gates
everything), and nothing today would restart either.

## Architecture review sections
§11 (watchdog), §14 item 5, §8.6 (wolfSSL wedge), AD-011; RSK-08.

## Prerequisites
TASK-007 DONE (package + pattern + proven unit-file change). Bench access.

## Files
- **Read first:** `lexa-hub/internal/watchdog/`, `cmd/northbound/main.go` (walk loop),
  `cmd/modbus/main.go` (`publishMeasurements`), `cmd/telemetry/main.go` (post loop),
  `cmd/ocpp/main.go`, `cmd/api/main.go`, all five unit files in `lexa-hub/systemd/`.
- **Modify:** the five `main.go` files (kick wiring + `watchdog.Ready()` after startup
  completes); the five unit files.
- **Create:** nothing new (reuse `internal/watchdog`).

## Blast radius
Five `cmd/*` main files (wiring only — no internal package changes); five unit files.
`Type=notify` means each service must send READY or systemd start times out — the READY
call placement per service matters (after subscriptions/listeners are up).

## Implementation strategy
Mechanical replication of TASK-007 per service, but rolled out **one service per deploy**
with ≥24 h between (RSK-08 stagger; northbound and modbus last since they're the
highest-consequence restarts), each verified by the same STOP-wedge test, ending with a
full FAST campaign once all five are live.

## Detailed steps
1. **northbound:** kick at the top of the walk-loop `for` body and once after the initial
   `runDiscovery`; `watchdog.Ready()` after MQTT connect + subscriptions succeed
   (before the walk goroutine starts). Unit: `Type=notify`, `WatchdogSec=120`,
   `NotifyAccess=main`, comment with sizing rationale.
2. **modbus:** kick as the first statement of the `for upd := range updates` body in
   `publishMeasurements`; `Ready()` after `reg.Start()` + `go publishMeasurements(...)`.
   Unit: `WatchdogSec=60`.
3. **telemetry:** in the post-loop select, add `kick := time.NewTicker(10 *
   time.Second)` and a `case <-kick.C: watchdog.Kick()`; `Ready()` after MUP
   registration loop completes (registration retries on failure — Ready still sent;
   startup must not hang on an unreachable server: verify `registerMUP` has bounded
   retries before placing Ready). Unit: `WatchdogSec=60`.
4. **ocpp:** replace the bare `<-quit` block with a select over `quit` and a 10 s kick
   ticker gated on `mc.IsConnected()`; `Ready()` after `go srv.Start()`. Unit:
   `WatchdogSec=60`; comment: "liveness = process + MQTT connectivity; OCPP listener
   health not probed (follow-up in TASK-044 metrics)."
5. **api:** same select-with-ticker pattern; kick iff `mc.IsConnected()` AND a loopback
   `GET /healthz` (2 s timeout) returns 200. `Ready()` after `ListenAndServe` goroutine
   is up (probe once before Ready). Unit: `WatchdogSec=60`.
6. Local: `go build ./...`, `go test -race ./internal/...`, and run each binary without
   `NOTIFY_SOCKET` (no-op path).
7. Rollout, one per deploy session on 69.0.0.1 (order: telemetry → api → ocpp → modbus →
   northbound). For each: deploy (full `deploy-hub-pi.sh` redeploys all — acceptable;
   re-run `hub-replay-tune.sh fast` after each), `systemctl show <svc> -p WatchdogUSec`,
   STOP-wedge test (`kill -STOP`, expect restart ≤ WatchdogSec, `kill -CONT`/cleanup),
   ≥24 h soak with zero fires before the next service.
8. After all five: full FAST campaign ≤ V6 baseline; specifically confirm
   `northbound-hang` and `wan-outage-hold`/`wan-outage-expiry` verdicts unchanged (a
   server that stops responding must NOT fire northbound's watchdog — the walk loop
   keeps iterating on fetch errors; verify in the journal during the scenario).

## Testing changes
No new Go tests beyond TASK-007's package tests (wiring is exercised on the bench).
Bench evidence per service: WatchdogUSec value, wedge-restart journal excerpt, soak
NRestarts.

## Documentation changes
- `lexa-hub/CLAUDE.md`: extend the TASK-007 watchdog note to "all six services", with
  the per-service WatchdogSec table.
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Kicking from a free-running timer goroutine in northbound/modbus — those two have real
  loops; the timer shortcut is only acceptable where documented (telemetry-in-select,
  ocpp/api probing).
- Sending READY before subscriptions are up — a watchdog restart storm at boot if MQTT
  is slow; READY placement is per-service deliberate (steps 1–5).
- northbound `WatchdogSec=60` with stock 20 s walks + a slow server — walks legitimately
  take >20 s under `northbound-hang` conditions; 120 s is the floor. Do not "tighten it
  later" without re-running that scenario.
- Rolling out all five at once — RSK-08 says stagger; a shared bug (e.g. READY misplaced)
  would flap everything simultaneously.
- Forgetting `hub-replay-tune.sh fast` after each deploy.

## Things that must NOT change
- northbound's fail-closed walk discipline (`runDiscovery` error → publish nothing,
  retained last-good stands — QA 2026-07-02 `northbound-hang`/`wan-outage-hold`): the
  watchdog must not convert a failing-but-iterating walk loop into restarts.
- modbus Tier-0 interlock and reconnect/reassert paths (radioactive per 05 §12) — kick
  wiring goes in `publishMeasurements` only; do not touch `retryDevice`/interlock code.
- telemetry NaN-init discipline ("don't post zeros before first poll").
- All six services' crash-only behavior (AD-011).

## Acceptance criteria
- [ ] All five units show `Type=notify` + intended `WatchdogUSec` on the Pi.
- [ ] STOP-wedge restarts verified per service (journal evidence ×5).
- [ ] ≥24 h soak per service, zero spurious fires; final all-services 48 h with zero fires.
- [ ] Full FAST campaign ≤ V6 baseline; `northbound-hang`, `wan-outage-*` verdicts unchanged with zero watchdog fires during those scenarios.

## Regression checklist
- [ ] `go test -race ./internal/...` green (lexa-hub)
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: full FAST campaign (post-rollout) + targeted `northbound-hang,wan-outage-hold,wan-outage-expiry,mqtt-broker-restart`
- [ ] Soak evidence recorded per service

## Mayhem scenarios affected
`northbound-hang`, `wan-outage-hold`, `wan-outage-expiry` (northbound walk-loop kicks
under server faults); `mqtt-broker-restart`/`-latency` (kick gating on `IsConnected` in
ocpp/api must not restart-loop during broker outage — verify: broker down >60 s means
ocpp/api DO restart; that is accepted crash-only behavior, note it in the PR);
`hub-restart-mid-cap` unchanged.

## Conformance implications
None; MUP posting (telemetry) restart re-registers via existing `registerMUP` retry path.

## Suggested commit message
`feat(services): systemd watchdogs for northbound/modbus/telemetry/ocpp/api (review §11 item 5)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Watchdogs for the remaining five services (staged rollout)
**Description:** Per-service liveness points + WatchdogSec table (see task file);
ocpp/api use probing tickers (weaker, documented). Evidence: 5× wedge tests, staged
soaks, full campaign. Rollback: per-unit revert to Type=simple.

## Code review checklist
- Each kick site is the service's real liveness point per the table; no bare timers on
  northbound/modbus.
- READY placement after each service's startup completes.
- Broker-down behavior for ocpp/api restarts explicitly reasoned about in the PR.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated.

## Possible follow-up tasks
TASK-044 (export watchdog-fire/restart counters as metrics), TASK-045 (heartbeat-stall
alerting), backlog: probe OCPP listener health for the ocpp kick.
