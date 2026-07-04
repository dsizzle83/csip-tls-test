# TASK-007 — systemd `WatchdogSec` + `sd_notify` for lexa-hub

*Status: DONE, code only (2026-07-04, lexa-hub@1eced54 on `task/007-watchdog-hub`) —
arm64 build/deploy, the `kill -STOP` wedge test, targeted Mayhem
(`mqtt-broker-restart,mqtt-broker-latency,hub-restart-mid-cap`), and the 48 h bench
soak are deferred to the wave-gate deploy agent per this session's launch
instructions (code + unit files + tests only this wave; no bench deploy, no service
restart). Acceptance-criteria items 1–4 (`systemctl show`, wedge restart, targeted
Mayhem, 48 h soak) and the regression-checklist "Mayhem" and "48 h soak" rows are
therefore NOT YET satisfied — do not merge until the deploy/soak wave closes them.
· Phase: P0 · Effort: M (≈4–6 h + 48 h soak) · Difficulty: med · Risk: med*

## Objective
A live-but-wedged `lexa-hub` (deadlocked tick loop, stalled paho publish, hung state
read) is automatically restarted by systemd within ~60 s: the unit gains
`Type=notify` + `WatchdogSec=60`, and the hub emits `READY=1` at startup and
`WATCHDOG=1` from its per-tick plan observer — via a minimal hand-rolled
`NOTIFY_SOCKET` writer, no new dependency.

## Background
Verified current state:
- `lexa-hub/systemd/lexa-hub.service`: `Type=simple`, `Restart=on-failure`,
  `RestartSec=5s`, no `WatchdogSec`. A crash restarts; a wedge never does — review §11:
  "your own C08 investigation hypothesized exactly this wedge."
- The hub's control loop is `Engine.run()` in
  `lexa-hub/internal/orchestrator/engine.go` (line ~248): one goroutine ticking every
  `engine_interval_s` (3 s FAST / 15 s STOCK; `configs/hub.json` ships 15). With the
  Tier-1 fast loop configured it ticks at `safetyInterval` and runs the economic pass
  every Nth tick.
- `cmd/hub/main.go` wires `orchestrator.Config.PlanObserver` (the `planObserver` closure,
  main.go ~line 103). The engine calls it **on the engine goroutine on every economic
  tick** (engine.go `tick()` step 5) and on safety passes that produce commands. If the
  engine goroutine wedges anywhere in `tick()` — `ReadSystemState`, `Optimize`,
  `executePlan` (synchronous MQTT publishes, 5 s PUBACK timeout each), or the observer's
  own publishes — the observer stops being called. That makes it the correct liveness
  point: **the heartbeat must ride the tick loop, not a timer goroutine** (a timer would
  happily kick while the control loop is dead).
- sd_notify protocol: write datagrams like `READY=1` / `WATCHDOG=1` to the unix socket
  in `$NOTIFY_SOCKET` (an abstract or filesystem `unixgram` address; `@`-prefixed means
  abstract). ~30 lines of Go with `net.DialUnix`. `coreos/go-systemd` would do it but is
  a new supply-chain item for one datagram — decision: hand-roll (record in the PR).

**WatchdogSec sizing (justify in the unit file comment):** ≥4× the slowest economic tick
(stock 15 s → ≥60 s). Worst legitimate tick under a sick-but-alive broker: plan-log
publish (5 s timeout) + breach alert (5 s) + up to 4 actuator publishes (4×5 s) ≈ 30 s —
still under 60. So `WatchdogSec=60` is safe for both FAST and STOCK and still catches a
true wedge in ≤1 min. (This also quantifies review §11's "synchronous publish waits"
risk — fixed properly by TASK-046; the watchdog must tolerate it meanwhile.)

## Why this task exists
Review §11 first bullet / §14 item 5: no watchdog anywhere; heartbeat exists
(`lexa/hub/plan`) but nothing acts on it. AD-011 (crash-only design) explicitly extends
to "live-but-wedged" via watchdogs.

## Architecture review sections
§11 (watchdog), §14 item 5, W5-adjacent (restart re-seeds from retained topics),
AD-011; RSK-08 (flap risk); 03 P0 risks ("WatchdogSec ≥ 4× tick, soak 48 h").

## Prerequisites
TASK-001 (commit discipline). TASK-002 useful (CI). Bench access to 69.0.0.1.

## Files
- **Read first:** `lexa-hub/internal/orchestrator/engine.go` (`run()`, `tick()`,
  `safetyTick()`, `Config.PlanObserver`), `lexa-hub/cmd/hub/main.go` (planObserver
  closure, engine start), `lexa-hub/systemd/lexa-hub.service`,
  `lexa-hub/scripts/deploy-hub-pi.sh` (unit install path).
- **Modify:** `lexa-hub/cmd/hub/main.go` (wire kicks + READY),
  `lexa-hub/systemd/lexa-hub.service`.
- **Create:** `lexa-hub/internal/watchdog/watchdog.go` (+ `watchdog_test.go`).

## Blast radius
New tiny package `internal/watchdog` (pure Go, no deps). `cmd/hub/main.go` planObserver
closure gains one call. Unit file semantics change (`Type=notify`: systemd now waits for
READY before "started"). **No change** to `internal/orchestrator` — the radioactive zone
stays untouched.

## Implementation strategy
Introduce the package, wire it in cmd/hub only (TASK-008 rolls it out to the other
five), deploy to the hub Pi behind the existing unit-file install path, verify the
restart-on-wedge behavior with a forced stall, then 48 h bench soak with zero spurious
fires before calling it done.

## Detailed steps
1. Create `internal/watchdog`:
   - `func Enabled() bool` — true iff `NOTIFY_SOCKET` set.
   - `func Ready()` — send `READY=1` (ignore errors; log once).
   - `func Kick()` — send `WATCHDOG=1`; must be allocation-light and non-blocking
     (`SetWriteDeadline` ~100 ms; drop on failure — a missed kick under real trouble is
     the desired signal).
   - Handle abstract sockets (`@` → leading NUL) and plain paths. No goroutines, no
     state beyond the dialed conn (lazy-init, mutex-guarded).
   - Unit test with a fake `NOTIFY_SOCKET` unixgram listener asserting datagram content.
2. `cmd/hub/main.go`: at the top of the `planObserver` closure add `watchdog.Kick()`
   (first line — before any publish, so a sick broker's 5 s waits don't delay the kick
   *for that tick*; the next tick's kick is what detects a full wedge). After
   `eng.Start()` call `watchdog.Ready()`.
3. `systemd/lexa-hub.service`: `Type=notify`, `WatchdogSec=60`, `NotifyAccess=main`,
   plus a comment block with the 4×-tick sizing math from Background. Keep
   `Restart=on-failure` (watchdog fire counts as failure) and `RestartSec=5s`.
4. Local check: `NOTIFY_SOCKET` unset → binary runs unchanged (dev laptops, tests).
5. Build arm64 (`make build-arm64`; sysroot note), deploy via
   `bash scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`, **re-run
   `scripts/hub-replay-tune.sh fast`**. Confirm `systemctl show lexa-hub -p
   WatchdogUSec,NotifyAccess,Type` and that the unit is `active (running)` (READY
   arrived).
6. Wedge test on the Pi: `sudo kill -STOP $(pidof lexa-hub)`; within ≤60 s systemd must
   log a watchdog timeout and restart the service; retained `lexa/csip/control` re-seeds
   state (this is the `hub-restart-mid-cap` recovery path). `kill -CONT` beforehand if
   the STOP'd process lingers. Record journal evidence.
7. Targeted Mayhem sanity (the kick rides the tick under broker faults):
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only
   mqtt-broker-restart,mqtt-broker-latency,hub-restart-mid-cap` — verdicts unchanged, and
   `journalctl -u lexa-hub | grep -i watchdog` shows **zero** fires during the run.
8. 48 h soak (bench idle + normal demo traffic): zero watchdog fires
   (`systemctl show lexa-hub -p NRestarts` stable). Then merge.

## Testing changes
- `internal/watchdog/watchdog_test.go`: datagram content for Ready/Kick; no-op when
  unset; abstract-socket path.
- Run: `go test -race ./internal/watchdog/` (joins `make test` automatically).

## Documentation changes
- `lexa-hub/CLAUDE.md`: note under invariants/ops: "lexa-hub is Type=notify with
  WatchdogSec=60; the kick rides the engine tick via PlanObserver — anything that stops
  the tick loop for >60 s restarts the service (intended)."
- 00_MASTER_INDEX status.

## Common mistakes to avoid
- Kicking from a separate timer goroutine — defeats the entire purpose; a wedged tick
  must starve the heartbeat (brief/review both explicit on this).
- `Type=notify` without sending READY — systemd kills the service at start timeout.
  READY goes right after `eng.Start()`.
- Editing `internal/orchestrator` to add a hook — unnecessary (PlanObserver already runs
  on the engine goroutine every economic pass) and radioactive (05 §12).
- Forgetting `hub-replay-tune.sh fast` after the deploy (STOCK-reset gotcha).
- Sizing WatchdogSec at 4×3 s=12 s because the bench runs FAST — the product ships
  STOCK (15 s); 12 s would flap in production timing. 60 s covers both.
- Using `pkill -f` over SSH during tests — can kill your own session; use
  `systemctl`/`kill $(pidof …)`.

## Things that must NOT change
- Engine tick semantics and ordering (observer → executePlan) — untouched.
- planObserver's existing duties: breach-edge alerting (`activeBreachMRID` logic,
  QA reject-write/enable-gate-curtail findings) and dedupe resets (QA 2026-07-03
  0 W-ceiling finding) run exactly as before; the kick is prepended, nothing reordered.
- `Restart=on-failure` + retained-topic re-seed recovery (backs `hub-restart-mid-cap`
  PASS).
- Crash-only design (AD-011): no `recover()` added anywhere.

## Acceptance criteria
- [ ] `systemctl show lexa-hub -p WatchdogUSec` = 1min on the Pi; unit active with Type=notify.
- [ ] `kill -STOP` wedge → automatic restart ≤60 s, journal shows watchdog timeout (evidence pasted in PR).
- [ ] Targeted scenarios (step 7) verdict-identical; zero watchdog fires during run.
- [ ] 48 h soak: zero fires, `NRestarts` unchanged.
- [ ] `NOTIFY_SOCKET` unset ⇒ behavior identical to today (dev/test).

## Regression checklist
- [ ] `go test -race ./internal/...` green (lexa-hub)
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: targeted `mqtt-broker-restart,mqtt-broker-latency,hub-restart-mid-cap`
- [ ] 48 h soak on bench before merge (03 P0 risk mitigation)

## Mayhem scenarios affected
`hub-restart-mid-cap` (restart path now also reachable via watchdog — behavior must stay
PASS); `mqtt-broker-*` (tick slow-down under broker faults must NOT fire the watchdog).

## Conformance implications
None (no protocol surface). Restart behavior remains fail-closed via retained control +
scheduler discipline.

## Suggested commit message
`feat(hub): systemd watchdog — sd_notify from the tick loop, WatchdogSec=60 (review §11 item 5)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** lexa-hub watchdog: Type=notify + WatchdogSec=60, kicks ride the engine tick
**Description:** Hand-rolled NOTIFY_SOCKET writer (no new dep — decision documented);
kick in PlanObserver so a wedged tick starves the heartbeat. Sizing math in the unit
file. Evidence: STOP-wedge restart journal, targeted scenario verdicts, 48 h soak.
Rollback: revert unit file to Type=simple (binary's kicks become no-ops).

## Code review checklist
- Kick is first statement in planObserver; no goroutine-based timer anywhere.
- Socket writer non-blocking with deadline; no error can panic or stall the tick.
- Unit comment contains the 4×-stock-tick justification.
- Soak + wedge evidence attached.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated.

## Possible follow-up tasks
TASK-008 (other five services), TASK-044/045 (metrics + heartbeat-stall alerting consume
the same liveness concept), TASK-046 (removes the 5 s sync-publish worst case).
