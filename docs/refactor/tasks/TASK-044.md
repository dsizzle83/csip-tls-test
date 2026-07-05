# TASK-044 — Prometheus `/metrics` on all six services + bench scrape

*Status: DONE (2026-07-05, lexa-hub metrics ×6 merged pre-wave-gate; csip-tls-test
scrape config + BENCH.md ports landed at the wave gate — see closure note) ·
Phase: P4 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

**Wave-gate closure note (2026-07-05):** this file's status header had been left at
TODO despite the lexa-hub metrics code being merged and live (00_MASTER_INDEX already
listed 044 as done). Found at the wave gate: the paired csip-tls-test deliverable —
`scripts/prometheus-bench.yml` + the `docs/BENCH.md` port table — was never actually
committed (no file, no git history), contradicting both this task's own "Suggested PR
title & description" and the wave-gate brief's premise that it existed. Created both
per this file's §"Detailed steps" step 5 spec (static scrape of 69.0.0.1:9100–9105,
15 s interval, podman one-liner in the file header) and verified: all six `/metrics`
endpoints golden-format-checked (0 malformed lines each; no `promtool` on this desktop)
and `lexa_up 1` on all six from the desktop. Counters-move criterion (forcing an MQTT
publish failure via a live mosquitto stop) was deliberately skipped — disruptive to the
concurrently-running full Mayhem campaign and not requested by the wave-gate brief;
the mqtt-broker-restart scenario in that campaign exercises the same reconnect path
indirectly. `lexa_mb_shadow_*` counters (TASK-027) also present and correctly typed —
that package's metrics registration composes cleanly with this one's.

## Objective
Every lexa service exposes a Prometheus-text-format `/metrics` endpoint with
the core operational signals (tick duration, MQTT publish failures, control
adoption age, convergence/breach state, goroutines/fds/RSS), and the bench
desktop scrapes them — turning "QA needs journal forensics to see it" into
"there is a metric" (05 §9).

## Background
Repo `~/projects/lexa-hub` (product), plus a scrape config in
`~/projects/csip-tls-test`. Today the only HTTP surface in the product is
lexa-api's `:9100` (`cmd/api/config.go` `ListenAddr`, default ":9100");
the other five services have no listener. Review "Operational readiness: D
— no metrics".

**Library decision (make it in this task, record in 02):** use a minimal
in-repo `internal/metrics` package emitting Prometheus text exposition
(counters + gauges, no labels beyond fixed name suffixes), NOT
`prometheus/client_golang`. Justification: the repo's dependency posture is
deliberately lean (compare `cmd/mqttproxy/inject.go`, which hand-rolls MQTT
3.1.1 rather than import paho into the harness); client_golang pulls a
sizeable dependency tree into six `CGO_ENABLED=0` services for what is here
~40 metric series; the text format is trivial
(`name{} value\n` + `# TYPE` lines). If a reviewer prefers client_golang,
the package's API is shaped so the swap is mechanical — note this in the
package doc.

Ports (checked against docs/BENCH.md + quick port map — 11111/11112, 8080,
5020/6020, 5021/6021, 5022/6022, 6024, 9100, 8887, and mqttproxy 11882 are
taken): metrics listeners
`lexa-hub :9101 · lexa-northbound :9102 · lexa-modbus :9103 ·
lexa-ocpp :9104 · lexa-telemetry :9105 · lexa-api :9100/metrics (existing
listener, new route)`. Config key `metrics_addr` per service JSON (empty =
default above; `"off"` disables). Bench configs bind the LAN IP (scrapable
from the desktop, as step 6's curl loop assumes); the product default stays
127.0.0.1 — the bench bind is a bench property, mirroring AD-008's stance.

Metric inventory (initial; names snake_case with unit suffixes):
- all services: `lexa_up` (gauge 1), `lexa_goroutines`, `lexa_open_fds`
  (count `/proc/self/fd`), `lexa_rss_bytes` (`/proc/self/statm` × page),
  `lexa_mqtt_publish_failures_total`, `lexa_mqtt_reconnects_total`,
  `lexa_bus_decode_failures_total` (hook exists after TASK-042).
- hub: `lexa_hub_tick_duration_seconds` (gauge, last), 
  `lexa_hub_tick_overruns_total` (real source lands in TASK-046 — register
  the counter now), `lexa_hub_control_adoption_age_seconds` (now − last
  ActiveControl change), `lexa_hub_breach_active` (0/1),
  `lexa_hub_breaches_total`, `lexa_hub_dispatches_total`,
  `lexa_hub_control_stale_adoptions_total` + `lexa_hub_rewalk_requests_total`
  (TASK-042 counters).
- northbound: `lexa_nb_walk_duration_seconds`, `lexa_nb_walk_failures_total`
  (`discoveryFailures` exists, cmd/northbound/main.go:264),
  `lexa_nb_responses_posted_total`, `lexa_nb_clock_offset_seconds`.
- modbus: `lexa_mb_poll_duration_seconds`, `lexa_mb_device_reconnects_total`,
  `lexa_mb_write_failures_total`, `lexa_mb_interlock_trips_total`.
- ocpp/telemetry: connection state gauge + post/transaction counters.
MQTT counters need small hooks in `internal/mqttutil` (publish failure,
reconnect — the `SetConnectionLostHandler`/`OnConnect` sites,
mqttutil.go:88–94, 119–129).

## Why this task exists
Review §11/Top-20 item 14: no metrics, no way to see reconnect storms, tick
overruns, queue problems, or resource leaks; GAP-12's soak (TASK-078) and
GAP-06/10's oracles (TASK-049/051) explicitly need these counters.

## Architecture review sections
§11 (reliability findings), §13 (observability of tribal state), item 14.
Roadmap: 03 Phase 4; 05 §9; 07 GAP-06/10/12 (consumers); 04 row 044.

## Prerequisites
None. (TASK-042/046/007 add richer sources for some counters — register
the names now, wire later; a registered-but-zero counter is fine.)

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go`
  - `~/projects/lexa-hub/cmd/api/{main.go,config.go,handlers.go}` (existing HTTP wiring to copy)
  - `~/projects/lexa-hub/cmd/{hub,northbound,modbus,ocpp,telemetry}/main.go` + `config.go` (wiring points)
  - `~/projects/csip-tls-test/docs/BENCH.md` (ports)
- **Modify:**
  - `~/projects/lexa-hub/internal/mqttutil/mqttutil.go` (failure/reconnect counters via injectable hooks)
  - all six `cmd/*/main.go` + `cmd/*/config.go` + `configs/*.json`
- **Create:**
  - `~/projects/lexa-hub/internal/metrics/metrics.go` (+ `metrics_test.go`)
  - `~/projects/csip-tls-test/scripts/prometheus-bench.yml` (scrape config)

## Blast radius
Adds an HTTP listener to five services (new network surface — bench-only
acceptability must be documented per 05 §7; the SOM product story is
"metrics_addr binds localhost by default, exposed deliberately").
`internal/mqttutil` gains counters (behavior unchanged). No control-path
changes.

## Implementation strategy
Build `internal/metrics` (Registry with `Counter(name)`/`Gauge(name)`,
`Handler() http.Handler`, plus a `Collect(func(*Registry))` hook for
scrape-time gauges like fds/RSS/goroutines). Wire per service:
`metrics.Serve(addr)` in main (own goroutine, `http.Server` with
ReadHeaderTimeout). Instrument mqttutil via package-level counters injected
from the registry (avoid import cycles: metrics package is a leaf; mqttutil
takes an optional `Instrumentation{OnPublishFail, OnReconnect func()}`).
Then the scrape config + verification on the bench.

## Detailed steps
1. `internal/metrics`: ~150 lines. Text format:
   `# TYPE <name> counter|gauge` + `<name> <value>`; float formatting via
   `strconv.FormatFloat(v,'g',-1,64)`. Thread-safe (atomic/mutex). Unit
   tests: registration idempotence, output format golden test, concurrent
   increments under `-race`.
2. Process gauges collector: goroutines (`runtime.NumGoroutine`), RSS
   (parse `/proc/self/statm` field 2 × `os.Getpagesize()`), fds
   (`os.ReadDir("/proc/self/fd")` length). Linux-only fine (deploy targets
   are Linux; guard with build tag or runtime check returning 0).
3. mqttutil instrumentation: counters for publish timeout/error
   (publishJSON error paths, mqttutil.go:125–128), reconnect
   (OnConnectHandler after first connect), connection-lost. Nil-safe when
   uninstrumented.
4. Per-service wiring (six small diffs): config key, registry, serve,
   service-specific counters listed in Background. Hub: time each
   `tick()`/`executePlan` via the existing `PlanObserver` timestamp or a
   wrapper in cmd/hub — do NOT modify `internal/orchestrator` (I/O-free
   rule); measure around `eng` callbacks in cmd/hub where possible, else
   defer detailed timing to TASK-046 and expose adoption-age/breach metrics
   now (both computable in cmd/hub from existing state).
5. `scripts/prometheus-bench.yml` (csip-tls-test): static scrape of
   69.0.0.1:9101–9105 + 69.0.0.1:9100, 15 s interval, plus a comment with
   the one-liner to run it on the desktop:
   `podman run --rm -p 9090:9090 -v $PWD/scripts/prometheus-bench.yml:/etc/prometheus/prometheus.yml docker.io/prom/prometheus`
   (or a native prometheus binary if installed — keep both notes; this file
   is config + runbook comment, no service unit).
6. Deploy all six services (`make build-arm64 && bash
   scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`; then
   `~/projects/csip-tls-test/scripts/hub-replay-tune.sh fast`). Verify:
   `for p in 9100 9101 9102 9103 9104 9105; do curl -s http://69.0.0.1:$p/metrics | head -3; done`.
7. Run one full FAST campaign — metrics collection must not perturb
   verdicts.

## Testing changes
- `internal/metrics` unit tests (format, concurrency).
- mqttutil instrumentation test (counter increments on forced publish
  failure via disconnected client).
- Bench: step 6 curl evidence + campaign.
- Run: `go test -race ./internal/... ./cmd/...`.

## Documentation changes
- 02: new AD note — "AD-0xx metrics: minimal in-repo text exposition, not
  client_golang (rationale); port map 9100–9105".
- lexa-hub CLAUDE.md: port list + `metrics_addr` key.
- csip-tls-test docs/BENCH.md: add metrics ports to the port map.

## Common mistakes to avoid
- Import cycles: `internal/metrics` must import nothing from lexa-hub;
  mqttutil hooks are function values, not registry imports.
- Don't block anything on the metrics listener: `Serve` failures log and
  continue (a port collision must not kill lexa-hub).
- Don't add per-message metrics work in hot paths beyond an atomic add.
- fd counting opens a dir handle itself — fine, but do it at scrape time
  only, never per tick.
- `internal/orchestrator` stays I/O-free — no metrics imports there
  (05 §1); hub-side wrappers only.
- New network surface: default bind should be the LAN-appropriate address
  via config; document the bench-only openness (05 §7, BENCH.md gotcha
  pattern).
- Deploy gotcha: `hub-replay-tune.sh fast` after deploy.

## Things that must NOT change
- No control-flow changes anywhere — instrumentation is strictly additive;
  the full-campaign gate exists to prove it.
- lexa-api's existing `/status`, `/logs` behavior on :9100 (dashboard + QA
  harness + metersim consume it — review W7 list).
- mqttutil publish/subscribe semantics (QoS 1, 5 s timeout, resubscribe
  replay — `mqtt-broker-restart` scenario ledger).
- systemd unit files unchanged (listeners come from service config, not
  units).

## Acceptance criteria
- [x] All six endpoints serve valid exposition text (no `promtool` on this desktop;
      golden-format regex check: 0 malformed lines across all six /metrics bodies).
- [~] Counters move: SKIPPED live (stopping mosquitto mid-campaign was blocked as
      disruptive); `lexa_mqtt_publish_failures_total`/`lexa_mqtt_reconnects_total`
      are present, correctly typed, and the full campaign's mqtt-broker-restart
      scenario exercises the same reconnect path indirectly.
- [x] Bench scrape config resolves all targets — `scripts/prometheus-bench.yml`
      created at the wave gate (was missing); `curl` loop evidence: `lexa_up 1` on
      all six (69.0.0.1:9100–9105) from the desktop.
- [x] Full FAST campaign ≤ baseline — see wave-gate campaign report `qa-mayhem-20260705-151009.md` (34P/17D/0F/0B, within the 32–35P band; targeted battery set `qa-mayhem-20260705-140802.md`).
- [x] `go test -race ./internal/... ./cmd/...` green.

## Regression checklist
- [x] `go test -race ./internal/...` (lexa-hub) green (+ `./cmd/...`)
- [x] Conformance logic tests: none (no protocol surface)
- [x] Mayhem: full FAST campaign (six services redeployed) — see wave-gate report.
- [x] `hub-replay-tune.sh fast` re-applied after deploy (confirmed post-restart:
      engine=3s/discovery=5s/poll=2s).

## Mayhem scenarios affected
None should change verdict. Enables future oracles: TASK-049 (reconnect
counter), TASK-051 (publish-failure/drop counters), TASK-078 soak trends,
TASK-045 heartbeat alert metric.

## Conformance implications
None.

## Suggested commit message
`feat(metrics): /metrics on all six services + minimal exposition library; bench scrape config (TASK-044)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Metrics endpoints for all services + bench Prometheus scrape (TASK-044)
**Description:** Minimal in-repo Prometheus text exposition (dependency-lean,
rationale in 02); ports 9100–9105; mqttutil failure/reconnect counters;
process gauges. Additive only; campaign-gated. Paired csip-tls-test commit
adds scripts/prometheus-bench.yml + BENCH.md ports. Rollback: config
`metrics_addr:"off"` or revert.

## Code review checklist
- No hot-path allocation/locking beyond atomics.
- Port collisions handled non-fatally.
- Exposition format valid (TYPE lines, no NaN output — skip NaN gauges).
- orchestrator untouched.
- Both repos' commits reference each other (lockstep rule 05 §11).

## Definition of done
Acceptance + regression checklists green; 02/CLAUDE.md/BENCH.md updated;
status headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-045 (heartbeat alerting consumes these), TASK-046 (tick overrun
counter source), TASK-049/051 (scenario oracles), TASK-078 (soak trends),
TASK-072 (cert-expiry gauge).
