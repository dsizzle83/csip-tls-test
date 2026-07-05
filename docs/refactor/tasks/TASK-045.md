# TASK-045 — Structured logging + plan-heartbeat stall alerting

*Status: DONE (2026-07-05, lexa-hub@0645827) · Phase: P4 · Effort: M (≈4–6 h) · Difficulty: low · Risk: low*

Implemented on `lexa-hub` branch `task/045-logging` (worktree lane; not yet
merged/reviewed). Code + tests only — bench validation (stop/start lexa-hub,
Mayhem `hub-restart-mid-cap`/`export-cap-full-battery` spot runs + full FAST
campaign, `hub-replay-tune.sh fast` re-apply) is **batched at the wave gate**
per this session's launch instructions, not run here. Deviation: the hub
priority list's TASK-037 (wall-clock policy) and TASK-042 (retained-control
staleness/corrupt-alarm) call sites do not exist yet (both still TODO
upstream) — skipped rather than invented ahead of their own tasks;
`docs/JOURNAL_FORENSICS.md` (TASK-040) also does not exist yet, so nothing to
refresh there. See the commit message for the full migration/demotion list.

## Objective
Move the six services onto `log/slog` structured logging with
transition-not-steady-state discipline, and make the existing retained
`lexa/hub/plan` heartbeat actionable: lexa-api detects a stalled plan
timestamp, exposes it as an alarm metric + `/status` field with an
INCONCLUSIVE-safe distinction between "never seen" and "stalled", and the
crash-only operating model (AD-011) gets written down in operator terms.

## Background
Repo `~/projects/lexa-hub`, Go 1.21 (go.mod) — `log/slog` is stdlib.

- Logging today is `log.Printf` with ad-hoc `[hub]`/`lexa-hub:` prefixes
  (grep any `cmd/*/main.go`). Journald is the sink (systemd units). The
  QA culture greps exact strings (e.g. the harness reads journals in
  diagnosis), so line CONTENT must be preserved where scenarios grep it.
- The heartbeat already exists: `bus.PlanLog` published **retained** on
  `lexa/hub/plan` (`bus.TopicHubPlan`) on EVERY engine pass — economic and
  safety tick alike — by the planObserver (cmd/hub/main.go:124–132); the
  topic doc (internal/bus/topics.go:53–61) says: "a hub whose /status
  last_plan timestamp stops advancing has a wedged control loop (QA gaps
  doc, 'wedge detection')". lexa-api subscribes (cmd/api/main.go:93–95,
  `store.onPlanLog`) and serves it as `/status.last_plan`
  (cmd/api/handlers.go:107–120). **Nothing consumes it for action**
  (review §11: "You now publish a plan heartbeat; nothing consumes it for
  action").
- Stall threshold: the hub publishes at the safety-tick cadence
  (`safety_interval_s` default 1 s; FAST bench) and at worst the economic
  cadence (`engine_interval_s`, 15 s STOCK). A stall bound of
  `5 × engine_interval_s` (75 s STOCK / 15 s FAST) is safe in both modes;
  lexa-api doesn't know the hub's interval — make it config
  (`plan_stall_after_s`, default 75).
- AD-011: crash-only is intentional — no blanket `recover()`; systemd
  restarts (5 s); retained topics re-seed. TASK-007/008 add watchdogs.
  This task documents the model for operators (what a restart means, what
  is lost, what to check) — the review asked for exactly this
  (§10.6 "document it as the intended crash-only design").

## Why this task exists
Top-20 item 14 (second half), §11 watchdog finding (heartbeat unconsumed),
§13 (tribal observability), 05 §9 ("every service: a heartbeat… if QA needs
journal forensics to see it, it needs a metric").

## Architecture review sections
§10.6 (crash-only doc), §11 (heartbeat), item 14. Roadmap: 02 AD-011;
03 Phase 4; 05 §9; 04 row 045 (depends on 044).

## Prerequisites
TASK-044 DONE (metrics registry to expose the alarm). Bench FAST for the
validation run.

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/bus/topics.go` (TopicHubPlan doc), `messages.go` (PlanLog)
  - `~/projects/lexa-hub/cmd/api/{main.go,state.go,handlers.go}` + `plan_test.go`
  - `~/projects/lexa-hub/cmd/hub/main.go` (planObserver)
  - `docs/refactor/05_ENGINEERING_PRINCIPLES.md` §9 (this repo)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` lines 440–560 (what the sampler greps from /status — `decisionLine`, `last_plan` usage)
- **Modify:**
  - `~/projects/lexa-hub/cmd/api/{main.go,state.go,handlers.go,config.go}` (stall detection + /status field + metric)
  - `~/projects/lexa-hub/cmd/{hub,northbound,modbus,ocpp,telemetry,api}/main.go` (slog setup; call-site migration limited — see strategy)
- **Create:**
  - `~/projects/lexa-hub/internal/logutil/logutil.go` (slog handler setup helper: service name attr, text key=value handler, level from env/config)
  - `~/projects/lexa-hub/docs/OPERATIONS.md` (crash-only operator doc)

## Blast radius
Log output format for migrated call sites (journald consumers: humans, the
Mayhem diagnosis snippets that quote logs, `docs/JOURNAL_FORENSICS.md`
recipes). lexa-api `/status` gains a field (additive JSON — dashboard and
harness tolerate unknown fields). No control-path changes.

## Implementation strategy
Pragmatic slog adoption: one `logutil.Setup(service string)` installing a
`slog` default with a text handler writing key=value to stderr (journald
adds timestamps — do not duplicate them). Migrate **structured-value call
sites** (state transitions: staleness edges, adoption/release, breach
edges, reconnects) to `slog` with stable keys; leave low-value `log.Printf`
lines as-is (slog's default bridge keeps them working) — a full sweep is
churn without payoff and risks QA-grep breakage. Heartbeat alerting is a
small state machine in lexa-api's store. Operator doc last.

## Detailed steps
1. `internal/logutil`: `Setup(service string, level slog.Level)` →
   `slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("svc", service))`.
   Level from service config (`"log_level": "info"` default) — add the key
   to each config struct with a default.
2. Call it first thing in each of the six `main()`s.
3. Migrate transition sites to slog (keep message text recognizable —
   prepend nothing, keys carry the data). Priority list (verified sites):
   - hub: staleness edges (`noteStaleness`, state.go:181–195), frozen-meter
     edges (state.go:318–331), control adoption/expiry (state.go:348–371),
     breach begin/clear (main.go:141–145), local-step alarm (TASK-037),
     stale-adoption/decode alarms (TASK-042).
   - northbound: discovery error/hold (main.go:264–266), rewalk handling
     (TASK-042), response posts (main.go:826 region).
   - modbus: reconnect/reassert lines (main.go:347, 356, 445 region).
   For each migrated line that a Mayhem diagnosis or the forensics doc
   greps, keep the distinctive phrase intact (e.g. "COMPLIANCE BREACH",
   "STALE") — grep csip-tls-test `cmd/dashboard/*.go` and
   `docs/JOURNAL_FORENSICS.md` for quoted fragments before changing text.
4. Per-tick lines audit: anything logging every tick at info level gets
   demoted to debug or made edge-triggered (05 §9 + TASK-009 flash budget).
   List the demotions in the PR.
5. Heartbeat stall detection (lexa-api): store tracks
   `lastPlanTs` (server value) AND `lastPlanArrivedAt` (monotonic
   `time.Now()` at onPlanLog — arrival stamping, TASK-037 pattern). A
   ticker (5 s) evaluates: state `ok` / `stalled`
   (`time.Since(lastPlanArrivedAt) > plan_stall_after_s`) / `never`
   (no PlanLog ever — fresh boot or hub never up; retained delivery means
   even a restarted api usually has one — `never` must NOT alarm, it's the
   INCONCLUSIVE-safe state). Edge-triggered slog alarm on ok→stalled and
   recovery; metric `lexa_api_plan_heartbeat_stalled` gauge 0/1 +
   `lexa_api_plan_heartbeat_age_seconds`; `/status` gains
   `"plan_heartbeat": {"state": "ok|stalled|never", "age_s": N}`.
6. `docs/OPERATIONS.md`: one page — the crash-only contract (AD-011): what
   dies with a service (RAM guard state, breach episode pre-041), what
   comes back (retained control, snapshot post-041, journal), what restarts
   look like (systemd 5 s, watchdog post-007/008), what to check after
   (heartbeat state, /status control, journal tail), and the explicit rule:
   do not add `recover()`.
7. Deploy; verify: stop lexa-hub (`sudo systemctl stop lexa-hub`) → within
   `plan_stall_after_s` the api reports `stalled` + metric flips; start →
   recovery. Run `python3 scripts/mayhem.py --dashboard
   http://localhost:8080 --only hub-restart-mid-cap,export-cap-full-battery`
   + full campaign (log-format changes are the risk — the harness's
   `decisionLine`/status parsing must be unaffected since it reads JSON,
   not logs; the campaign proves it).

## Testing changes
- Unit: heartbeat state machine (never/ok/stalled/recovered transitions,
  injected clock) in `cmd/api`; extend `plan_test.go` for the new /status
  field.
- logutil: handler smoke test (key=value output contains svc attr).
- Run: `go test -race ./internal/... ./cmd/...`; bench validation step 7.

## Documentation changes
- New `~/projects/lexa-hub/docs/OPERATIONS.md` (step 6).
- 02 AD-011: add "documented in operator terms (docs/OPERATIONS.md)".
- lexa-hub CLAUDE.md: log-level config key; heartbeat /status field.
- `docs/JOURNAL_FORENSICS.md` (TASK-040): refresh any quoted log lines that
  changed shape.

## Common mistakes to avoid
- Breaking QA greps: search BOTH repos for quoted log fragments before
  rewording any migrated line
  (`grep -rn "COMPLIANCE BREACH\|STALE\|holding last" ~/projects/csip-tls-test/cmd/dashboard`).
- Duplicating timestamps into journald (slog default adds `time=` — that is
  fine and greppable; do NOT also print RFC3339 in the message).
- Alarming on `never`: a bench bring-up order where api starts before hub
  would page falsely; `never` is silent by design.
- The stall ticker uses ARRIVAL time (monotonic), not `PlanLog.Ts` (a hub
  with a stepped clock would false-alarm — TASK-037 lesson).
- Do not touch `internal/orchestrator` logging (I/O-free; it returns
  decisions, cmd/hub logs them).
- Retained PlanLog redelivery on api reconnect resets `lastPlanArrivedAt` —
  that is correct (bus is alive) but the plan Ts may be old: the stall
  detector must key on arrival age only, and expose plan-ts age separately.

## Things that must NOT change
- `/status` existing fields and semantics (`last_plan` relay behavior,
  cmd/api/plan_test.go pins it; the QA harness's decision introspection
  depends on it — topics.go:53–61 history).
- PlanLog publish cadence/retention (heartbeat producer, cmd/hub) — this
  task only consumes.
- AD-011: no `recover()` added anywhere.
- Log lines quoted by Mayhem diagnoses/docs keep their distinctive
  fragments.

## Acceptance criteria
- [x] All six services boot with slog text output including `svc=` attr —
      verified via `internal/logutil`'s handler smoke test
      (`TestSetupTextHandlerHasSvcAttr`), not a live bench journal excerpt
      (batched at wave gate).
- [ ] Stop/start lexa-hub on the bench: api `/status.plan_heartbeat` goes
      ok→stalled→ok; metric follows; alarm logs are edge-triggered (exactly
      one line each way). — **BATCHED AT WAVE GATE.** Unit-proven instead:
      `cmd/api.TestHeartbeatOkThenStalledThenRecovered` and
      `TestHeartbeatTickEdgeTriggeredExactlyOnce` (injected clock; asserts
      exactly one "stalled" line and one "recovered" line across repeated
      ticks while each state persists, and re-arms on a second episode).
- [x] `never` state verified: `cmd/api.TestHeartbeatNeverBeforeAnyPlanLog`
      (no PlanLog ever ⇒ never, indefinitely, no alarm) — unit-level;
      bench "fresh api with hub stopped and retained topic cleared" variant
      batched at wave gate.
- [x] Per-tick info-level log audit table in the PR — see the implementer's
      final report / commit message: northbound discovery-OK (per-walk),
      ocpp bare MeterValues + TransactionEvent Updated (per-sample), and
      telemetry per-post line, all demoted Info→Debug; three call sites
      reviewed and left at Info because they are already bounded to ≥60s by
      an existing dedupe/reassert window (modbus battery/solar "control
      applied").
- [ ] Full FAST campaign ≤ baseline. — **BATCHED AT WAVE GATE** (no bench
      access in this lane).

## Regression checklist
- [x] `go test -race ./internal/... ./cmd/...` (lexa-hub) green
- [x] Conformance logic tests: none (confirmed — no conformance suite
      touches logging or /status)
- [ ] Mayhem: `hub-restart-mid-cap` + `export-cap-full-battery` spot runs +
      full campaign — **BATCHED AT WAVE GATE**
- [ ] `hub-replay-tune.sh fast` re-applied after deploy — **BATCHED AT WAVE
      GATE** (no deploy performed in this lane)

## Mayhem scenarios affected
None should change verdict. The heartbeat alarm gives future scenarios a
wedge oracle (the C08 investigation class); note it in QA_FINDINGS if the
harness later consumes `/status.plan_heartbeat`.

## Conformance implications
None.

## Suggested commit message
`feat(logging,api): slog structured logging + plan-heartbeat stall alarm; crash-only operator doc (TASK-045)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Structured logging + heartbeat stall alerting + crash-only doc (TASK-045)
**Description:** slog with per-service attrs and transition-only discipline
(demotion table included); lexa-api now ACTS on the retained lexa/hub/plan
heartbeat (stalled/never/ok, metric + /status field, arrival-time based);
AD-011 documented for operators. Additive; campaign-gated. Rollback: revert;
config log_level/plan_stall_after_s are optional keys.

## Code review checklist
- Grep evidence that no QA-quoted log fragment changed.
- Stall detection uses arrival monotonic age; `never` is silent.
- Demoted lines really are steady-state (spot-check three).
- OPERATIONS.md accurate against actual restart behavior (test one restart
  while reading it).

## Definition of done
Acceptance + regression checklists green; docs added/updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-007/008 (watchdogs — heartbeat becomes sd_notify source), TASK-078
(soak dashboards over these logs/metrics), backlog: dashboard tile for
plan_heartbeat.
