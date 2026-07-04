# TASK-070 — Context propagation walker-deep

*Status: TODO · Phase: P6 · Effort: M (≈4–6 h) · Difficulty: low · Risk: low*

## Objective
A `context.Context` flows from each service main through the discovery
loop into the walker and down to every fetcher call, so shutdown (and a
future watchdog-driven cancel) aborts an in-flight walk between fetches
instead of letting it run to completion. No other behavior changes.

## Background
Verified current state (lexa-hub):
- `cmd/northbound/main.go:173` creates `ctx, cancel :=
  context.WithCancel(context.Background())`; the discovery goroutine
  checks `ctx.Done()` only BETWEEN ticks (:220-228) — `runDiscovery`
  itself (post-TASK-068: `internal/northbound/run`) takes no ctx, so a
  shutdown mid-walk waits out the whole resource-tree fetch.
- `discovery.Walker` (internal/northbound/discovery/walker.go):
  `NewWalker(f Fetcher, lfdi string)` (:117), `Discover(dcapPath string)`
  (:132), and ~15 `fetchX(path)` helpers (:352-427) — none take ctx. The
  `Fetcher` interface consumed by the walker (defined in walker.go — read
  the exact shape) is `Get(path)`-style.
- `tlsclient.WolfSSLFetcher.Get/Post/GetStatus` (fetcher.go:105-151) — no
  ctx. True per-read cancellation is NOT available: wolfSSL does blocking
  read(2) on the fd with SO_RCVTIMEO (client.go:136-150), so cancellation
  granularity is "between HTTP requests, and within one request bounded
  by ReadTimeout." That is the honest contract this task implements and
  documents.
- Other services: `cmd/telemetry` also uses tlsclient (MUP POSTs) — give
  its loop the same treatment; `cmd/hub`/`cmd/modbus`/`cmd/ocpp`/`cmd/api`
  shutdown paths are out of scope except where they already have ctx
  (leave them).

## Why this task exists
R5 tail: "Add context propagation walker-deep." Today a SIGTERM during a
slow walk (server stalling short of the ReadTimeout) delays shutdown by
up to (resources × ReadTimeout); systemd then SIGKILLs, which is exactly
the unclean-death shape §9's persistence family worries about. Watchdog
integration (TASK-007/008) also wants a cancelable walk.

## Architecture review sections
R5 · §11 (goroutine hygiene: every goroutine has a shutdown path) ·
05 §4 · item 17.

## Prerequisites
TASK-068 DONE (the walk loop lives in `internal/northbound/run`; doing
this before 068 means threading ctx through code about to move).
TASK-069 coordination: if the http.Transport shim landed, `http.Request.
WithContext` gives per-request cancellation — integrate rather than
duplicate.

## Files
- **Read first:** internal/northbound/run/ (068 result),
  internal/northbound/discovery/walker.go (Fetcher interface + Discover),
  internal/tlsclient/fetcher.go + client.go, cmd/northbound/main.go,
  cmd/telemetry/main.go.
- **Modify:** walker.go (ctx parameter), the walker's Fetcher interface +
  both implementations (tlsclient real, walker_test.go fake),
  run package (RunOnce(ctx)), cmd/northbound/main.go,
  cmd/telemetry/main.go, internal/tlsclient/fetcher.go
  (`GetContext(ctx, path)` alongside `Get` or signature change — see
  step 2 decision).
- **Create:** none.

## Blast radius
lexa-northbound + lexa-telemetry (both CGo). Walker API (internal). No
config, no bus schema, no wire-format change. Behavior change is ONLY
faster shutdown.

## Implementation strategy
Thread `ctx` as the first parameter through Discover → fetchX → Fetcher,
checking `ctx.Err()` before each fetch (between-request granularity).
Keep the tlsclient signatures backward-compatible where telemetry uses
them, or update both callers in one commit — this repo has exactly two
consumers, so a clean signature change (`Get(ctx, path)`) is preferred
over parallel methods. Document the cancellation granularity on the
Fetcher interface.

## Detailed steps
1. Change the walker's `Fetcher` interface to context-first
   (`Get(ctx context.Context, path string) ([]byte, error)` — match the
   real interface shape found in walker.go, including GetStatus/Post if
   present there); update walker fakes in walker_test.go.
2. tlsclient: add ctx-first methods; implementation checks
   `ctx.Err()` before dialing/sending; NO attempt to interrupt a blocked
   wolfSSL read (SO_RCVTIMEO already bounds it) — doc comment states:
   "cancellation is honored between requests; an in-flight read returns
   within ReadTimeout."
3. `Discover(ctx, dcapPath)`: check ctx at each fetch site (the fetchX
   helpers take ctx); on cancellation return `ctx.Err()` wrapped with the
   walk stage (`fmt.Errorf("walk canceled at %s: %w", path, err)`).
4. run package: `RunOnce(ctx)`; ticker loop selects on ctx (already does
   post-068 — verify) and passes it down. A canceled walk must count as a
   failed walk for `discoveryFailures`/fail-closed logging ONLY if not
   shutting down — distinguish `errors.Is(err, context.Canceled)` and log
   at info, not the fail-closed warning (avoid poisoning triage greps
   with shutdown noise).
5. telemetry: same treatment for its POST loop.
6. Shutdown test: unit test that a Discover with a stalling fake fetcher
   returns promptly on cancel; service-level check on bench: `systemctl
   stop lexa-northbound` during an active walk completes in <2 s (journal
   timestamps).
7. Run `--only wan-outage-hold,northbound-hang` ×1 smoke (error-path
   logging touched).

## Testing changes
- walker_test.go: cancel-mid-walk test (fake fetcher blocks on ctx).
- tlsclient: ctx-preflight test.
- Run: `make test` (lexa-hub); bench smoke per steps 6-7.

## Documentation changes
- Fetcher interface doc: cancellation granularity contract.
- lexa-hub CLAUDE.md: nothing (internal API); note in
  internal/northbound/CLAUDE.md if it documents the walker API.

## Common mistakes to avoid
- Trying to make wolfSSL reads truly cancelable (closing the fd from
  another goroutine mid-read = RSK-07 segfault territory; SO_RCVTIMEO is
  the boundary, leave it).
- Classifying shutdown-cancel as a discovery FAILURE — it would increment
  `discoveryFailures` and emit fail-closed warnings on every restart,
  polluting the journal signals QA diagnosers and operators grep.
- Leaving telemetry on the old signatures (two consumers, one interface —
  half-migrations rot).
- Any behavior change beyond shutdown latency (scheduler/publish paths
  untouched).

## Things that must NOT change
- Fail-closed discipline: a genuinely failed/partial walk still holds
  last-known-good (scheduler untouched); cancel ≠ failure.
- Walk order, resource set, headers, timeouts (ReadTimeout value
  untouched).
- `wolfssl.Init()` once-per-process; fetcher session lifecycle
  (never Free mid-walk).
- northbound-hang / wan-outage scenario verdicts.

## Acceptance criteria
- [ ] `Discover` + all fetch helpers + Fetcher interface are ctx-first;
  both real consumers migrated.
- [ ] Cancel-mid-walk unit test green; bench stop-during-walk <2 s.
- [ ] Shutdown cancel logged as info, not counted as walk failure.
- [ ] Smoke scenarios at accepted verdicts.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests green (walker touched — run
  `go test ./tests/` in csip-tls-test)
- [ ] Mayhem: smoke only (wan-outage-hold, northbound-hang)
- [ ] arm64 + amd64 CGo builds green

## Mayhem scenarios affected
wan-outage-hold, wan-outage-expiry, northbound-hang — verdicts unchanged;
only shutdown-path logging differs.

## Conformance implications
None (no wire behavior change).

## Suggested commit message
`refactor(northbound): context propagation main→run→walker→fetcher; prompt shutdown mid-walk`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Context propagation walker-deep (R5)
**Description:** ctx-first Fetcher/walker APIs; between-request
cancellation with documented granularity; shutdown-vs-failure log
classification. Risk: low. Rollback: single revert.

## Code review checklist
- No fd manipulation added for cancellation.
- Cancel classified correctly at every error branch.
- Interface docs state the granularity honestly.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-071 (poll scheduling sits naturally on the ctx-aware loop);
watchdog-driven walk abort (TASK-007/008 integration, backlog).
