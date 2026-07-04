# TASK-071 — Honor server-advertised poll intervals; conditional walk

*Status: TODO · Phase: P6 · Effort: M (≈4–6 h) · Difficulty: med · Risk: med*

## Objective
The northbound walker honors the server-advertised `pollRate` attributes
per 2030.5 function set — refetching each resource class no more often
than the server asks — instead of refetching the ENTIRE tree every
`discovery_interval_s`. A config override (the FAST-bench mode) is
retained and explicit. "Conditional walk" (If-Modified-Since/ETag) is
implemented only to the extent gridsim supports it — which today is NOT
AT ALL (verified) — so this task ships poll-rate compliance, documents
the conditional-GET descope with evidence, and files the backlog entry.

## Background
Verified:
- Model support exists on both sides: `pollRate` XML attrs decode into
  `PollRate uint32` across DeviceCapability, EndDeviceList, FSA list,
  DERProgramList, DERControlList, Time, etc.
  (lexa-hub internal/northbound/model/resources.go:51-53, 92, 136, 183,
  222, 306, 374; round-trip tested in resources_test.go). The walker
  already carries at least EndDevice PollRate into its tree
  (walker.go:477).
- gridsim SERVES pollRate values: 300 s on dcap/lists, 900 s on /tm, 60 s
  on DERControlList (sim/gridsim/server.go:157, 392, 444, 452, 536, 565,
  667; pricing.go:15; extended.go:17).
- gridsim has NO If-Modified-Since / ETag / 304 handling
  (`grep -rn "If-Modified\|ETag\|304" sim/gridsim sim/tlsserver` → 0).
- Today's loop: `runDiscovery` fetches the full tree every
  `discovery_interval_s` (northbound.json: 20 s on the bench —
  configs/northbound.json; FAST tuning drives it lower via
  `scripts/hub-replay-tune.sh`). Review §12: "at minimum honor
  server-advertised poll intervals before a utility rate-limits you."
- The scheduler re-evaluates from the CACHED tree; only fetching is
  rate-limited by this task. Control expiry/local clock discipline do not
  depend on walk cadence (fail-closed + ValidUntil) — but CannotComply
  Response timing and control ADOPTION latency do: a new DERControl is
  only seen on a DERControlList refetch, so the 60 s pollRate on controls
  bounds adoption latency. Mayhem scenarios post controls and expect
  adoption in seconds — the FAST override must therefore keep the bench
  at today's cadence, and scenario timing must be unaffected.

## Why this task exists
§12 [Likely] finding: re-fetching the entire resource tree every ~5 s
(fast mode) is impolite at best; a utility head-end WILL rate-limit or
blacklist a walker that ignores its advertised pollRates. 09 checklist:
"Server poll-interval compliance verified against gridsim."

## Architecture review sections
§12 · R5-adjacent · 09 (Conformance & protocol) · 05 §6 (config
override explicitness).

## Prerequisites
TASK-068 (run package) and ideally TASK-070 (ctx) DONE. Bench for
verification.

## Files
- **Read first:** internal/northbound/run/ (the loop),
  internal/northbound/discovery/walker.go (which fetches happen per walk;
  where PollRate lands in ResourceTree), model/resources.go,
  configs/northbound.json, scripts/hub-replay-tune.sh (what it tunes —
  the override must survive it), sim/gridsim/server.go pollRate sites.
- **Modify:** walker or run package (per-class fetch scheduling),
  cmd/northbound config (`poll_rate_mode`: `"honor"` | `"override"`,
  plus `discovery_interval_s` semantics documented), northbound.json
  example; csip-tls-test: `scripts/hub-replay-tune.sh` if it must now set
  the override mode (verify what it edits).
- **Create:** `internal/northbound/run/pollsched.go` (+test) — per-class
  next-due bookkeeping.

## Blast radius
lexa-northbound fetch cadence. Scenario timing risk if the bench override
is wrong. No bus schema; the published ActiveControl cadence follows the
DERControlList class cadence.

## Implementation strategy
Add a small poll scheduler: per resource class (dcap, time, edev, fsa,
derp, derc, curves, defaults, mup…), record the last-served `pollRate`
and last-fetch time; each loop iteration (which keeps running at a short
base cadence) fetches only the classes that are DUE. `poll_rate_mode:
"override"` restores today's fetch-everything behavior and is what the
bench runs in FAST mode. Absent pollRate on a resource = class default
(2030.5 DeviceCapability pollRate as the fallback, else the configured
interval).

## Detailed steps
1. Map the walk (walker.go Discover) into classes and decide the cut
   points: the tree is hierarchical (derc URLs come from derp results),
   so a due-derc fetch reuses the CACHED derp hrefs; refresh parent
   classes on their own cadence. Document staleness implications (an href
   changed server-side surfaces on the parent's next due fetch — bounded
   by the parent's pollRate; acceptable per 2030.5 polling model).
2. Implement `pollsched`: `Due(class, now) bool`, `Served(class, rate,
   now)`; clamp insane rates (0 → class default; cap at e.g. 24 h;
   plausibility discipline per 05 §3 — a hostile pollRate=4e9 must not
   freeze discovery; log+clamp).
3. Wire into the run loop: base ticker stays (min granularity); classes
   fetch when due; `/tm` clock resync follows the Time pollRate but never
   exceeds a configured max-staleness (clock discipline is safety-
   relevant — set max 15 min regardless of server value, documented).
4. Config: `"poll_rate_mode": "honor"` default for PRODUCT config;
   bench northbound.json deployed with `"override"` + comment. Verify
   `hub-replay-tune.sh`/`deploy-hub-pi.sh` end state leaves the bench in
   override mode (the STOCK-reset gotcha applies — check what those
   scripts rewrite and update them explicitly).
5. Verification against gridsim: with `honor` mode on the desktop (run
   northbound against gridsim locally or on the hub), capture one hour of
   gridsim access logs; assert per-class request rates ≤ advertised
   pollRate + jitter (write a small check in tests/ or a script;
   gridsim logs requests — verify its logging surface first, else count
   via a wrapper).
6. Conditional-GET descope: add to 10_BACKLOG ("conditional walk:
   requires gridsim If-Modified-Since/ETag support first; 2030.5
   subscription/notification is the fuller answer"), and record the
   descope in 02 as an AD-009-style note under this task.
7. Bench in override mode: `--only expired-control,conflicting-primacy,
   clock-jump-forward` ×3 (adoption-latency-sensitive) proving scenario
   timing unchanged.

## Testing changes
- pollsched unit tests (due/served/clamp/fallback).
- Walk-composition test: a due-set → exactly those fetches (fake fetcher
  recording paths).
- Rate-compliance check vs gridsim (step 5) — attach evidence.
- Run: `make test` (hub), `go test ./tests/` (bench repo), scenarios per
  step 7.

## Documentation changes
- northbound config reference (poll_rate_mode + max clock staleness).
- BENCH.md / CLAUDE.md: bench runs override mode; product default honors.
- 10_BACKLOG + 02 descope note (step 6).

## Common mistakes to avoid
- Letting the bench default to `honor` — control adoption at 60 s
  pollRate would break most Mayhem scenario timing and fake a regression
  wave (RSK-13 alarm fatigue).
- Honoring a hostile/absurd pollRate without clamps (walk freeze = the
  fail-open-by-omission shape).
- Fetching children from stale parent hrefs after a server restructures
  the tree — on a 404/410 of a child, force the parent class due
  immediately (add this rule + test).
- Slowing the /tm resync below the clock-discipline bound (clock-jitter
  regression class — the scheduler guards assume reasonably fresh
  offsets).
- Forgetting deploy scripts rewrite configs (the phantom-FAIL detour
  precedent): make the mode explicit in what they deploy.

## Things that must NOT change
- Bench scenario timing (override mode pinned by scenario runs ×3).
- Fail-closed discipline and scheduler behavior (only FETCH cadence
  changes).
- Clock resync max-staleness ≤15 min in all modes.
- Retained ActiveControl publish semantics.

## Acceptance criteria
- [ ] `honor` mode: measured per-class request rate complies with
  gridsim's advertised pollRates (evidence attached).
- [ ] `override` mode: request pattern identical to pre-task (bench).
- [ ] Clamp/fallback/404-reparent tests green.
- [ ] Targeted scenarios ×3 unchanged; product config documented.
- [ ] Descope recorded (backlog + 02).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `go test ./tests/` (csip-tls-test) green — protocol-adjacent
- [ ] Mayhem: targeted set ×3 (adoption-latency sensitive)
- [ ] Bench left in override mode; deploy scripts verified

## Mayhem scenarios affected
expired-control, conflicting-primacy, clock-jump-forward, malformed-csip
(walk-loop changes) — all must hold verdicts in override mode.

## Conformance implications
Positive: poll-rate compliance is 2030.5-polite behavior a test lab will
check. Conditional GET/subscriptions remain descoped IN WRITING (09
checklist line satisfied by the poll-rate half + descope note).

## Suggested commit message
`feat(northbound): per-class poll scheduling honoring server pollRate; bench override mode`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Server poll-interval compliance (§12)
**Description:** Poll scheduler per function-set class with clamps and
404-reparenting; honor/override modes (bench = override, evidence that
scenario timing is unchanged); conditional GET descoped with backlog
entry. Risk: med (fetch cadence). Rollback: `poll_rate_mode: override`.

## Code review checklist
- Class cut-points cover every fetch in Discover (none left unscheduled).
- Clamps + /tm staleness bound present.
- Bench/product config split explicit in deploy scripts.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
Backlog: gridsim conditional-GET support + walker If-Modified-Since;
2030.5 subscription/notification function set evaluation.
