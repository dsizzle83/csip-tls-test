# TASK-022 — Extract `ocppserver` into lexa-proto; both repos consume

*Status: TODO · Phase: P1 · Effort: M (≈4–6 h) · Difficulty: low · Risk: med*

## Objective
One OCPP 2.0.1 CSMS library lives at `lexa-proto/ocppserver`; `lexa-hub/internal/ocppserver`
and `csip-tls-test/internal/ocppserver` are deleted; all consumers in both repos import the
shared package; the EV scenario family still passes on the bench.

## Background
`internal/ocppserver` is a pure-Go (no wolfSSL) OCPP 2.0.1 CSMS library built on
`github.com/lorenzodonini/ocpp-go v0.19.0` (pinned identically in both repos' go.mod).
Files: `server.go`, `handlers.go`, `simulator_test.go`, `CLAUDE.md`.

Verified divergence between the copies: **none in Go source** — `server.go` and
`handlers.go` are byte-identical; `simulator_test.go` differs only in its import line
(`lexa-hub/...` vs `csip-tls-test/...`); `CLAUDE.md` texts differ (repo-specific wording).
This is the easy extraction — the risk is consumer coverage, not reconciliation.

Verified consumers:
- **lexa-hub:** `cmd/ocpp/main.go` (the lexa-ocpp service: bridges CSMS ↔ MQTT, applies
  `bus.EVSECommand` via SetChargingProfile, publishes `bus.EVSEState`).
- **csip-tls-test:** `sim/server/main.go` (gridsim binary embeds a CSMS on
  `-ocpp-port`, default `ocppserver.DefaultPort`), `sim/orchestrator/main.go` (legacy
  orchestrator sim), `sim/evsim/main_test.go` (evsim's tests spin up a local CSMS to test
  the charger sim against), and `cmd/hub/main.go` (the obsolete monolith — deleted by
  TASK-010; if still present, its import gets the same mechanical rewrite).

The bench's production CSMS for the live bench is the hub's lexa-ocpp on
`ws://69.0.0.1:8887/ocpp`; evsim connects to it (`bin/evsim -csms ws://69.0.0.1:8887/ocpp
-api-port 6024` — flag is `-csms`, not `-hub`).

## Why this task exists
W3/D4: `internal/ocppserver` is one of the two packages the CLAUDE.md lockstep rule names.
It has not diverged *yet* — extracting it now, while the copies are identical, is free
insurance; after any one-sided edit it becomes another TASK-020.

## Architecture review sections
W3, D4, R2, §14 item 4; 02 AD-003; 08 RSK-16 (shared-lineage caveat applies to OCPP too).

## Prerequisites
- TASK-019 DONE (module skeleton + go.work both repos).
- TASK-010 status known (whether the monolith import still exists).
- Bench available for the EV scenario spot-runs.

## Files
- **Read first:** both repos' `internal/ocppserver/CLAUDE.md` (merge their content);
  `lexa-hub/cmd/ocpp/main.go` (consumer API surface: `ocppserver.New`,
  `ocppserver.Config{Port,CertPath,KeyPath,BasicAuthUser,BasicAuthPass}`, `srv.CSMS()`,
  `srv.Start/Stop`, `DefaultPort`); `sim/server/main.go`.
- **Modify:** import lines in `lexa-hub/cmd/ocpp/main.go`;
  `csip-tls-test/sim/server/main.go`, `sim/orchestrator/main.go`, `sim/evsim/main_test.go`
  (+ `cmd/hub/main.go` if extant); both repos' `go.mod` (require lexa-proto).
- **Create:** `lexa-proto/ocppserver/{server.go,handlers.go,simulator_test.go}` +
  merged package `CLAUDE.md`; lexa-proto `go.mod` gains `lorenzodonini/ocpp-go v0.19.0`
  (+ its transitive requirements — copy the pins from lexa-hub's go.mod, do not upgrade;
  TASK-006 owns dependency refresh).
- **Delete:** `internal/ocppserver/` in both repos.

## Blast radius
lexa-ocpp (the EVSE control path on the hub Pi), gridsim's embedded CSMS, evsim's test
harness. No topics, configs, or register maps. OCPP wire behavior must be unchanged —
the library is moved, not edited.

## Implementation strategy
Mechanical move of the identical source, one consumer-flip commit per repo, delete both
copies, validate with the module's own simulator test plus evsim tests plus targeted EV
scenarios on the bench. Introduce → flip → delete in three commits per AD-003's rollback
model (each consumer flip independently revertible).

## Detailed steps
1. Verify the copies are still identical:
   `diff -rq ~/projects/lexa-hub/internal/ocppserver ~/projects/csip-tls-test/internal/ocppserver`
   — expect only CLAUDE.md and the simulator_test.go import line. Any new drift: stop,
   reconcile first with a TASK-020-style disposition note.
2. Copy `server.go`, `handlers.go`, `simulator_test.go` (import rewritten) into
   `lexa-proto/ocppserver/`; write the merged `CLAUDE.md` (union of both, incl. the OCPP-1
   invariant: charging sessions are TransactionEvent Started/Updated/Ended lifecycles,
   never bare MeterValues). Add ocpp-go v0.19.0 + transitives to lexa-proto go.mod at the
   exact versions lexa-hub pins.
3. `cd ~/projects/lexa-proto && CGO_ENABLED=0 go test ./ocppserver/` — simulator test green.
4. Flip lexa-hub: rewrite `cmd/ocpp/main.go` import; delete `internal/ocppserver/`;
   `make test` green. One commit.
5. Flip csip-tls-test: rewrite `sim/server`, `sim/orchestrator`, `sim/evsim/main_test.go`
   (and monolith if present); delete `internal/ocppserver/`; `make test-fast` +
   `go test ./sim/evsim/` green. One commit.
6. `diff -rq` between repos finds no `ocppserver` anywhere.
7. Bench: rebuild + redeploy lexa-ocpp (full hub deploy:
   `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`, then
   `bash scripts/hub-replay-tune.sh fast`); rebuild gridsim + dashboard on the desktop
   (`go build -o bin/dashboard ./cmd/dashboard`; restart the transient units). evsim on
   .14 unchanged binary is fine (protocol peer, not consumer) — verify it reconnects:
   `curl -s http://69.0.0.14:6024/state`.
8. Targeted Mayhem: the 7 OCPP scenarios —
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only ev-profile-reject,ev-accept-but-ignore,ev-min-current-floor,ev-meter-freeze,ev-connector-flap,ev-delayed-obey,ev-wrong-units`
   — verdicts match the V6 baseline (no new FAIL/BLIND).

## Testing changes
None added; `simulator_test.go` moves with the package and keeps running in lexa-proto.
Commands: steps 3–5, 8.

## Documentation changes
- Both repos' root `CLAUDE.md` directory maps lose the `internal/ocppserver` line
  (leave the lockstep-rule paragraphs themselves for TASK-024).
- `lexa-proto/README.md`: ocppserver package now populated.

## Common mistakes to avoid
- Upgrading ocpp-go "while we're here" — dependency refresh is TASK-006, isolated for a
  reason (RSK-04: reconnect behavior under the exact faults that protect everything).
- Forgetting `sim/server/main.go` — gridsim embeds a CSMS; a missed consumer breaks the
  desktop gridsim build, which `bench-up.sh` masks until restart.
- Restarting desktop services without rebuilding `bin/dashboard` (unit execs
  `bin/dashboard`; D8 stale-binary trap).
- Editing handler logic during the move. If you spot a bug, file it; byte-identical move.

## Things that must NOT change
- **OCPP-1 invariant:** TransactionEvent lifecycles, never bare MeterValues, is
  implemented by consumers/handlers — wire behavior identical before/after.
- lexa-ocpp's MeterValues plausibility gate (`implausibleCurrent`,
  `cmd/ocpp/main.go`) — untouched consumer code, pinned by `ev-wrong-units`.
- CSMS listen port :8887 and ws URL shape (evsim + BENCH.md depend on them).
- Preservation ledger: no entries touched (no defensive-code replacement here).

## Acceptance criteria
- [ ] `lexa-proto/ocppserver` exists; `go test ./ocppserver/` green, CGo-free.
- [ ] Both repos' `internal/ocppserver` deleted; both repos' full test targets green.
- [ ] evsim reconnected to the redeployed lexa-ocpp on the bench (simapi `/state` shows
      the station connected).
- [ ] 7 EV scenarios at baseline verdicts (`--json` output archived).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) / `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: `go test ./tests/` (cheap; EV CSMS copy used in tests)
- [ ] Mayhem: targeted 7 OCPP scenarios (full campaign at phase exit / TASK-024)
- [ ] `hub-replay-tune.sh fast` after the hub deploy

## Mayhem scenarios affected
`ev-profile-reject`, `ev-accept-but-ignore`, `ev-min-current-floor`, `ev-meter-freeze`,
`ev-connector-flap`, `ev-delayed-obey`, `ev-wrong-units` — verdicts must not move.

## Conformance implications
OCPP 2.0.1 behavior unchanged. Note for TASK-074 (security profile 2): the shared module
is now the single place TLS+BasicAuth lands for both repos.

## Suggested commit message
lexa-proto: `feat(ocppserver): import shared OCPP 2.0.1 CSMS library (TASK-022)`
consumers: `refactor(ocpp): consume lexa-proto/ocppserver; delete in-repo copy`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1: extract ocppserver to lexa-proto (identical copies, mechanical)
**Description:** Copies verified identical pre-move; three commits (module import, hub
flip, bench flip); EV scenario evidence attached. Rollback: revert either flip commit
independently.

## Code review checklist
- Pre-move identity diff shown in the PR.
- ocpp-go pinned at v0.19.0 in lexa-proto (no upgrades).
- All five consumers rewritten (incl. gridsim + orchestrator sim + monolith if present).
- No handler edits.

## Definition of done
Acceptance criteria + regression checklist; docs updated; status headers (this file +
00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-024 (pin gate), TASK-030 (EVSE reconciler lands next to this consumer),
TASK-074 (OCPP security profile 2 in the shared module).
