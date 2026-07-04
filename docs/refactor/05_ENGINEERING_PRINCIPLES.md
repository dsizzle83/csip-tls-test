# 05 — Engineering Principles

*Standards for all work from Phase 0 onward. These exist to prevent the
drift that produced W1–W7. PR reviews enforce them; CI automates what it
can. When a principle must be broken, say so in the PR description and in
`02_ARCHITECTURE_DECISIONS.md` if it's structural.*

---

## 1. Package boundaries & layering

- **Dependency direction:** `cmd/*` → `internal/*` → shared modules
  (`lexa-proto`) → stdlib/vendored. Never sideways between `cmd/`s, never
  upward. `internal/orchestrator` stays **I/O-free** (reads `SystemState`,
  returns `Plan`) — this property is why it has real unit tests; defend it.
- **One owner per concept.** Before adding a guard/timer/counter, find the
  owning package (reconciler, `utilitytime`, constraint session). If it has
  no owner, the task is first to create one — not to add owner #5.
- **CGo containment:** wolfSSL only behind `internal/wolfssl` +
  `internal/tlsclient`, linked only by northbound/telemetry (+ bench cgo
  binaries). `lexa-hub`/`lexa-modbus`/`lexa-ocpp`/`lexa-api` stay
  `CGO_ENABLED=0`. Shared modules must be CGo-free.
- **File size:** soft cap 600 lines for new/refactored files; a file over
  cap needs a split plan or a justification in the PR.

## 2. Interfaces

- Define interfaces where they are **consumed**, not where implemented.
- Interfaces exist for testability and layering, not speculation: two
  implementations (real + test) or one proven seam requirement.
- Bus messages are the real inter-service interface: every schema lives in
  `internal/bus` (or the shared module), carries `"v"`, uses `*float64`
  for absent values, **never NaN in JSON**.

## 3. Error handling & fail-closed

- **Fail closed on the control plane.** Ambiguity between "no control" and
  "can't tell" always resolves to hold-last-known-good until expiry
  (`ValidUntil`/local expiry discipline). This is the scheduler's
  established discipline — every new consumer inherits it.
- Errors are values; wrap with `%w` and context at each boundary; no
  `panic` outside init-time impossibilities (AD-011 crash-only otherwise).
- Silent zero-values are the enemy (XML namespace lesson): decode paths
  must distinguish absent/malformed from zero, and plausibility-gate what
  they accept.

## 4. Concurrency

- One writer per state struct; snapshot reads. (Engine mutex consolidation,
  TASK-067, is the model.)
- No state in closures. If it has a name in a bug report, it needs a name
  in the code (`activeBreachMRID` lesson).
- Every goroutine has an owner, a shutdown path, and a bounded channel
  policy (drop-with-counter or block-with-timeout — chosen, not defaulted).
- `-race` in CI is non-negotiable; new subscribe/publish paths get a
  concurrency test.
- Nothing in a tick/poll loop may block unboundedly: publishes are
  fire-with-timeout (TASK-046), Modbus ops carry deadlines, tick overruns
  are counted and exported.

## 5. Time

- All utility-time reads go through `utilitytime` (post P3). New grace
  constants, debounces, or offsets outside it are review-blocking.
- Thresholds are denominated in **wall-clock seconds**, scaled to ticks at
  the edge (`scaleTicks` pattern) — FAST and STOCK must mean the same
  seconds.
- In-process durations use the monotonic clock; utility semantics use
  server time; never mix in one comparison.

## 6. Configuration

- Every constant that encodes plant physics (ramp, lag, taper, step
  estimates) is a **plant-model parameter** with units in its name
  (`maxRampWPerS`), a documented provenance, and a config path. "Calibrated
  for the 20× demo" comments mark debt to burn down, never to add.
- Config files versioned like bus messages; unknown keys warn, missing
  keys get explicit defaults in one place.
- Deploy scripts must not silently reset tuned configs (the
  `deploy-hub-pi.sh` STOCK-reset gotcha): scripts preserve or restate
  timing mode explicitly.

## 7. Security

- New network surface ⇒ authn story in the same PR (bench-only exceptions
  documented as such). No plaintext credentials in repos; keys stay
  gitignored; certs deployed `install -m 600 -o lexa`.
- Cipher/mTLS invariants are frozen: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`,
  `RequireClientCert` on every server, `wolfSSL_Init` once per process.
- Anything parsing bytes from outside the box (utility HTTP/XML, OCPP
  frames, Modbus responses) needs size caps and a fuzz target.

## 8. Testing philosophy (details in 06)

- **Assert invariants and outcomes, not decision strings.** `hasDecisionContaining(...)`-style
  assertions are legacy; new tests check measured effect, published
  desired state, or invariant compliance.
- Every bug fix lands with the test that would have caught it, tagged with
  the scenario/finding ID (existing culture — keep it).
- Mutation-check safety tests: a safety test that still passes with the
  guard unwired is not a test (the `TestOptimizer_ExportChurnEscalatesCannotComply`
  standard).
- Touching orchestrator/scheduler/actuation/reconnect ⇒ full Mayhem
  campaign before merge (FAST); release gates add STOCK.

## 9. Logging & observability

- Structured (key=value or JSON), rate-conscious (journald caps, TASK-009);
  per-tick lines are budgeted — flash is a consumable.
- Every service: `/metrics`, a heartbeat, and a "last decision/action"
  surface. If QA needs journal forensics to see it, it needs a metric.
- Log the *state transition*, not the steady state.

## 10. Documentation

- Load-bearing behavior gets a comment naming the QA finding
  (`// QA v5 cluster 2:` pattern — keep it).
- Structural decisions → this doc set (02); mechanical how-tos → runbooks;
  invariants → CLAUDE.md files (both repos, same session when shared).
- A task is not done until 06/09/CLAUDE.md reflect any changed invariant.

## 11. Code review & process

- Everything through a PR; CI green required; no direct pushes to `main`.
- **Nothing uncommitted overnight.** WIP goes on a branch, pushed.
- Lockstep changes (shared module bump, bus schema, register maps) ship as
  paired PRs referenced in each other's description, deployed same session.
- Review checklist per PR: invariants list touched? preservation ledger
  consulted? campaign run if radioactive zone? rollback stated?
- Deleting defensive code requires: the replacing mechanism named, the
  originating scenario green on the replacement, and the deletion in its
  own commit (revertible).

## 12. The radioactive zone (until M4)

`internal/orchestrator/*`, `internal/northbound/scheduler/*`,
`cmd/hub/actuators.go`, `cmd/modbus` reconnect/interlock paths: changes
here are one-per-PR, full-campaign-gated, never batched with unrelated
work, and never merged the same day they're written.

One narrow exception: **purely additive, provably-unwired code** (a new
file nothing imports yet, e.g. TASK-057/058 skeletons) may skip the
campaign — but the PR that first *wires* it pays the full gate, and the
skipping PR must state this exception explicitly.
