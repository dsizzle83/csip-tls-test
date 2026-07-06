# 02 — Architecture Decisions (living document)

*Append-only in spirit: decisions get superseded, not erased. Each entry:
Problem / Decision / Alternatives / Tradeoffs / Migration / Open questions.
ADR-0001 lives in `lexa-hub/docs/` and is incorporated by reference.
New decisions made during the refactor are added here (AD-00X) and, when
they affect the product repo, mirrored as `lexa-hub/docs/ADR-000N`.*

Status legend: ✅ decided · 🔶 decided-pending-validation · ❓ open

---

## AD-001 ✅ Keep the distributed six-service topology (= ADR-0001)

Incorporated by reference: `lexa-hub/docs/ADR-0001-distributed-vs-monolith.md`.
The review's grade (A−) confirms it. Nothing in this roadmap adds or removes
a process; the two-loop hierarchy (Tier 0/1/2) is preserved through every
phase. **Never revisit without new latency-budget measurements.**

## AD-002 ✅ Convergence: one Device Reconciler, declarative desired state (R1)

**Problem.** Four uncoordinated mechanisms (restore re-command, cmdDeduper+
watchdog+breach-reset, retryDevice.lastCtrl, five-hop CannotComply chain)
solve "device must reach hub's desired state"; guard×guard interactions are
the dominant defect class (review W2).

**Decision.** Optimizer publishes a retained, versioned, per-device
desired-state document; a reconciler co-located with the hardware driver
(`lexa-modbus`, `lexa-ocpp`) owns write-on-diff, verify-by-readback,
reassert-on-reconnect, escalating retry, and non-convergence reporting.

**Alternatives considered.**
- *Keep hardening the four layers* — rejected: each fix multiplies the
  interaction surface (empirically proven, 2026-07-03 dedupe/breach bug).
- *Reconciler inside lexa-hub* — rejected: reassert-on-reconnect must
  survive hub death and broker restarts; the ADR-0001 tiering puts local
  reflexes next to hardware.
- *Non-retained command stream with acks* — rejected: retained desired
  state gives free crash recovery (the pattern already proven by
  `lexa/csip/control`).

**Tradeoffs.** Retained desired state inherits the stale-retained-message
risk (§8.3) → mitigated by mandatory `issuedAt`/`seq` + staleness policy
(TASK-025/042). Reconciler adds a state machine per device — but it
*replaces* four.

**Migration.** Shadow (observe/compare, no writes) → flip per device class
(battery → solar → EVSE) → collapse CannotComply chain → delete legacy.
Behavior-preservation ledger in TASK-025 maps every deleted guard to the
Mayhem scenario that created it.

**Open questions — both resolved by AD-013/TASK-025 (2026-07-05).**
✅ The Tier-0 interlock stays **measurement-only**, above the reconciler: it
does not read the desired-state doc (would defeat its hub/broker-death
independence, ADR-0001). Revisit only at P5 if a latency case appears.
✅ Meter gets **no** desired document — verified no actuator exists for it
(`cmd/hub/main.go:213–232` registers actuators for battery/inverter/EVSE
only; `cmd/modbus` `subscribeControls` gates on role battery/inverter,
`cmd/modbus/main.go:203–241`). See AD-013.

## AD-003 ✅ Shared protocol code: one module, versioned, CI-pinned (R2)

**Decision.** Extract `sunspec` (+derbase layouts), `ocppserver`, and the
2030.5 model into a shared module (working name `lexa-proto`), developed
via `go.work`, consumed by both repos at a pinned version; CI fails on
version skew. Product side is merge authority for today's divergence, but
each diff hunk is reviewed — the sim side may hold real fixes.

**Alternatives.** Mono-repo merge (rejected: product/test-bench release
cadences differ; the review only requires shared *modules*); keep
duplication + better diff CI (rejected: divergence already happened under
a documented rule).

**Open questions — resolved (TASK-019/024).** ~~One module or three?~~ One
module, five packages (`sunspec`, `derbase`, `modbus`, `ocppserver`,
`csipmodel` — see (b) below); split later only if versioning pressure
appears. No open question remains on this decision.

**Extension (TASK-019, 2026-07-05): module path, package layout, pinning
mechanism, go.work policy — decided, not deferred.**

`~/projects/lexa-proto` now exists (fresh git repo, `main`, skeleton commit)
with the five packages below, each holding only a `doc.go` naming the
source package it absorbs and the task that moves it. Neither consumer
imports it yet.

**(a) Module path.** `go.mod` declares bare `module lexa-proto` — **not**
`github.com/dsizzle83/lexa-proto` — for now. Per AD-012, `lexa-proto` gets a
repo under `dsizzle83` "when it's extracted"; that repo does not exist yet
and repo creation on github.com is a human step (no `gh` CLI / API
credential is available in this execution environment — the same gap
AD-012 already recorded for branch protection). Inventing the hosted path
today would make `go mod tidy` in either consumer try to fetch it and fail.
**Flip rule:** rename the module to `github.com/dsizzle83/lexa-proto` (one
commit: the `go.mod` line in lexa-proto + every import statement in both
consumers that references it) as soon as the hosted repo exists, and no
later than TASK-024 — if hosting lands before TASK-020 starts moving code,
do the flip first and TASK-020 imports the hosted path from its first
commit; if not, TASK-020 proceeds against the bare path and the rename is
its own follow-up commit before TASK-024's pin gate goes live.

**(b) Package layout** (one module, five packages — the open question above
resolves to "one module" for V1.0):
- `sunspec` — SunSpec register codec + layout engine (absorbs product's
  `layout.go`/`derlayout.go` too).
- `derbase` — CSIP `DERControlBase` → SunSpec writes; imports `sunspec` and
  `csipmodel`.
- `modbus` — `Transport` abstraction; imported by `sunspec` (the dependency
  that makes `sunspec` and `modbus` move together, TASK-020).
- `ocppserver` — OCPP 2.0.1 CSMS library; no intra-module dependency
  (TASK-022).
- `csipmodel` — IEEE 2030.5 XML model structs; consumed by `derbase`
  (TASK-023).

**(c) Pinning mechanism for TASK-024 — decided: `proto.pin` today, go.mod
pseudo-version once hosting + a fetch credential exist.** There is no
fetchable remote for `lexa-proto` right now (no hosted repo, no GitHub API
credential in this environment — same constraint as AD-012's branch-
protection blocker), so the go.mod-pseudo-version mechanism (`require
lexa-proto vX.Y.Z-<timestamp>-<sha>` compared between the two consumers'
`go.mod` files) **cannot** be the mechanism until that changes. Effective
now: each consumer repo commits a `proto.pin` file at its root holding the
required `lexa-proto` commit SHA (one line, e.g.
`a1b2c3d4e5f6...`); the TASK-024 gate (a) compares the two consumers'
`proto.pin` files to each other and fails on mismatch, and (b) where a
local `../lexa-proto` checkout is available (developer machines, and any
CI runner that has been given a sibling checkout the way the existing
`lockstep` job checks out `dsizzle83/lexa-hub` via `LEXA_HUB_RO_TOKEN`),
verifies that checkout's `HEAD` matches the pinned SHA. This is the same
shape as the `lockstep` job already running in `csip-tls-test`'s CI
(TASK-004) — reuse its PAT pattern (a fine-grained, read-only,
single-repo-scoped token) for `lexa-proto` once it is hosted, rather than
inventing a second mechanism. **When hosting + a credential land** (repo
created under `dsizzle83`, either a PAT-based git credential rewrite
`url."https://x-access-token:${TOKEN}@github.com/".insteadOf
"https://github.com/"` for `go mod download`, or SSH deploy-key `insteadOf`
reuse — either makes the module actually fetchable), TASK-024 may switch to
comparing `go.mod`'s `require lexa-proto vX` line instead of `proto.pin`;
this is a mechanism swap, not a new decision, and does not block anything
before it — no code imports `lexa-proto` yet.

**(d) `go.work` is committed in both repos for the migration window.**
`lexa-hub/go.work` and `csip-tls-test/go.work` (both created via `go work
init . ../lexa-proto`, own module listed first) are checked in now and
removed by TASK-024 once `proto.pin` (or its go.mod-pseudo-version
successor) is authoritative. **Hosted CI cannot see `go.work`'s
`../lexa-proto`** — GitHub-hosted runners check out exactly one repo, so
`../lexa-proto` does not exist on the runner and Go's automatic workspace
discovery would otherwise fail every job. Both repos' `ci.yml` set
`GOWORK: off` at the workflow level (all jobs) as of this task — safe today
because the skeleton is unreferenced (`GOWORK=off` is functionally
identical to no `go.work` file existing, which is exactly today's build
graph); this line comes out together with the `go.work` files at TASK-024.

No `replace` directives were added to either consumer's `go.mod` — `go.work`
is the one local-dev mechanism; a `replace` would be redundant under
`go.work` and would fight the `proto.pin`/pseudo-version gate later.

**(e) Interim vendoring (TASK-021, 2026-07-05): `require` + `replace` +
committed `vendor/lexa-proto/`, superseding the "no replace" line in (d).**
Once TASK-020/021 gave `csip-tls-test` real imports of `lexa-proto/sunspec`
and `lexa-proto/modbus` (and TASK-022/023 added `ocppserver`/`csipmodel`,
TASK-023 `derbase`), hosted CI needed to actually *build* those imports —
and hosted runners have no `../lexa-proto` to satisfy a bare `go.work`-only
setup (see (d)). Both consumers' `go.mod` now carry `require lexa-proto
v0.0.0` + `replace lexa-proto => ../lexa-proto`, and both commit a
`vendor/lexa-proto/` tree (`GOWORK=off go mod vendor`) covering every
package they actually import. Go's default `-mod=vendor` behavior (active
whenever `vendor/modules.txt` is present and consistent with `go.mod`, which
is the case whenever there's no `go.work` in effect) means hosted CI builds
straight from the committed vendor tree — it never needs `../lexa-proto` to
exist at all, closing the gap `GOWORK=off` alone left open. `replace`'s
target path is metadata only in vendor mode (Go doesn't resolve it); it
still matters for local `go.work`/non-vendor dev, where it's superseded by
the `go.work` module list anyway.

**(f) TASK-024 landing (2026-07-05): pin gate is live; `go.work` retired;
hosted-flip is a recorded follow-up, not a blocker.** `scripts/check-proto-pin.sh`
(csip-tls-test) is the gate described in (c), wired into both repos' CI as a
`proto-pin` job (replacing TASK-004's `lockstep` job, which only ran in
csip-tls-test — TASK-024 fixed the one-sided gating too: lexa-hub's CI now
checks out csip-tls-test via a new `CSIP_TLS_TEST_RO_TOKEN` secret, the same
class of pending-human-PAT item as `LEXA_HUB_RO_TOKEN`/AD-012 branch
protection). Both repos' `proto.pin` are seeded at the same `lexa-proto`
commit (`77e32e447185dedb2adc799b1373894a526b58b5`, `main` HEAD as of
TASK-023's landing). Both `go.work` files are deleted from version control
and gitignored per (d); the interim vendoring from (e) is what actually lets
hosted CI build with no `go.work` and no fetchable `lexa-proto` — nothing
about (e) changes at this task.

The go.mod-pseudo-version mechanism from (c) is still the intended long-run
replacement for `proto.pin`, still blocked on the same hosting + credential
gap as AD-012. Recorded as a follow-up (10_BACKLOG.md, "lexa-proto hosted-
flip") rather than re-litigated here: **hosted-flip checklist**, to run in
one commit as soon as a `dsizzle83/lexa-proto` GitHub repo + fetch
credential both exist —
1. Rename `lexa-proto`'s module path to `github.com/dsizzle83/lexa-proto`
   (go.mod line + every import statement in both consumers) per the (a)
   flip rule.
2. Push `lexa-proto`'s history to the new hosted repo; set up branch
   protection (AD-012) at the same time as lexa-hub/csip-tls-test's, if
   still pending.
3. In both consumers: drop `replace lexa-proto => ../lexa-proto`, change
   `require lexa-proto v0.0.0` to a real `require
   github.com/dsizzle83/lexa-proto vX.Y.Z-<timestamp>-<sha>` pseudo-version
   (or a tagged release once `lexa-proto` starts tagging), delete
   `vendor/lexa-proto/` (and `vendor/modules.txt`'s entry for it, or the
   whole `vendor/` tree if nothing else needs vendoring), run `go mod tidy`.
4. Swap `scripts/check-proto-pin.sh`'s ground truth from `proto.pin` files
   to the two consumers' `go.mod` `require` lines (mechanism swap per (c),
   not a new decision) — delete `proto.pin` from both repos once the gate
   no longer reads it.
5. Re-run the fresh-clone build proof and the forced-divergence proof
   (TASK-024 §5-equivalent) against the new mechanism before trusting it.
6. Retire this checklist from 10_BACKLOG.md once done; record the SHA/tag
   the flip landed on.

**Extension (TASK-082, 2026-07-05): bench `derbase` fork disposed; bench
`internal/csip/{discovery,scheduler}` fork kept as a referee, not extracted.**

TASK-020/021 left two forks alive in `csip-tls-test` pending an explicit
decision (TASK-010's punt, resolved here):

**(g) Bench `derbase` + driver forks — disposed, not kept.** Unlike the csip
walker/scheduler (below), the bench's own `internal/southbound/derbase`
(the trimmed IEEE-1547/legacy mapping layer TASK-021 adapted onto the shared
`sunspec` codec) had **no referee argument for staying independent**: it
doesn't check the hub's behavior against a second reading of the spec, it's
a debug/validation helper (`sim/modsim-client`, a Pi-side CLI) that drives
the *same* sims the hub itself talks to. Keeping it forked meant that CLI's
manual validation could silently drift from what the real hub (via
`lexa-proto/derbase`) actually does — a liability, not an asset. TASK-020's
disposition doc (§2c/§2d) had already adjudicated every behavioral
difference between the two generations product-authoritative with **zero
bench-side fixes lost** (D1-D3, S1-S8: every row resolved to "product"), so
there was no unreviewed semantic risk in finishing the merge. Disposition:
`internal/southbound/battery` and `internal/southbound/inverter` now embed
`lexa-proto/derbase.Base` directly (same package lexa-hub consumes);
`internal/southbound/device.Measurements` is a type alias to
`lexa-proto/derbase.Measurements` (the identical alias trick TASK-023 used
for lexa-hub's own `device.Measurements`); the bench's `internal/southbound/
derbase/derbase.go` is deleted outright — `grep -rn "derbase"
internal/southbound/` now only finds the `lexa-proto/derbase` import lines
and the local `M701St*` shim constants (three integers per file, the
spec-value enum the shared codec deliberately leaves unsymbolized — not
protocol-semantics duplication in the sense this program cares about).
Consuming the fuller `lexa-proto/derbase.ApplyControl` also means
battery/inverter pick up capability they didn't have before (`OpModFixedW`,
`GenLimW`/`LoadLimW` ceilings, reversion timers, the full VoltVar/VoltWatt/
trip/droop/WattVar curve surface) — this is not treated as an
out-of-process behavior change requiring escalation, because TASK-020 had
already ruled every one of those code paths product-superset with nothing
the bench held that the product lacked; the only paths the bench's own
tests exercise (legacy M103/121/123/802/201 via `SetConnect`/
`SetExportLimit`/`SetImportLimit`) are byte-identical between the two
generations and pass unchanged (`go test ./internal/southbound/...`, cached
and re-run, all green, zero assertion changes).
`battery`/`meter`/`registry` (not `inverter`) turned out to have **no
consumer at all** outside their own test files, now that `cmd/hub` and
`sim/orchestrator` are deleted (TASK-010) — noted in
`internal/southbound/CLAUDE.md` for visibility; not deleted, since deleting
un-consumed-but-passing code that no task assigned as in-scope is scope
creep, not fork disposal.

**(h) Bench `internal/csip/{discovery,scheduler}` — kept as an independent
referee, renamed to `internal/csipref/{discovery,scheduler}`.** This is the
opposite call from (f), and deliberately so: these packages are this repo's
own implementation of the CSIP **client-side** walk-and-evaluate logic
(resource discovery from `/dcap`, DER event priority resolution), consumed
by `sim/conformance`, `sim/client`/`sim/client-http`, and `tests/*` — none of
which are lexa-hub code. There is no lexa-hub counterpart for this logic to
diverge FROM in the first place (lexa-hub's own client-facing walker, if it
has one, was never forked into this repo — TASK-010 already noted `internal/
csip` is "NOT deletable... the review's phrasing 'csip fork' " is imprecise
for exactly this reason). The value of keeping it separately maintained is
the self-confirmation hazard named in architecture review §9: if the
conformance suite's walker and the hub's own request-handling logic were
ever unified into one shared implementation, a bug in that shared
interpretation of the spec would make the hub agree with itself in every
test — conformance evidence would stop meaning anything. Extraction (option
b) is rejected for the stated reason it's rejected everywhere else in this
program: no second consumer needs a shared walker today, and manufacturing
one to "reduce duplication" would destroy the one property that makes this
package valuable.

Disposition: `internal/csip/discovery` and `internal/csip/scheduler` moved
(`git mv`, package names unchanged) to `internal/csipref/discovery` and
`internal/csipref/scheduler`; six importers repointed (`sim/client`,
`sim/client-http`, `sim/conformance`, `internal/tlsclient/fetcher_test.go`,
`tests/integration_test.go`, `tests/csip_conformance_test.go`,
`tests/wolfssl_integration_test.go`) — mechanical import-path rewrite only,
zero logic changes, `go test ./...` green throughout. Both packages' doc
comments now state the referee role and the "must not be synced" rule
explicitly (the point of maximum leverage — read before anyone is tempted to
"deduplicate" them against a future shared walker). `internal/csip` itself
shrinks to `identity` + `dnssd` (LFDI/SFDI derivation, mDNS browse) — neither
is spec-interpretation logic with a self-confirmation hazard, so neither is
part of this decision.

**CI divergence gate:** `scripts/ci/lockstep-check.sh`'s `TREES` array only
ever compared `internal/southbound/sunspec` and `internal/ocppserver` (both
now retired to `lexa-proto` from both repos — TASK-021/022) — it was never
wired to scan `internal/csip{,ref}` or `derbase` at all. There is therefore
**no `lockstep-allowlist.txt` entry to add**: the gate cannot flag a tree it
doesn't compare, and adding one defensively would be documentation for a
check that doesn't exist. A comment was added at the `TREES` declaration
recording this explicitly, so a future reader doesn't go looking for a
missing allowlist line. TASK-024 (still TODO) should carry this forward when
it replaces the whole gate with `lexa-proto` version pinning — pinning
doesn't apply to `internal/csipref` either, for the same reason (nothing on
the other side to pin against).

**Phase 1 exit criterion updated** (`03_REFACTOR_PHASES.md`): the `diff -rq`
"no duplicated protocol packages" criterion now carries this one documented
exception for `internal/csipref` — it is a single-sided reference
implementation, not a duplicated pair, so there is nothing for `diff -rq` to
ever find equal or unequal.
## AD-012 ✅ Hosting & CI platform: GitHub (de facto)

**Decision.** Both repos stay on private GitHub under the single-maintainer
account: `dsizzle83/lexa-hub`, `dsizzle83/csip-tls-test` (both remotes
verified live 2026-07-04 via `git ls-remote`, contra an earlier "no remote"
assumption). CI = GitHub Actions with a self-hosted desktop runner for
wolfSSL-cgo jobs (TASK-002/003). Workflow: feature branch → PR → CI green →
merge; lockstep changes (bench ↔ product, e.g. `internal/southbound/sunspec`
audit MTR-4) ship as paired PRs that reference each other (05 §11). TASK-001
is the one intentional exception: it commits/merges directly to `main` in
both repos to land the pre-existing QA-arc fixes and this doc set, then the
PR-only discipline starts. `lexa-proto` (AD-003) gets a repo in the same
account when it's extracted; its version-pin mechanism (go.mod version vs
committed SHA pin) is decided in TASK-019's ADR.

**Alternatives considered.** Self-hosted Gitea on the desktop — rejected for
now: no material benefit over GitHub for a single maintainer, adds an
availability dependency (the desktop is also a bench node), and GitHub
Actions is needed regardless for TASK-002/003's CI. A new GitHub
organization — rejected: no team, no billing/seat reason to split from the
personal account. Revisit either if the air-gap policy ever extends from the
bench network to source hosting.

**Branch protection — 2026-07-04 status: attempted, blocked, unresolved.**
TASK-001 tried to enable "require PR before merging" on `main` in both repos
via `gh api -X PUT repos/dsizzle83/<repo>/branches/main/protection`. Neither
the `gh` CLI nor any GitHub API token/credential (checked: `~/.netrc`, `gh`
config, git credential helpers) was available in the execution environment —
only SSH deploy-key auth for `git push`/`git pull`, which the REST/GraphQL
API does not accept. Confirmed the API needs auth (unauthenticated
`GET /branches/main/protection` → 401). **Branch protection is NOT yet
active on either repo's `main` — this is the one open item TASK-001 could
not close.** A human with a GitHub PAT or the `gh` CLI logged in must run
(or click through Settings → Branches):
```
gh api -X PUT repos/dsizzle83/lexa-hub/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f required_pull_request_reviews.required_approving_review_count=0 \
  -F required_status_checks=null -F enforce_admins=false \
  -F restrictions=null -f required_linear_history=false \
  -f allow_force_pushes=false -f allow_deletions=false
```
(and the equivalent for `csip-tls-test`). Enable "require PR before merging"
now; add "require status checks" once TASK-002/003 land CI. Direct-push
lockout applies to the human maintainer too — that's the point. Track
closing this as a fast follow-up before any task after TASK-001 merges its
PR (the workflow this program adopts assumes protection is live).

## AD-004 ✅ Time: single `utilitytime` owner (R3)

**Decision.** One package owns offset acquisition (from `/tm`), smoothing +
step classification, `serverNow`, event-window evaluation, expiry, and the
grace policies (`expiryConfirmTicks`, `csipReportGraceS`, both scheduler
clock-regression guards, default-fallback hold). Consumers: walker,
scheduler, hub state, lexa-api, optimizer TOU.

**Non-negotiable ports (verbatim semantics + tests):** clock-regression
guard both halves; the 2026-07-03 default-fallback guard (hold still-served
unexpired event over a resolved DefaultDERControl); `serverNow = local +
offset` everywhere. Local (SOM) clock steps get an explicit policy
(TASK-037). **Verified 2026-07-04:** hub freshness windows are *already*
monotonic-safe (`time.Now()`+`Sub`); the local-step exposure is confined to
utility-time comparisons (expiry, TOU) — TASK-037 documents receiver-side
arrival stamping as the cross-process freshness mechanism rather than
rewriting freshness code. Accepted behavior change: wall-clock-denominating
`expiryConfirmTicks` (TASK-036) shifts STOCK control-expiry release from
45 s to 30 s (FAST unchanged at 9 s) — deliberate per 05 §5; campaign-gated.

**Implemented (TASK-034, 2026-07-05):** core library landed at
`lexa-hub/internal/utilitytime` — `Clock`/`New`/`SetOffset` (returns
`StepClass`: `First`/`Wobble`/`Step`, classification never alters the value
`ServerNow` returns)/`Offset`/`ServerNow`/`ServerNowAt`, plus window/expiry
helpers `Expired` and `InWindow` matching `scheduler.controlExpired`/
`activeEvent` boundary semantics exactly. Two composable expiry policies in
`expiry.go`: `DebouncedExpiry` (generalizes `expiryConfirmTicks`) and
`ReportGrace` (generalizes `csipReportGraceS`). Zero consumers by design —
`go test -race ./internal/utilitytime/` 100% statement coverage; walker/
scheduler/hub/api/optimizer migrations are TASK-035/036 (verbatim-port
comparison against today's scheduler happens there).

**Migrated (TASK-035, 2026-07-05, branch `task/035-scheduler-time`):**
consumers 1–3 of 5 — the walker/serverNow and scheduler. `cmd/northbound`
constructs one `utilitytime.Clock`; `runDiscovery` feeds each successful
walk's raw `tree.ClockOffset` via `clk.SetOffset` (logging only a real
`Step` transition) and reads `serverNow` back through `clk.ServerNow()`
(was `scheduler.ServerNow(tree.ClockOffset)` — byte-identical: local + raw
offset, still computed once per walk and shared across Evaluate/Build/
SupersededMRIDs). `responseTracker` holds that shared Clock instead of a
cached `clockOffset`; Response `CreatedDateTime` arithmetic is unchanged.
Inside the scheduler, `controlExpired` delegates to `utilitytime.Expired`
and the `activeEvent`/`SupersededMRIDs` interval checks to
`utilitytime.InWindow`; **`failClosed`, `stillServed`, `plausibleControl`
and all guard ordering are untouched** — the two clock-regression guards
and the 2026-07-03 default-fallback guard keep bit-identical semantics.
`failclosed_test.go`/`scheduler_test.go` pass with an empty diff; a new
`utilitytime_equiv_test.go` differential proves `Evaluate` resolves
identical `*ActiveControl` whether `serverNow` comes from the legacy
formula or the Clock. `scheduler.ServerNow` retained but deprecated (hub-
side TASK-036 still uses the formula until it migrates). Deployed
lexa-northbound only (bench 028-active elsewhere); gate + full FAST
campaign at the wave gate.

**Migrated (TASK-036, 2026-07-05, branch `task/036-time-consumers`):**
consumers 4 and 5 of 5 — hub state, lexa-api, and the optimizer TOU check.
Phase 3 exit criterion met: zero grace/debounce/offset *policy* constants
remain outside `internal/utilitytime` (remaining offset-plumbing fields —
`clockOffset` on `MQTTSystemReader`/`snapshot`, `ClockOffset` on bus/journal
messages — are data, not arithmetic, and are out of scope by design).
`cmd/hub/state.go`'s `MQTTSystemReader` now holds a `utilitytime.DebouncedExpiry`
sized at construction from the engine interval via `confirmTicksFor`
(`expiryConfirmWindowS = 9`, floored at 2 ticks); `ReadSystemState`'s expiry
check delegates to `utilitytime.ServerNowAt` + `utilitytime.Expired` and
`expiry.Observe` in place of the bare `csipExpiredTicks` counter — reset-on-
false / confirm-on-Nth-true semantics unchanged, log line content unchanged.
**Accepted behavior change realized:** FAST is bit-identical (3 s tick → 3
ticks → 9 s, matching the removed `expiryConfirmTicks=3` exactly); STOCK now
floors to 2 ticks = 30 s instead of the legacy tick-counted 3 ticks = 45 s —
the deliberate wall-clock-denomination correction this decision called out
in advance. `cmd/api/handlers.go`'s inline `ValidUntil+GraceS` comparison now
delegates to `utilitytime.ReportGrace{GraceS: csipReportGraceS}.Reportable`
with `serverNow` from `utilitytime.ServerNowAt`; `csipReportGraceS` stays a
local `15` constant (kept for `stale_test.go`'s direct reference) but only
feeds the delegated policy, doing no arithmetic itself — semantics and the
15 s boundary test are unchanged. `internal/orchestrator/optimizer.go`
Rule 5's `serverNow` now sources from `utilitytime.ServerNowAt(now,
state.ClockOffset)` — a pure-function swap only; the package imports no
`utilitytime.Clock` and gains no wall-clock read, preserving the I/O-free
property (05 §1). New tests: FAST/STOCK/1s confirm-tick table
(`TestConfirmTicksFor_ScalesToEngineCadence`), a STOCK-cadence debounce test
including the transient-excursion-rides-out case
(`TestReadSystemState_ExpiryDebounce_STOCKCadence`), a `cmd/hub`-level
differential equivalence test against the removed inline counter
(`expiry_equiv_test.go`, mirroring `internal/utilitytime/expiry_test.go`'s
`TransientJumpRidesOut` coverage), and a nonzero-`ClockOffset` Rule 5 test
(`TestOptimizer_TOU_PeakHour_UsesServerTimeViaClockOffset`).
`go test -race ./internal/... ./cmd/...` green. Not yet deployed to the hub
Pi / gated through Mayhem — bench validation rides the next batched gate
(per the deadline-amendment framing in 05 §12); STOCK spot-check
(`wan-outage-expiry` + `clock-jump-forward` at 45 s→30 s) still pending.

Found in passing, out of this task's scope: `cmd/telemetry/main.go`'s
`postMeasurements` still computes `now := time.Now().Unix() + clockOffset`
inline for MUP reading timestamps — a 6th `serverNow` site AD-004's original
five-consumer list didn't enumerate. Not touched here (not in TASK-036's
Files list); flagged for a follow-up task/backlog entry.

**Local (SOM) clock-step policy — TASK-037, GAP-04, 2026-07-05, lexa-hub
`task/037-local-clock` 8f7e60e (unmerged), csip-tls-test docs
`task/037-local-clock` (this entry).** Extends AD-004 from hardening the
*utility server's* clock to hardening the hub's own *local* wall clock (an
NTP correction at commissioning, an RTC drift fix-up). `go test -race
./internal/... ./cmd/...` green in lexa-hub; not yet deployed to the bench
or gated through Mayhem (TASK-038's HIL scenario is the bench proof).

*Verified before implementing (per this decision's 2026-07-04 note above):*
hub freshness windows (`cmd/hub/state.go`'s `measStaleAfter`/
`evseStaleAfter`/`meterFrozenAfter`) were **already** monotonic-safe — they
stamp arrival with `time.Now()` and compare with `now.Sub(s.at)`, and Go's
`time.Time` carries a monotonic reading from `time.Now()` that `Sub` prefers
over the wall reading. **Decision recorded: receiver-side arrival stamping
is THE cross-process freshness mechanism** — not a message's own `Ts` field.
Every bus message's `Ts` (`bus.Measurement`, `bus.ActiveControl`,
`bus.DERScheduleMsg`, `bus.PricingUpdate`, `bus.BillingUpdate`,
`bus.FlowReservationStatusMsg`, journal events, ...) is publisher-side
observability only; no freshness check anywhere in the codebase reads it,
and this task did not change that. What genuinely was local-wall-clock-
sensitive: control expiry (`cmd/hub/state.go`), lexa-api's report grace
(`cmd/api/handlers.go`), and the optimizer's TOU check — all three compute
`serverNow = local + offset`, which a local step shifts by the step size
until the next accepted offset.

**The fix: monotonic anchoring inside `internal/utilitytime`.**
`Clock.Anchor(serverUnix int64)` records `(serverUnix, cfg.Now())` — the
`time.Time` value keeps an intact monotonic reading as long as it is never
round-tripped through `Round(0)`, marshaling, or Unix-second arithmetic.
Once anchored, `Clock.ServerNow()` returns `anchorServer +
int64(cfg.Now().Sub(anchorMono).Seconds())` instead of re-deriving from
`local + offset` — a local wall step after the anchor cannot move it, by the
same Go-runtime guarantee (`CLOCK_MONOTONIC` immune to `settimeofday`/NTP)
that already made freshness safe. Every fresh utility-time observation
re-anchors: `cmd/hub`'s `MQTTSystemReader.onCSIPControl` anchors at
`msg.Ts+msg.ClockOffset` on every retained-control arrival (same-host
assumption: lexa-northbound stamps `Ts` with `time.Now().Unix()` at publish
on the SAME hub Pi/SOM clock, MQTT localhost latency ≪ 1 s — commented at
the call site; a split-host deployment would have to re-derive); lexa-api's
`stateStore.onCSIPControl` mirrors it for `/status`'s report grace;
`cmd/northbound`'s `runDiscovery` re-anchors its shared `Clock` right after
computing each walk's `serverNow`, so the `responseTracker`'s
`CreatedDateTime` and every other reader of that Clock get the same
immunity between walks — including during a WAN-outage holdover, which is
exactly when a local step would previously have compounded the outage's own
exposure. `Clock.LocalStep()` (`drift := wallElapsed − monoElapsed since the
anchor; stepped := |drift| >= StepThresholdS`, default 30 s) is a pure
detector, decoupled from `ServerNow`, feeding the policy below.

**Local-step policy:** forward steps re-anchor silently (enforcement already
correct via the anchor; a plain transition log only) — backward steps get
the identical anchored correctness plus an alarm-level log, since a backward
RTC/NTP correction is the more operationally surprising direction (log
wall-times can appear to regress). Either direction logs exactly once per
transition (edge-triggered, mirroring `noteStaleness`) via a pure decision
function (`cmd/hub`'s `localStepEdge`) factored out specifically so the
"exactly once" claim is unit-testable without needing to fake a genuine
OS-level wall/monotonic desync — which cannot be constructed through Go's
public `time.Time` API (`Time.Add` shifts wall and monotonic components by
the identical duration; there is no way to desync them from user code). Test
suites therefore prove the anchored formula is elapsed-time-based (immune to
`SetOffset`/wall-`Unix()` reads once anchored) and contrast it against what
the pre-anchoring raw formula would have produced under a simulated ±1 h
step, rather than attempting to fake the OS-level desync itself.

**Orchestrator stays I/O-free (05 §1):** rather than touching
`internal/orchestrator`, both `cmd/hub/state.go`'s `ReadSystemState` and
`cmd/api/state.go`'s `snapshot()` publish a *derived* offset —
`r.utclk.ServerNow() − now.Unix()` — into the existing `ClockOffset` field
the optimizer/report-grace code already consumes via
`utilitytime.ServerNowAt`. Under a stable local clock this is bit-identical
to the raw offset (both equal server-minus-local); it only diverges during
the monotonic holdover between control arrivals under a local step, which is
exactly the case this task closes. One-line change at each call site;
`internal/orchestrator` untouched.

**Sweep (TASK-037 step 6, `grep -rn "\.Unix()" cmd internal --include=*.go`,
excluding tests, run in lexa-hub):** classified every hit. Stamps
(publisher-side observability, unaffected — `Ts` fields on
`bus.Measurement`, `bus.ActiveControl`, `bus.DERScheduleMsg`,
`bus.PricingUpdate`, `bus.BillingUpdate`, `bus.FlowReservationStatusMsg`,
`bus.PlanLog`, `bus.ComplianceAlert`, journal events,
`cmd/hub/desired.go`'s `doc.IssuedAt`, `cmd/modbus`'s measurement `Ts`);
offset acquisition (`internal/northbound/discovery/walker.go`'s
`tree.ClockOffset = tm.CurrentTime - time.Now().Unix()` — the source of
truth every anchor ultimately derives from, not itself a comparison);
local-time bucketing, not utility time (`cmd/hub/main.go`'s pricing-window
5-min snap; `internal/orchestrator`'s window/EV-departure bucketing —
unaffected, package untouched per this task's scope); dead code
(`internal/northbound/scheduler.ServerNow`, deprecated TASK-035, zero live
callers). Two **known, already-flagged, out-of-scope enforcement gaps**
remain wall-clock-sensitive and are NOT fixed by this task (neither is in
TASK-037's Files list; both pre-date it): `cmd/telemetry/main.go`'s
`postMeasurements` (the "6th serverNow site" this decision already flagged
after TASK-036, immediately above) still computes `now.Unix() +
clockOffset` inline; `internal/reconcile/reconcile.go`'s `SetDesired` stale
gate (`now.Unix()-doc.IssuedAt > staleAfter`) compares raw Unix seconds
rather than a monotonic `Sub` — both are candidates for a follow-up backlog
entry (anchor-hardening or receiver-arrival conversion respectively) but sit
inside `cmd/telemetry`/`internal/reconcile`, which this task's launch
instructions place out of bounds (owned by concurrent in-flight work on the
reconciler/actuator path, TASK-031).

**Not this task's job:** the Mayhem HIL proof (forward/backward local-step
scenarios) is TASK-038; a metric on the local-step alarm is TASK-044; DST/
timezone TOU edge cases are TASK-079.

## AD-005 ✅ Persistence: append-only event journal + guard snapshots, not a database (W5)

**Decision.** Newline-delimited, size-rotated, fsync-batched journal on
its own quota (journald-style), recording controls adopted, dispatches,
breach episodes, CannotComply — doubles as the utility-facing audit log.
Separately, a small guard/breach snapshot (JSON, atomic rename) restored on
start behind a flag. Retained MQTT remains the *bus* recovery mechanism;
the journal is the *record*; the snapshot only covers state whose loss
causes protocol noise (duplicate CannotComply begin) or safety regressions.

**Alternatives.** SQLite (rejected for now: flash wear, fsync cost, new
dependency; revisit for fleet telemetry), rely on MQTT retention alone
(rejected: §8.3 rollback risk + no audit record).

**TASK-039 update (2026-07-05): journal half implemented as a pure library,
schema version 1.** `lexa-hub/internal/journal` (`journal.go`/`schema.go`/
`reader.go`) lands the writer, schema, and reader — no consumers yet
(TASK-040 wires the first caller; blocked on TASK-031). Schema v1's Event
envelope (`v`/`ts`/`srv_t`/`seq`/`type`/`svc`/`data`) wraps nine transition-
only payload types (`control_adopted`, `control_released`, `dispatch`,
`breach_begin`/`breach_end` keyed by `episode_id = mrid + "/" + beginTs`,
`cannot_comply_posted`, `service_start`, `snapshot_written`/
`snapshot_restored` for TASK-041) — deliberately no per-tick event, matching
05 §9. Rotation is rename-then-create (`name` → `name.1` → … → `name.MaxFiles`,
oldest dropped), never copy. Fsync is batched on `FlushEvery` (default 32)
events OR `FlushInterval` (default 5 s) elapsed, checked lazily on `Append` —
no goroutines in the library itself, matching 05 §4's ownership rule. The
reader (`Scan`) tolerates a torn final line from a power cut; `Open` pads a
newline onto a torn tail before resuming writes, so a subsequent Append
can't silently concatenate onto garbage.

**Write-budget numbers (package doc comment, `internal/journal/journal.go`,
cites RSK-14):** representative line sizes measured, not hand-waved —
control_adopted 229 B, dispatch 124 B, breach_begin/breach_end 252 B (the
largest type). Pathological FAST ceiling (every tick transitions on every
axis at once): 201,600 events/day ≈ 52.4 MB/day of input volume. Default
quota (`MaxBytes` 1 MiB × (`MaxFiles` 4 + 1) = 5 MiB) bounds resident size
regardless of input rate — a storm just rotates the window faster (≈2.3 h
retention at the pathological ceiling, self-healing once it clears) rather
than growing past 5 MiB. `docs/FLASH_BUDGET.md`'s 2026-07-05 P0-exit
measurement (hub 108 lines/min ≈ 155k lines/day FAST, journald's own
per-tick log, a different budget) confirms the estimate's order of
magnitude; the journal's 5 MiB cap is a rounding error against journald's
200 MB `SystemMaxUse` — it fits *inside* that existing flash budget rather
than stacking a second one on top, per that doc's "Related budgets" note.
fsyncs/day bounded at ≈17,280 (one per `FlushInterval` while active) at the
pathological ceiling's event rate, below the crossover to the count-boundary
governing instead.

Tests: `go test -race ./internal/journal/`, 95.1% coverage — round-trip +
Seq-resume-across-reopen, rotation shift-chain + `MaxFiles` honored, torn-tail
tolerance (both `Scan` and resume), fsync batching at both boundaries
(`FlushEvery`/`FlushInterval`, observed via on-disk file size), and the
disk-full/permission-loss error path (a read-only directory forcing a
rotation failure) proving edge-triggered logging + error return + recovery
after the directory becomes writable again (AD-011: journal failure must
never crash a caller). Zero consumers today (`grep -rn "internal/journal"
~/projects/lexa-hub --include=*.go | grep -v internal/journal` empty).

## AD-006 🔶 Bus schema: version envelope, reject-and-alarm

**Decision.** Every bus JSON message carries `"v": N`; subscribers reject
unknown majors, alarm via metrics/log, and (for retained control-plane
topics) trigger the re-request path instead of running with zero-values.
Design in TASK-017; the desired-state document (AD-002) is the first
new schema born versioned. Pending validation: rolling-upgrade test.

**Decode-policy table (landed TASK-017: `lexa-hub/internal/bus/envelope.go`).**

| Wire shape | Policy | Mechanism |
|---|---|---|
| `"v"` absent (indistinguishable from explicit `"v":0`, since the field is `omitempty`) | Legacy v0 — **accepted** while the transition is open | `bus.LegacyV0Accepted` (package var, default `true`) |
| `1 ≤ v ≤ supported` | Accepted | `bus.CheckVersion` returns `nil` |
| `v > supported` or `v < 0` | **Reject + alarm** | `bus.CheckVersion` returns `*bus.VersionError`; caller invokes `bus.RejectAndAlarm` |
| Same-major, unrecognized fields | Ignored (additive evolution stays cheap) | `encoding/json`'s default unmarshal behavior — no extra code |
| Malformed JSON / non-numeric `"v"` | Not `CheckVersion`'s concern — surfaces at the real `json.Unmarshal` a line later | Documented on `CheckVersion`, single-responsibility |
| Rejected message on a **retained control-plane** topic | Hold last-known-good now (existing scheduler fail-closed discipline); active re-request is TASK-042 (P3, not yet built) | Enforced (TASK-018): every subscriber calls `CheckVersion` (`mqttutil.Subscribe`'s gate, plus the one raw `mc.Subscribe` in cmd/northbound for FR-request) |

Granularity is per-schema, not global: `bus.MeasurementV`, `bus.BattMetricsV`,
`bus.ActiveControlV`, `bus.ComplianceAlertV`, `bus.BattCommandV`,
`bus.SolarCommandV`, `bus.EVSEStateV`, `bus.EVSECommandV`,
`bus.PricingUpdateV`, `bus.BillingUpdateV`, `bus.FlowReservationRequestV`,
`bus.FlowReservationStatusV`, `bus.DERScheduleV`, `bus.PlanLogV` — all born
at `1`. Rejects are counted per-topic (`bus.VersionRejects()`, atomic,
scraped by TASK-044 once a metrics endpoint exists) and logged rate-limited
(first occurrence + every 100th per topic) to stay inside the journald
budget (TASK-009).

TASK-017 was introduce-only (type, constants, `CheckVersion`,
`RejectAndAlarm` — nothing wired). TASK-018 (2026-07-04) did the wiring:
every publish site in the inventory grep (`lexa-hub` cmd/modbus, cmd/hub +
actuators.go, cmd/northbound, cmd/ocpp) stamps its per-schema `V`; every
subscriber gates on `CheckVersion` before decode. `Measurement`'s voltage
field moved from `V`/`"v"` to `VoltageV`/`"voltage_v"` in the same change —
embedding `Envelope` (also field `V`, tag `"v"`) would otherwise have
silently shadowed the version field on the wire (Go's same-JSON-key
conflict resolution keeps the shallower, non-embedded field and drops the
embedded one with no error) rather than a compile-time signal. Code and
unit tests (`go test -race ./internal/bus/ ./internal/mqttutil/`, full
`go test -race ./internal/... ./cmd/...`) are green.

**Status stays 🔶, not ✅, deliberately**: this rollout landed during a
program-wide deploy freeze (TASK-012 unmerged) with bench access authorized
for read-only/verification only, not deploys. The rolling-upgrade
validation this AD's "pending validation" line names — mixed v0/v1
publishers against a v1 subscriber, observed on the real bench mid-restart
— did **not** run in this session; it is deferred to the P0-exit gate
alongside TASK-012's merge, per the task's lane instructions. See
`docs/refactor/tasks/TASK-018.md`'s status header for the explicit
deferral note.

**Enforcement-flip criteria** (for the later, separate change that sets
`LegacyV0Accepted = false`): every retained control-plane topic
(`lexa/csip/control`, pricing, billing, FR status, `lexa/northbound/schedule`,
`lexa/hub/plan`) must be observed carrying `"v":1` on the live bench — via
`mosquitto_sub -C 1 -t <topic>` after a fresh publish from each — **and** one
full FAST Mayhem campaign must run clean after that observation. Only then
flip the var; in the same change, `csip-tls-test`'s
`cmd/dashboard/mqtt_scenarios.go` injected payloads for
`mqtt-malformed-control` and `mqtt-stale-retained` gain `"v":1` (today they
stay v0-shaped on purpose, since v0 is still tolerated).

## AD-007 🔶 Optimizer split: constraint controller over economic layer, plant model (R4)

**Decision.** Priority-ordered constraint controller (safety > compliance >
economics) with one `session` struct per constraint; per-device plant model
(ramp rate, control latency, taper curve — configured now, discovered
later) replaces bench-calibrated globals. Shadow-mode dual-run gates every
flip. Multi-device from the start (breach list, per-device sessions).
Pending validation: shadow-diff results (TASK-059).

**Open questions.** ❓ Plant-model discovery (probe ramps on commissioning)
is P6/backlog — configured-only for V1.0. ❓ DP planner stays as-is below
the constraint layer; revisit only if shadow diffs implicate it.

## AD-008 🔶 Security: broker ACLs now, API token+TLS now, OCPP profile 2 at P6

**Decision.** Per-service Mosquitto credentials + topic ACLs (config
sketch already exists in `mosquitto-lexa.conf`); lexa-api gets bearer-token
auth + TLS (consumers verified 2026-07-04: dashboard proxy/logmux, mayhem +
replay drivers via the dashboard's hub client, metersim linked mode — all
updated in lockstep, TASK-014); OCPP moves to security profile 2 in P6.
**Verified 2026-07-04:** SP2 is *already implemented* on both sides
(`ocppserver` has `ws.NewTLSServer` + constant-time BasicAuth; evsim has
`-tls-ca/-auth-user/-auth-pass`) — TASK-074 is enablement/provisioning
(certs, configs, lockstep deploy, negative-auth test), not development.
Bench admin/simapi surfaces stay open *on the air-gapped bench only* —
documented as a bench property, never a product default. Deployed-vs-repo
mosquitto config differs (the Pi runs a slimmed conf.d drop-in) — ACL work
must edit both (TASK-013).

**TASK-014 update (2026-07-04): API-token half delivered, TLS half explicitly
deferred.** Bearer-token auth on lexa-api `/status`/`/logs` landed
(constant-time compare, `api_token_file` staged rollout — empty ⇒ open,
today's behavior preserved until the bench explicitly flips it), with every
verified consumer migrated in the same task: dashboard proxy Director +
logmux hub stream + Mayhem/replay driver HTTP helpers (scoped to the
`"hub"` base only — simapi/gridsim stay open), metersim `-hub-token-file`.
`/healthz` stays unauthenticated (TASK-008 watchdog self-probe).
**TLS on :9100 is deferred, not delivered**: the bench is air-gapped
LAN-only (same justification as the admin/simapi surfaces above), and a TLS
listener is meaningful extra surface (cert provisioning + lockstep client
changes in the dashboard/metersim/driver HTTP clients) that doesn't reduce
risk on an already-token-gated, non-routable segment. Backlog: TLS listener
on :9100 (follow-up, unnumbered) if/when lexa-api leaves the air-gapped
bench assumption.

## AD-009 ❓ HTTP client on the northbound boundary (R5/D9)

**Problem.** Hand-rolled HTTP/1.1 parsing over wolfSSL parses hostile
utility bytes. **Evidence correction (verified 2026-07-04):** the review's
"chunked decoding" claim is wrong — `tlsclient` *rejects* chunked responses
outright, and a 10 MiB body cap (`maxResponseBody`) already exists; the
real gaps are the unbounded **header** read and hand-rolled status/header/
Content-Length parsing, plus the missing chunked support itself if a
utility server ever requires it. **Options:** (a) `net.Conn` shim over the
wolfSSL session under Go's `http.Transport`; (b) fuzz + harden the existing
parser. The correction narrows (b)'s cost but (a) also *closes the chunked
functional gap*; still leaning (a). Decision in TASK-069, informed by
TASK-047 fuzz findings. Until then the parser gets the header cap
(part of TASK-047).

**TASK-047 findings (2026-07-05):** the parsing core (`readResponse`'s
header loop + `responseContentLength` + `isChunkedEncoding`) moved into a
new CGo-free leaf package, `lexa-hub/internal/tlsclient/httpwire`
(stdlib-only imports), so it fuzzes on any machine without the wolfSSL
sysroot `internal/tlsclient` itself needs. Added the missing header-block
cap (`maxResponseHeader = 64 KiB`, unbounded before this task — the body
cap already existed). Three go-native fuzz targets
(`FuzzReadHTTPResponse`, `FuzzResponseContentLength`,
`FuzzIsChunkedEncoding`), seeded with 11 real gridsim-captured responses
plus structural edge cases (negative/huge/duplicate Content-Length,
header-only flood, chunked header, split-across-reads), 15 minutes each
locally (~25–46M execs/target) — **zero crashers**. This narrows option
(b)'s residual risk (the review's original worry — "parsing bugs = security
bugs" — has 15 CPU-minutes/target of fuzz coverage behind it now with no
findings) but doesn't resolve the chunked functional gap that only option
(a) closes; TASK-069 decision still open. Nightly CI job added
(`.github/workflows/ci.yml` `fuzz`, schedule-only, no wolfSSL sysroot
needed) so fuzz coverage keeps accumulating between now and that decision.

## AD-010 ❓ CSIP curve functions (volt-var / volt-watt)

derbase has write paths; nothing drives them from CSIP. V1.0 must either
implement closed-loop curve dispatch or explicitly de-scope in product
claims + conformance statement. Decision in TASK-080 after utility/market
input. De-scope is acceptable for V1.0; silence is not.

## AD-011 ✅ Crash-only design is intentional

MQTT handlers do not `recover()`; a panic kills the service; systemd
restarts (5 s) + retained topics + (post-P3) snapshot restore re-seed
state. This is the documented intended design (review §10.6) — watchdogs
(TASK-007/008) extend it to live-but-wedged. Do not add blanket recovers.
Documented in operator terms (TASK-045): `lexa-hub/docs/OPERATIONS.md` covers
what each of the six services loses/keeps across a restart, systemd
Restart/WatchdogSec timing, and what to check afterward (plan heartbeat,
`/status`, journal, `/metrics`).

## AD-013 ✅ Desired-state document: schema, topic, seq/staleness policy (AD-002's wire contract)

**Problem.** AD-002 decided the optimizer publishes a retained, versioned,
per-device desired-state document that a co-located reconciler converges the
hardware to, but left the wire contract unspecified: topic layout, field set +
per-field absence meaning, and the anti-rollback (seq/staleness) policy a
*retained* control document needs (§8.3). TASK-026…033 each replace a legacy
convergence mechanism against this schema; without one fixed contract each
would re-invent field semantics (RSK-01).

**Decision — topic.** `lexa/desired/{class}/{device}`, `class ∈
{battery, solar, evse}`, **retained, QoS 1** (control-plane precedent
`lexa/csip/control`). Retained + QoS 1 gives free crash recovery: a reconciler
that (re)subscribes — after its own restart, a broker restart, or a device
reconnect — is redelivered the standing intent immediately, without waiting for
the publisher to re-emit. For EVSE, `{device}` is the OCPP stationID and the
connector rides *inside* the document (`connector_id`); one retained doc per
station, matching `lexa/evse/{station}/command`. Meter has **no** desired topic
(see resolution below).

**Decision — document fields** (JSON, snake_case wire tags; `*T` = "absent /
no opinion", the NaN-as-nil bus rule):

| Field | Wire key | Type | Meaning |
|---|---|---|---|
| version | `v` | `int` (=`DesiredStateV`=1) | AD-006 envelope; born versioned |
| class | `device_class` | `string` | `battery`\|`solar`\|`evse` |
| id | `device_id` | `string` | device name / stationID |
| ceiling | `ceiling_w` | `*float64` | **solar** generation ceiling (W); restore = an explicit large value (`restoreCeilingW`-style 1e9), **never** "field absent" |
| setpoint | `setpoint_w` | `*float64` | **battery** setpoint (W): +discharge / −charge |
| connect | `connect` | `*bool` | **battery** cease/energize |
| current | `max_current_a` | `*float64` | **EVSE** max current (A); explicit `0` = suspend |
| connector | `connector_id` | `int` | **EVSE** connector (0 = station default per OCPP) |
| source | `source` | `string` | `csip-event`\|`csip-default`\|`economic`\|`safety` |
| mrid | `mrid` | `string` | active CSIP control, for CannotComply attribution (TASK-031) |
| issued | `issued_at` | `int64` | Unix seconds, publisher wall clock |
| seq | `seq` | `uint64` | **monotonic per device**, publisher-owned |

**Field-absence semantics (the silent-zero XML lesson applied to the bus).**
`nil`/omitted ≠ zero. A `nil` typed field is "no opinion — leave that surface
as the last standing intent set it"; an explicit zero is a *command*:
`setpoint_w:0` idles the battery (and per ledger L1 is what *enforces* the SOC
reserve — never confuse it with "no setpoint"), `max_current_a:0` suspends the
EVSE. Solar restore is likewise an explicit large `ceiling_w`, not an absent
field — the modbus layer already learned an EMPTY control is a silent no-op
(`cmd/modbus/main.go:263–277`, `solarCommandToControl`). Per class only its own
fields carry opinion; the others stay `nil` (a battery doc's `ceiling_w` /
`max_current_a` are always `nil`, etc.).

**Decision — seq / staleness policy (RSK-17).** A consumer keeps, per device,
the last-applied `(seq, issued_at)`. On each received document:

1. **Reject as out-of-order / replay** iff `seq <= lastAppliedSeq` **AND**
   `issued_at <= lastAppliedIssuedAt` — the retained-redelivery / duplicate
   case. Count it (per-device reject counter) and log rate-limited.
2. **Accept with a `SeqReset` signal** when `issued_at` is **strictly newer**
   than `lastAppliedIssuedAt` but `seq` is lower or reset (e.g. back to 0).
   This is the publisher-restart case: the hub restarts and its per-device
   `seq` resets to 0, but its wall clock advanced, so fresh intent legitimately
   carries a *smaller* seq than the pre-restart retained doc. Emit a structured
   `SeqReset` log + counter (a restart must be observable, not silent) and
   adopt the new `(seq, issued_at)` as the baseline.
3. **Reject as stale**, regardless of seq, any document whose `issued_at` is
   older than the staleness bound (below): an old retained doc carrying a high
   seq must not win over reality.

The rules compose: (1) is the anti-rollback guard within one publisher epoch,
(2) tolerates the epoch change a restart creates, (3) bounds trust in the
retained message's age. `seq` is deliberately **per device**, not per-class or
global: reconcilers compare monotonicity per device, and a shared counter would
couple independent devices and cause spurious rejects.

**Absence of fresh documents is NOT a release (fail-closed, 05 §3).** If no
document arrives the reconciler **holds last-known-good** — silence is never
"return the device to full output / unsuspend". After a wall-clock staleness
threshold it emits a *staleness report* (observability only; it does not change
the held command). **Default threshold: 300 s** — long enough to survive a
broker blip and a publisher restart + first re-publish (hub systemd restart
≈5 s + first economic tick), short enough to surface a wedged publisher within
one CSIP reporting-grace window; being a reported condition and not an
actuation change, erring long is safe. Full retained-trust hardening (active
re-request instead of waiting; tuning this bound against measured restart
timings) is TASK-042; this AD fixes the schema and the *hold-and-report*
discipline it depends on.

**Alternatives considered.** *Absence = restore* (rejected: reintroduces the
silent-zero bug class the schema exists to kill — a dropped/late doc would
silently uncurtail a plant). *Single global / per-class `seq`* (rejected:
couples independent devices, causes cross-device replay rejects). *Timestamp
only, no seq* (rejected: two docs within one wall-clock second are unordered).
*`seq` only, no `issued_at`* (rejected: a restart to `seq=0` could not be
distinguished from a replay — rule 2 needs the clock).

**Tradeoffs.** Consumers carry two extra scalars per device and one clock
comparison; in exchange the legacy convergence mechanisms (ledger L1–L7)
collapse to one reconciler reading one retained doc. The staleness bound is a
policy knob, not a safety boundary (safety stays fail-closed on the held value
plus the Tier-0 interlock).

**Migration.** Types land now (`internal/bus/desired.go`, `DesiredStateV`),
compiled but unused. TASK-026 builds the reconciler core, unwired.
TASK-027 (2026-07-05) is the first thing to ever put a message on this topic
family: it lands the first publisher (`cmd/hub/desired.go`, additive —
battery only, wraps the legacy actuator) and the first subscriber
(`cmd/modbus/reconcile_shadow.go`, shadow mode — a passive recorder, zero
writes), and — since neither TASK-026 nor anything before it had ever
subscribed the topic — adds the `lexa/desired/` → `DesiredStateV` case to
`bus.SupportedV` (`internal/bus/topics.go`) that this paragraph originally
described as TASK-026's; it was deferred in practice to whichever task wired
the first real subscriber, cited as such in TASK-027's commit. Solar/EVSE
publishers (TASK-029/030) follow the same pattern. Every legacy mechanism the
doc replaces is tracked to its originating QA scenario in
`docs/refactor/PRESERVATION_LEDGER.md` (TASK-025, shadow-observation notes
added by TASK-027) and may not be deleted until its gate scenarios pass on the
reconciler (05 §11) — TASK-027's shadow soak (bench, deferred to the wave
gate) is that proof for battery; TASK-028 is the flip.

**Resolves AD-002's open questions.** ✅ **Meter gets no desired document** —
no actuator exists for it: `cmd/hub` registers actuators only for
`battery`/`inverter` roles and EVSE stations (`cmd/hub/main.go:213–232`), and
`cmd/modbus` `subscribeControls` gates writes on role `battery`/`inverter`
(`cmd/modbus/main.go:203–241`); the meter is read-only, so no `class` for it
exists. ✅ **Tier-0 interlock stays measurement-only**, above the reconciler
(`cmd/modbus/interlock.go`): it does not read the desired doc and never
reconnects a pack — a local reflex that must survive hub/broker death
(ADR-0001), so coupling it to a bus document would defeat its purpose. Revisit
only at P5.

**✅ Confirmed in practice at the TASK-028 battery flip (2026-07-05):** with the
reconciler holding write authority, the interlock stayed measurement-only and
senior. A read-only `isTripped` accessor (no logic change) lets the active
reconciler defer to Tier-0: while a pack is force-disconnected the reconciler
suppresses connect-restoring writes (reports `InterlockHold`) rather than fight
it. `battery-wrong-sign` PASS with INV-SOC/SAFETY held and no INV-HUNT
oscillation — the guard-vs-guard interaction the reconciler design set out to
avoid did not materialise.

---

## Superseded / rejected log

| Date | Decision | Status |
|---|---|---|
| 2026-07-01 | Monolith rewrite | Rejected (ADR-0001) |
| 2026-07-04 | Keep four convergence layers | Rejected (AD-002) |
| 2026-07-04 | SQLite persistence for V1.0 | Rejected (AD-005) |
