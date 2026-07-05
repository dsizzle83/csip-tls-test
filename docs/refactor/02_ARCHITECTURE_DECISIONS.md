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

**Open questions.** ❓ Does the Tier-0 interlock read the desired-state doc
directly (bypassing hub) for its reflexes, or stay measurement-only?
Default: measurement-only (unchanged) until P5. ❓ Meter gets no desired
state (read-only device) — confirm no code path assumes otherwise.

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

**Open questions.** ❓ One module or three? Start with one module, three
packages — split later only if versioning pressure appears.

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

---

## Superseded / rejected log

| Date | Decision | Status |
|---|---|---|
| 2026-07-01 | Monolith rewrite | Rejected (ADR-0001) |
| 2026-07-04 | Keep four convergence layers | Rejected (AD-002) |
| 2026-07-04 | SQLite persistence for V1.0 | Rejected (AD-005) |
