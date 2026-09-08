# LEXA DERMS Edge Gateway — Architecture Review & Engineering Audit

*Scope: `lexa-hub` (~28.5k LOC Go) + `csip-tls-test` (~41.5k LOC Go) treated as one system. Findings are tagged **[Proven]** (code evidence), **[Likely]** (strong indicators), **[Speculative]** (needs validation).*

---

## 1. Executive Summary

This is a **well-shaped prototype with an exceptional test culture and an accreting control core**, roughly 12–18 months of disciplined work away from being something a utility should depend on.

The distributed six-service architecture is correct and defensible — ADR-0001 rejects the monolith with an actual latency-budget measurement, which is more rigor than most teams ever apply. The Mayhem HIL suite (51 hostile scenarios, cross-cutting invariants, 10-cycle campaigns) is genuinely rare at this stage and is the single most valuable asset in the company.

But the product's core — `internal/orchestrator/optimizer.go`, 2,329 lines — is **scar tissue**. Every QA campaign added a guard, a counter, a tolerance band, or a sticky flag. There are now at least **four independent, uncoordinated mechanisms** whose only job is "make the device's actual state converge to the hub's desired state," and last night's finding (the dedupe/breach interaction) proved they can silently fight each other. The intentional cross-repo duplication has **already diverged** despite the lockstep rule. Utility time is handled by five different local patches. There is **no persistence, no process watchdog, no authorization model, no cert lifecycle, and no CI** — and the last month of safety-critical fixes sits **uncommitted in two working trees**, which alone would stall an acquisition.

Verdict: **not commercially deployable today**; the skeleton and the QA harness are worth keeping and building on; the control core and the state-convergence machinery should be redesigned around an explicit desired-state reconciler before any fleet deployment.

---

## 2. Overall Architecture Grade

| Dimension | Grade | One-line justification |
|---|---|---|
| Process/service topology | **A−** | Right split, right isolation, right CGo containment; ADR-backed |
| Control-loop core (optimizer) | **D+** | 2,329-line rule cascade with 9+ pieces of inter-tick guard state; bench constants baked in |
| State convergence / actuation | **C−** | Four overlapping ad-hoc mechanisms; proven emergent interactions |
| Northbound protocol stack | **B−** | Solid walker/scheduler with fail-closed discipline; hand-rolled HTTP; time model scattered |
| Southbound (Modbus/SunSpec) | **B** | Clean layering (registry → retryDevice → derbase → sunspec); single-vendor assumptions |
| Testing / QA | **A−** | HIL mayhem is outstanding; self-confirmation and fuzzing blind spots remain |
| Operational readiness | **D** | No watchdog, no metrics, no persistence, no cert lifecycle, no CI |
| Security posture (as a product) | **D+** | Reasonable transport crypto; essentially no authz anywhere behind it |

**Composite: C+ as a product, B+ as an engineering effort.** The delta is precisely the productization backlog.

---

## 3. Biggest Strengths

1. **The two-loop, six-service topology** [Proven]. `cmd/{hub,northbound,modbus,ocpp,telemetry,api}` over localhost Mosquitto with retained CSIP control. Fault isolation is real: a wolfSSL segfault cannot take down the battery-disconnect path. `lexa-modbus` and `lexa-hub` are `CGO_ENABLED=0`. ADR-0001 shows the topology was *measured*, not assumed.

2. **Mayhem QA + invariants engine** [Proven]. 51 adversarial HIL scenarios, cross-cutting safety invariants (INV-SOC, INV-EXPORT, INV-HUNT, INV-CONVERGE), verdict laddering, 10-cycle campaigns with per-cycle JSON evidence. The V3→V6 FAIL trajectory (5.0 → 2.1 → 0.6/cycle) with journal-level root-causing is a working reliability flywheel. This is the acquisition's crown jewel — more than the product code.

3. **Fail-closed discipline in the scheduler** [Proven]. `internal/northbound/scheduler/scheduler.go` `failClosed()`: last-known-good retention, malformed-control rejection, explicit-clear vs. anomaly distinction, clock-regression guards (both halves now), all pinned by regression tests including mutation-verified ones.

4. **Closed-loop actuation philosophy** [Proven]. "Trust measurement, not the command" is implemented: gen/import/export convergence checkers with meter-independent floors (`checkGenLimitConvergence`'s `gen ≥ export − batteryDischarge` bound at optimizer.go:1286-1297), plausibility gating in `cmd/modbus` (`plausibleW`), Tier-0 battery interlock (`cmd/modbus/interlock.go`), CannotComply reporting. Most vendors ship open-loop and pray.

5. **MQTT plumbing done right at the small scale** [Proven]. `mqttutil`'s `subRegistry.replay()` handles the paho resubscribe-after-reconnect trap that silently deafens most Go MQTT services. Mosquitto config bounds queues, persists retained state, documents its own ACL upgrade path.

6. **Key hygiene** [Proven]. Private keys gitignored, deployed via `install -m 600 -o lexa`, LFDI derived from the cert.

---

## 4. Biggest Weaknesses

### W1 — The optimizer is an accretion disk, not a design [Proven]
`optimizer.go` (2,329 lines) holds a strictly ordered rule cascade (Rules 1→6 + restore + safety backstop) threading a mutable `batteries` slice and `*Plan` through every rule, with inter-tick state in **nine+ places**: `expGuard` (8 fields), `impGuard` (5), `genGuard`, `expOverTicks`, `battDrainTicks`, `battWrongDirTicks`, `lastBattCmd`, `genCapActive`, plus tick-scaling (`scaleTicks`). Constants are bench-calibrated and admit it in comments: `socStepEstimate` is "Calibrated for the 20× demo (10 kWh / 5 kW pack, 3 s tick)" (optimizer.go:761-768); the ceiling slew (`maxDropW=1500/maxRiseW=500`) and `filterAlpha=0.4` encode *this bench's meter lag*. Each guard exists because a specific Mayhem scenario failed. That is how you harden a prototype; it is not how you ship a controller that must work on Sunny Boy + Powerwall + random CT meters with different lags. **The rule interactions are now the primary bug source** — the QA history shows nearly every recent defect was a guard×guard or guard×reset interaction, not a missing feature.

### W2 — Desired-state convergence is implemented four times, nowhere explicitly [Proven]
The same problem — "the device must end up in the state the hub wants" — is solved by:
(a) `applyRestoreRule` re-commanding every device every tick;
(b) `cmdDeduper` suppressing identical publishes with a 60 s watchdog *plus* the breach-triggered reset added 2026-07-03 (`cmd/hub/actuators.go`);
(c) `retryDevice.lastCtrl` reassert-on-reconnect (`cmd/modbus/main.go:302-446`);
(d) convergence checkers + CannotComply chain (optimizer → `plan.Breach` → `breachAlert` closure edge-detector → MQTT alert → northbound `responseTracker` → HTTP POST — five hops, stateful at each).
These layers were each added to fix a QA finding, and they interact: the 30-second "inverter ignores a 0 W ceiling while the hub posts CannotComply about it" incident was (b) defeating (a) while (d) watched. There is no single place where "desired state," "last written," and "last measured" exist together. **This is the system's deepest structural flaw.**

### W3 — The lockstep duplication has already failed [Proven]
`internal/southbound/sunspec` differs between repos today (`der1547.go`, `models.go`, `reader.go` differ; `layout.go`/`derlayout.go` exist only in the product). Worse, `csip-tls-test/cmd/hub` — the "obsolete, reference-only" monolith — drags a **stale 1,237-line fork of the orchestrator**, plus forked `derbase`, `csip` model, and tlsclient, all still compiled and maintained-by-accident. The MTR-4 audit finding exists because this class of divergence already misread hardware once. There is no CI check enforcing sync; the rule lives in a CLAUDE.md.

### W4 — Utility time has five owners [Proven]
Clock offset is independently handled by: the walker's per-walk `/tm` resync; the scheduler's `serverNow` + two clock-regression guards; `cmd/hub`'s `expiryConfirmTicks` debounce (state.go:348-371); `lexa-api`'s `csipReportGraceS`; and the optimizer's TOU `serverNow`. Four different grace/debounce constants for one concept. The clock-jitter saga (four separate fixes across three services over three days) is the empirical proof that time needs a single owned abstraction.

### W5 — Nothing survives a restart except by luck of MQTT retention [Proven]
No persistence layer exists in the product. All guard state, breach episodes (`activeBreachMRID` lives in a *closure* in `cmd/hub/main.go`), EV cooldowns, and the daily plan are RAM-only. The retained `lexa/csip/control` message is the only durable state — and Mosquitto's `autosave_interval 60` means **a power cut can resurrect a control up to 60 s stale** on reboot (see QA Blind Spots). No dispatch/compliance/metering event log exists, which utilities will contractually require.

### W6 — Dead monolith plumbing inside the live control loop [Proven]
`Engine.SetCSIPPrograms` / `e.sched` / `hasDisconnectControl` (engine.go:198-226, 506-530) is a second, unused CSIP-resolution path from the monolith era, guarded by a comment saying "never both." Production wires only the MQTT reader. A dead scheduler evaluation site inside `tick()`, with its own mutex, is exactly where a future engineer creates a split-brain control source.

### W7 — Zero authorization model behind the crypto [Proven]
`lexa-api` :9100 is plaintext, unauthenticated HTTP that exposes full system state and is consumed by the dashboard, the QA harness, *and metersim*. Mosquitto is `allow_anonymous true` (localhost-only, documented tradeoff — but any local code execution = full hardware control, and the config file itself admits it). OCPP CSMS is `ws://` (no TLS) on :8887 with no charger authentication visible. Admin/simapi surfaces are unauthenticated "by design" for the air-gapped bench — fine for the bench, but there is no designed-in path to a secured product; it's all "add auth later."

---

## 5. Technical Debt Inventory

| # | Item | Type | Evidence | Cost of carrying |
|---|---|---|---|---|
| D1 | `csip-tls-test/cmd/hub` monolith + stale orchestrator/derbase/csip forks (~4–5k LOC) | Dead code | 1,314 LOC in cmd/hub + `internal/orchestrator/optimizer.go` @1,237 vs product 2,329 | Confuses every grep; silently diverging "reference" |
| D2 | `gui/sim_gui.py`, `sim_*.txt` root-level guides | Dead/legacy docs | files present | Onboarding noise |
| D3 | `SetCSIPPrograms` dual-source path in engine | Obsolete abstraction | engine.go:198-226,506-530 | Split-brain foot-gun in the core loop |
| D4 | Lockstep sunspec/ocppserver duplication, already diverged | Duplicated logic | `diff -rq` above | Register-map bug class (MTR-4) recurs |
| D5 | QoS-1-for-everything vs. documented QoS 0 measurements | Doc/code divergence | `mqttutil.publishJSON` hardcodes `1`; topics.go header says QoS 0 | Misleads; sync PUBACK waits in hot paths |
| D6 | Bench physics baked into product constants | Calibration debt | optimizer.go:761-768 ("20× demo"), slew/filter constants | Won't transfer to real vendors |
| D7 | `golang.org/x/crypto` @2019, `x/net` v0.8.0, Go 1.21 | Dependency rot | go.mod | CVE exposure, audit findings |
| D8 | `mayhem.go` 3,123-line scenario/driver/diagnosis monolith; scenarios require Go rebuild + binary redeploy | Harness debt | the stale-`bin/dashboard` incident (2026-07-03) | Slow iteration; deployment traps |
| D9 | Hand-rolled HTTP/1.1 parser over wolfSSL | Risky NIH | tlsclient/client.go:268-364 (`readResponse`, chunked parsing) | Parsing bugs = security bugs |
| D10 | Whole QA-arc fix series uncommitted in both repos (weeks of work) | Process debt | `git status` both repos | Bus factor ≈ 1; unreviewable; unbisectable |
| D11 | CannotComply chain: 5 hops, closure state, edge-detection | Fragile chain | cmd/hub/main.go:98-130 + northbound responseTracker | Already produced 3 QA race classes |
| D12 | `cmd/northbound/main.go` 831-line god-file (walk+publish+responses+flow-reservations) | Cohesion | file size + function list | Hard to test; hard to own |

---

## 6. Architecture Diagram (in words)

**Northbound plane.** `lexa-northbound` dials the utility over wolfSSL mTLS (CGo, `internal/tlsclient` — persistent keep-alive fetcher with hand-rolled HTTP parsing). Every ~5 s (fast) it walks DeviceCapability → Time → EndDevices → FSA → DERPrograms → Controls/Curves/Defaults (`internal/northbound/discovery/walker.go`), resyncs clock offset from `/tm`, resolves §12.3 precedence in `internal/northbound/scheduler` (fail-closed, last-known-good retention), and publishes: the resolved `ActiveControl` (retained, QoS 1) plus schedule/pricing/billing/flow-reservation summaries onto localhost Mosquitto. It also consumes compliance alerts and POSTs CannotComply Responses back to the server (`responseTracker`).

**Brain.** `lexa-hub` subscribes to measurements/metrics/EVSE state/control; `MQTTSystemReader` (cmd/hub/state.go) assembles `SystemState` per tick with freshness/frozen-meter gating and local control-expiry debounce. `Engine` (internal/orchestrator) runs the economic tick (3 s fast / 15 s stock): `DefaultOptimizer.Optimize()` — the six-rule cascade — plus a 1 s fast safety tick (`EvaluateSafety`) and a 15-min DP planner goroutine. Plans fan out through per-device MQTT actuators with dedupe/watchdog/breach-reset, and a plan-log/heartbeat topic feeds `lexa-api`.

**Southbound plane.** `lexa-modbus` subscribes to control topics, translates to `DERControlBase`, and writes SunSpec registers via `derbase` → `sunspec` layouts; a `Registry` polls devices concurrently (waitgroup-bounded, 5 s per-device deadline), publishes measurements (nameplate-plausibility-gated), runs the Tier-0 battery interlock, and wraps every device in `retryDevice` (reconnect + desired-state reassert). `lexa-ocpp` is an embedded OCPP 2.0.1 CSMS bridging one EVSE. `lexa-telemetry` POSTs MUP readings northbound. `lexa-api` is a read-only aggregator for dashboards/harness.

**Test plane** (`csip-tls-test`): gridsim (2030.5 server + admin fault API), four device sims sharing a `sim/southbound` register-level world model with fault injectors, simapi sidecars, the dashboard hosting Mayhem + bench replay, and conformance suites. The sims' SunSpec codecs are siblings of the product's — which is both the point and the peril.

---

## 7. Refactoring Opportunities (ranked)

### R1 — **Critical**: Replace the four convergence mechanisms with one Device Reconciler
*Why limiting:* W2. Emergent cross-layer bugs are now your dominant defect class; every new device type multiplies the interaction surface.
*Replacement:* a per-device **desired-state document** (`{ceilingW, setpointW, connect, maxCurrentA, source, mrid, issuedAt}`) owned by one reconciler per device (natural home: `lexa-modbus`/`lexa-ocpp`, next to the hardware). The optimizer's output becomes *declarative* — it publishes desired state (retained, per device), full stop. The reconciler owns: write-on-diff, verify-by-readback, reassert-on-reconnect, escalating retry, and *non-convergence reporting* (which feeds CannotComply). Delete `cmdDeduper`, the restore-rule spam, `lastCtrl`, and the breach-reset hack — each is a special case of the reconciler.
*Migration:* introduce the desired-state topic alongside existing command topics; make `retryDevice` consume it while still honoring legacy commands; flip the optimizer to publish desired state; delete legacy paths. Mayhem is your safety net — run the full campaign at each step. **Effort: 6–8 engineer-weeks. Risk: medium (mitigated by Mayhem). Payoff: eliminates your worst bug class and is the foundation for multi-vendor.**

### R2 — **Critical**: Extract shared protocol modules; delete the monolith and forks
Make `sunspec` (+ `derbase` layouts), `ocppserver`, and the 2030.5 `model` proper Go modules (or a `go.work` mono-repo). Delete `csip-tls-test/cmd/hub`, `gui/`, `sim_*.txt`, the forked orchestrator/csip/tlsclient. Add a CI job that fails on register-map divergence. **Effort: 2–3 weeks. Risk: low. Payoff: kills the MTR-4 bug class permanently; −5k LOC.**

### R3 — **High**: A single `utilitytime` package
One type owning offset acquisition, smoothing/step-classification, event-window evaluation, and expiry — consumed by walker, scheduler, hub, api, optimizer. Fold `expiryConfirmTicks`, `csipReportGraceS`, and both regression guards into it as policies with one test suite. **Effort: 2 weeks. Risk: low-medium (touchy, but the QA suite covers exactly this). Payoff: ends the clock whack-a-mole.**

### R4 — **High**: Split the optimizer into constraint layer vs. economic layer with a plant model
Compliance enforcement (caps, convergence, CannotComply) becomes a small, formally-testable constraint controller consuming a **per-device capability/latency model** (ramp rate, control delay, taper curve — discovered or configured), replacing bench-calibrated globals. Economic rules (TOU, self-consumption, plan-following) sit strictly below it. Target: no file >600 lines, guard state consolidated into one `session` struct per constraint. **Effort: 6–10 weeks. Risk: medium-high — do it *after* R1 shrinks its responsibilities. Payoff: multi-vendor viability, reviewable safety core.**

### R5 — **Medium**: Northbound decomposition + real HTTP client policy
Split `cmd/northbound/main.go` (walk loop / publishers / responseTracker / flowReservation into packages); either wrap wolfSSL under Go's `http.Transport` via a `net.Conn` shim or fuzz+harden `readResponse`. Add context propagation walker-deep. **Effort: 3 weeks. Risk: low.**

### R6 — **Medium**: Scenarios-as-data for Mayhem
Extract the 51 scenario definitions from `mayhem.go` into declarative specs; the 3,123-line file becomes engine + interpreters. Eliminates the rebuild-redeploy trap that burned a validation cycle. **Effort: 2–3 weeks. Risk: low.**

### R7 — **Low**: Engine cleanup
Delete `SetCSIPPrograms`/`e.sched`; collapse the five engine mutexes into one state struct with a single writer + snapshot reads; move `activeBreachMRID`/`dedupeResets` out of closures into a named, documented component. **Effort: 1 week.**

---

## 8. High-Risk Areas

1. **Optimizer guard interactions** [Proven — this week's incidents]. Any change to one guard can silently defeat another. Until R1/R4, treat `optimizer.go` as radioactive: full Mayhem campaign per change (you already do — keep it mandatory).
2. **The CannotComply chain** [Proven]. Five hops, two edge-detectors, closure state. A dropped MQTT alert or a northbound restart mid-episode loses the breach edge; the utility never learns. (Partially mitigated by retained plan-log heartbeat — but the alert itself is QoS 1 *non-retained*, and `activeBreachMRID` dies with the process.)
3. **Retained-message trust** [Likely]. The hub treats retained `lexa/csip/control` as authoritative on startup with only local expiry as defense. Mosquitto `autosave_interval 60` + power cut ⇒ stale resurrection (see §9). No schema/version field in bus messages either — a rolling upgrade with a changed JSON shape yields silent zero-values (the XML lesson, unlearned for the bus).
4. **Local clock steps** [Speculative but urgent]. All the clock hardening addresses the *server's* clock. If the SOM's own wall clock steps (NTP on commissioning, battery-backed RTC drift), `Ts` fields, freshness windows (`snap.fresh(now)`), `reassertEvery`, and TOU boundaries all shift. Go's monotonic clock protects in-process `Sub()` only. Untested anywhere.
5. **Single-EVSE / single-inverter assumptions** [Proven]. Export rule picks the *first* active EVSE (optimizer.go:702-709); nameplate-share solar split is untested with >1 inverter (bench has one); `plan.Breach` holds exactly one breach. Fleet reality breaks these quietly.
6. **wolfSSL CGo lifecycle** [Likely]. Process-global init, manual `FreeSSL/FreeCtx`, fd dup for timeouts. One misordered Free under a reconnect storm is a segfault in the service that talks to the utility. The northbound-hang fix added fd timeouts; there's no soak test for reconnect churn (certificate rotation will churn it).

---

## 9. QA Blind Spots (what Mayhem does *not* test)

Your suite is excellent at single-fault, app-layer injection. The gaps cluster in five families:

**Self-confirmation** — The sims' SunSpec codecs share lineage with the product's. A register-map misunderstanding would be *bilaterally consistent* and invisible to all 51 scenarios. Mitigation: golden binary register fixtures from real vendor hardware, replayed byte-exact; or a third-party SunSpec implementation as referee.

**Persistence/restart family:**
- **Retained-store rollback**: kill power to the hub Pi (not `systemctl restart` — that flushes); Mosquitto restores `lexa/csip/control` up to 60 s stale; hub re-adopts a superseded cap. Nothing tests unclean broker death. [Likely-provable]
- **Corrupted retained payload** (truncated JSON in the store): `Subscribe[T]` logs and drops — hub then runs with *no* control forever (no re-request path).
- **Disk full** (journald + mosquitto persistence on the same partition): never injected.

**Time family:** local (hub-side) clock step forward/backward; DST transition across a TOU peak boundary (`CostModel.IsPeakHour` — any `time.Location` handling?); leap-second smear vs. event expiry.

**Identity/topology family:** duplicate MQTT client ID (second `lexa-hub` instance → paho mutual-kick reconnect storm and *interleaved control outputs* — a plausible operator error with catastrophic output); two devices claiming the same Modbus unit ID; a *second* meter appearing.

**Value-domain family:** int16 register boundary sweep (±32,767 W crossing under scale factors — you fixed GS-1/MTR-1 by audit, not by generative test); oscillating measurements at guard thresholds (battery SoC dithering exactly at reserve, export dithering at `complianceBreachW` — leaky counters are hold-biased, but nobody has *swept* the boundary); NaN arriving in *bus JSON* despite the convention (a non-lexa publisher or version skew — `*float64` nil is handled, `"NaN"` string isn't).

**Load/duration family:** no soak (fd/goroutine/RSS trend over weeks — the 92-day replay is clock-warped, ~20 h wall); no MQTT storm (publish flood vs. `max_queued_messages 1000` overflow behavior on QoS 1); no TLS reconnect storm; no packet-level loss/reorder (all faults are app-layer via simapi — `tc netem` on the bench LAN would be cheap and brutal).

Also: **tests verifying implementation** — a minority, but the optimizer unit tests that assert specific decision strings (`hasDecisionContaining("battery not absorbing")`) will shatter during R4 without catching behavior changes. The invariant-based HIL verdicts are the good pattern; lean harder on them.

---

## 10. Security Findings

1. **No authorization anywhere behind transport crypto** [Proven — W7]. lexa-api plaintext/unauthenticated; broker anonymous; OCPP `ws://` unauthenticated; simapi/admin open. Acceptable on the air-gapped bench, indefensible in a product. Needs: broker per-service credentials + ACLs (the config file already sketches them), TLS+auth on the API, OCPP security profile ≥2 (TLS + Basic Auth) or 3 (mTLS).
2. **Hand-rolled HTTP parsing on the untrusted boundary** [Proven]. `readResponse`/chunked decoding in `tlsclient` parses hostile utility bytes. Malformed chunk sizes / header floods / unbounded bodies — I found a read timeout but no visible response-size cap. Fuzz it or replace it (R5).
3. **XML robustness** [Likely-OK with caveats]. Go's `encoding/xml` doesn't expand entities (billion-laughs safe), and the namespace-or-zero-value hazard is documented and handled by plausibility checks — but zero-value structs from *valid-namespace garbage* still reach the scheduler; `plausibleControl` covers limits only, not e.g. absurd intervals.
4. **Dependency rot** [Proven]. `x/crypto` @2019, `x/net` v0.8.0, paho 1.4.3, Go 1.21, no CI/scanning. For due diligence this reads as "no vulnerability management process."
5. **Cert lifecycle absent** [Proven — Phase 4 open]. No rotation, no expiry monitoring, no re-enrollment. A CSIP deployment *will* hit cert expiry; today that's a silent discovery-error loop (at least it fails closed now).
6. **Panic safety** [Proven, good]. Only two panics, both init-time-appropriate. MQTT handlers don't `recover()` — a panic in any subscriber callback kills the service; systemd restarts it (5 s), state re-seeds from retained topics. Acceptable, but document it as the intended crash-only design.

---

## 11. Reliability Findings

- **No `WatchdogSec`/`sd_notify`** [Proven]. `Restart=on-failure` only. A live-but-wedged `lexa-hub` (deadlock, paho stall) is never restarted — and your own C08 investigation hypothesized exactly this wedge. You now publish a plan heartbeat; nothing consumes it for action. Two lines of systemd + one `sd_notify` call per tick closes it.
- **Broker as SPOF is handled adequately** [Proven]: auto-reconnect, resubscribe replay, retained re-seed, bounded 5 s publish waits with idempotent re-issue — and `mqtt-broker-restart/latency` scenarios pass. Good.
- **Synchronous QoS-1 publish waits in the tick path** [Proven]: worst case, one tick can spend 5 s *per publish* (plan log + alert + N commands) against a sick-but-alive broker — fast-mode ticks (3 s) overrun. Move actuator publishes to fire-with-timeout-check-later, or budget the tick.
- **Flash wear** [Likely]: 2 journald lines/tick (≈50k lines/day fast) + Mosquitto autosave on Pi SD/eMMC. Needs journald rate/size caps in the units and a wear budget for the SOM.
- **Goroutine/resource hygiene** [Proven, mostly good]: registry polls are waitgroup-bounded with per-device deadlines; subscriber channels drop-on-full with counters; `registries sync.Map` never deletes (harmless at one client/process, latent leak if that changes).
- **Crash recovery is retained-message-shaped** [Proven]: works (hub-restart-mid-cap passes), but see §8.3 for its trust problem, and note breach-episode state doesn't survive, so a restart mid-breach re-sends a duplicate CannotComply "begin" (harmless today, protocol-noise tomorrow).

---

## 12. Performance Findings

Not a bottleneck-driven system — the ADR proved the box is ~99% idle and the poll/tick constants dominate all latency. Real observations: JSON marshal/unmarshal per message per hop is fine at this scale and wrong at fleet scale (hundreds of devices → consider batching measurements per poll cycle rather than per-device topics); the walker re-fetches the *entire* resource tree every ~5 s in fast mode with no conditional GET (2030.5 supports poll rates/subscription semantics — at minimum honor server-advertised poll intervals before a utility rate-limits you) [Likely]; `Optimize()` is sub-ms and irrelevant. The one perf-adjacent risk is the synchronous publish waits above.

---

## 13. Maintainability Findings

- **Documentation culture is genuinely excellent** [Proven]: CLAUDE.md invariants, ADR, per-fix comments citing QA scenario IDs, audit tags (GS-1, MTR-4). A new engineer can archaeology every guard. That said, needing archaeology is the smell — the comments are load-bearing because the *structure* isn't.
- **Onboarding cost**: moderate for the services, **high** for the optimizer (you must internalize ~9 guard state machines and their reset semantics before touching anything) and for the cross-repo choreography (deploy scripts, tune scripts, FAST/STOCK duality, `bin/dashboard` vs `./dashboard` — the kind of tribal knowledge currently living in one person and one memory file).
- **The FAST/STOCK timing duality is a validation hole** [Proven]: `scaleTicks` keeps wall-clock semantics, but the product *ships* in a timing regime that QA doesn't run. One stock-timing campaign before any release is mandatory.
- **Process**: no CI, no PR review evident, weeks of uncommitted safety fixes across two repos, deploy-by-script-overwriting-configs (which already caused a phantom-FAIL detour). This is the cheapest, highest-leverage fix in the entire report.

---

## 14. Top 20 Action Items

| # | Priority | Item | Effort |
|---|---|---|---|
| 1 | Critical | Commit the uncommitted QA-arc work; branch/PR discipline from today | hours |
| 2 | Critical | CI: build + `-race` tests + conformance smoke on every PR, both repos | 2–3 d |
| 3 | Critical | Device Reconciler (R1) — one desired-state mechanism | 6–8 w |
| 4 | Critical | Extract shared modules; delete monolith + forks (R2) | 2–3 w |
| 5 | Critical | systemd `WatchdogSec` + `sd_notify` from the tick loop, all services | 2 d |
| 6 | High | Broker credentials + ACLs; TLS+token on lexa-api; OCPP security profile | 1–2 w |
| 7 | High | `utilitytime` package (R3) | 2 w |
| 8 | High | Dependency refresh + `govulncheck` in CI; Go 1.22+ | 3 d |
| 9 | High | Persistence: append-only event journal (controls adopted, dispatches, breaches, CannotComply) + guard-state snapshot | 2–3 w |
| 10 | High | Fuzz `tlsclient.readResponse` + XML decode + bus JSON (`go test -fuzz`) | 1 w |
| 11 | High | Stock-timing Mayhem campaign as a release gate | 1 d/release |
| 12 | High | Mayhem additions: power-cut retained rollback, corrupted retained JSON, duplicate client ID, local clock step, disk-full | 1–2 w |
| 13 | Medium | Split optimizer per R4 with per-device plant model | 6–10 w |
| 14 | Medium | Metrics endpoint (Prometheus) + structured logs; alert on plan-heartbeat stall | 1–2 w |
| 15 | Medium | Delete `SetCSIPPrograms` dual path; engine mutex consolidation (R7) | 1 w |
| 16 | Medium | Golden register fixtures from ≥2 real vendor devices; third-party SunSpec referee test | 2 w + hardware |
| 17 | Medium | Northbound split + context propagation (R5) | 3 w |
| 18 | Medium | Version field + schema check on all bus messages; reject-and-alarm on unknown | 3 d |
| 19 | Low | Scenarios-as-data for Mayhem (R6) | 2–3 w |
| 20 | Low | Soak rig: 30-day bench run with RSS/fd/goroutine trend capture + `tc netem` chaos | 1 w setup |

---

## 15. "If this were my project…" — the 12-month plan

**Months 0–1 — Stop the bleeding (no feature work).** Commit everything; CI with race tests, vuln scanning, and a lockstep-divergence check; watchdogs; broker ACLs; API auth; dependency refresh; delete the monolith, the dead engine path, and the deprecated GUI. One stock-timing Mayhem campaign to baseline what you actually ship. *Nothing here risks behavior; all of it converts tribal process into institutional process.*

**Months 2–4 — The Reconciler (R1) + shared modules (R2).** This is the structural bet. Land the per-device desired-state topic and reconciler behind the existing command topics, migrate device by device (battery first — it has the Tier-0 interlock as a safety net), and delete the dedupe/restore/reassert trio as each device flips. Run full Mayhem campaigns at every milestone; the suite's verdict history is your regression oracle. Simultaneously extract `sunspec`/`ocppserver`/`model` into shared modules so the sims and product provably share one codec again.

**Months 4–6 — Time, persistence, observability.** `utilitytime` with the four grace policies folded in; the append-only event journal (this is also your utility-facing audit log — design the schema once, with retention/rotation for flash); Prometheus metrics and heartbeat-driven alerting. Add the §9 Mayhem scenarios as each mechanism lands — power-cut rollback *before* trusting persistence.

**Months 6–9 — Optimizer split (R4).** Constraint controller (small, formally testable, per-device plant model) over economic layer. Port the QA-derived semantics as *behavioral* tests (invariant-style, not decision-string assertions). This is when the bench constants become discovered/configured device parameters — and when a second inverter and second EVSE join the bench to kill the single-device assumptions.

**Months 9–12 — Commercialization surface.** Cert rotation + expiry monitoring (finish Phase 4); OCPP security profiles; multi-vendor validation against ≥2 real inverters and ≥1 real EVSE with golden fixtures; CSIP scope decision — either implement closed-loop curve functions (volt-var/volt-watt already have derbase write paths; nothing drives them from CSIP today [Likely]) or explicitly de-scope them in the product claims; begin third-party conformance/certification (IEEE 1547.1 / CSIP test-lab engagement) using your conformance suite as the pre-audit.

**Due-diligence questions I would ask the team:** Why is a month of safety-critical work uncommitted, and who besides one person can deploy this bench? What happens at 200 devices — topic-per-device, per-message JSON, one goroutine per poll? Where is the compliance event record a utility's lawyers will subpoena? Who owns the wolfSSL wrapper when its author leaves? And the one I'd push hardest: *show me the last three bugs — if all three are guard-interaction bugs (they are), why is the answer another guard?*

The honest bottom line: you've built the **hardest part** — a hostile-QA flywheel that finds real bugs and a team culture that root-causes to the journal line. That's the asset. The control core it's been polishing is the liability. Spend the refactor budget on R1/R2/R4, keep Mayhem as the invariant through all of it, and this becomes a product I'd sign off on. Ship it as-is to a utility, and the first NTP correction, cert expiry, or second inverter in the field will write your first incident report for you.
