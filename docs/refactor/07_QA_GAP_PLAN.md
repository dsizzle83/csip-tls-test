# 07 — QA Gap Plan

*Every blind spot from review §9 (plus §11/§13 test-shaped findings),
converted to engineering work, prioritized by (field probability × harm ×
how blind the current suite is). The 2026-07-01 blind-spot wave
(`docs/QA_GAPS_20260701.md`) already closed WAN outage, CT inversion,
clock jump, churn, flicker, release-edge, and hub restart — this plan
covers what remains.*

Priority: P1 = before M3 · P2 = before M4 · P3 = before V1.0.

---

## P1 — Persistence/restart family (the suite has *zero* unclean-death coverage)

### GAP-01 Retained-store rollback after power cut → TASK-042 + 043
**Why it matters:** Mosquitto `autosave_interval 60` + power cut can
resurrect a control up to 60 s stale on reboot; the hub adopts it as
authoritative (§8.3). A superseded 5 kW cap resurrected during a 0 W event
is a compliance violation the utility measures.
**Work:** hub-side staleness bound on retained `lexa/csip/control`
(issuedAt vs `utilitytime` now, bounded adoption grace) — then a Mayhem
scenario that kills power (or SIGKILLs mosquitto + restores an old store
copy, the software-only equivalent) and asserts the stale control is
rejected and a fresh walk re-adopts.
**Validation:** scenario PASS ×10 solo; INV-EXPIRED clean; wan-outage-expiry
unaffected (the local-expiry discipline must not regress).

### GAP-02 Corrupted retained payload → hub runs control-less forever → TASK-042 + 043
**Why:** `Subscribe[T]` logs-and-drops a truncated JSON; there is no
re-request path, so the hub silently runs without a control until the next
walk *happens* to publish. Fail-closed becomes fail-open-by-omission.
**Work:** on decode failure of a retained control-plane message: alarm +
request northbound re-publish (or force re-walk); scenario injects a
truncated retained payload via a rogue publisher.
**Validation:** hub regains control within one walk period; alarm metric
fires; verdict stable ×10.

### GAP-03 Disk full (journald + mosquitto persistence share the partition) → TASK-050
**Why:** flash fills; if mosquitto can't persist or journald stalls, what
breaks first is unknown — never injected.
**Work:** scenario fills the target partition (tmpfs-bounded copy on the
hub Pi or loopback quota), runs a control cycle, restores space.
**Validation:** control enforcement unaffected; degradation visible in
metrics; no wedge after space returns.

## P1 — Time family (local half)

### GAP-04 Local (SOM) clock step → TASK-037 + 038
**Why:** every clock hardening so far covers the *server* clock. An NTP
step on commissioning shifts `Ts` freshness windows, `reassertEvery`, TOU
boundaries — untested anywhere; plausibly wedges freshness gating
("everything stale forever" after a backward step).
**Work:** `utilitytime` local-step policy (monotonic freshness; wall-clock
only where utility semantics demand) then a scenario stepping the hub Pi's
clock ±1 h mid-control (`date -s` via the hub-restart SSH pattern;
INCONCLUSIVE without SSH, per hub-restart-mid-cap precedent).
**Validation:** control held, no flap, freshness recovers; both directions.

### GAP-05 DST / leap-smear across a TOU peak boundary → TASK-079
**Why:** `CostModel.IsPeakHour` behavior across a `time.Location`
transition is unverified; a wrong peak window misprices an entire evening
fleet-wide, twice a year.
**Work:** table-driven tests over DST-forward/back days and a smeared leap
second for TOU window evaluation; fix whatever they find.
**Scheduling note:** TASK-079 is numbered in P6 but gated only on TASK-036 —
run it during P3/P4 to honor this P1 priority; do not wait for Phase 6.

## P1 — Identity/topology family

### GAP-06 Duplicate MQTT client ID → TASK-049
**Why:** a second `lexa-hub` (operator error, stale unit on the old dev
kit) causes paho mutual-kick reconnect storms with *interleaved control
outputs* — catastrophic and plausible.
**Work:** scenario launches a second hub instance (or a client-ID clone
publishing benign noise), asserts: detection (metric/alarm), no interleaved
actuation reaches devices (reconciler seq/issuedAt gives detection means
post-P2).
**Validation:** INV-CONNECT/INV-EXPORT clean during the storm; alarm fires.

## P2 — Value-domain family

### GAP-07 int16 / scale-factor boundary sweep → TASK-053
**Why:** GS-1/MTR-1 were found by audit, not by test; ±32,767 W crossings
under every scale factor is exactly what a generative test proves and a
human audit misses. Bilateral (sim+product share the codec) until 075.
**Work:** property-based sweep against the shared sunspec module: encode →
decode round-trip and clamp/multiplier behavior across the full int16 range
× scale factors; runs in CI.

### GAP-08 Threshold dither (hold-biased leaky counters, unswept) → TASK-054
**Why:** SoC dithering exactly at reserve, export dithering at
`complianceBreachW`: leaky counters are believed hold-biased, but no one
has swept the boundary; INV-HUNT only catches sustained oscillation.
**Work:** scenarios driving measurements in ±ε square/sine around each
guard threshold (batsim SoC, metersim export) for several minutes;
verdict on breach-seconds + INV-HUNT + CannotComply correctness.

### GAP-09 `"NaN"` string in bus JSON → TASK-055
**Why:** the `*float64`-nil convention protects lexa publishers; the review
flagged literal `"NaN"`/`Infinity` from a non-lexa publisher as unhandled.
**Correction (verified 2026-07-04):** stdlib `encoding/json` already
rejects both forms into typed float fields — the residual risk is *silent*
log-and-drop (no alarm) and any future lax decoder (`UseNumber`/
`interface{}`).
**Work (rescoped):** regression-pinning tests, defense-in-depth finiteness
check, alarm-routing the drop via the TASK-018 envelope path, and proof a
NaN control limit never reaches the optimizer.
**Landed (055, DONE 2026-07-05):** `internal/bus/nan_reject_test.go` pins
stdlib's existing bare/quoted NaN/Inf rejection; `Finite() error` added to
every `*float64`-bearing message type and wired into `mqttutil.Subscribe`
(type-asserted after `Unmarshal`); both a `Finite()` failure and a plain
`Unmarshal` failure now increment `bus.RecordDecodeFailure` (sibling of
`RejectAndAlarm`), closing the "silent" half of the gap. Scope grep for lax
decoders (`UseNumber`/`json.Number`/`map[string]any`/`interface{}`/
`ParseFloat`) found none on the bus decode path. `ActiveControl` NaN-limit
safety case covered — see AD-006 note.

## P2 — Load/duration family

### GAP-10 MQTT storm / queue overflow → TASK-051
**Why:** `max_queued_messages 1000` overflow behavior on QoS 1 is
unobserved; a chatty device or QA harness bug could starve the control
topic.
**Work:** flood scenario via mqttproxy/rogue publisher; assert control
latency stays bounded and dropped-message counters surface.

### GAP-11 Packet-level chaos (`tc netem`) → TASK-052
**Why:** all injection today is app-layer via simapi; real LANs corrupt,
reorder, and delay at the packet level — cheap to inject, never done.
**Work:** netem harness (loss/reorder/delay/jitter profiles on the bench
LAN, applied via SSH to Pis), folded into 2–3 scenarios + soak background.

### GAP-12 Soak / resource trends → TASK-078
**Why:** the 92-day replay is clock-warped (~20 h wall); fd/goroutine/RSS
leaks over weeks are invisible; `registries sync.Map` never deletes
(latent), wolfSSL churn (§8.6) untested over time.
**Work:** 30-day bench run, per-service RSS/fd/goroutine scrape (needs
TASK-044 metrics), weekly netem chaos windows, zero-watchdog-fire target.
**Scheduling note:** the rig must *start* by end of P5 — 30 days of wall
clock must finish before the V1.0 gate (TASK-081 front-loads this check).

## P2 — Self-confirmation family

### GAP-13 Golden vendor fixtures + third-party referee → TASK-075
**Why:** a register-map misunderstanding is bilaterally consistent between
sims and product — invisible to all 51 scenarios by construction. This is
the suite's deepest epistemic hole; it is also hardware-gated (order
early, during P2).
**Work:** capture byte-exact register images from ≥2 real inverters (+1
EVSE OCPP transcript), replay against the shared codec as CI fixtures;
cross-check with an independent SunSpec implementation (e.g. pysunspec2)
as referee.
**Validation:** any divergence is a P1 bug against `lexa-proto`.

## P3 — Test-quality debt

### GAP-14 Decision-string assertions → TASK-056
**Why (§9 tail):** `hasDecisionContaining("battery not absorbing")` tests
shatter on R4 refactors without catching behavior changes — they verify
implementation, not behavior.
**Work:** rewrite orchestrator tests to assert plans/desired-state/
invariants; delete string oracles. Blocks all of P5.

### GAP-15 STOCK-timing validation hole → TASK-015 (then 081)
**Why (§13):** `scaleTicks` preserves wall-clock semantics in theory; the
product ships STOCK but is validated FAST — the shipped latencies are
literally untested.
**Work:** `bench-up.sh --stock` campaign runner + triage doc; STOCK
campaign at M0 (baseline), M2, M4, V1.0.

---

## Explicitly deferred (with reasons, inherited from QA_GAPS_20260701 §4)

Backward server-clock jump (no defensible oracle); meter magnitude drift
(undetectable without second reference); OCPP lifecycle-reorder injector
(deepest-covered device already; revisit when evsim is next touched);
Modbus unit-ID/tearing faults (framing handled by library; effects covered
by value faults — revisit with 065's second inverter); DNS-SD flap (needs
second gridsim); TLS rotation mid-session as HIL (conformance-suite
territory; approximated by hub-restart; addressed for real in TASK-073);
matrix/chaos cells for new faults (add after first campaign shows
interactions).
