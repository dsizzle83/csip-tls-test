# QA Completeness Audit — LEXA DERMS Bench (Phase 4)

**Date:** 2026-07-15
**DUT:** `lexa-hub` (the product — IEEE 2030.5/CSIP DER client, SunSpec/Modbus poller,
OCPP 1.6/2.0.1 CSMS, OpenADR 3.1 VEN, energy optimizer).
**Suite:** `csip-tls-test` (mayhem fault-injection, conformance suites, device/grid/EV/VTN sims).
**Method:** every claim below was verified against **current code** in both repos
(`csip-tls-test@feat/dashboard-v2`, `lexa-hub@standards-buildout`), not against prior
recon or the lexa-hub planning docs — several of which are stale (see §0).

---

## 0. Headline findings (read this first)

1. **One genuine, unfixed PRODUCT BUG surfaced by QA.** The hub cannot read a
   spec-compliant **137-register SunSpec model 701** in one Modbus transaction:
   `vendor/lexa-proto/sunspec/reader.go:46` issues a single
   `ReadHolding(base, Length)` and `simonvetter/modbus` hard-refuses any read
   `>125` registers (`client.go:1017-1020`). Model 701 is 137 registers
   (`vendor/lexa-proto/sunspec/derlayout.go:17-67`). Commit `474e4e7` **only
   documents** the bug (a one-line `00_PROGRESS.md` edit); no code fix exists. The
   sim masks it by truncating 701 to 121 regs (`sim/southbound/solar_adv.go:176-183`),
   so every advanced-DER test passes while a real certified inverter would fail.
   This is a shipping defect, not merely a coverage gap. **Fix is cross-repo
   (lexa-proto transport + proto.pin bump).**

2. **The lexa-hub bench-deferred docs are STALE.** `lexa-hub/docs/standards-buildout/
   VERIFICATION_SWEEP.md` and `00_PROGRESS.md` (dated 2026-07-14) list a 9-item
   "bench validation queue" whose blockers are described as *unbuilt paired
   csip-tls-test work*. Those blockers were **closed** on the csip-tls-test side the
   next day by commits `89c4f01` (DER* PUT + LogEvent endpoints, `/admin/redirect`
   knob, Table-27 acceptance, `UseCertChainFile` chain serving + COMM-004 fixtures)
   and `8269e52` (OCPP 1.6J evsim). Do not plan from those lexa-hub docs — plan from
   `csip-tls-test/docs/QA_STANDARDS_BUILDOUT.md` (2026-07-15) and this audit.

3. **The "15 of 17 standards scenarios deferred" is a RUN gap, not an
   implementation gap.** All 17 standards-buildout scenarios are implemented and in
   the live catalog (`mayhem.py --list` = **87** scenarios). Two already ran live
   and PASSED on the dev kit (`der-report-roundtrip`, `dcap-redirect` —
   `QA_STANDARDS_BUILDOUT.md:80`). The other 15 need a **dedicated non-soak bench
   session** and, for most, one hub config flip each — none is blocked on a missing
   seam (§3).

4. **Two prior recon claims are REFUTED at the code level** (the hub already does
   the thing; only the *bench scenario* is missing): the hub **does** POST
   Cancelled(6)/Superseded(7) responses (`responses/tracker.go:346-365`, unit-tested)
   and **does** consume `randomizeDuration` (`scheduler/scheduler.go:625-647`,
   unit-tested). See §2 P1-2 / P1-3.

5. **Every P2/P3 "seam that doesn't exist" is already a documented roadmap row** in
   `docs/QA_FAULT_INJECTION.md` (the "Fault matrix (roadmap)", lines 164-174: crc_error,
   tcp_drop, partition, dns_fail, resource_410, event_delay, supersede, slow_loris,
   cert_expire, ca_rollover) and/or a consciously-deferred item in
   `docs/QA_GAPS_20260701.md:148-159`. This audit confirms which remain open, corrects
   their feasibility, and turns them into file-level tasks. **One deferral is now
   stale-by-design:** TLS cert rotation was deferred as "a restart event"
   (`QA_GAPS_20260701.md:157`) *before* lexa-hub gained an in-process rotation path
   (`cmd/northbound/rotate.go`, `internal/tlsclient/fetcher.go:124` `Reload`) — that
   path now has real code and deserves a seam.

---

## 1. Coverage matrix (per standard)

| Standard | Product implements | Suite exercises | Delta (what's untested) |
|---|---|---|---|
| **IEEE 2030.5 / CSIP transport** | wolfSSL mTLS, TLS1.2, single cipher `ECDHE-ECDSA-AES128-CCM-8`, mutual-auth, wrong-CA/wrong-cipher reject | `TestClient_CipherIsCSIPCompliant`, `RejectsServerWithWrongCA/WrongCipher`, 0xC0AE on wire; 42/42 CSIP logic tests (`tests/csip_conformance_test.go`) | COMM-004 3/4-deep MICA chains: fixtures (`certs/comm004/004a-e`) + `UseCertChainFile` (`sim/tlsserver/server.go:71`) now EXIST; **pcap capture run pending**. **Cert-expiry / CA-rotation mid-session: no seam** (P2-1). |
| **IEEE 2030.5 discovery / lists** | link-driven walk from `/dcap`, FSA→DERProgram→DERControl, DER/MUP/curve/pricing | full happy-path walk (`csip_conformance_test.go`), malform survivability (10 kinds) | **List pagination: neither side does it** — gridsim ignores `s/l/a` (`sim/gridsim/server.go:18-22,307-317`), hub has NO paging loop (`internal/northbound/discovery/walker.go:454-479`, single GET). A paginating server ⇒ silent resource loss past page 1 (P1-1). |
| **IEEE 2030.5 events / scheduling** | primacy, cancelled-skip, supersede-within-program, randomizeStart+Duration, DefaultDERControl fallback | scheduler unit tests (lexa-hub); `conflicting-primacy` scenario (primacy only) | **randomizeDuration e2e untested** (hub consumes+unit-tests it; gridsim never serves it) (P1-3). **Cross-program supersede is by-design absent** (absolute primacy); no bench scenario drives hub 6/7 emission (P1-2). |
| **IEEE 2030.5 responses** | POSTs Received(1)/Started(2)/Completed(3)/**Cancelled(6)**/**Superseded(7)** (`responses/tracker.go:318,346-365`) | CORE-022 test POSTs 1/2/3 *itself*; `/admin/alerts` captures CannotComply | **No scenario drives the hub to emit 6/7 over the wire**; `/admin/control` can't arm superseded/cancelled (`admin.go:291-313`) (P1-2). |
| **CSIP-AUS (gen/load limits)** | `enforce_aus_limits` cascade + `constraint_shadow` mirror (`internal/orchestrator/{auslimits,constraint/genlimaus,loadlimaus}.go`) | `aus-gen-cap`/`aus-load-cap` scenarios (`mayhem_adv.go`, implemented) | **≥1-week zero-diff shadow soak pending** (time-gate, WP-11); scenarios runnable after `enforce_aus_limits=true` flip. `/status` lacks GenLimW/LoadLimW (observability gap). |
| **SunSpec / Modbus (base 1/101/103/802…)** | 3-base probe (40000/0/50000), scale factors, saturating clamp on writes | `modsim-conformance` 19/22/9 PASS (inverter/battery/meter); write faults (ack/reject/wrong_sign/enable_gate/ramp/soc), transport faults (nan/latency/exception/bad_scale/invert) | **>125-reg chunking BROKEN + untested (P0)**. **crc_error (infeasible on TCP), tcp_drop, unit-ID, register-tearing: no seam** (P2-2). **Out-of-range writes**: hub clamps (fuzz-tested in proto) but no e2e scenario (P3-2). **Boundary SOC**: exact-0/reserve-edge untested (P3-3). |
| **Advanced DER (7xx: 701/704/705/706/711/712)** | measured-readback adopt (curve/PF/energize), `reconciler.adv` off/shadow/active | `TestAdvDER_*` (adopt success, curve_adopt_lies divergence, pf measured convergence); `adv-shadow-no-writes`/`curve-adopt-readback-divergence`/`pf-var-measured-convergence` scenarios | Tests pass only because sim truncates 701 to 121 regs (see P0). Real-inverter soak hardware-gated (RSK-08). |
| **OCPP 2.0.1 (CSMS)** | TransactionEvent, SetChargingProfile, pairing gate, Security Profile 2 | 6 evsim faults (`profile_reject`, `apply_next_tx`, `stop_metervalues`, `apply_delayed`, `wrong_units`, `min_current_floor`) + `pairing-gate-hold`/`ev-setpoint-clamp` | **Out-of-order TransactionEvent + boot-mid-transaction: no seam** (P2-5); hub `OnTransactionEvent` logs but doesn't validate `SequenceNo` (`cmd/ocpp/main.go:1131`), `OnBootNotification` doesn't void active tx (`:940`). |
| **OCPP 1.6J** | `port_16` dual-stack bridge, byte-identical 2.0.1 path | `ocpp16-smart-charge`/`clear-profile-release` scenarios + evsim `-proto 1.6` (`8269e52`, exists) | **Run pending** — needs evsim relaunched `-proto 1.6` + hub `port_16` set (config, non-soak session). |
| **OpenADR 3.1 (VEN)** | `lexa-openadr` VEN, price/limit adoption, D9 CSIP-precedence | `vtnsim` exists+bench-deployed (`bench-up.sh:104`); `openadr-limit-adopt`/`openadr-csip-precedence` scenarios | Scenarios **inject `lexa/openadr/*` on the MQTT bus directly** (`mayhem_ocpp_openadr.go:719,758`) — they test hub adoption, NOT the VEN↔vtnsim poll/OAuth2/translate path (P2-6 / run gap). |

---

## 2. Prioritized gap catalog

Priority reflects **field-risk × correctness**, re-scored after verification.
"csip-tls-test only" vs "needs lexa-hub change" is called out per gap.

### P0 — Real product defect (fix before anything else)

**P0-1 · Model-701 >125-register read is broken (unchunked).**
- **Severity:** Critical — the hub cannot read a spec-compliant 137-reg model 701;
  a real 1547-2018-certified inverter serving it fails at discovery.
- **Field failure caught:** "advanced inverter with full 701 measurement block →
  hub logs `sunspec: read model 701 … quantity of registers exceeds 125` and never
  reads AC power/voltage/alarm."
- **Evidence:** hub single-shot read `vendor/lexa-proto/sunspec/reader.go:46`;
  transport passthrough `vendor/lexa-proto/modbus/transport.go:92-94`; library refusal
  `simonvetter/modbus@v1.6.4/client.go:1017-1020`; 701=137 regs
  `vendor/lexa-proto/sunspec/derlayout.go:17-67`; docs-only "fix" `git show 474e4e7`;
  sim truncation `sim/southbound/solar_adv.go:176-183` (`dataLen = L701.Offset("MnAlrmInfo") // 121`).
- **Seam / fix:**
  1. **lexa-hub / lexa-proto:** chunk reads at the 125-register boundary in
     `lexa-proto/modbus/transport.go` `ReadHolding` (loop of ≤125-reg `ReadRegisters`,
     concatenate) or in `sunspec/reader.go` `ReadModel`. Paired proto.pin bump in
     both repos.
  2. **csip-tls-test:** un-truncate the sim — serve the full 137-reg 701 in
     `sim/southbound/solar_adv.go:populate701` (declare L=137).
  3. **csip-tls-test:** add a test that reads the full 137-reg 701 and asserts the
     values (forces the chunk path) — `tests/modbus_adv_test.go`.
- **Needs lexa-hub change:** YES (the fix). Cross-repo paired.

### P1 — Implemented-but-untested / conformance

**P1-1 · CSIP list pagination — no paging on either side.**
- **Severity:** High (conformance; low field-risk on a 1-2-DER home, real for a
  multi-program utility).
- **Field failure caught:** "utility server returns `all=40, results=10` across
  pages → hub silently enforces only the first 10 programs/controls."
- **Evidence:** gridsim ignores `s/l/a`, returns full list (`sim/gridsim/server.go:18-22`
  doc, `:307-317` bare map lookup, no `r.URL.Query()`); hub has **no** paging loop —
  each list fetched once (`internal/northbound/discovery/walker.go:454-479`), never
  builds `?s=/?l=/?a=`, never loops on `All` vs `Results`. Only robustness test is
  `malform-pagination` (lying `all=999`, `sim/gridsim/malform.go:118-126`).
- **Seam:** **csip-tls-test** — add a positive-pagination mode: parse `s/l/a` in
  `handleGET` (`server.go:264`) / `serveXML` (`:423`) and slice `List.DERProgram`
  etc. with correct `All`/`Results`; a `/admin` knob to force a small page size. Plus
  a scenario asserting the hub collects all N. **lexa-hub** — add a paging loop to
  the walker's list fetchers (`walker.go:454-479`) that re-requests `?s=offset` while
  `Results < All`.
- **Needs lexa-hub change:** YES.

**P1-2 · Cancelled(6)/Superseded(7) emission — hub emits, no scenario drives it.**
- **Severity:** High (conformance CORE-022/023).
- **Recon claim REFUTED:** the hub DOES POST both — `responses/tracker.go:346-350`
  (Cancelled), `:364-365` (Superseded), via `postResponse` `:499-524`; constants
  `ResponseEventCancelled=6`/`Superseded=7` (`vendor/lexa-proto/csipmodel/resources.go:459-460`);
  unit-tested `tracker_test.go:95-131`. **Cross-program supersede is deliberately
  absent** (absolute-primacy design, `CONFORMANCE_REPORT.md:49` C-3).
- **Actual gap:** no bench scenario forces a server-cancel or a within-program
  supersede over the wire; `/admin/control` can't arm either (`adminCtrlReq` has no
  `PotentiallySuperseded`/`CurrentStatus`, `sim/gridsim/admin.go:291-313`); the CORE-022
  test POSTs 1/2/3 itself (`csip_conformance_test.go:812-815`).
- **Seam:** **csip-tls-test only** — widen `adminCtrlReq` (`admin.go:291-313`) with
  `PotentiallySuperseded *bool` / `CurrentStatus *uint8`, set into the built
  `ctrl.EventStatus` (~`admin.go:358-366`); scenario posts two overlapping
  same-program controls (later supersedes earlier ⇒ hub 7) and one server-cancelled
  control (⇒ hub 6), asserting via `/admin/alerts`/a response-capture endpoint.
- **Needs lexa-hub change:** NO.

**P1-3 · randomizeDuration — hub consumes+unit-tests it, no e2e scenario.**
- **Severity:** Medium (conformance CORE-021).
- **Recon claim REFUTED at unit level:** consumed at `scheduler/scheduler.go:625-647`
  (`randomizedDuration`, cached per-MRID `randDurs`, §11.10.4.2), asserted by
  `scheduler_test.go:454,478`.
- **Actual gap:** csip-tls-test CORE-021 drives the *independent referee*
  `internal/csipref/scheduler`, not the real hub; gridsim never serves
  `RandomizeDuration` (only `RandomizeStart=30` on SP-004, `server.go:829`);
  `/admin/control` can't inject it.
- **Seam:** **csip-tls-test only** — serve a nonzero `randomizeDuration` (static tree
  or a widened `adminCtrlReq`) and add a scenario asserting the hub's honored window
  falls within `[dur - |rand|, dur]`.
- **Needs lexa-hub change:** NO.

### P2 — Rogue-parameter seams that don't exist (all on the QA_FAULT_INJECTION roadmap)

**P2-1 · TLS cert-expiry / CA-rotation mid-session — no seam.**
- **Severity:** High (the deferral reasoning is now stale — see §0.5).
- **Field failure caught:** "leaf cert expires / CA rotates while the hub holds a
  live wolfSSL session → does `certmon` WARN/ERROR + `rotate.go` re-handshake, or
  silently stall?"
- **Evidence:** lexa-hub side EXISTS — `cmd/northbound/certmon.go` (Monitor `:139`,
  `inspectCertFile` `:63`, 24h), `cmd/northbound/rotate.go` (RotationController,
  sentinel watch `:64`, probe `:56`), `internal/tlsclient/fetcher.go:124` `Reload`.
  csip-tls-test side: all gen scripts mint fixed validity (no expiry knob);
  `scripts/cert-churn-soak.sh` drives rotation but only same-LFDI **file** churn (not
  expiry, not CA rotation), is standalone and deferred; **no mayhem scenario**.
- **Seam:** **csip-tls-test only** — add a near-expiry/expired cert knob to the gen
  scripts + a gridsim/tlsserver cert-swap seam (`/admin` re-load) + a scenario that
  drives `certmon` days_left and `rotate.go`'s sentinel path.
- **Needs lexa-hub change:** NO (monitor + rotation already exist).

**P2-2 · Modbus crc_error / tcp_drop / unit-ID / register-tearing — no seam.**
- **Severity:** Medium.
- **Feasibility (corrected):**
  - `crc_error` — **INFEASIBLE / meaningless.** modsim runs Modbus **TCP** (MBAP
    header, no checksum); CRC16 is RTU-serial only. Nothing to corrupt on the wire.
    Document and drop.
  - `tcp_drop` (mid-transaction RST), unit-ID confusion, register-tearing —
    **FEASIBLE but need NEW server-layer seams**, not the existing `faults.go`
    register hooks: `tcp_drop` at the listener/`net.Conn` (`sim/southbound/sim.go`
    `startServerRaw:356-359`); unit-ID at `HandleHoldingRegisters` (`sim.go:236`,
    which currently ignores `req.UnitId`); register-tearing at the read branch
    (`sim.go:262-266`, currently `RLock`-consistent) via a deliberate spliced snapshot.
- **Field failure caught:** stale reading not expired; acting on a torn/garbage value;
  answering the wrong slave.
- **Seam:** **csip-tls-test only** (new `FaultKind` consts in `sim.go` ~`:169` +
  handler branches). May surface hub bugs → then lexa-hub fix.
- **Needs lexa-hub change:** MAYBE (if a seam exposes a bug).

**P2-3 · Network partition / dns_fail — no seam (netem is degrade-only).**
- **Severity:** High (WAN loss is the #1 field event; partial coverage today).
- **Evidence:** `scripts/netem.sh` = loss/reorder/delay/jitter only (`:2-3,125`);
  gridsim outage is app-layer 503/hang (`sim/gridsim/outage.go`, "no connection
  hijacking" `:20-23`); `wan-outage-*`/`northbound-hang` use it (`mayhem_world.go:942-1006`).
  No `iptables`/`ip link`/blackhole (L3 partition), no `resolv.conf`/`/etc/hosts`/
  zeroconf-fail (DNS).
- **Seam:** **csip-tls-test only** — a partition script (`iptables -j DROP` / `ip link
  set down` to the gridsim IP) + a DNS-fail seam (rewrite resolv/hosts or fail
  zeroconf) + `mayhem_world.go` scenarios. Note `QA_GAPS_20260701.md:156` deferred
  DNS-SD flap as "needs a second gridsim instance" — a resolv/hosts seam is the
  cheaper first cut.
- **Needs lexa-hub change:** NO.

**P2-4 · CSIP server-edge kinds resource_410 / event_delay / supersede-as-fault / slow_loris — no seam.**
- **Severity:** Medium (conformance + resilience).
- **Evidence:** gridsim returns 200/201/204/301/302/400/403/404/405/500/501/503 but
  **never 410**; `serveXML` hardcodes 200 (`server.go:440`); malform produces bodies
  only, never status/timing. Grep for `410`/`slow`/`loris`/`event_delay` in
  `sim/gridsim/` is empty.
- **Seam (all csip-tls-test only):**
  - `resource_410` — new `sim/gridsim/gone.go` (`goneState{path,remaining}` +
    `goneIntercept`) modeled on `redirectIntercept`, `/admin/gone` in the mux
    (`admin.go:27`), called from `handleGET` after the redirect intercept (`server.go:269`).
  - `event_delay` — per-path response delay in `handleGET`/`serveXML` (`server.go:264/423`).
  - `supersede-as-fault` — **same as P1-2** (widen `adminCtrlReq`).
  - `slow_loris` — `OutageSlow` const in `outage.go:34` + `http.Flusher` paced writes
    in `outageIntercept` (`:99-112`) (or in `serveXML:423` to slow-drip a real body).
- **Needs lexa-hub change:** NO (already read-deadline-bounded, `QA_FAULT_INJECTION.md:172`).

**P2-5 · OCPP out-of-order TransactionEvent / boot-mid-transaction — no seam.**
- **Severity:** Medium (lifecycle correctness; `QA_GAPS_20260701.md:154` deferred as
  "next candidate when evsim is next touched" — evsim WAS just touched for 1.6J).
- **Evidence:** all TxEvents flow through one monotonic emitter `sendEvent`
  (`sim/evsim/ocpp201.go:118-135`, `seq := p.txSeqNo; p.txSeqNo++`), no reorder path;
  `BootNotification` only at start/post-reset/1.6-trigger, never during an active
  2.0.1 tx. Hub side: `OnTransactionEvent` reads `SequenceNo` but only logs it
  (`cmd/ocpp/main.go:1131`), applies meter samples unconditionally; `OnBootNotification`
  (`:940`) doesn't void an active session — both **untested** against these faults.
- **Seam:** **csip-tls-test only** — new `evFaults` bool + `ApplyFault` case
  (`sim/evsim/state.go:272,311`) + reorder buffer in `sendEvent` (`ocpp201.go:118`);
  boot-mid-tx injector calling `cs.BootNotification` during a live session
  (near `state.go:257`). May surface hub bugs → then lexa-hub fix.
- **Needs lexa-hub change:** MAYBE.

**P2-6 · lexa-openadr VEN ↔ vtnsim end-to-end — untested (bypassed via MQTT inject).**
- **Severity:** Medium.
- **Evidence:** `vtnsim` exists + is bench-deployed (`Makefile:72`, `bench-up.sh:104`
  unit `csip-vtnsim:6030`); but `openadr-limit-adopt`/`openadr-csip-precedence`
  inject `lexa/openadr/limits` directly on the bus (`mayhem_ocpp_openadr.go:719,758`)
  — testing hub adoption, not the VEN poll/OAuth2/translate path
  (`cmd/openadr` + `internal/openadr/translate.go`).
- **Seam:** **csip-tls-test** — a scenario that arms `vtnsim` `/admin/events` and
  asserts the real lexa-openadr (with `vtn_url` pointed at vtnsim) polls, translates,
  and publishes `lexa/openadr/*`. Needs the lexa-openadr bench deploy wiring (`vtn_url`
  + restart), not a hub code change.
- **Needs lexa-hub change:** NO (deploy/config only).

### P3 — Boundary / rogue values

**P3-1 · NaN/Inf on a CSIP-served setpoint — structurally impossible; reframe to NEGATIVE.**
- **Severity:** Low (already defended) → the *actionable* variant is a **negative
  opModExpLimW/opModMaxLimW**.
- **Evidence:** `ActivePower{Multiplier int8; Value int16}` (`vendor/lexa-proto/
  csipmodel/resources.go:255-258`) — XML cannot decode NaN/Inf into an int. gridsim's
  only setpoint malform is `MalformHugeActivePower` = 32767e9 W (huge but **finite
  positive**, `malform.go:128-133`). Northbound guards magnitude/finite:
  `plausibleLimit()` rejects `NaN||Inf|| |w|>1e9` (`scheduler/scheduler.go:521-527`),
  fail-closed (never adopted / never stored LKG). Bus `Finite()` gate
  (`internal/bus/finite.go:100,192`) genuinely fires only on the **Modbus-read float
  path** (the `nan_sentinel` fault), never on a served int setpoint.
- **Actual gap:** a **negative** served `opModExpLimW`/`opModMaxLimW` is
  representable and northbound accepts it as plausible (`failclosed_test.go:281` pins
  `Value:-5000`→plausible), but **no gridsim malform kind produces one**.
- **Seam:** **csip-tls-test only** — add `MalformNegativeActivePower` to
  `malform.go:27-55` + `malformedXML` switch; scenario asserts hub behavior on a
  negative served limit.
- **Needs lexa-hub change:** NO (decide-and-document whether negative is legal; the
  hub currently treats it as a real limit).

**P3-2 · Out-of-range control WRITES — hub clamps (fuzz-tested), no e2e scenario.**
- **Severity:** Low (hub is defended).
- **Evidence:** semantic clamp `derbase.go:419-435` (`w`→`[0,WMax]` before pct);
  encoding clamp `sunspec/scale.go:32-63` (int16 ±32767 **saturates, never wraps**;
  uint clamps neg→0); fuzz-tested `lexa-proto/sunspec/scale_fuzz_test.go:30,71`. No
  csip-tls-test scenario writes `WMaxLimPct>100` / negative / int16-wrap and asserts.
- **Seam:** **csip-tls-test only** — a scenario driving a servedcontrol that maps to
  an out-of-range raw write, asserting saturation (not wrap) at the meter.
- **Needs lexa-hub change:** NO.

**P3-3 · Boundary SOC — exact-100% covered (as setup); exact-0 / reserve-edge untested.**
- **Severity:** Low-Medium (safety edges).
- **Evidence:** inject seam pins any SOC (`sim/southbound/battery.go:210-239`,
  `POST /inject {"SoC_pct":0-100}`); reserve floor 10% (`:418`). Exact-100% is a
  *setup* precondition in 6 scenarios (`export-cap-full-battery` etc.) but no
  charge-at-100% assertion; exact-0% (closest 5%, `battery-empty-import-cap.json`)
  and exact-reserve-edge(10%) untested.
- **Seam:** **csip-tls-test only** — two scenarios injecting `SoC_pct:0` (discharge
  command) and `SoC_pct:10` (charge+discharge at the reserve edge), asserting INV-SOC.
  Trivial; seam already exists.
- **Needs lexa-hub change:** NO.

### Minor hub-side observability gaps (follow-up, not blocking)

- `GET /status` surfaces Exp/Max/Imp/Fixed/Connect but **not GenLimW/LoadLimW**
  (`QA_FAULT_INJECTION.md:263-267`) — blocks a clean AUS oracle.
- `lexa_constraint_shadow_divergence_total` is a single aggregate (no per-constraint
  attribution).
- `lexa_mb_adv_divergences_total` covers only measured axes (curve-axis routes to
  `lexa_mb_adv_failed_total`).

---

## 3. The 15 bench-deferred standards scenarios

All 17 standards-buildout scenarios are **implemented and in the live catalog**; 2 ran
live + PASSED (`der-report-roundtrip`, `dcap-redirect`, `QA_STANDARDS_BUILDOUT.md:80`).
The 15 below need a **dedicated non-soak bench session** (`QA_STANDARDS_BUILDOUT.md:86-97`).
Readiness is scored against the stated Phase-3 deploy state (**advanced_der=on,
reconciler.adv=active, modsim -advanced, lexa-openadr commissioned vs vtnsim**). Every
seam already exists — "UNMET" means a hub **config flip** or a **sim relaunch**, never a
missing implementation.

| # | Scenario | WP / INV | Precondition to run live | Phase-3 readiness |
|---|---|---|---|---|
| 1 | `adv-shadow-no-writes` | WP-10 / INV-ADV-READBACK | modsim -advanced + reconciler.adv≥shadow | **READY** (both on) |
| 2 | `curve-adopt-readback-divergence` | WP-10 / INV-ADV-READBACK | modsim -advanced + `curve_adopt_lies` fault | **READY** |
| 3 | `pf-var-measured-convergence` | WP-10 / INV-ADV-READBACK | modsim -advanced (704 PF/Var) | **READY** |
| 4 | `logevent-alarm-pair` | WP-6 / INV-REPORT | modsim -advanced (`raise_alarm` 701 Alrm) + gridsim `/admin/logevents` (exists) | **READY** |
| 5 | `openadr-limit-adopt` | WP-15 / INV-OPENADR | bus inject (unit-covered) or vtnsim | **READY** (inject); vtnsim e2e = P2-6 |
| 6 | `openadr-csip-precedence` | WP-15 / INV-OPENADR | same as #5 | **READY** (inject); vtnsim e2e = P2-6 |
| 7 | `redirect-storm` | WP-3 / INV-REDIRECT | gridsim `/admin/redirect` (exists) + `redirect_max` | **READY** (seam present; `dcap-redirect` already passed) |
| 8 | `aus-gen-cap` | WP-11 / INV-AUS | reconciler.adv=active + `enforce_aus_limits=true` | **1 FLAG** (flip enforce_aus_limits) |
| 9 | `aus-load-cap` | WP-11 / INV-AUS | same as #8 (+≥1-wk zero-diff soak for the default-flip proposal) | **1 FLAG** (+ time-gated soak) |
| 10 | `pin-freeze-egress-halt` | WP-7 / INV-REPORT | hub `registration_pin` armed vs gridsim `/edev/2/reg` mismatch | **1 FLAG** (arm registration_pin) |
| 11 | `cannotcomply-table27` | WP-7 / INV-CANNOTCOMPLY-VOCAB | hub `legacy_cannotcomply_code=false` + gridsim Table-27 accept (exists, `server.go:1000-1030`) | **1 FLAG** (flip legacy_cannotcomply_code) |
| 12 | `ocpp16-smart-charge` | WP-12 / INV-OCPP16 | evsim relaunched `-proto 1.6` (built, `8269e52`) + hub `port_16` set | **RECONFIG** (relaunch evsim + set port_16) |
| 13 | `clear-profile-release` | WP-13 / INV-OCPP16 | same as #12 | **RECONFIG** |
| 14 | `pairing-gate-hold` | WP-13 / INV-PAIRING | hub `pairing_mode="gated"` + an unconfigured station | **CONFIG** (pairing_mode + station) |
| 15 | `ev-setpoint-clamp` | WP-14 / INV-V2G-CHARGEONLY | hub `ev_storage=true` + evsim | **1 FLAG** (ev_storage) |

**Summary:** 7 READY as-is, 5 need a single hub flag flip, 2 need an evsim relaunch to
1.6J, 1 needs a pairing config. The whole set is one non-soak bench session
(`QA_STANDARDS_BUILDOUT.md:86-97` gives the exact `mayhem.py --only …` recipes),
plus the `enforce_aus_limits` week-soak (#9) and vtnsim e2e (P2-6) as separate tails.

**Note on the two deferred lists.** The lexa-hub `VERIFICATION_SWEEP.md` 9-item queue
(PIN drill, COMM-004 pcaps, ERR-001 redirect, dersite/PUT+LogEvent, CannotComply flip,
AUS week, adv-shell soak, 1.6 evsim, openadr deploy) is a *bench-task* list that
overlaps this scenario table. Re-verified against current csip-tls-test code, its
"blocked on unbuilt paired work" items are **stale** — the redirect knob, PUT/LogEvent
endpoints, chain-file loader + COMM-004 fixtures, and 1.6J evsim all shipped
(`89c4f01`, `8269e52`). What genuinely remains is: run the scenarios (this table),
capture COMM-004 pcaps (fixtures/loader now present), run the AUS week-soak, and the
hardware-gated adv real-inverter soak.

---

## 4. Ordered closure plan (4 batches)

Grouped so each batch is independently delegable. Tag: **[TT]** = csip-tls-test-only,
**[HUB]** = needs a lexa-hub (or lexa-proto) change.

### Batch 1 — The product bug + the free wins (do first)
1. **[HUB+TT] Fix the 701 chunking bug (P0-1).** In `lexa-proto/modbus/transport.go`
   `ReadHolding` (or `sunspec/reader.go:46` `ReadModel`), split reads into ≤125-reg
   requests and concatenate. Un-truncate the sim to full 137 regs
   (`sim/southbound/solar_adv.go:populate701`). Add a full-701 read+assert test
   (`tests/modbus_adv_test.go`). Paired proto.pin bump in both repos + `vendor/`
   regen (CI enforces lockstep).
2. **[TT] Boundary-SOC scenarios (P3-3).** Add `battery-soc-empty` (`SoC_pct:0` +
   discharge) and `battery-soc-reserve-edge` (`SoC_pct:10`) as `qa/scenarios/*.json`,
   oracle `diagnoseSOC` / INV-SOC. Seam already at `battery.go:235`.
3. **[TT/config] Run the standards-scenario campaign (§3).** Execute
   `QA_STANDARDS_BUILDOUT.md:86-97`'s two `mayhem.py --only …` waves in a non-soak
   session (Track D reconfig: evsim -proto 1.6, pairing_mode gated, ev_storage true;
   Tracks B/C flags: enforce_aus_limits true, legacy_cannotcomply_code false,
   registration_pin armed). Restore soak config after. No new code.

### Batch 2 — CSIP conformance seams + scenarios (server-edge)
4. **[HUB+TT] Pagination (P1-1).** csip-tls-test: positive-pagination mode honoring
   `s/l/a` in `server.go:handleGET/serveXML` + `/admin` page-size knob + a
   multi-page scenario. lexa-hub: paging loop in `walker.go:454-479` list fetchers.
5. **[TT] Supersede/Cancel + randomizeDuration (P1-2, P1-3, P2-4 supersede).** Widen
   `sim/gridsim/admin.go:291-313` `adminCtrlReq` with `PotentiallySuperseded`,
   `CurrentStatus`, `RandomizeDuration`; set into `ctrl.EventStatus`. Scenarios:
   within-program supersede (assert hub 7), server-cancel (assert hub 6), randomized
   event (assert honored window). Response-capture via `/admin/alerts` or a new
   `/admin/responses` endpoint.
6. **[TT] resource_410 / event_delay / slow_loris (P2-4).** `sim/gridsim/gone.go` +
   `/admin/gone`; per-path delay in `handleGET`; `OutageSlow` + `http.Flusher` in
   `outage.go`. Scenarios assert no walker deadlock / LKG hold.

### Batch 3 — Transport / network / OCPP fault seams (may surface hub bugs)
7. **[TT] Modbus tcp_drop / unit-ID / register-tearing (P2-2).** New `FaultKind`
   consts (`sim/southbound/sim.go:~169`) + server-layer seams: listener/`net.Conn`
   wrap in `startServerRaw:356`, `req.UnitId` branch in `HandleHoldingRegisters:236`,
   spliced-snapshot read at `:262-266`. **Explicitly skip crc_error** (infeasible on
   Modbus TCP — document in the fault matrix). Scenarios via INV-CONVERGE.
8. **[TT] Network partition + dns_fail (P2-3).** Partition script (`iptables -j DROP`
   / `ip link set down` to the gridsim IP) + DNS-fail seam (resolv/hosts rewrite) +
   `mayhem_world.go` scenarios (INV-EXPORT/INV-RESTORE hold through the partition).
9. **[TT] OCPP out-of-order TxEvent + boot-mid-tx (P2-5).** evsim `state.go:272,311`
   fault kinds + reorder buffer in `ocpp201.go:118` + boot-during-session injector.
   Assert hub tolerance; file a lexa-hub bug if `OnTransactionEvent`/`OnBootNotification`
   mishandle (likely — no ordering validation / no tx-void today).
10. **[TT] TLS cert-expiry / CA-rotation (P2-1).** Near-expiry/expired cert knob in the
    gen scripts + gridsim/tlsserver cert-swap `/admin` seam + a scenario driving
    `certmon` days_left + `rotate.go` sentinel. lexa-hub monitor/rotation already exist.
11. **[TT] Negative served setpoint (P3-1) + out-of-range write (P3-2).**
    `MalformNegativeActivePower` in `malform.go` + a scenario; a scenario mapping to an
    int16-boundary raw write asserting saturation.

### Batch 4 — End-to-end + soak tails (longer / gated)
12. **[TT/deploy] lexa-openadr ↔ vtnsim e2e (P2-6).** Point lexa-openadr `vtn_url` at
    `csip-vtnsim:6030`, arm `vtnsim /admin/events`, assert the real VEN poll/translate
    publishes `lexa/openadr/*`. Needs the openadr deploy wiring (config), not hub code.
13. **[bench] COMM-004 D–G pcap capture.** Fixtures (`certs/comm004/`) + chain loader
    (`sim/tlsserver`) now exist; run the 7-scenario capture per `VERIFICATION_SWEEP.md:81-183`.
14. **[bench/soak] AUS ≥1-week zero-diff shadow soak** (WP-11 default-flip gate) and the
    **hardware-gated adv real-inverter soak** (WP-10, RSK-08). Time/HW-bound; schedule
    around the running soak.
15. **[HUB] Observability follow-ups.** Add GenLimW/LoadLimW to `/status`; per-constraint
    shadow-divergence attribution. Enables clean AUS/adv oracles for Batch 3-4.

**Delegation split:** Batches 2-4 are almost entirely **[TT]** (csip-tls-test-only).
The **[HUB]** work is concentrated: the P0 chunking fix (Batch 1, cross-repo, urgent),
the pagination paging loop (Batch 2), and observability (Batch 4). Batch 3's OCPP/
transport seams are [TT] to build but likely surface [HUB] bugs to fix after.
