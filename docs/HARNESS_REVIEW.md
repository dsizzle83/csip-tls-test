# Simulation Harness Review & Dashboard Enhancement Plan

**Date:** 2026-06-10
**Scope:** `csip-tls-test` simulation harness (sims, gridsim, TLS layer, dashboard) plus the
endpoints it exercises on `lexa-hub` (OCPP CSMS, hub API). The obsolete `cmd/hub` in this repo
was excluded except where its docs mislead.
**Prior art:** `CONFORMANCE_REPORT.md` (2026-06-08) already covers the northbound CSIP client
audit; its fixes (S-1, Q-1, Q-2) were re-verified here and are in place. This review covers
everything that report did not: the southbound sims, OCPP, the smart meter, the dashboard, and
the harness's own code quality.

Severity scale: **H** = wrong results or security exposure, **M** = protocol deviation or
demo-visible bug, **L** = polish / robustness.

### Resolution status (2026-06-10)

| Finding | Status |
|---|---|
| GS-1 admin int16 truncation | ✅ Fixed — `apFromWatts` scales into multiplier + `admin_test.go` |
| OCPP-5 connector-map race | ✅ Fixed — IDs copied under RLock |
| MOD-3 battery OnWrite race | ✅ Fixed — hook installed before server start |
| MTR-1 meter ±32.7 kW wrap | ✅ Fixed — W/VA/VAR now sf=1 (10 W steps, ±327 kW) |
| OCPP-1 no TransactionEvent | ✅ Fixed — Started/Updated/Ended lifecycle in evsim; handled in both CSMS copies + lexa-hub MQTT bridge; e2e tests in `sim/evsim/main_test.go` |
| OCPP-2 RequestStart/Stop/Reset hollow | ✅ Fixed — start/stop act on the session (reject on mismatch); Reset ends tx + replays BootNotification |
| OCPP-4 stale connected flag | ✅ Fixed — Snapshot reports live `cs.IsConnected()` |
| OCPP-3 wss://+auth off | ✅ Capability complete — evsim `-tls-ca`/`-auth-user`/`-auth-pass` flags, constant-time compare in both CSMS copies, `scripts/gen-ev-cert.sh`, enabling steps in lexa-hub `DEVKIT.md`, SP2 e2e test. Deployment config still defaults to plain ws:// until certs are deployed to the dev kit. |
| OCPP-6 empty Get/SetVariables responses | ✅ Fixed — one UnknownVariable result per requested variable |
| OCPP-7 multi-connector quirks | ✅ Fixed — single-EV model documented; auto-session picks first Available connector; battery current zeroed at session end; TriggerMessage targets the session connector |
| GS-2 admin event status | ✅ Fixed — future controls created as Scheduled(0), actderc only gets open-window events; regression tests |
| MTR-2 no energy accumulators | ✅ Fixed — TotWhImp/TotWhExp integrated on every SetNetW tick, exposed in /state |
| MTR-3 no meter conformance coverage | ✅ Fixed — `modsim-conformance -device meter` (MTR-001..006); 9/9 pass against live metersim |
| MTR-4 meter register maps non-standard (new, **H**) | ✅ Fixed — M201/202/203 constants corrected to published SunSpec layouts in both repos (deploy hub + metersim together) |
| MTR-5 stale VA/VAR/A registers (new) | ✅ Fixed — derived registers refreshed on every SetNetW |
| DB-1 scenario assertions | ✅ Fixed — per-scenario import/export-cap assertions with sustained-hold rule, live status box, PASS/FAIL chart markers, localStorage execution history + CSV export |
| DB-2 unified protocol log | ✅ Fixed — simapi + gridsim-admin gained SSE `/logs` (log-tee ring buffers); dashboard server merges all six backends into one `/api/logs/all` stream (browser connection-limit safe); new Logs tab with per-source chips, text filter, pause, JSON/CSV export. Note: `sim/server` tee needs a Pi/WSL build to verify (cgo). |
| GS-3..6 · MOD-1/2/4/5 · DB-3..5 · DOC-1..3 | ⬜ Open |

---

## 1. Smart meter protocol — identified and documented

The smart meter is **SunSpec Modbus TCP, Model 201 (Single-Phase AC Meter)**, served by
`bin/metersim` (port 5022, simapi on 6022). Implementation: `sim/southbound/meter.go`.

Register layout (all Modbus holding registers, FC03 read / FC06+FC16 write):

| Address range | Block | Contents |
|---|---|---|
| 40000–40001 | SunS header | 0x5375 0x6E53 magic |
| 40002–40069 | Model 1 (Common) | Mn="SunSpec Sim", Md="CSIP-Meter-1Ph", SN="SN-MTR-001" |
| 40070–40176 | Model 201 | W (signed, sf=0), PhV/PhVphA (sf=−1), Hz (sf=−2), VA, VAR, PF (sf=−2), A/AphA (sf=0) |
| 40177–40178 | End marker | 0xFFFF, 0 |

Sign convention: **W > 0 = site importing from grid; W < 0 = exporting**.

Two operating modes (`sim/metersim/main.go`):
- **Sine mode** (default): net power follows `peak·sin(2πt/600)`.
- **Linked mode** (`-solar-api/-battery-api/-ev-api/-hub-api`): every 5 s it polls the other
  sims' simapi `/state` endpoints and computes the PCC balance
  `meter_W = load_W + ev_W − solar_W − battery_W`. EV power comes from the hub's `/status`
  (OCPP MeterValues) when `-hub-api` is set, else from evsim directly. All fetches fail safe
  to 0 W with a 3 s HTTP timeout.

Flow (linked mode):

```
modsim /state ──┐
batsim /state ──┼──(HTTP poll, 5 s)──▶ metersim ──(Modbus M201 W reg)──▶ lexa-hub meter reader
evsim or hub ───┘                        │
                                         └──(simapi :6022)──▶ dashboard "Meter" card
```

Gaps (see findings MTR-1..3): ±32,767 W range limit, no energy accumulators (TotWhExp/Imp),
no meter section in `modsim-conformance`.

---

## 2. Findings by component

### 2.1 SunSpec Modbus simulators (`sim/southbound`, modsim/batsim/metersim)

**MOD-1 (M) — Battery control deviates from SunSpec: signed `WMaxLimPct` encodes charge
direction.** `battery.go:390-406` (`hubBatteryW`) interprets a *negative* Model 123
`WMaxLimPct` as "charge at |pct|·WMax". In SunSpec, `WMaxLimPct` is an output *limit*
(0–100 %); storage dispatch belongs in Model 124 (`StorCtl_Mod`, `InWRte`/`OutWRte`) or
Model 802 controls. A real battery inverter pointed at the hub would not honor this
convention. It is a documented in-house convention (comment at `battery.go:393`), so it works
for the demo — but flag it to any third party, and plan a Model 124 migration if real hardware
is ever attached. *Fix: implement M124 in batsim + lexa-hub battery adapter; keep the signed
convention behind a `-legacy-signed-pct` flag during transition.*

**MOD-2 (M) — `simTime()` causes a phase jump when speed changes.**
`sim.go:137-139` computes `time.Now().Unix() × Speed()`. Changing speed from 1→10 mid-run
multiplies the *absolute* epoch, teleporting every sinusoid to a random phase (visible as a
power/SoC discontinuity in demos). *Fix: accumulate `simTime += dt × speed` per tick instead
of scaling wall-clock.*

**MOD-3 (L) — `RegisterMap.OnWrite` assigned without synchronization.**
`battery.go:442` sets `r.OnWrite` from the animation goroutine after the Modbus server is
already accepting writes that read it under `r.mu` (`sim.go:58-69`). Unsynchronized
write-vs-read — a data race `go test -race` would flag. *Fix: pass the callback into the
constructor before `srv.Start()`, or guard the assignment with `r.mu`.*

**MOD-4 (L) — Inject endpoints accept out-of-range values silently.** `uint16(val)` on
`Conn`, `St`, `ChaSt` wraps negatives (e.g. `{"St":-1}` → 65535); meter `W_W` wraps beyond
±32,767. No clamping or 400. *Fix: validate ranges in each Inject switch arm.*

**MOD-5 (L) — Solar energy accumulator is wrong and wraps.** `solar.go:435-436` adds
`uint16(w·5/3600)` (integer-truncated, ignores speed factor) into only the low word of the
acc32 `ActWh`, wrapping at 65,535 Wh. Harmless today (nothing reads it) but it will mislead
the first client that does. *Fix: keep a float64 accumulator × speed, write both words.*

**MTR-1 (M) — Meter range limited to ±32.7 kW.** `meter.go:54-57` uses sf=0 into an int16
register. A 40 kW site (e.g. two EVs + load) silently wraps negative — linked mode makes this
reachable. *Fix: sf=1 (10 W resolution, ±327 kW) or compute sf dynamically.*

**MTR-2 (L) — No energy accumulators.** M201 `TotWhExp`/`TotWhImp` never populated, so the
hub/dashboard can't show kWh delivered/received. *Fix: integrate in the linked/sine tick.*

**MTR-3 (M) — No meter conformance coverage.** `modsim-conformance` supports
`-device inverter|battery` only; Model 201 has zero checks (header, mandatory fields, sign
convention, scale-factor sanity). *Fix: add a `-device meter` section (DISC + MEAS-001..006
against M201 offsets).*

**MTR-4 (H) — Meter register maps deviate from the published SunSpec models**
*(found while implementing MTR-3, after the original report)*. The M201/M202/M203 offset
constants in `internal/southbound/sunspec/models.go` (both repos) were an invented compressed
layout (`W=8`, 16 points) that doesn't match the published models (`W=16`, 105-register
common-meter layout — verified against sunspec/models model_201/202/203.json). Sim and hub
agreed with each other, so the bench worked — but a **real SunSpec meter would have been
misread** (its `Hz` register lands where the old map expected `W`). Fixed in lockstep in both
repos; all consumers reference the constants symbolically, so updated peers interoperate
unchanged. **Deployment caveat: hub and metersim must be updated together** — an old metersim
against a new hub (or vice versa) reads garbage.

**MTR-5 (M) — `SetNetW` left VA/VAR/A frozen at startup values** *(caught by the new MTR-005
conformance check on its first live run: VA=0 while W=4 kW)*. The sim refreshed only W;
apparent power, reactive power, and current were written once at populate time. Fixed —
derived registers now track every power update via `writeDerivedPower`.

**What is solid:** register maps are thread-safe; scale factors are consistently applied via
`sunspec.ApplyScale*` round-trip helpers; model chains (1→120→121→[122]→103→123→[802]) are
correctly linked with valid lengths and end markers; FC06/FC16 writes land atomically and the
battery applies hub writes immediately even while paused (`applyNow`); simonvetter server is
bounded (8 clients, 30 s timeout).

### 2.2 OCPP 2.0.1 EV charger (`sim/evsim` ↔ `lexa-hub/internal/ocppserver`)

**OCPP-1 (H) — No `TransactionEvent` messages: sessions are not OCPP transactions.**
evsim simulates a charging session purely with `StatusNotification(Occupied)` + periodic
`MeterValues` + `StatusNotification(Available)` (`main.go:276-333`). OCPP 2.0.1 requires
`TransactionEvent(Started/Updated/Ended)` with a `transactionId`, seqNo, and meter data
attached (use cases E01–E12); standalone `MeterValues` is for non-transactional sampling.
Any real CSMS — and any OCPP compliance tool — will see a station that never starts a
transaction. The hub's energy accounting currently works only because its CSMS handler was
written to consume bare MeterValues. *Fix: send TransactionEvent Started/Ended around the
charging loop and move the sampled values into TransactionEvent Updated; handle it in
`lexa-hub` ocppserver (keep MeterValues for backward compat during transition).*

**OCPP-2 (M) — `RequestStart/StopTransaction` accepted but ignored.** Handlers at
`main.go:601-608` return `Accepted` and do nothing — no session starts/stops, violating the
F01/F02 contract (accept ⇒ act, otherwise reject). Same for `OnReset` (accepts, never resets
or re-boots). *Fix: wire them to `startSession`/`cancelSession`; for Reset, drop the
connection and replay BootNotification.*

**OCPP-3 (M) — Security Profile 2 exists in code but is OFF in the deployment.**
`ocppserver` supports TLS + Basic Auth, but `lexa-hub/configs/ocpp.json` has empty
`cert_path`/`basic_auth_*`, and evsim *cannot* speak anything but plain `ws://` (no
`-tls`/credentials flags). The EV control channel — which carries charging current commands —
runs unencrypted and unauthenticated on the LAN. Also the Basic Auth comparison at
`server.go:65` is non-constant-time. *Fix: add `wss://` + basic-auth flags to evsim, issue a
cert from the existing vault CA, turn it on in ocpp.json, and use
`subtle.ConstantTimeCompare`.*

**OCPP-4 (M) — Connection state is write-once.** `h.setConnected(true)` is called once after
`cs.Start`; no disconnected/reconnected callbacks are registered, so the dashboard shows
"connected" forever even after the CSMS dies. *Fix: `cs.SetDisconnectedHandler` /
`SetReconnectedHandler` (ocpp-go supports both) updating the flag.*

**OCPP-5 (M) — Data race in `OnTriggerMessage`.** The MeterValues branch iterates
`h.connectors` without holding `h.mu` (`main.go:631`), while `setConnector` writes the map
concurrently. The StatusNotification branch takes the lock correctly two lines above. *Fix:
copy IDs under RLock like the sibling branch.*

**OCPP-6 (L) — `OnGetVariables` returns an empty response.** OCPP requires one
`getVariableResult` per requested variable; an empty result list is schema-invalid and a
strict CSMS will raise a CallError. Same pattern for `OnSetVariables`.

**OCPP-7 (L) — Single shared battery across connectors; auto-session always targets
connector 1.** Fine for the current 1-connector demo; will produce nonsense if
`-connectors 2` is used.

**What is solid:** the CC/CV battery model is genuinely good (correct taper, energy
integration with sim-speed scaling, IEC 61851 6 A floor on session start); SetChargingProfile
→ commanded current → MeterValues closes the control loop with *actual* (not commanded)
current; heartbeat honors the BootNotification interval; simapi inject (sessions, SOC, speed,
fault status) is exactly what the dashboard needs.

### 2.3 IEEE 2030.5 grid simulator (`sim/gridsim`, `sim/tlsserver`, `sim/server`)

Prior audit items re-verified: S-1 (client-supplied `X-Peer-LFDI` stripped in
`tlsserver/handlers.go:55` before the verified value is injected), Q-1 (405+Allow / 501
split, fixture disclaimer in the package comment), Q-2 (`AddResource` locked). The mTLS layer
still pins exactly `ECDHE-ECDSA-AES128-CCM-8` TLSv1.2 with `RequireClientCert`.

**GS-1 (H) — Admin API truncates watt values to int16.** `admin.go:329-334` (`ap16`) does
`int16(*v)` with Multiplier 0. A dashboard operator entering an export limit of 40,000 W gets
−25,536 W on the wire; ≥32,768 silently flips sign. This is reachable from the Grid Controls
tab today. *Fix: scale into Multiplier (value=4000, multiplier=1) or reject >32,767 with 400.*

**GS-2 (M) — Admin-created controls are always `CurrentStatus=1` (Active).**
`admin.go:251-253` marks the event Active even when `start_offset_s > 0` and also mirrors it
into `actderc` regardless of window. A spec-correct client must treat status by the *event's*
state machine — a future event marked Active is contradictory and could make a stricter
client start it early. *Fix: status 0 when `StartOffset > 0`; only mirror into actderc when
the window is open.*

**GS-3 (L) — Admin + simapi + dashboard are unauthenticated by design.** `/admin/*` (11112),
every simapi port, and the dashboard proxy have no auth and `Access-Control-Allow-Origin: *`,
and all bind 0.0.0.0. Acceptable for the air-gapped 69.0.0.x bench; do not bridge that LAN.
One cheap hardening for third-party demos: bind dashboard/admin to specific interfaces and
note the trust model in README.

**GS-4 (L) — `requestWantsClose` greps the entire request.** `tlsserver/server.go:191-193`
does `bytes.Contains` over headers *and body*, so a POSTed payload containing the literal
"connection: close" closes a keep-alive session. *Fix: inspect only `data[:headerEnd]`.*

**GS-5 (L) — No read deadline on TLS sessions.** `readHTTPMessage` loops on `wolfssl.Read`
with no timeout; a hung client pins a goroutine + fd forever (1 MB cap bounds memory, not
connections). *Fix: `conn.SetReadDeadline` before handing the fd to wolfSSL, or a watchdog.*

**GS-6 (L) — Stale default cert paths.** `sim/server/main.go:22-24` defaults to
`/home/dmitri/csip-tls-test/...` (missing `projects/`) — the path does not exist, so the
binary fails when run without flags. Scripts always pass flags, which is why nobody noticed.

### 2.4 Dashboard & simapi — current state

What exists (`cmd/dashboard`: 62-line Go proxy + ~2,000-line embedded SPA):
- Reverse proxy fan-out (`/api/{hub,gridsim,solar,battery,meter,ev}/…`) — no CORS issues,
  one origin, SSE pass-through enabled.
- Header KPIs (hub link state, CSIP program count, clock offset), clickable per-device power
  cards, live multi-series power chart with pause and **CSV export including scenario
  annotations**.
- Tabs per component: telemetry panels, injection forms, animation pause/resume/speed,
  decoded **register tables** for solar/battery, DERControl composer (Grid Controls tab:
  exp/imp/gen/load/fixed W limits, connect/energize, PF/var) + DefaultDERControl editor.
- **5 narrated demo scenarios** (export-limit, import-cap, zero-import emergency, DR
  dispatch, self-consumption) that stage all four sims then fire the grid event — exactly the
  third-party demo flow requested.
- Live hub log panel via lexa-api `GET /logs` SSE.
- The old CustomTkinter GUI (`gui/sim_gui.py`) is deprecated but still in-tree with docs that
  still reference it (root `CLAUDE.md`).

Gaps vs. the stated goals:

**DB-1 — Scenarios have no pass/fail.** They narrate and stage but never assert (e.g. "PCC
import ≤ 500 W within 60 s, sustained 3 ticks"). Each scenario already knows its expected
condition — evaluate it from polled meter data and render PASS/FAIL with a timestamped result
history. This is the single highest-value addition: it converts the demo into the requested
built-in test runner with execution history.

**DB-2 — Logging is hub-only and ephemeral.** Only lexa-api MQTT events stream to the panel;
no gridsim request log, no Modbus read/write trace, no OCPP frame capture; no filtering,
search, time-range, or JSON/CSV export of *logs* (only chart data exports). Recommended
architecture: a `GET /events` ring-buffer + SSE endpoint in simapi (each sim already logs the
interesting lines) and in gridsim admin; dashboard merges streams into one filterable,
exportable view tagged by `{source, protocol, direction, status}`.

**DB-3 — No protocol-error injection.** Inject covers values and states but not malformed
frames, timeouts, or dropped connections (the "Response injection / endpoint mock" goal).
Cheap wins: simapi `{"cmd":"hang", "duration_s":N}` (stop answering Modbus), gridsim admin
"respond 503 for N s" and "garble next XML response", evsim "drop WebSocket". These also
become the error-case test scenarios.

**DB-4 — No energy-flow diagram.** The hub tab shows cards; a simple SVG site one-line
(grid—meter—bus—solar/battery/EV/load with animated arrows scaled by W) is the standard demo
visual. All data is already polled.

**DB-5 — Proxy robustness.** `httputil.NewSingleHostReverseProxy` default error handler
returns 502 with a Go log line; the SPA shows "—" without explaining which backend is down.
Add a `/api/health` aggregator that pings each target and surface per-backend status chips.

### 2.5 Test coverage matrix

| Component / concern | Happy path | Error cases | Compliance | Load | Where |
|---|---|---|---|---|---|
| CSIP northbound client (hub) | ✅ | ✅ wrong-CA/cipher | ✅ 42 logic tests, 4 layers | — | `tests/csip_conformance_test.go`, `scripts/run-conformance.sh` |
| mTLS transport | ✅ | ✅ | ✅ pcap 0xC0AE | — | `tests/wolfssl_integration_test.go`, `sim/tlsserver/*_test.go` |
| gridsim resource tree | ✅ | partial (405/501/404) | fixture-only (documented) | — | exercised via above |
| gridsim **admin API** | ❌ | ❌ | n/a | — | **no tests** (GS-1 would have been caught) |
| Solar/battery Modbus | ✅ | partial | ✅ DISC/MEAS/NAME/CTRL/STAT/BAT | — | `sim/modsim-conformance`, `tests/modbus_conformance_test.go` |
| **Meter (M201)** | ✅ implicit | ❌ | ❌ no meter device mode | — | **gap (MTR-3)** |
| metersim linked-mode balance | ❌ | fail-safe-to-0 only | n/a | — | **no tests** |
| **OCPP evsim ↔ CSMS** | partial (`simulator_test.go` in lexa-hub) | ❌ | ❌ no TransactionEvent at all | — | **gap (OCPP-1)** |
| simapi (state/inject/control/ws) | ❌ | ❌ | n/a | — | **no tests** |
| Dashboard SPA / proxy | ❌ | ❌ | n/a | — | manual only |
| Load/stress (any protocol) | — | — | — | ❌ | **nothing** (modbus MaxClients=8 untested) |

### 2.6 Documentation issues

- **DOC-1:** Root `CLAUDE.md` says `bin/evsim -hub 69.0.0.1:8887`; the actual flag is `-csms`
  and the built-in default is the stale `ws://192.168.10.1:8887/ocpp`. Also `sim_dashboard.txt`
  places the hub API at `69.0.0.2:9100` while `CLAUDE.md` uses `69.0.0.1` — pick one address
  plan and fix both.
- **DOC-2:** `CLAUDE.md` still documents `gui/sim_gui.py` as *the* GUI; the web dashboard
  (`cmd/dashboard`) isn't mentioned. Swap them and mark the Tkinter GUI deprecated (or delete it).
- **DOC-3:** The setup guides living as root-level `sim_*.txt` files would be more
  discoverable as `docs/*.md`, and the meter protocol description (section 1 above) should
  land in `docs/` as the requested smart-meter reference.

---

## 3. Prioritized recommendations

**P0 — correctness bugs reachable from the dashboard today**
1. GS-1 int16 truncation in admin API (one-line scale fix + test).
2. OCPP-5 connector-map race + MOD-3 OnWrite race (run `go test -race`, fix both).
3. MTR-1 meter ±32.7 kW wrap (scale factor).

**P1 — protocol fidelity before any third-party demo**
4. OCPP-1/2: TransactionEvent lifecycle + honor RequestStart/Stop (largest single work item;
   touches evsim and lexa-hub ocppserver).
5. OCPP-3: turn on wss:// + Basic Auth (config + small evsim flag work).
6. GS-2: correct event status for future admin controls.
7. MTR-3: meter section in modsim-conformance.

**P2 — dashboard, in value order**
8. DB-1 scenario assertions with PASS/FAIL history (converts demo → test runner).
9. DB-2 unified protocol log: simapi/gridsim `/events` ring buffer + SSE, merged filterable
   view, JSON/CSV export.
10. DB-4 energy-flow one-line diagram.
11. DB-3 fault-injection controls (hang/garble/drop) per endpoint.
12. DB-5 backend health chips.

**P3 — hygiene**
13. MOD-2 simTime accumulation; MOD-4 inject validation; MOD-5 Wh accumulator; GS-4/5
    keep-alive parsing + read deadlines; GS-6 stale default paths; DOC-1..3; delete or
    quarantine `gui/sim_gui.py`; commit-or-ignore the root `dashboard` ELF binary
    (it is currently untracked clutter).

## 4. Dashboard wireframe (proposed additions only)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ HEADER KPIs (existing)              │ NEW: backend health chips           │
│ Hub ● | Programs 3 | Offset 0.2s    │ [hub ✓][grid ✓][sol ✓][bat ✓][ev ✗] │
├──────────────────────────────────────────────────────────────────────────┤
│ NEW: ENERGY FLOW ONE-LINE                                                 │
│   GRID ◄──1.0kW── METER ──┬── LOAD 1.0kW                                  │
│                            ├── SOLAR 8.0kW ─►                             │
│                            ├── BATTERY ◄─5.1kW (charging, SOC 43%)        │
│                            └── EV ◄─1.9kW (CC, SOC 24%)                   │
├──────────────────────────────────────────────────────────────────────────┤
│ POWER CHART (existing, + event markers)                                   │
├──────────────────────────────────────────────────────────────────────────┤
│ Tabs: Hub | Solar | Battery | EV | Grid | ▶ Scenarios | NEW: Logs | Tests │
│                                                                            │
│ [Scenarios tab + NEW assertions]      [NEW Logs tab]                       │
│  S2 Import-Limit      ▶ Run           src:[all▾] proto:[all▾] q:[____]    │
│  ✓ setup complete                     12:01:02 gridsim GET /derp/0/derc 200│
│  ✓ event delivered (hub log)          12:01:03 modbus  WR 40230=2500 OK   │
│  ⏱ asserting: import ≤ 500W…          12:01:04 ocpp    MeterValues 1.9kW  │
│  ✅ PASS — held 500W for 3 ticks      [Export JSON] [Export CSV] [⏸]      │
│  History: S2 ✅ 12:01 | S1 ✅ 11:48   │                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

## 5. What is solid overall

- The mTLS path is the strongest part of the codebase: single pinned CCM-8 cipher, enforced
  client certs, live LFDI derivation from the peer cert, header-spoofing fixed and
  regression-tested, air-gapped cert layout with keys gitignored.
- The CSIP fixture tree is rich (3 programs, supersession/cancel/randomize cases) and honest
  about being a fixture, not a server EUT.
- The simulator architecture (Modbus/OCPP truth + uniform simapi sidecar + single proxying
  dashboard) is clean, and the linked-mode meter closing the physical energy balance across
  four processes is a genuinely good design.
- The dashboard is already demo-capable; the gap to "demonstration-ready with testing
  features" is assertions, unified logging, and fault injection — not a redesign.
