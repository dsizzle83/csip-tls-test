# CSIP Simulation & Conformance Harness

## What this repo is
The **test bench** for the LEXA DERMS hub. The product itself lives in
`~/projects/lexa-hub` (separate repo, separate sessions). This repo provides:

- IEEE 2030.5 / CSIP grid server simulator (wolfSSL mTLS) + admin API
- SunSpec Modbus device sims: solar, battery, bi-directional meter
- OCPP 2.0.1 EV charger sim (`evsim`) + shared CSMS (`lexa-proto/ocppserver`) for tests
- CSIP + Modbus conformance suites
- Web dashboard (`cmd/dashboard`, :8080) — the demo/test UI

Shared protocol code (`sunspec`, `derbase`, `modbus`, `ocppserver`, `csipmodel` — this
repo used to duplicate `sunspec` and `ocppserver` in-tree; audit MTR-4) now lives in the
`lexa-proto` module, imported by both this repo and lexa-hub via a pinned commit SHA
(`proto.pin` at each repo's root — `lexa-proto` has no hosted remote yet, AD-003(c); a
committed `vendor/lexa-proto/` tree, AD-003(e), lets both repos build without fetching
it). **Both repos must pin the identical `lexa-proto` commit — CI enforces it**
(`scripts/check-proto-pin.sh`, TASK-024, replacing TASK-004's retired raw-diff
`lockstep-check.sh`). Version bumps ship as paired PRs (both `proto.pin` files + both
`vendor/lexa-proto/` regenerated in the same session) and deploy hub + sims together —
the code half of MTR-4 lockstep is now CI-gated; the deploy half remains an operational
discipline (see `docs/BENCH.md`). A local `go.work` (`go work init . ../lexa-proto`,
gitignored, never committed) is still the normal way to develop against a live
`lexa-proto` checkout.

## Stack
Go 1.26 · wolfSSL cgo (`internal/wolfssl` only) · lorenzodonini/ocpp-go · simonvetter/modbus · grandcat/zeroconf

## Directory map
```
sim/gridsim/            IEEE 2030.5 server simulator library (+ admin API on :11112)
sim/tlsserver/          wolfSSL mTLS server library (pins ECDHE-ECDSA-AES128-CCM-8)
sim/server/             mTLS gridsim binary (desktop, cgo)
sim/{modsim,batsim,metersim,evsim}/   Device sim binaries
sim/southbound/         In-memory Modbus device models (no hardware)
sim/mbapsdev/           Secure Modbus (mbaps) DEVICE sim: internal/mbtls server +
                        lexa-proto/mbap dispatch over sim/southbound's animated
                        register world (-model inverter|battery). Southbound TARGET
                        for the lexa-gw gateway / T06.4 aggregator emulator to poll
                        over Secure SunSpec Modbus. cgo (see internal/mbtls below).
sim/simapi/             REST + WS + SSE /logs sidecar for every sim
sim/conformance/        CSIP conformance runner (Pi, cgo)
sim/modsim-conformance/ Modbus conformance runner (-device inverter|battery|meter)
cmd/dashboard/          Go proxy + embedded SPA; hosts the Mayhem hostile-QA engine
                        (mayhem.go, /api/qa/*), the Bench Replay driver (replay.go,
                        /api/replay/*), and the what-if cost API (whatif_api.go).
                        V2 UI: cmd/dashboard/ui/ (Vite+React+TS, dist/ committed,
                        `make ui` rebuilds) served at /; legacy dashboard.html at
                        /legacy. See docs/DASHBOARD.md + docs/dashboard-v2/.
internal/tariff/        Real-tariff engine (TOU periods/tiers/demand/export, NEM
                        monthly credit cap, itemized bills) — CONTRACTS.md §1
internal/whatif/        Deterministic 15-min what-if cost sim (3 policies) — §3
internal/scenariodata/  Scenario dataset loader (real ERA5 weather) — §2
data/tariffs/           Sourced July-2025 tariffs w/ provenance (SOURCES.md; never
                        invent rates — confidence: filed|published|estimated)
data/scenarios/         Committed weather datasets (scripts/fetch-scenario-data.py)
internal/csip/          identity (LFDI/SFDI), DNS-SD (model types moved to
                        lexa-proto/csipmodel — TASK-023; walker/scheduler moved out to
                        internal/csipref — TASK-082)
internal/csipref/       2030.5 walker (discovery/) + DER event scheduler (scheduler/) — this
                        repo's OWN independent client-side implementation, deliberately kept
                        unsynced with lexa-hub's walker for conformance-referee value
                        (AD-003(f), TASK-082). Consumed by sim/conformance, sim/client(-http),
                        tests/*.
internal/tlsclient/     wolfSSL mTLS client (persistent keep-alive fetcher)
internal/mbtls/         Secure SunSpec Modbus (mbaps) wolfSSL glue: client (Dial) + server
                        (Listen/Accept) profiles, independent role extraction (RoleFromDER).
                        DELIBERATELY not lexa-platform/securemodbus — referee independence
                        (T06 PN-1/C9): shares only lexa-proto/mbap (framing) with the product.
internal/aggregator/    SunSpec Modbus aggregator emulator CORE (T06.4/T06.5): a northbound
                        mbaps CLIENT that plays the utility/VPP driving the gateway's :802
                        server. Role sessions (ConnectAs over internal/mbtls), a
                        lexa-proto/modbus.Transport adapter over mbap.Client, per-unit
                        device discovery (SunSpec Model 1), telemetry polling, and the
                        typed control / readback / role-denial primitives + JSON run state
                        the scenario engine (T06.6+) composes. Uses the bench's OWN mbtls +
                        RoleFromDER (C9), shares only lexa-proto/{mbap,modbus,sunspec}. cgo.
internal/southbound/    Modbus/SunSpec device drivers + sim world model; codec (sunspec/modbus)
                        and DER control/measurement mapping (derbase) all now imported from
                        lexa-proto — TASK-021/082. No bench-local codec or derbase fork remains.
tests/                  Conformance + integration test suites
docs/                   HARNESS_REVIEW.md (audit findings), BENCH.md (live bench), pcaps
```

## Bench & ports
Live topology, IPs, SSH users, service models: **read `docs/BENCH.md`** before any deploy/SSH work.
Quick port map: gridsim 11111/11112 + dashboard 8080 (desktop 69.0.0.20) ·
modsim 5020/6020 (.10) · batsim 5021/6021 (.11) · metersim 5022/6022 (.12) ·
evsim simapi 6024 (.14) · mbapsdev 8021/6031 (mbaps/TLS + simapi, desktop-only —
cgo wolfSSL, PN-2) · hub: lexa-api 9100, OCPP CSMS 8887 (69.0.0.2 — ConnectCore 93
dev kit, `root@`, since 2026-07-07; Pi hub 69.0.0.1 is standby).
Pattern: Modbus port / simapi port. simapi: `GET /state`, `POST /inject`, `POST /control`, `GET /logs` (SSE).

## Commands
```bash
make test-fast                    # unit tests, no network (<1 s) — run after every change
go test ./tests/                  # 2030.5 discovery + MUP + conformance logic
go test ./internal/southbound/... # Modbus/SunSpec unit tests
make test-integration             # wolfSSL mTLS handshake tests (amd64 sysroot on desktop),
                                   # incl. sim/mbapsdev's loopback mbaps device-sim proof
make gen-mbaps-certs              # bench mbaps PKI (T06.1): certs/mbaps/ — role certs +
                                   # device cert + negative-fixture matrix (git-tracked
                                   # public certs, keys gitignored, see certs/mbaps/README.md)
make build-mbapsdev               # secure Modbus device sim (cgo); real runs need
                                   # certs/mbaps/ (`make gen-mbaps-certs`, already committed) —
                                   # its own tests mint a throwaway PKI instead, so
                                   # `make test-integration` proves it without any cert-gen step
make build                        # all binaries → bin/
scripts/run-conformance.sh        # full CSIP conformance evidence (layers 1-3)

bin/evsim -csms ws://69.0.0.2:8887/ocpp -api-port 6024   # NOTE: flag is -csms, not -hub
# OCPP Security Profile 2 (TASK-074): ws:// is bench-only; product default is wss://:
bin/evsim -csms wss://69.0.0.2:8887/ocpp -tls-ca certs/ca-cert.pem \
          -auth-user evse-bench -auth-pass <secret> -api-port 6024
make gen-client-cert CN=csip-pi-002
make gen-ev-cert IPS=69.0.0.2    # issue the OCPP CSMS cert (Security Profile 2, TASK-074)
scripts/hub-replay-tune.sh fast|stock   # hub engine/discovery timing for bench replay
bash scripts/bench-up.sh --fast|--stock # bring desktop services up + set hub timing
python3 scripts/mayhem.py --dashboard http://localhost:8080   # run the hostile-QA suite
```

CI: `.github/workflows/ci.yml` — `pure-go` (builds, vet, southbound + QA-harness unit
gate + `go test ./tests/`, all `CGO_ENABLED=0`), `cgo-fast` (cached wolfSSL 5.7.6,
`make test-fast` + cgo binary build), and `proto-pin` (lexa-proto version-pin gate,
TASK-024 — see above) on every PR and push to `main`. Bench-touching suites
(`make test-integration`, `scripts/run-conformance.sh`, `make qa-bench`, anything
on 69.0.0.x) stay desktop/bench-only, out of hosted CI.

## Mayhem hostile-QA
Adversarial HIL fault-injection driving the real bench through 59 worst-case scenarios and
diagnosing where the hub's fault handling breaks. Engine: `cmd/dashboard/mayhem.go` +
`mayhem_world.go` (`/api/qa/*`, dashboard QA tab); headless runner: `scripts/mayhem.py`
(`--list`, `--only id,id`, `--json`, `--extended`). Verdicts: PASS / DEGRADED / FAIL / BLIND / INCONCLUSIVE.
Three scenarios (`netem-loss-export-cap`, `netem-reorder-northbound`, `netem-jitter-evse`,
TASK-052/GAP-11) are the first to fault the actual wire (`tc netem` loss/reorder/delay/
jitter on a bench Pi's real interface over SSH, via `scripts/netem.sh` / the
`netemModifier` helper in `mayhem_world.go`) rather than only the application layer;
INCONCLUSIVE without SSH + passwordless sudo on the target node (guaranteed only on the
hub — BENCH.md).
Two scenarios (`export-dither-at-breach`, `soc-dither-at-reserve`, TASK-054/GAP-08) sit ON
the optimizer's guard thresholds and oscillate ±ε for ~5 min rather than holding/ramping a
fault once — long enough (`mayScenario.Extended`) that a default/full run excludes them
(RSK-12); run them via `--only <id>` or `--extended` in nightly / release-gate campaigns.
**FAST for development campaigns; STOCK via `scripts/mayhem-campaign.sh` for release
gates** — scenario `HoldS`/settle margins are calibrated against FAST latencies
(`bench-up.sh --fast`), so day-to-day campaigns stay in FAST. `scripts/mayhem-campaign.sh
--mode fast|stock --cycles N` mode-manages the hub timing (verifies the switch took over
SSH), runs N cycles with per-cycle JSON evidence under `logs/campaign-<mode>-<ts>/` +
a scenario-drift table, and restores FAST unconditionally on exit (trap, fires even on
Ctrl-C/error) — FAST is the bench's resting state. STOCK campaigns are release gates
(first baseline: GAP-15/TASK-015); triage every non-PASS with
`docs/QA_STOCK_TRIAGE_TEMPLATE.md` — STOCK-only failures are findings, not blockers,
unless they reveal a safety-invariant regression (INV-SOC/INV-CONNECT/INV-EXPORT/
INV-EXPIRED). Findings + fix log: `docs/QA_TRIAGE_20260624.md`, `docs/QA_FINDINGS.md`;
blind-spot review: `docs/QA_GAPS_20260701.md`.
**Scenarios-as-data (TASK-076/077):** `qa/scenarios/*.json` scenario specs
(`cmd/dashboard/scenariospec.go`) compile into the same `mayScenario` the Go
literals in `mayhem.go`/`mayhem_world.go`/`mqtt_scenarios.go` build, but
`-scenario-dir` (default `qa/scenarios`, `main.go`) is re-read fresh on
**every** `POST /api/qa/start` — add or edit a spec file with no `go
build`/dashboard restart, closing the trap that produced the 2026-07-03
stale-`bin/dashboard` incident. Boundary: **oracles are code, scenarios are
data** — the `diagnose*` funcs stay Go, registered by name in
`oracleRegistry`; a spec only selects one + params and supplies
setup/per_tick/teardown steps from a fixed action vocabulary (no
conditionals/loops — a scenario needing real logic stays a Go literal). A
spec ID colliding with a Go scenario's is a load-time error, logged and
skipped, never a silent shadow. `scripts/mayhem.py --list` tags each
scenario `[go]`/`[spec]`. TASK-077 migrated the first 24 scenarios (the
constraint/converge/SOC/disconnect/recovery family plus the transport/
battery-garbage/reboot/expiry family — all straightforwardly-expressible in
the v1 vocabulary) to `qa/scenarios/*.json` and deleted their Go twins; ~35
remain Go literals (malformed-resource delayed-fault family, per-tick
computed-value scenarios like `clock-jitter`/`stale-meter`/`perfect-storm`,
`ev-connector-flap`'s alternating status, all of `mayhem_world.go`/
`mqtt_scenarios.go`, and the `matrix.go` generator) — see
`docs/qa-spec-migration.md` for the full table + retained-in-Go reasons.
See `qa/scenarios/README.md` for the schema.

## Bench replay (hardware-in-the-loop cost sim)
Dashboard "3-Month Cost Sim" tab: synthetic 92-day sweep (browser worker) plus **Bench
Replay** — a server-side driver (`cmd/dashboard/replay.go`, `/api/replay/*`) that injects
the same environment into the real Pi sims, warps gridsim's CSIP clock
(`POST :11112/admin/clock {offset_s|set_unix}` — the hub's TOU windows follow it), issues
real DERControls, and measures cost/compliance from the real meter. Full summer ≈ 20 h at
8 s/tick. Run `hub-replay-tune.sh fast` first, `stock` after; the driver restores the
bench (clock 0, programs cleared, sims 1×) on finish/abort.

## Critical invariants — read before touching crypto, XML, or registers
- **Cipher**: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2` only (CSIP §5.2.1.1). Never change.
- **mTLS**: `wolfssl.RequireClientCert()` in every server setup, or wolfSSL silently accepts anyone.
- **wolfSSL_Init**: process-global C state. Exactly once per process (`TestMain` or `main()`).
- **XML**: every 2030.5 root element needs `xmlns="urn:ieee:std:2030.5:ns"` or unmarshal silently yields zero-value structs.
- **Clock**: `serverNow = time.Now().Unix() + tree.ClockOffset` for every `scheduler.Evaluate()`.
- **Registers**: int16 watt fields wrap at ±32,767 — scale into the SunSpec multiplier, never raw-cast (audit GS-1/MTR-1; regression-swept by TASK-053 — `internal/southbound/sunspecsweep` + `sim/gridsim` `apFromWatts` sweep). When W changes, refresh derived VA/VAR/A registers too (MTR-5).
- **OCPP**: charging sessions are `TransactionEvent` Started/Updated/Ended lifecycles, never bare MeterValues (OCPP-1).
- **Keys**: private keys gitignored (`*-key.pem`). `certs/client-cert.pem` (public) IS tracked.
- **Fetcher**: `WolfSSLFetcher` holds one keep-alive TLS session; never `Free()` mid-walk.
- **Cross-compile**: sims are pure Go (`GOOS=linux GOARCH=arm64`); only conformance/server binaries need cgo wolfSSL.
