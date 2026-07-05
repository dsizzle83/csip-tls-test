# CSIP Simulation & Conformance Harness

## What this repo is
The **test bench** for the LEXA DERMS hub. The product itself lives in
`~/projects/lexa-hub` (separate repo, separate sessions). This repo provides:

- IEEE 2030.5 / CSIP grid server simulator (wolfSSL mTLS) + admin API
- SunSpec Modbus device sims: solar, battery, bi-directional meter
- OCPP 2.0.1 EV charger sim (`evsim`) + CSMS copy for tests
- CSIP + Modbus conformance suites
- Web dashboard (`cmd/dashboard`, :8080) — the demo/test UI

**Lockstep rule:** `internal/southbound/sunspec` register maps and `internal/ocppserver`
are duplicated in lexa-hub and must change in both repos together (audit MTR-4). Deploy
hub + sims in the same session. Enforced by `scripts/ci/lockstep-check.sh` in
csip-tls-test CI (TASK-004) — report-only until Phase 1 replaces the duplication with a
shared module (AD-003/TASK-024).

## Stack
Go 1.26 · wolfSSL cgo (`internal/wolfssl` only) · lorenzodonini/ocpp-go · simonvetter/modbus · grandcat/zeroconf

## Directory map
```
sim/gridsim/            IEEE 2030.5 server simulator library (+ admin API on :11112)
sim/tlsserver/          wolfSSL mTLS server library (pins ECDHE-ECDSA-AES128-CCM-8)
sim/server/             mTLS gridsim binary (desktop, cgo)
sim/{modsim,batsim,metersim,evsim}/   Device sim binaries
sim/southbound/         In-memory Modbus device models (no hardware)
sim/simapi/             REST + WS + SSE /logs sidecar for every sim
sim/conformance/        CSIP conformance runner (Pi, cgo)
sim/modsim-conformance/ Modbus conformance runner (-device inverter|battery|meter)
cmd/dashboard/          Go proxy + embedded SPA (KPIs, scenarios, logs, register tables);
                        also hosts the Mayhem hostile-QA engine (mayhem.go, /api/qa/*) and
                        the Bench Replay driver (replay.go, /api/replay/*)
internal/csip/          2030.5 model, walker, scheduler, identity, DNS-SD
internal/tlsclient/     wolfSSL mTLS client (persistent keep-alive fetcher)
internal/southbound/    Modbus/SunSpec stack (mirrored in lexa-hub — lockstep!)
internal/ocppserver/    OCPP 2.0.1 CSMS library (pure Go; copy exists in lexa-hub)
tests/                  Conformance + integration test suites
docs/                   HARNESS_REVIEW.md (audit findings), BENCH.md (live bench), pcaps
```

## Bench & ports
Live topology, IPs, SSH users, service models: **read `docs/BENCH.md`** before any deploy/SSH work.
Quick port map: gridsim 11111/11112 + dashboard 8080 (desktop 69.0.0.20) ·
modsim 5020/6020 (.10) · batsim 5021/6021 (.11) · metersim 5022/6022 (.12) ·
evsim simapi 6024 (.14) · hub: lexa-api 9100, OCPP CSMS 8887 (69.0.0.1).
Pattern: Modbus port / simapi port. simapi: `GET /state`, `POST /inject`, `POST /control`, `GET /logs` (SSE).

## Commands
```bash
make test-fast                    # unit tests, no network (<1 s) — run after every change
go test ./tests/                  # 2030.5 discovery + MUP + conformance logic
go test ./internal/southbound/... # Modbus/SunSpec unit tests
make test-integration             # wolfSSL mTLS handshake tests (amd64 sysroot on desktop)
make build                        # all binaries → bin/
scripts/run-conformance.sh        # full CSIP conformance evidence (layers 1-3)

bin/evsim -csms ws://69.0.0.1:8887/ocpp -api-port 6024   # NOTE: flag is -csms, not -hub
make gen-client-cert CN=csip-pi-002
scripts/hub-replay-tune.sh fast|stock   # hub engine/discovery timing for bench replay
bash scripts/bench-up.sh --fast|--stock # bring desktop services up + set hub timing
python3 scripts/mayhem.py --dashboard http://localhost:8080   # run the hostile-QA suite
```

CI: `.github/workflows/ci.yml` — `pure-go` (builds, vet, southbound + QA-harness unit
gate + `go test ./tests/`, all `CGO_ENABLED=0`) and `cgo-fast` (cached wolfSSL 5.7.6,
`make test-fast` + cgo binary build) on every PR and push to `main`. Bench-touching
suites (`make test-integration`, `scripts/run-conformance.sh`, `make qa-bench`, anything
on 69.0.0.x) stay desktop/bench-only, out of hosted CI.

## Mayhem hostile-QA
Adversarial HIL fault-injection driving the real bench through 51 worst-case scenarios and
diagnosing where the hub's fault handling breaks. Engine: `cmd/dashboard/mayhem.go` +
`mayhem_world.go` (`/api/qa/*`, dashboard QA tab); headless runner: `scripts/mayhem.py`
(`--list`, `--only id,id`, `--json`). Verdicts: PASS / DEGRADED / FAIL / BLIND / INCONCLUSIVE.
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
- **Registers**: int16 watt fields wrap at ±32,767 — scale into the SunSpec multiplier, never raw-cast (audit GS-1/MTR-1). When W changes, refresh derived VA/VAR/A registers too (MTR-5).
- **OCPP**: charging sessions are `TransactionEvent` Started/Updated/Ended lifecycles, never bare MeterValues (OCPP-1).
- **Keys**: private keys gitignored (`*-key.pem`). `certs/client-cert.pem` (public) IS tracked.
- **Fetcher**: `WolfSSLFetcher` holds one keep-alive TLS session; never `Free()` mid-walk.
- **Cross-compile**: sims are pure Go (`GOOS=linux GOARCH=arm64`); only conformance/server binaries need cgo wolfSSL.
