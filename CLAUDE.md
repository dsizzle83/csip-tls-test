# CSIP Simulation & Conformance Harness

## What this repo is

This is the **conformance/QA harness and independent referee for `lexa-gw`** —
the single-inverter SunSpec Modbus/TCP DER gateway (`~/projects/lexa-gw`,
separate repo, separate sessions), an IEEE 2030.5-2018/CSIP DER client and
optional Secure SunSpec Modbus (`mbaps`) server. **`lexa-hub` (a multi-device
DERMS hub product this repo used to test) was abandoned 2026-08-03 and
archived off-disk; `lexa-gw` is the only product any doc here should name.**

The live referee is:

- `cmd/certify` — drives the published SunSpec/CSIP conformance test
  procedures from `testdata/catalog/catalog.json` and emits a third-party
  verifiable **evidence bundle** (packet capture + machine-checkable frame
  citations). See `docs/CONFORMANCE_TOOL.md`.
- `cmd/gw-campaign` — the continuous adversary: seeded concurrent fault
  injection against the gateway (or hermetic loopback), judged against ten
  invariants, with automatic shrink-to-minimal-reproducer and its own evidence
  bundle.
- `sim/gridsim` — the IEEE 2030.5 / CSIP grid server simulator (northbound,
  wolfSSL mTLS) that plays the utility head-end the gateway talks to.
- `sim/modsim` — a plain SunSpec Modbus/TCP inverter simulator (southbound
  target for the gateway's own poller).
- `sim/mbapsdev` — a Secure SunSpec Modbus (mbaps) **device** simulator (cgo,
  `internal/mbtls`), the southbound target for the gateway when it speaks
  Secure Modbus to its DER.
- `internal/evidence/*`, `internal/invariant`, `internal/aggregator`,
  `internal/mbtls`, `internal/wolfssl` — the evidence engine, invariant
  judges, the bench's own northbound mbaps client, and the crypto/TLS glue
  those all sit on.

`Makefile`'s `CERTIFY_LIVE_SET` is the authoritative package list for this —
`make live-set-print` derives it fresh from `go list -deps` over
`./cmd/certify ./cmd/gw-campaign`, `make live-set-committed` prints the
committed list, and `make live-set-check` (`scripts/check-live-set.sh`) fails
the moment they drift. CI's `pure-go`, `cgo-fast` and `referee` jobs are wired
to exactly this set.

## Referee independence

The referee must never share an implementation with the product under test —
a bug the two share is a bug neither side can catch (PN-1 / C9 / AD-003(f)).
Two independence axes matter here:

- **Crypto/TLS**: this repo's stack is **wolfSSL** (`internal/wolfssl`,
  `internal/mbtls`, `internal/tlsclient`) end to end. `lexa-gw`'s cgo packages
  link **Mbed TLS 4.1 + TF-PSA-Crypto** instead (its
  `docs/BUILD_ENVIRONMENT.md`). Different TLS stacks on each side of the wire
  is deliberate — a handshake or cipher-negotiation bug shared by both
  implementations is exactly the class of bug a same-stack referee would be
  blind to.
- **Register/model semantics**: the referee's SunSpec/Modbus checks
  (`internal/certify/suitemodbusserver`, `suitemodbusclient`, `suitessm`)
  currently share `lexa-proto/{mbap,modbus,sunspec}` wire-format code with the
  product, because the wire format is the wire format — but a golden,
  independently-sourced table of point offsets and scale factors is landing as
  `internal/certify/sunspecgolden` (WP4-T5: hand-transcribed from an
  independently fetched upstream `sunspec/models` copy, asserted against the
  `lexa-proto` layouts in `make test-certify`), closing the gap where both
  sides currently trust the same generated layout.
- `internal/certify/suitecsip` is its own independent CSIP client-side
  implementation — it does **not** depend on `internal/csipref` (the old
  hub-era walker below), which is exactly what keeps a scheduler/discovery bug
  from hiding behind a shared client.

Only `lexa-proto/{mbap,modbus,sunspec,csipmodel}` (wire format) is
intentionally shared with the product; everything that judges behavior is
independent.

## Build environment

`GOWORK=off GOFLAGS=-mod=vendor` for every command that has to resolve exactly
what the shipped binaries resolve to (`make live-set-print`, CI, any
comparison against the committed `CERTIFY_LIVE_SET`) — a developer's untracked
local `go.work` (`go work init . ../lexa-proto`, gitignored, never committed;
still the normal way to develop against a live `lexa-proto` checkout) must not
change which packages a shipped binary sees. `proto.pin` / `platform.pin` +
committed `vendor/` trees pin `lexa-proto` and `lexa-platform` at fixed
commits (`scripts/check-proto-pin.sh` CI-gates the `lexa-proto` half); version
bumps ship as paired PRs, same session, per `lexa-gw`'s own convention.
`internal/wolfssl`/`internal/mbtls`/cgo binaries need `WOLFSSL_SYSROOT` (see
the Makefile header) — a **different, keylog-capable** sysroot
(`WOLFSSL_KEYLOG_SYSROOT`, `-tags keylog`) builds the evidence-grade binaries
that export TLS session secrets for a certification campaign; see
`docs/CONFORMANCE_TOOL.md` §2.

## Bench & ports

Live topology, IPs, SSH users, service models, and the WAN/LAN split
evidence-capture posture: **read `docs/BENCH.md`** before any deploy/SSH work
— it is current for the referee's own bench rig even where its top section
still documents the retired flat hub demo bench.

Quick port map for the parts that are the referee (desktop, `69.0.0.20` /
WiFi `wlp2s0` for the WAN/LAN split posture):
- `gridsim` (northbound CSIP simulator): mTLS `:11111` / admin `:11112` on the
  flat bench; `:11113` / `:11114` (bound to the desktop's WiFi address) under
  the WAN/LAN split evidence-capture posture (`docs/BENCH.md` "WAN/LAN split
  bench" section) — different ports, different purpose from the flat bench.
- `modsim` (southbound plain SunSpec Modbus/TCP inverter sim): `:5020` /
  simapi `:6020`.
- `mbapsdev` (southbound Secure Modbus device sim, cgo wolfSSL): `:8021` /
  simapi `:6031`.
- The gateway itself is not this repo's bench node — its dev-kit IP, mbaps
  listener, and WAN/LAN addresses are `lexa-gw`'s own bench facts
  (`GW_HOST`, `-gateway-ssh`), tracked in `docs/BENCH.md`'s split-bench
  section and `lexa-gw/docs/BENCH_WANLAN_SPLIT_SOAK_2026-08-10.md`.

## Gating campaigns

A **campaign** (`-campaign csip|mbaps|modbus-client`) is a named, closed
selection whose DUT precondition is proven before case 1 — the only bundle
shape allowed to gate anything. Everything else (`-suite`/`-doc`/`-uid`, a
whole-catalog sweep) is **exploratory** and marked `NOT GATING`. Rules that
apply only to a gating run (`docs/CONFORMANCE_TOOL.md` §2-4,
`docs/CAMPAIGNS.md`):

- **No weakening switches.** `-require-citation=false` and `-skip-preflight`
  are refused outright on a gating campaign (honored, and recorded in
  `bundle.json`'s `campaign.weakened`, only on an exploratory run). A dirty
  worktree (`-allow-dirty`) forces a bundle to `NOT GATING` regardless of
  `-campaign` — a bundle may never claim both gating and weakened.
- **`-dut-build`** records the DUT's build identity as part of the
  precondition; `preflight_provenance.go`'s `verifyDUTBuild` is fatal on a
  gating run if it cannot be read against a stated claim.
- **Signed, always.** A gating campaign refuses to run with no `-sign-key` —
  an unsigned `MANIFEST.sha256` has no legitimate disclosed shape as
  certification evidence. `-verify -pubkey <pub>` is how a third party checks
  the signature; a hash-only `-verify` (no `-pubkey`) is internal consistency
  only and says so as `Unsigned: true`.
- The three campaigns are disjoint (no catalog row belongs to two), which
  `internal/certify/suites/campaign_test.go` pins against the linked suites.

## Hub-era surface — NOT part of the referee (quarantine pending WP7-T9b)

These packages exist because this repo used to be the test bench for the
abandoned `lexa-hub` multi-device DERMS product. They are not in
`CERTIFY_LIVE_SET`, are not exercised by `cmd/certify`/`cmd/gw-campaign`, and
are slated for quarantine (a build tag or removal) under WP7-T9b. Do not build
new gateway-referee features on them, and do not describe them as part of the
conformance story:

- `cmd/dashboard` — the hub demo/QA web UI (Mayhem hostile-QA engine, Bench
  Replay, what-if cost API).
- `internal/tariff`, `internal/whatif`, `internal/scenariodata` — the hub's
  cost-simulation stack.
- `sim/evsim` + OCPP (`lorenzodonini/ocpp-go`, `lexa-proto/ocppserver`) — the
  EV charger simulator; `lexa-gw` has no OCPP surface.
- `sim/batsim`, `sim/metersim` — battery/meter device sims for the hub's
  multi-device southbound fan-out; `lexa-gw` serves one inverter, no separate
  battery/meter southbound target.
- `internal/csipref` (discovery walker + DER event scheduler) — the hub-era
  CSIP client library; superseded, for referee purposes, by
  `internal/certify/suitecsip`'s own independent implementation.
- `tests/` — the pre-`cmd/certify` integration test suite this package
  predates.

## Stack

Go 1.26 · wolfSSL cgo (`internal/wolfssl` only) · `simonvetter/modbus`

## Directory map (live referee)

```
sim/gridsim/            IEEE 2030.5 server simulator library (+ admin API)
sim/tlsserver/          wolfSSL mTLS server library (pins ECDHE-ECDSA-AES128-CCM-8)
sim/server/             mTLS gridsim binary (desktop, cgo)
sim/modsim/             Plain SunSpec Modbus/TCP inverter sim binary
sim/mbapsdev/           Secure Modbus (mbaps) DEVICE sim: internal/mbtls server +
                        lexa-proto/mbap dispatch over sim/southbound's animated
                        register world. Southbound TARGET for the lexa-gw
                        gateway to poll over Secure SunSpec Modbus. cgo.
sim/southbound/         In-memory Modbus device models (no hardware)
sim/simapi/             REST + WS + SSE /logs sidecar for the sims above
sim/aggregator/         Interactive REPL over internal/aggregator
sim/gw-mayhem/          Gateway hostile-QA runner (gwloopback) driving the
                        mbaps-northbound-authz family + qa/gw-scenarios specs
cmd/certify/            The conformance evidence tool CLI: modes, flags, exit
                        codes, keylog shims
cmd/gw-campaign/        The continuous-adversary CLI: wiring only
cmd/gw-mayhem/          Gateway hostile-QA runner binary
internal/certify/       The framework — catalog, registry, runner, frame
                        attribution, evidence citation, coverage report
internal/certify/suites/          links all suites; the loopback acceptance test
internal/certify/report/          SS-CSIP-RESULTS-v1.1 + SS-MODBUS-RESULTS-v1.2
                                   and the submission generator
internal/certify/suitecsip/       CSIP-CONF-v1.3 (independent CSIP client)
internal/certify/suitemodbusclient/  SS-MODBUS-CLIENT-CONF-v1.1
internal/certify/suitemodbusserver/  SS-MODBUS-CONF-v1.4 + SS-1547-TEST-v1.0
internal/certify/suitepki/        SS-TEST-PKI
internal/certify/suitessm/        SSM-CONF-v0.8 (Secure SunSpec Modbus)
internal/certify/sunspecgolden/   (landing, WP4-T5) independent register golden
internal/campaign/      gw-campaign's fault-layer engine
internal/invariant/     gw-campaign's I1-I10 judges
internal/aggregator/    SunSpec Modbus aggregator emulator: a northbound mbaps
                        CLIENT that plays the utility/VPP driving the gateway's
                        :802 server. cgo.
internal/mbtls/         Secure SunSpec Modbus (mbaps) wolfSSL glue: client (Dial)
                        + server (Listen/Accept), independent role extraction —
                        DELIBERATELY not lexa-platform/securemodbus (PN-1/C9).
internal/evidence/      the evidence engine: capture, pcapng, dissection, TLS
                        dissection/decryption, bundles (pure Go)
internal/writeset/      -writes: what the gateway actually wrote
internal/mbapref/       independent mbap-frame reference decode
internal/tlsprobe/      real wolfSSL handshake probes
testdata/catalog/catalog.json  the specification: 285 extracted test cases
docs/CONFORMANCE_TOOL.md   how the tool works, coverage, evidence, verification
docs/CAMPAIGNS.md          gating vs exploratory, the three campaigns
docs/BENCH.md               live bench topology (mixed: flat hub-demo history +
                             current WAN/LAN split evidence posture)
```

## Commands

```bash
make test-fast                       # unit tests, no network (<1 s) — run after every change
make test-certify                    # referee live set (nocgo half)
CGO_ENABLED=0 go build -o bin/certify ./cmd/certify
bin/certify -list                    # coverage table + every gap by name; exits 1 on regression
bin/certify -list -details           # every one of the 285 cases, with its status
scripts/run-conformance.sh           # CSIP logic + wolfSSL TLS suite + full stack
make build-gw-campaign               # cgo
bin/gw-campaign -loopback -pki certs/mbaps          # hermetic, no bench
```

CI: `pure-go` (build/vet/southbound + `go test ./tests/`, `CGO_ENABLED=0`),
`cgo-fast` (cached wolfSSL, `make test-fast` + `make test-certify` cgo half +
cgo binary build), `referee` (nocgo half of `make test-certify`),
`vulncheck` (`govulncheck`, pinned reachable-findings gate), `proto-pin`
(`lexa-proto`/`lexa-platform` pin-lockstep gate against `lexa-gw`). Bench/
network-touching suites stay desktop/bench-only, out of hosted CI.

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
