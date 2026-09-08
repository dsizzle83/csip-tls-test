# CSIP Simulation & Conformance Harness

The **conformance/QA harness and independent referee for `lexa-gw`** — a
single-inverter SunSpec Modbus/TCP DER gateway (`~/projects/lexa-gw`,
separate repo) that is an IEEE 2030.5-2018/CSIP DER client and, optionally, a
Secure SunSpec Modbus (`mbaps`) server. This repo provides the CSIP grid
server simulator, the SunSpec device simulators the gateway polls
southbound, and `cmd/certify`/`cmd/gw-campaign` — the tools that drive the
published conformance procedures and the continuous fault-injection adversary
against it and emit third-party-verifiable evidence.

`lexa-hub` — an earlier, multi-device DERMS hub product this repo used to
test — was **abandoned 2026-08-03 and archived off-disk**. `lexa-gw` is the
only product; see `CLAUDE.md` for the full picture, including the packages
left over from the hub era that are not part of the referee and are slated
for quarantine (WP7-T9b).

Target hardware for `lexa-gw`: NXP i.MX 93 (production); see `lexa-gw`'s own
README for its build/flash/deploy instructions — this repo does not own them.

## Architecture

```
Utility Grid Server (IEEE 2030.5)          ← this repo: sim/gridsim
        │  wolfSSL mTLS (ECDHE-ECDSA-AES128-CCM-8 / TLS 1.2)
        ▼
   [ lexa-gw gateway ]                     ← ~/projects/lexa-gw
        │
        └── Modbus TCP ──► SunSpec inverter (Model 1/103/120-123/701-712)
                            ← sim/modsim (plain) or sim/mbapsdev (Secure Modbus)
```

`lexa-gw` is a single-inverter gateway (unit 1) — there is no separate
battery/meter/EV southbound fan-out to simulate; `sim/batsim`, `sim/metersim`
and `sim/evsim` are hub-era leftovers (see CLAUDE.md's "Hub-era surface").

## Certificates

mTLS (grid server ↔ gateway, and this repo's conformance clients) requires
three files:

| File                    | Purpose                                   |
|-------------------------|-------------------------------------------|
| `certs/ca-cert.pem`     | CA that signed the server cert            |
| `certs/client-cert.pem` | Client identity (tracked in git)          |
| `certs/client-key.pem`  | Private key (gitignored — copy manually)  |

Issue a new client certificate:

```bash
make gen-client-cert CN=csip-pi-002
```

`certs/mbaps/` is the separate Secure SunSpec Modbus PKI (`make
gen-mbaps-certs`) — role certs + device cert + a negative-fixture matrix; see
`certs/mbaps/README.md`.

## Bench & simulator setup

Live topology, ports, and deploy commands: `docs/BENCH.md` (read it before
any deploy/SSH work — its top section documents the retired flat hub-demo
bench, its "WAN/LAN split bench" section is the current evidence-capture
posture). `CLAUDE.md`'s "Bench & ports" section is the quick-reference for the
parts of that topology that are actually the referee.

## Development

```bash
make test-fast                      # unit tests, no network
make test-certify                   # referee live set (nocgo half)
make test-integration               # wolfSSL mTLS handshake tests
make build                          # server + client binaries → bin/
CGO_ENABLED=0 go build -o bin/certify ./cmd/certify && bin/certify -list
```

See `docs/CONFORMANCE_TOOL.md` for how `cmd/certify` works — coverage,
evidence bundles, and third-party verification — and `docs/CAMPAIGNS.md` for
gating vs. exploratory runs and the three certification campaigns.
