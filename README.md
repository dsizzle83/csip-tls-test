# CSIP Simulation & Conformance Harness

The **test bench** for the LEXA DERMS hub. The hub product itself — the IEEE 2030.5 /
CSIP DERMS implementation that connects northbound to a utility grid management server
over wolfSSL mTLS and controls DER assets southbound over Modbus/SunSpec and OCPP 2.0.1 —
lives in `~/projects/lexa-hub` (separate repo). This repo provides the CSIP grid server
simulator, the SunSpec device simulators, the OCPP EV charger simulator, the conformance
suites, and the web dashboard used to demo and test the hub.

Target hardware for the hub: Raspberry Pi 4/5 (development), NXP i.MX 93 (production).

## Architecture

```
Utility Grid Server (IEEE 2030.5)          ← this repo: sim/gridsim
        │  wolfSSL mTLS (ECDHE-ECDSA-AES128-CCM-8 / TLS 1.2)
        ▼
   [ Hub Pi — lexa-hub ]                   ← ~/projects/lexa-hub
        │
        ├── Modbus TCP ──► Solar inverter   (SunSpec M103/121/123)  ← sim/modsim
        ├── Modbus TCP ──► Battery storage  (SunSpec M103/802)      ← sim/batsim
        ├── Modbus TCP ──► Smart meter      (SunSpec M201, bi-directional) ← sim/metersim
        └── OCPP 2.0.1 ◄── EV charger       (station connects inbound)     ← sim/evsim
```

Home load is inferred from the energy balance — no separate load meter needed:
```
load_W = solar_W + battery_W - meter_W
```

## The Hub (product repo)

Hub configuration, build, run, and systemd-service instructions live in
`~/projects/lexa-hub`'s own README. That repo also owns `hub-example.json`,
the device-role config schema, and the `onCSIPControl`/orchestrator logic.
Pushing hub code: `lexa-hub`'s `scripts/deploy-hub-pi.sh` (see below).

## Certificates

mTLS (grid server ↔ hub, and this repo's conformance clients) requires three files:

| File                    | Purpose                                   |
|-------------------------|-------------------------------------------|
| `certs/ca-cert.pem`     | CA that signed the server cert            |
| `certs/client-cert.pem` | Client identity (tracked in git)          |
| `certs/client-key.pem`  | Private key (gitignored — copy manually)  |

Issue a new client certificate:

```bash
make gen-client-cert CN=csip-pi-002
```

## Demo Network Layout

All Pis connect via Ethernet to a dedicated switch on `69.0.0.x/24`. WiFi is a separate subnet used for internet access only.

| Hostname   | IP        | Binary   | Port        |
|------------|-----------|----------|-------------|
| hub-pi     | 69.0.0.1  | hub      | 8887 (OCPP) |
| solar-pi   | 69.0.0.10 | modsim   | 5020        |
| battery-pi | 69.0.0.11 | batsim   | 5021        |
| meter-pi   | 69.0.0.12 | metersim | 5022        |
| ev-pi      | 69.0.0.14 | evsim    | → hub:8887  |

## Simulator Setup & Deployment

Live topology, ports, and deploy commands: `docs/BENCH.md`. Bringing the whole
demo up (or recovering it post-reboot): the `run-demo` skill
(`.claude/skills/run-demo/SKILL.md`). Pushing hub code: `lexa-hub`'s
`scripts/deploy-hub-pi.sh`; pushing sim code: `scripts/update-sim-pis.sh`.

## Development

```bash
make test-fast                      # unit tests, no network
make test-integration               # wolfSSL mTLS handshake tests
go test ./tests/                    # 2030.5 discovery + MUP integration
go test ./internal/southbound/...   # Modbus/SunSpec unit tests
make build                          # server + client binaries → bin/
```
