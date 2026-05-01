# CSIP DER Hub

## What this system does
DERMS hub for IEEE 2030.5 / CSIP compliance. Bridges utility grid management (northbound, wolfSSL mTLS) to DER assets — solar PV, battery storage, bi-directional smart meter, EVSE (southbound, Modbus/SunSpec + OCPP 2.0.1). Target hardware: Raspberry Pi (dev) / NXP i.MX 93 (prod).

## Stack
Go 1.21 · wolfSSL cgo (one package) · lorenzodonini/ocpp-go · simonvetter/modbus · grandcat/zeroconf · customtkinter (Python GUI)

## Directory map

### Product code (the hub device)
```
cmd/hub/               Long-running Pi hub binary — the product
internal/csip/         2030.5 model, discovery walker, scheduler, identity, DNS-SD
internal/tlsclient/    wolfSSL mTLS client — persistent keep-alive fetcher
internal/wolfssl/      ONLY cgo package. wolfSSL_Init is process-global.
internal/southbound/   Modbus/SunSpec: device, inverter, battery, meter, registry
internal/bridge/       CSIP ↔ southbound glue (imports both sides; nothing else should)
internal/ocppserver/   OCPP 2.0.1 CSMS (Security Profile 2, pure Go — no wolfSSL)
internal/orchestrator/ Control optimizer + cost models + device adapters
```

### Simulation code (not part of the product)
```
sim/server/            mTLS gridsim server (WSL-side, for conformance testing)
sim/client/            CSIP TLS client smoke test (Pi-side)
sim/conformance/       Full CSIP conformance test suite (Pi-side)
sim/{modsim,batsim,metersim,evsim}/          Device simulator binaries
sim/modsim-client/     Modbus diagnostic client
sim/httpsim/           Plain-HTTP gridsim (no mTLS, dev only)
sim/orchestrator/      Example orchestrator wiring
sim/gridsim/           IEEE 2030.5 server simulator library
sim/tlsserver/         wolfSSL mTLS server library (test harness only)
sim/simapi/            REST + WebSocket API wrapper for simulator binaries
sim/southbound/        In-memory Modbus device simulators (no hardware required)

gui/sim_gui.py         CustomTkinter live dashboard for all simulators
```

## Commands
```bash
make test-fast                            # unit tests, no network (< 1 s)
make test-integration                     # wolfSSL mTLS handshake tests
go test ./tests/                          # 2030.5 discovery + MUP integration
go test ./internal/southbound/...         # Modbus/SunSpec unit tests
make build                                # all binaries → bin/

# Start simulators (each on own Pi, or localhost):
bin/modsim   -port 5020 -api-port 6020   # solar PV
bin/batsim   -port 5021 -api-port 6021   # battery
bin/metersim -port 5022 -api-port 6022   # bi-directional smart meter
bin/evsim    -hub 69.0.0.1:8887 -api-port 6024      # EVSE

# Python GUI (on desktop, not Pi):
cd gui && pip install -r requirements.txt
python sim_gui.py --solar 69.0.0.10 --battery 69.0.0.11 --meter 69.0.0.12 ...

make gen-client-cert CN=csip-pi-002      # issue new client cert
```

## Critical invariants — read before touching crypto or XML
- **Cipher**: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2` only (CSIP §5.2.1.1). Never change.
- **mTLS**: `wolfssl.RequireClientCert()` enforces client auth. Without it wolfSSL silently accepts unauthenticated clients.
- **XML namespace**: every 2030.5 root element needs `xmlns="urn:ieee:std:2030.5:ns"` or the walker fails to unmarshal.
- **wolfSSL_Init**: process-global C state. Call exactly once via `wolfssl.Init()` in `TestMain` or `main()`.
- **Keys**: private keys are gitignored (`*-key.pem`). `certs/client-cert.pem` (public, no key) IS tracked.
- **Cross-compile**: wolfSSL headers are arm64-only on Pi. Build cgo on Pi; push from WSL2 and `git pull` on Pi.
- **Fetcher**: `WolfSSLFetcher` holds one keep-alive TLS session. It auto-redials on error; never call `Free()` mid-walk.
