# CSIP DER Hub

## What this system does
DERMS hub for IEEE 2030.5 / CSIP compliance. Bridges utility grid management (northbound, wolfSSL mTLS) to DER assets — solar PV, battery storage, grid meter, home load, EVSE (southbound, Modbus/SunSpec + OCPP 2.0.1). Target hardware: Raspberry Pi (dev) / NXP i.MX 93 (prod).

## Stack
Go 1.21 · wolfSSL cgo (one package) · lorenzodonini/ocpp-go · simonvetter/modbus · grandcat/zeroconf · customtkinter (Python GUI)

## Directory map
```
internal/csip/         2030.5 model, discovery walker, scheduler, identity, DNS-SD
internal/tlsclient/    wolfSSL mTLS client — persistent keep-alive fetcher
internal/tlsserver/    wolfSSL mTLS server — multi-request loop, dispatchHTTP bridge
internal/wolfssl/      ONLY cgo package. wolfSSL_Init is process-global.
internal/southbound/   Modbus/SunSpec: device, inverter, battery, meter, registry, sim
internal/bridge/       CSIP ↔ southbound glue (imports both sides; nothing else should)
internal/gridsim/      IEEE 2030.5 HTTP server simulator (pure Go, net/http)
internal/ocppserver/   OCPP 2.0.1 CSMS (Security Profile 2, pure Go — no wolfSSL)
cmd/hub/               Long-running Pi hub binary
cmd/{modsim,batsim,metersim,loadsim,evsim}/  Simulator binaries
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
bin/metersim -port 5022 -api-port 6022   # grid meter
bin/loadsim  -port 5023 -api-port 6023   # home load
bin/evsim    -hub 192.168.10.1:8887 -api-port 6024  # EVSE

# Python GUI (on desktop, not Pi):
cd gui && pip install -r requirements.txt
python sim_gui.py --solar 192.168.10.10 --battery 192.168.10.11 ...

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
