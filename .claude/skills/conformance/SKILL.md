---
name: conformance
description: Run and interpret the CSIP / Modbus / meter conformance suites, and update CONFORMANCE_REPORT.md. Use for "run conformance", "prove compliance", or before demos/releases.
---

# Conformance runs

The EUT is the DER **client** (the hub northbound). Evidence layers:

## 1. CSIP logic + TLS (desktop, one command)
```bash
scripts/run-conformance.sh             # layers 1-3: logic suite, wolfSSL TLS suite, full stack
scripts/run-conformance.sh --capture   # + live pcap proving cipher 0xC0AE on the wire (needs dumpcap perms)
```
Layer 1 = `go test ./tests/` (COMM-002, CORE-*, BASIC-*, ERR-001) — pure Go, fastest to iterate.

## 2. Modbus/SunSpec device conformance (against live sims)
```bash
go build -o bin/modsim-conformance ./sim/modsim-conformance
bin/modsim-conformance -server 69.0.0.10:5020 -device inverter
bin/modsim-conformance -server 69.0.0.11:5021 -device battery
bin/modsim-conformance -server 69.0.0.12:5022 -device meter      # MTR-001..006, 9 checks
```
Local loop: start the sim on localhost first (`bin/modsim -port 5020 -api-port 6020`).

## 3. Pi-side full-stack (only when asked — needs the bench)
`make conformance-pi`, `make modbus-conformance-pi` (SSH to bench, cgo wolfSSL on the Pi).

## Interpreting results
- Each check prints `PASS/FAIL <ID>`. On FAIL, quote the check ID, expected vs got, and the
  register/resource involved — these IDs map to SunSpec CSIP Test Procedures v1.3.
- A meter FAIL on derived registers (VA/VAR/A vs W) is usually MTR-5 class: derived values
  not refreshed on power update.
- Record outcomes in `CONFORMANCE_REPORT.md` (root) using its existing format and date the entry.
