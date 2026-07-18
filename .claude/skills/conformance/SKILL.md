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

## 3. Secure SunSpec Modbus (mbaps) — 62-requirement suite (desktop, cgo)
The `sim/ssm-conformance` walker checks all 62 SunSpecTCP requirements
(SunSpecTCP-1..62) against an mbaps gateway. It is the bench's INDEPENDENT mbaps
referee (its own `internal/mbtls` client + role parser, never the product's
`securemodbus` — PN-1/C9), so a profile/authz bug in the gateway can't hide.

```bash
make ssm-conformance                       # loopback self-test: mints a throwaway PKI,
                                           # stands up an in-process authz-enforcing mbaps
                                           # server, runs all 62 — zero bench access, zero churn
make ssm-conformance TARGET="-target 69.0.0.2:802 -pki certs/mbaps"   # vs the LIVE gateway
# client-direction rows (TCP-12/27/28/43/44/61) additionally vs a device sim:
make ssm-conformance TARGET="-target 69.0.0.2:802 -pki certs/mbaps -device-target 69.0.0.20:8021"
# emit the CONFORMANCE_REPORT.md section:
bin/ssm-conformance -target 69.0.0.2:802 -pki certs/mbaps -md /tmp/ssm-section.md
```
Live runs need `make gen-mbaps-certs` first (role-cert + negative-fixture keys; the
loopback self-test mints its own and needs none). It is Layer 5 of
`run-conformance.sh` (loopback by default; `SSM_TARGET=host:802` for the live gateway).

Reading the 62-row output:
- Each row prints `PASS/FAIL/SKIP <SunSpecTCP-N> — <evidence>`; the binary exits non-zero
  if any row FAILs or is unaddressed. It ends with a tally and, crucially, flags any row
  that printed NOT ADDRESSED (a suite bug).
- `SKIP` rows are addressed-but-not-wire-assertable (server-config / project-policy: e.g.
  TCP-3 cert-manager, TCP-23/24/25/33-37 rules-DB meta, TCP-49/50/58, verified in lexa-gw).
  Their evidence names the reason. A SKIP is not a failure.
- The rows that print PASS against the LIVE gateway are the ones to flip `impl`→`verified`
  in `docs/requirements/secure-sunspec-modbus-traceability.md` (lexa-gw).
- Emit the dated section with `-md`, then append it to `CONFORMANCE_REPORT.md` (root).

## 4. Pi-side full-stack (only when asked — needs the bench)
`make conformance-pi`, `make modbus-conformance-pi` (SSH to bench, cgo wolfSSL on the Pi).

## Interpreting results
- Each check prints `PASS/FAIL <ID>`. On FAIL, quote the check ID, expected vs got, and the
  register/resource involved — these IDs map to SunSpec CSIP Test Procedures v1.3 (CSIP /
  Modbus) or Secure SunSpec Modbus v1.0 (the SunSpecTCP-N rows).
- A meter FAIL on derived registers (VA/VAR/A vs W) is usually MTR-5 class: derived values
  not refreshed on power update.
- Record outcomes in `CONFORMANCE_REPORT.md` (root) using its existing format and date the entry.
