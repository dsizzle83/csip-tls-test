---
name: csip-interface
description: Hard protocol rules for IEEE 2030.5 / CSIP work — TLS, XML namespaces, LFDI/SFDI identity, clock offset, DER event scheduling, MUP telemetry. Load before writing or modifying any northbound/gridsim code.
---

# CSIP northbound rules

These are non-negotiable. Internalize before writing code.

## TLS / mTLS
- Cipher suite: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`. CSIP §5.2.1.1. Zero exceptions.
- `wolfssl.RequireClientCert()` must be in every server setup. Without it, wolfSSL accepts anyone.
- One `wolfssl.Init()` per process. It is process-global C state.
- `WolfSSLFetcher` keeps a persistent TLS session. Do not close it between requests in a walk.
- Never use `InsecureSkipVerify` in non-test code.

## XML
- Every 2030.5 root element: `xmlns="urn:ieee:std:2030.5:ns"`. Unmarshal silently produces zero-value structs without it — no error, just wrong data.
- Never hardcode resource URLs past `/dcap`. All other URLs come from `href` attributes in responses.

## Identity
- LFDI = leftmost 160 bits of SHA-256(cert DER). Hex, uppercase, 40 chars.
- SFDI = first 36 bits of SHA-256(cert DER), decimal. Both derived in `internal/csip/identity/`.
- The server must derive peer LFDI from the **verified** cert, never from a client-supplied header (audit S-1).

## Clock
- Always: `serverNow = time.Now().Unix() + tree.ClockOffset`.
- Pass `serverNow` to every `scheduler.Evaluate()` call. Using `time.Now().Unix()` directly silently breaks event scheduling.

## DER event rules (scheduler)
- `currentStatus == 6` → cancelled, always skip.
- Superseded: `potentiallySuperseded=true` + a later-created event covers the same window → later wins.
- Primacy: program primacy 1 beats 5 beats 10. Lower number = higher priority.
- Default fallback: no active event → use program's `DefaultDERControl`.
- Randomized start: offset applied once per MRID, cached — subsequent calls return same effective time.
- Server-side (gridsim admin): create future events as Scheduled(0), not Active(1); mirror into `actderc` only when the window is open (GS-2).

## MUP telemetry
1. At startup: `POST /mup` → 201 + Location. Save the path.
2. Per measurement: `POST /mup/{n}` with `MirrorMeterReading` XML → 204.
3. Post on new measurement, not on a timer.

## Test approach
- Unit/logic: `httpclient.Fetcher` + in-process gridsim. `go test ./tests/`.
- Integration (wolfSSL): `make test-integration` (covers `internal/tlsclient` + `sim/tlsserver`).
- Full evidence run: `scripts/run-conformance.sh` (see the `conformance` skill).
