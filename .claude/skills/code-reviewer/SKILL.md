---
name: code-reviewer
description: Review the recently changed code in this repo against CSIP/SunSpec/OCPP protocol invariants and known bug classes from the 2026-06 audit. Use before commits and when asked to review.
---

# Code reviewer

Read the diff, then check against these rules. Report only real issues — no style nits on unchanged code.

## Blockers (must fix before merge)
- [ ] wolfSSL cipher changed from `ECDHE-ECDSA-AES128-CCM-8`.
- [ ] `wolfssl.RequireClientCert()` removed or bypassed.
- [ ] XML root element missing `xmlns="urn:ieee:std:2030.5:ns"` on a new 2030.5 resource.
- [ ] `wolfssl.Init()` called more than once per process.
- [ ] `WolfSSLFetcher.Free()` called during a discovery walk.
- [ ] `scheduler.Evaluate()` called with `time.Now().Unix()` instead of `time.Now().Unix() + ClockOffset`.
- [ ] New cgo import outside `internal/wolfssl/`.
- [ ] Private key written or logged anywhere.
- [ ] Watt/register value raw-cast to int16/uint16 instead of scaled into the SunSpec multiplier (audit GS-1, MTR-1 — both shipped as real bugs).
- [ ] `internal/southbound/sunspec` register-map constants changed without the matching lexa-hub change (MTR-4: a lone change misreads real hardware).
- [ ] Charging session modeled as bare `MeterValues` instead of `TransactionEvent` Started/Updated/Ended (OCPP-1).
- [ ] Map or slice shared with another goroutine read/written without the lock (OCPP-5, MOD-3 — suggest `go test -race`).
- [ ] Basic Auth or token compare that isn't `subtle.ConstantTimeCompare`.

## Warnings (should fix)
- [ ] SunSpec scale factor 0x8000 not mapped to NaN.
- [ ] W updated without refreshing derived VA/VAR/A registers (MTR-5).
- [ ] Inject endpoint accepts out-of-range values silently — wrap/overflow instead of 400 (MOD-4).
- [ ] Error silenced with `_` on Modbus I/O, wolfSSL I/O, or XML unmarshal.
- [ ] Goroutine started without a stop mechanism.
- [ ] `time.Sleep` in non-test code.
- [ ] Simulator inject key doesn't match the corresponding `Snapshot()` field name.
- [ ] New exported identifier without a doc comment.
- [ ] Admin/gridsim event created with a status contradicting its window (future event marked Active — GS-2).

## Suggestions (optional)
- Consistency with adjacent code style.
- Test coverage for new error paths.

## Output format
`BLOCKER|WARNING|SUGGESTION  file:line  description` — one per line.
If nothing found: "No issues found."
