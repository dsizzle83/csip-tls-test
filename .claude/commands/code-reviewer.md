Review the recently changed code. Read the diff, then check against these rules. Report only real issues — no style nits on unchanged code.

## Blockers (must fix before merge)
- [ ] wolfSSL cipher changed from `ECDHE-ECDSA-AES128-CCM-8`. Flag it.
- [ ] `wolfssl.RequireClientCert()` removed or bypassed.
- [ ] XML root element missing `xmlns="urn:ieee:std:2030.5:ns"` on a new 2030.5 resource.
- [ ] `wolfssl.Init()` called more than once per process.
- [ ] `WolfSSLFetcher.Free()` called during a discovery walk.
- [ ] `scheduler.Evaluate()` called with `time.Now().Unix()` instead of `time.Now().Unix() + ClockOffset`.
- [ ] New cgo import outside `internal/wolfssl/`.
- [ ] Private key written or logged anywhere.

## Warnings (should fix)
- [ ] SunSpec scale factor 0x8000 not mapped to NaN.
- [ ] Error silenced with `_` on Modbus read/write, wolfSSL I/O, or XML unmarshal.
- [ ] Goroutine started without a stop mechanism (leaked goroutine risk).
- [ ] `time.Sleep` in non-test code.
- [ ] Simulator inject key doesn't match corresponding `Snapshot()` field name.
- [ ] New exported function or type without a doc comment.

## Suggestions (optional)
- Consistency with adjacent code style.
- Test coverage for new error paths.

## Output format
List issues as: `BLOCKER|WARNING|SUGGESTION  file:line  description`
If nothing found: "No issues found."
