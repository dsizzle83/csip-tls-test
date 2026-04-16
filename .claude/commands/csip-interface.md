You are working on the IEEE 2030.5 / CSIP northbound interface. The following rules are non-negotiable. Internalize them before writing any code.

## Hard constraints

**TLS / mTLS**
- Cipher suite: `ECDHE-ECDSA-AES128-CCM-8 TLSv1.2`. CSIP §5.2.1.1. Zero exceptions.
- `wolfssl.RequireClientCert()` must be in every server setup. Without it, wolfSSL accepts anyone.
- One `wolfssl.Init()` per process. It is process-global C state.
- `WolfSSLFetcher` keeps a persistent TLS session. Do not close it between requests in a walk.

**XML**
- Every 2030.5 root element: `xmlns="urn:ieee:std:2030.5:ns"`. Unmarshal silently produces zero-value structs without it — no error, just wrong data.
- Never hardcode resource URLs past `/dcap`. All other URLs come from `href` attributes in responses.

**Identity**
- LFDI = leftmost 160 bits of SHA-256(cert DER). Hex, uppercase, 40 chars.
- SFDI = first 36 bits of SHA-256(cert DER), decimal. Both derived in `internal/csip/identity/`.

**Clock**
- Always: `serverNow = time.Now().Unix() + tree.ClockOffset`
- Pass `serverNow` to every `scheduler.Evaluate()` call. Using `time.Now().Unix()` directly silently breaks event scheduling.

## DER event rules (scheduler)
- `currentStatus == 6` → cancelled, always skip.
- Superseded: `potentiallySuperseded=true` + a later-created event covers the same window → later wins.
- Primacy: program primacy 1 beats 5 beats 10. Lower number = higher priority.
- Default fallback: no active event → use program's `DefaultDERControl`.
- Randomized start: offset applied once per MRID, cached — subsequent calls return same effective time.

## MUP telemetry
1. At startup: `POST /mup` → 201 + Location. Save the path.
2. Per measurement: `POST /mup/{n}` with `MirrorMeterReading` XML → 204.
3. Post on new measurement, not on a timer.

## Test approach
- Unit: `httpclient.Fetcher` + in-process `gridsim` server. `go test ./tests/`.
- Integration (wolfSSL): `go test -tags=integration ./internal/tlsserver/ ./internal/tlsclient/`.
- Never use `InsecureSkipVerify` in non-test code.
