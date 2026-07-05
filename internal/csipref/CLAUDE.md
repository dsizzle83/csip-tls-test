# CSIP client referee — walker + scheduler (internal/csipref)

## What this is, and why it is NOT `internal/csip`
This package holds this repo's own, independently-written implementation of the CSIP
client-side resource walk and DER event evaluation — moved out of `internal/csip` in
TASK-082 (2026-07-05) and given its own top-level package specifically so its independence
is impossible to miss.

**It must never be synced, unified, or bug-for-bug matched with lexa-hub's own product
walker/scheduler.** Its entire conformance value is that `sim/conformance`, `sim/client`,
`sim/client-http`, and `tests/*` exercise the real hub through a *second, separately-written*
reading of the IEEE 2030.5 / CSIP spec. If this walker ever silently converged on the same
misreading the product's own client-facing logic has, no test here would catch it — that's
the "self-confirmation" hazard (architecture review §9). See
`docs/refactor/02_ARCHITECTURE_DECISIONS.md` AD-003(f) for the full decision record
(option chosen: keep-as-referee, over extracting a shared walker).

## Packages
```
discovery/  Link walker starting at /dcap. Follows href attributes — never hardcodes URLs past /dcap.
scheduler/  DER event state machine (cancelled, superseded, randomized-start, primacy, default fallback).
```

## Fetcher interface
`discovery.Fetcher`: `Get(path) ([]byte, error)` only. Keeps discovery decoupled from TLS.
- `WolfSSLFetcher` (`internal/tlsclient/`): persistent TLS session, sync.Mutex, auto-redial on error.
- `httpclient.Fetcher`: net/http, used in gridsim integration tests (`go test ./tests/`).

## Walker traversal order
`/dcap` → Time (→ ClockOffset) → EndDeviceList (find self by LFDI) → DERList → FSAList → DERPrograms → DERControlList + DefaultDERControl → MUPList

**ClockOffset**: `serverNow = time.Now().Unix() + tree.ClockOffset`. Required — CSIP §5.2.1.3 requires client within 30 s of server. Pass `serverNow` to every `scheduler.Evaluate()` call.

## Scheduler priority rules
1. `currentStatus=6` (cancelled) → always skip.
2. `potentiallySuperseded=true` + later event covers same window + later `creationTime` → later wins.
3. Randomized start: apply rand offset to startTime once per MRID; cache result.
4. Primacy: lower number wins (program primacy 1 beats 5 beats 10).
5. Default fallback: no active event in highest-priority program → use `DefaultDERControl`.

## MirrorUsagePoint telemetry flow
1. `POST /mup` → 201 + Location header (e.g. `/mup/0`). Save location.
2. `POST /mup/{n}` with `MirrorMeterReading` XML → 204. Post per measurement update.
MUP XML must include `xmlns="urn:ieee:std:2030.5:ns"` on root element.

## Consumers
`sim/conformance/main.go` (CSIP conformance runner), `sim/client/main.go` + `sim/client-http/main.go`
(reference clients), `tests/csip_conformance_test.go` + `tests/integration_test.go` +
`tests/wolfssl_integration_test.go`, `internal/tlsclient/fetcher_test.go`. None of these are
product (lexa-hub) code — this package has zero lexa-hub consumers, by design.
