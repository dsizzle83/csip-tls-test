# OCPP 2.0.1 CSMS (ocppserver/)

## Purpose
Central System Management System for EV chargers. Pure Go — intentionally
decoupled from wolfSSL. Do NOT wire wolfSSL here; this uses Go's `crypto/tls`,
not CSIP mTLS.

**Shared module (TASK-022):** this package used to be forked verbatim into
`lexa-hub/internal/ocppserver` (the production CSMS, consumed by `cmd/ocpp` —
the lexa-ocpp service, :8887, which bridges EVState onto MQTT) and
`csip-tls-test/internal/ocppserver` (the bench's copy, embedded in gridsim's
`sim/server` and exercised by `sim/evsim`'s test harness). Both consumers
imported `lexa-proto/ocppserver` directly at the time — there was exactly one
copy. **`lexa-hub` was abandoned 2026-08-03 and archived off-disk; the sole
current consumer is `csip-tls-test`.** `lexa-gw`, the current product, has no
OCPP client or server — its northbound is CSIP-only. WP6-T6 (plan of record)
moves this package out of lexa-proto and into csip-tls-test, its only
remaining consumer; not done yet. Tested end-to-end against `sim/evsim` in
`simulator_test.go`.

## Security Profile 2
TLS over WebSocket + HTTP Basic Auth (credential checked per-connection).
Basic Auth comparison must stay `subtle.ConstantTimeCompare` (audit OCPP-3).

## OCPP-1 invariant — do not violate
Charging sessions are carried by `TransactionEvent` Started/Updated/Ended
lifecycles, never bare MeterValues. Consumers may also observe legacy bare
MeterValues during a transaction (some stations send both), but the
transaction lifecycle itself must always be driven by TransactionEvent, not
inferred from MeterValues alone.

## Handlers
| Handler | Behavior |
|---|---|
| OnGetBaseReport / OnGetReport | provisioning no-ops, status Accepted |
| SetChargingProfile | stores limit_A from first ChargingSchedulePeriod |
| TriggerMessage | re-sends current status for all connectors |

## EVState (exposed via API)
```go
connected   bool
connectors  map[int]string          // connector_id -> status
last_meter  {connector_id, current_A, energy_Wh}
last_profile {connector_id, limit_A}
last_heartbeat string
```
In lexa-hub (abandoned, archived off-disk 2026-08-03), EVState was published
by `cmd/ocpp` to MQTT `lexa/evse/{station}/state`. That MQTT bridge went with
it, and — separately from the lexa-hub abandonment — this `EVState` shape and
the handler table above do not currently exist in `handlers.go`/`server.go`
(only `OnBootNotification`/`OnNotifyReport`/`OnHeartbeat`/
`OnStatusNotification`/`OnTransactionEvent` are implemented today); this
section is stale relative to the code and needs its own follow-up, filed
separately from this pass's lexa-hub cleanup.

## Driving it in tests / on the bench
Port 6024 is **evsim's simapi sidecar** (the charging *station* sim, in
csip-tls-test), not part of this package. To provoke CSMS behaviour, inject
into evsim:
```json
POST http://<ev-pi>:6024/inject
{"status":"Faulted","connector_id":1}        // station sends StatusNotification
{"action":"start_session","connector_id":1}  // station starts a TransactionEvent lifecycle
{"action":"stop_session"}                    // station ends the transaction
```

## Adding new OCPP handlers
Implement the relevant interface method on `csHandler`, register via
`cs.SetXxxHandler()`.
