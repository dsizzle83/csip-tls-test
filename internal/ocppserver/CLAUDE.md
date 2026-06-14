# OCPP 2.0.1 CSMS (internal/ocppserver/)

## Purpose
Central System Management System for EV chargers. Pure Go — intentionally decoupled from wolfSSL. Do NOT wire wolfSSL here; this uses Go's `crypto/tls`, not CSIP mTLS.

**Lockstep**: a copy of this package lives in `lexa-hub/internal/ocppserver` (the production CSMS). Protocol-level changes must land in both copies. Tested end-to-end against `sim/evsim` in `simulator_test.go`.

## Security Profile 2
TLS over WebSocket + HTTP Basic Auth (credential checked per-connection).
Cert pair: `certs/ev-server-cert.pem` / `certs/ev-server-key.pem`.
Configure via `cfg.BasicAuthUser` / `cfg.BasicAuthPass`.

## Implemented message handlers
| Message | Behaviour |
|---------|-----------|
| BootNotification | → Accepted + server time |
| Heartbeat | → CurrentTime |
| StatusNotification | → Accepted; updates connector status map |
| Authorize | → Accepted (no real IdToken check yet) |
| TransactionEvent | Started/Updated/Ended lifecycle — owns session state + energy_Wh (bare MeterValues kept only for backward compat) |
| SetChargingProfile | stores limit_A from first ChargingSchedulePeriod |
| TriggerMessage | re-sends current status for all connectors |

## EVState (exposed via API)
```go
connected   bool
connectors  map[int]string          // connector_id → status
session     {active, connector_id, start_time, energy_Wh}
last_profile {connector_id, limit_A}
last_heartbeat string
```

## Driving it in tests / on the bench
Port 6024 is **evsim's simapi sidecar** (the charging *station* sim), not part of this package.
To provoke CSMS behaviour, inject into evsim:
```json
POST http://<ev-pi>:6024/inject
{"status":"Faulted","connector_id":1}        // station sends StatusNotification
{"action":"start_session","connector_id":1}  // station starts a TransactionEvent lifecycle
{"action":"stop_session"}                    // station ends the transaction
```
Basic Auth comparison must stay `subtle.ConstantTimeCompare` (audit OCPP-3).

## Adding new OCPP handlers
Implement the relevant interface method on `csHandler`, register via `cs.SetXxxHandler()`.
Use the lorenzodonini/ocpp-go type aliases: `ocpp2` package prefix.
Field names follow the library: `IDToken` (not `IdToken`), `ID` on struct embeds, etc.
