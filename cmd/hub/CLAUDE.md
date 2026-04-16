# Hub Binary (cmd/hub/)

## Purpose
Long-running CSIP DER hub for Raspberry Pi. Wires northbound CSIP discovery ↔ southbound Modbus devices. Config: `hub.json` (see `hub-example.json`).

## Goroutine architecture
```
discoveryLoop   re-walks /dcap every pollRate s; updates bridge.SetPrograms + ClockOffset;
                drives response POST state machine (Received → Started → Completed)
telemetryLoop   registers one MUP per device × measurement at startup;
                consumes registry.Updates() → POST /mup/{n}
bridge          evaluates scheduler every 15 s; calls registry.ApplyControl
registry        polls Modbus every 10 s; emits MeasurementUpdates
```

## Response POST state machine (GEN.044 / CORE-022)
Tracked in `responseState map[MRID]int` inside hub main.

| State | When |
|-------|------|
| Received (1) | Event first seen in DERControlList (even before start time) |
| Started (2) | Scheduler first makes event active |
| Completed (3) | Event expires or is superseded |

## Device roles in hub.json
```json
{"role":"solar",   "url":"tcp://192.168.10.10:502"}  → inverter.New (M103/121/123)
{"role":"battery", "url":"tcp://192.168.10.11:502"}  → battery.New  (M103/802)
{"role":"meter",   "url":"tcp://192.168.10.12:502"}  → meter.New    (M201)
{"role":"load",    "url":"tcp://192.168.10.13:502"}  → meter.New    (M201, consume-only)
```

## Critical: clock offset
```go
// ALWAYS pass serverNow, not time.Now().Unix()
serverNow := time.Now().Unix() + tree.ClockOffset
active := sched.Evaluate(tree.Programs, serverNow)
```
Missing the offset causes events to fire at the wrong wall-clock time.

## Bridge package (internal/bridge/)
The ONLY package that imports both `csip/` and `southbound/`. All cross-protocol decisions live there.
`bridge.SetPrograms(programs)` called from discoveryLoop after each successful walk.
`bridge.Start()` / `bridge.Stop()` control the 15 s control tick goroutine.
