# Coverage of the conformance catalog

**Catalog:** `/home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json`  
**sha256:** `eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588`  
**Cases:** 290

This run selected **59** test case(s): 59 applicable to this product, 59 with an implementation, **0 applicable with none**.

> ✓ Every applicable selected test case has an implementation.

## CSIP-CONF-v1.3 (V1.3)

51 selected · 51 applicable · 51 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `BASIC-001` | DER Identification [C, A, S] | csip | csip-client | full |
| `BASIC-002` | Basic Group Management [C, A, S] | csip | csip-client | full |
| `BASIC-003` | Advanced Group Management [C, A, S] | csip | csip-client | full |
| `BASIC-004` | Basic Inverter Control (Low/High Voltage Ride-Through) [C, A, S] | csip | csip-client | full |
| `BASIC-005` | Basic Inverter Control (Low/High Frequency Ride-Through) [C, A, S] | csip | csip-client | full |
| `BASIC-006` | Basic Inverter Control (Volt/Var) [C, A, S] | csip | csip-client | full |
| `BASIC-007` | Basic Inverter Control (Ramp Rates) [C, A, S] | csip | csip-client | partial |
| `BASIC-008` | Basic Inverter Control (Fixed Power Factor) [C, A, S] | csip | csip-client | full |
| `BASIC-009` | Basic Inverter Control (Connect/Disconnect) [C, A, S] | csip | csip-client | partial |
| `BASIC-010` | Basic Inverter Control (Limit Max Active Power Mode) [C, A, S] | csip | csip-client | full |
| `BASIC-011` | Basic Inverter Control (Volt-Watt) [C, A, S] | csip | csip-client | full |
| `BASIC-012` | Basic Inverter Control (Frequency Droop/Frequency-Watt) [C, A, S] | csip | csip-client | full |
| `BASIC-013` | BASIC-013 - Basic Inverter Control (Set Active Power Mode - in % of Max Power) | csip | csip-client | full |
| `BASIC-014` | BASIC-014 - Basic Inverter Control (Set Active Power Mode – in Watts) | csip | csip-client | full |
| `BASIC-015` | BASIC-015 – Advanced Inverter Control [C, A, S] | csip | csip-client | full |
| `BASIC-016` | BASIC-016 - Event - 2 DERP, 2 DDERC, 0 DERC [C, A, S] | csip | csip-client | full |
| `BASIC-017` | BASIC-017 - Event - 1 DERP, 0 DDERC, 1 DERC [C, A, S] | csip | csip-client | full |
| `BASIC-018` | BASIC-018 - Event - 1 DERP, 1 DDERC, 1 DERC [C, A, S] | csip | csip-client | full |
| `BASIC-019` | BASIC-019 - Event - 1 DERP, 1 DDERC, 2 Non-overlapping Similar DERC [C, A, S] | csip | csip-client | full |
| `BASIC-020` | BASIC-020 - Event - 2 DERP, 2 DDERC, 2 Non-overlapping Similar DERC [C, A, S] | csip | csip-client | full |
| `BASIC-021` | Event - 2 DERP, 2 DDERC, 2 Overlapping Similar DERC - System DERC followed by Service Point DERC before Start of System DERC [C, A, S] | csip | csip-client | full |
| `BASIC-022` | Event - 2 DERP, 2 DDERC, 2 Overlapping Similar DERC - Service Point DERC followed by System DERC [C, A, S] | csip | csip-client | full |
| `BASIC-023` | Event - 2 DERP, 2 DDERC, 2 Overlapping Similar DERC - System DERC followed by Service Point DERC after Start of System Event [C, A, S] | csip | csip-client | full |
| `BASIC-024` | Event - 2 DERP, 2 DDERC, 2 Overlapping Independent DERC - System DERC followed by Service Point DERC before Start of System DERC [C, A, S] | csip | csip-client | full |
| `BASIC-025` | Event - 2 DERP, 2 DDERC, 2 Overlapping Independent DERC - Service Point DERC followed by System DERC [C, A, S] | csip | csip-client | full |
| `BASIC-026` | Event - 2 DERP, 2 DDERC, 2 Overlapping Independent DERC - System DERC followed by Service Point DERC after Start of System Event [C, A, S] | csip | csip-client | full |
| `BASIC-027` | Alarms [C, A, S] | csip | csip-client | full |
| `BASIC-028` | Inverter Status [C, A, S] | csip | csip-client | full |
| `BASIC-029` | Inverter Meter Reading [C, A, S] | csip | csip-client | full |
| `COMM-002` | Basic Discovery (Out-of-Band) [C, A, S] | csip | csip-client | full |
| `COMM-003` | Basic Security [C,A,S] | csip | csip-client | full |
| `COMM-004` | Advanced Security [C, A, S] | csip | csip-client | full |
| `COMM-004A` | Advanced Security — Certificate chain length two: SERCA -> Device Certificate | csip | csip-client | full |
| `COMM-004B` | Advanced Security — Certificate chain length three: SERCA->MICA->Device Certificate | csip | csip-client | full |
| `COMM-004C` | Advanced Security — Certificate chain length four: SERCA->MCA->MICA->Device Certificate | csip | csip-client | full |
| `COMM-004D` | Advanced Security — Invalid MICA Extended Key Critical value | csip | csip-client | full |
| `COMM-004E` | Advanced Security — Invalid MICA Name Non-Critical Value | csip | csip-client | full |
| `COMM-004F` | Advanced Security — Invalid MICA Policy Mapping Non-Critical value | csip | csip-client | full |
| `COMM-004G` | Advanced Security — Self-signed device certificate | csip | csip-client | full |
| `CORE-003` | Polling Interaction [C, A] | csip | csip-client | full |
| `CORE-005` | Basic Time [C, A, S] | csip | csip-client | full |
| `CORE-009` | Advanced End Device | csip | csip-client | full |
| `CORE-010` | Function Set Assignments | csip | csip-client | full |
| `CORE-011` | Advanced Function Set Assignments | csip | csip-client | full |
| `CORE-012` | Basic DER Program/Control | csip | csip-client | full |
| `CORE-013` | Advanced DER Program/Control | csip | csip-client | full |
| `CORE-014` | Basic DER Settings (Power Generating) | csip | csip-client | full |
| `CORE-021` | Randomized Events [C, A, S] | csip | csip-client | full |
| `CORE-022` | Responses [C, A, S] | csip | csip-client | full |
| `CORE-023` | Superseding Events [C, A, S] | csip | csip-client | full |
| `ERR-001` | Error Scenario 1 [C, A] | csip | csip-client | full |

## LOCAL-EXT-v1 (v1 (local extension family; not a published specification))

8 selected · 8 applicable · 8 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `EXT-001` | EXT-001 - opModWattVar curve execution against SunSpec model 712 | csip | csip-client | full |
| `EXT-002` | EXT-002 - a RESERVED EventStatus.currentStatus value must not be treated as Cancelled | csip | csip-client | full |
| `EXT-003` | EXT-003 - a Cancelled-with-Randomization event is not withdrawn before its end randomization | csip | csip-client | full |
| `EXT-004` | EXT-004 - an already-expired-at-receipt event is rejected (254), never received or started | csip | csip-client | full |
| `EXT-005` | EXT-005 - envelope refusal: an mbaps WMaxLimPct write above the CSIP envelope draws exception 03; within it, it is acked | csip | csip-client | full |
| `EXT-006` | EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default | csip | csip-client | full |
| `EXT-007` | EXT-007 - fail-safe engaged: an mbaps ceiling write above zero export is admitted (the documented override); 703 ES=1 stays refused | csip | csip-client | full |
| `EXT-008` | EXT-008 - envelope tightening / ownership take: a standing mbaps WSet stands, CSIP taking the axis drops it, release restores the device default | csip | csip-client | full |

