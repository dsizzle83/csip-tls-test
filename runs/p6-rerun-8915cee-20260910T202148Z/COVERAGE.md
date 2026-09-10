# Coverage of the conformance catalog

**Catalog:** `/home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json`  
**sha256:** `eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588`  
**Cases:** 290

This run selected **5** test case(s): 5 applicable to this product, 5 with an implementation, **0 applicable with none**.

> ✓ Every applicable selected test case has an implementation.

## CSIP-CONF-v1.3 (V1.3)

2 selected · 2 applicable · 2 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `BASIC-009` | Basic Inverter Control (Connect/Disconnect) [C, A, S] | csip | csip-client | partial |
| `CORE-022` | Responses [C, A, S] | csip | csip-client | full |

## LOCAL-EXT-v1 (v1 (local extension family; not a published specification))

3 selected · 3 applicable · 3 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `EXT-005` | EXT-005 - envelope refusal: an mbaps WMaxLimPct write above the CSIP envelope draws exception 03; within it, it is acked | csip | csip-client | full |
| `EXT-006` | EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default | csip | csip-client | full |
| `EXT-008` | EXT-008 - envelope tightening / ownership take: a standing mbaps WSet stands, CSIP taking the axis drops it, release restores the device default | csip | csip-client | full |

