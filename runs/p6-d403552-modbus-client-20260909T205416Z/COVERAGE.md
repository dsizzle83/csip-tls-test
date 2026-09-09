# Coverage of the conformance catalog

**Catalog:** `/home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json`  
**sha256:** `eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588`  
**Cases:** 290

This run selected **15** test case(s): 15 applicable to this product, 15 with an implementation, **0 applicable with none**.

> ✓ Every applicable selected test case has an implementation.

## SS-MODBUS-CLIENT-CONF-v1.1 (v1.1)

15 selected · 15 applicable · 15 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `CLI-1` | General Discovery for SunSpec Servers at Different IPv4 Addresses | modbus-client | modbus-client | full |
| `CLI-2` | General Discovery for SunSpec Servers at Different Ports | modbus-client | modbus-client | full |
| `CLI-3` | General Discovery for SunSpec Servers with Different Unit IDs | modbus-client | modbus-client | full |
| `CLI-4` | General Discovery for SunSpec Servers with Different Starting Register Values | modbus-client | modbus-client | full |
| `ERR-1` | Noncompliant Server | modbus-client | modbus-client | partial |
| `ERR-2` | Exception Tests | modbus-client | modbus-client | partial |
| `ERR-3` | Unknown Model ID Test | modbus-client | modbus-client | partial |
| `INFO-1` | SunSpec Type Interpretations | modbus-client | modbus-client | partial |
| `INFO-2` | Unimplemented Point Interpretations | modbus-client | modbus-client | partial |
| `PROT-1` | Partial Response | modbus-client | modbus-client | partial |
| `PROT-2` | TCP Segmentation (Only for Modbus TCP Clients) | modbus-client | modbus-client | partial |
| `READ-1` | Single Point Reads | modbus-client | modbus-client | partial |
| `READ-2` | Multiple Point Reads | modbus-client | modbus-client | full |
| `WR-1` | Write Single Point | modbus-client | modbus-client | partial |
| `WR-2` | Write Multiple Points | modbus-client | modbus-client | partial |

## Not applicable to this candidate

1 row(s) were NOT RUN because they are out of scope for the candidate under test. This is not an evidence gap and not a skip: there is nothing here to measure. Each row names the declaration that decided it, so a reader who disputes a scope decision knows whose document to take it up with.

| Case | Declared by | Reason |
|------|-------------|--------|
| `ss-modbus-client-conf-v1.1::WR-1` | manifest | this row requires the candidate to have claimed FC 6 for modbus_client.write_function_codes, and the candidate's manifest does not: it declares FC 16 |

