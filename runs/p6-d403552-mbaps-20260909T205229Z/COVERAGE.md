# Coverage of the conformance catalog

**Catalog:** `/home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json`  
**sha256:** `eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588`  
**Cases:** 290

This run selected **58** test case(s): 58 applicable to this product, 58 with an implementation, **0 applicable with none**.

> ✓ Every applicable selected test case has an implementation.

## SS-1547-TEST-v1.0 (1.0 (Approved; Revision History: 1.0 / 07-08-2024). MIGRATION (WP7-T8 / REV0907-E9, 2026-09-08): the doc key and uid prefix were re-keyed from 'SS-1547-TEST-v1.1' to 'SS-1547-TEST-v1.0' to match this line. The prior key was a misparse of the file name 'SunSpec-Modbus-for-1547-Test-Procedures-v1_10-8-24-1.pdf' (= v1, 10-8-24) as a v1.1 document; the PDF cover page has always stated Status: Approved, Version: 1.0 — the doc_version text itself was correct, only the doc/uid keys lagged it. See testdata/catalog/uid_aliases.json for the old-to-new uid mapping (ss-1547-test-v1.1::2.4 -> ss-1547-test-v1.0::2.4, ss-1547-test-v1.1::MOD-4 -> ss-1547-test-v1.0::MOD-4); bundles under runs/ minted before this migration carry the old uid verbatim as immutable evidence and are not rewritten.)

2 selected · 2 applicable · 2 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `2.4` | Scale Factor Test | modbus-server | modbus-server | full |
| `MOD-4` | MOD-4 - Mandatory Points | modbus-server | modbus-server | full |

## SS-MODBUS-CONF-v1.4 (v1.4)

16 selected · 16 applicable · 16 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `CRV-1` | Curve 1 Support | modbus-server | modbus-server | manual |
| `DEV-1` | General Discovery | modbus-server | modbus-server | full |
| `DEV-2` | Model 1 Support | modbus-server | modbus-server | full |
| `EXC-1` | Invalid Value | modbus-server | modbus-server | full |
| `EXC-2` | Writing a Read-Only Register | modbus-server | modbus-server | full |
| `EXC-3` | Illegal Function Code | modbus-server | modbus-server | full |
| `MB-1` | Modbus Single/Multiple Register Write | modbus-server | modbus-server | full |
| `MB-2` | Modbus Single Register Read | modbus-server | modbus-server | full |
| `MOD-1` | Model Implementation | modbus-server | modbus-server | full |
| `MOD-2` | Model Read | modbus-server | modbus-server | full |
| `MOD-3` | Point Write | modbus-server | modbus-server | full |
| `REV-1` | Reversion Timeout | modbus-server | modbus-server | full |
| `REV-2` | Reversion Time Update | modbus-server | modbus-server | full |
| `REV-3` | Reversion Cancel | modbus-server | modbus-server | full |
| `TCP-2` | Partial Request | modbus-server | modbus-server | partial |
| `TCP-3` | Multiple TCP Packets | modbus-server | modbus-server | partial |

## SS-TEST-PKI (current)

6 selected · 6 applicable · 6 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `PKI-1` | TLS with digital certificates is mandatory for all CSIP data connections | pki | pki | full |
| `PKI-3` | Separate client and server certificate package types with different intermediate CAs | pki | pki | partial |
| `PKI-8` | Test environment topology: DUT configured with a single certificate chain, framework emulates the peer | pki | pki | full |
| `PKI-11` | Device under test should use the mca-mica-dev certificate chain | pki | pki | partial |
| `PKI-19` | Certificate authority hierarchy: SERCA, MCA, MICA and the three valid device chains | pki | pki | partial |
| `PKI-20` | Error certificates: device certificates on the serca-mica-device chain containing deliberate errors | pki | pki | full |

## SSM-CONF-v0.8 (v0.8-TEST)

34 selected · 34 applicable · 34 implemented · 0 unimplemented · 0 inapplicable

### Implemented

| Case | Title | Suite | Role | Automatable |
|------|-------|-------|------|-------------|
| `CRYP-001` | CRYP-001 - Mandatory TLS v1.2 Cipher Suites [C, S] | ssm | mbaps-server | full |
| `CRYP-002` | CRYP-002 - TLS v1.3 Cipher Suites [C, S] | ssm | mbaps-server | full |
| `CRYP-003` | CRYP-003 - Disable Insecure Ciphers [C, S] | ssm | mbaps-server | full |
| `CRYP-004` | CRYP-004 - ECC Curve and Point Format Support [C, S] | ssm | mbaps-server | full |
| `CRYP-005` | CRYP-005 - Forbidden Hashes and HMAC Compliance [C, S] | ssm | mbaps-server | full |
| `CRYP-006` | CRYP-006 - IANA Registry Compliance [C, S] | ssm | mbaps-server | full |
| `CRYP-007` | CRYP-007 - Encryption-Capable Cipher Selection [C, S] (Negative Test) | ssm | mbaps-server | full |
| `OPS-001` | Cryptographic Export Compliance | ssm | mbaps-server | manual |
| `PKI-001` | PKI-001 - Root Store Capacity [C, S] | ssm | mbaps-server | partial |
| `PKI-002` | PKI-002 - Certificate Management: Add/Remove [C, S] | ssm | mbaps-server | partial |
| `PKI-003` | PKI-003 - Public Network Security [C, S] | ssm | mbaps-server | full |
| `PKI-004` | PKI-004 - Full Chain Delivery [C, S] | ssm | mbaps-server | full |
| `PKI-006` | PKI-006 - Session Resumption and Tickets [C, S] (Optional) | ssm | mbaps-server | full |
| `PKI-007` | PKI-007 - RFC 5280 Certificate Compliance [C, S] | ssm | mbaps-server | full |
| `PKI-008` | PKI-008 - X.509v3 Identity Authentication [C, S] | ssm | mbaps-server | full |
| `PROT-001` | MBAP Integrity | ssm | mbaps-server | full |
| `PROT-002` | Fragment Length Negotiation | ssm | mbaps-server | full |
| `PROT-004` | Renegotiation Indication | ssm | mbaps-server | full |
| `RBAC-001` | Role Extension Extraction | ssm | mbaps-server | full |
| `RBAC-002` | Mandatory Roles Support | ssm | mbaps-server | full |
| `RBAC-004` | Roles-to-Rights Database Audit | ssm | mbaps-server | manual |
| `RBAC-005` | Authorization Algorithm Review | ssm | mbaps-server | manual |
| `RBAC-006` | Role OID Verification | ssm | mbaps-server | full |
| `RBAC-007` | Role Encoding and Singular Role Validation | ssm | mbaps-server | full |
| `RBAC-008` | Missing Role Handling | ssm | mbaps-server | full |
| `RBAC-009` | Information Leakage Prevention | ssm | mbaps-server | full |
| `RBAC-010` | Rules Database Configuration | ssm | mbaps-server | partial |
| `RBAC-012` | Comprehensive Role-to-Rights Consistency Validation | ssm | mbaps-server | full |
| `TLSF-001` | TLS 1.2 Basic Operation [C, S] | ssm | mbaps-server | full |
| `TLSF-002` | TLS 1.3 Basic Operation [C, S] (Optional) | ssm | mbaps-server | full |
| `TLSF-003` | TLS 1.2 Bad Certificate Detection [S] (Negative Test) | ssm | mbaps-server | full |
| `TLSF-004` | Fatal Alert: Missing Certificate [S] (Negative Test) | ssm | mbaps-server | full |
| `TLSF-005` | TLSF-005 - Fatal Alert Persistence [S] (Negative Test) | ssm | mbaps-server | full |
| `TLSF-006` | TLSF-006 - CertificateRequest Verification [S] | ssm | mbaps-server | full |

