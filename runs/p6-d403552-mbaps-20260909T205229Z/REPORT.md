# Conformance evidence bundle

**Device under test:** lexa-gw at `192.168.0.69:802`

| | |
|---|---|
| Tool | csip-certify eb2c71acf25f |
| Source commit | 045ba8fd234a6e82b6162402ac2a4d817f9a0db0 |
| Operator | lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09 |
| Host | dmitri-HP-ENVY-TE01-1xxx |
| Started | 2026-09-09T20:52:29Z |
| Finished | 2026-09-09T20:53:08Z |
| DUT build | d403552 |
| Capture | `capture/run-20260909-205230.pcapng` — 6648 packets, 1176488 bytes, pcapng |
| Capture tool | dumpcap Dumpcap (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). |
| Interface | wlp2s0 |
| Capture hygiene | 6648 frame(s) captured; no filter was requested, so every frame the tool wrote is in this bundle |
| Key log | capture/bench-shared.keylog |

> **This bundle contains TLS session secrets.** `capture/bench-shared.keylog` is an NSS key log for the
> capture above: anyone holding this directory can decrypt every session it
> records. It is included on purpose — the application-layer citations below
> cannot be re-derived without it — and it is covered by the manifest, so it
> cannot be quietly dropped either. Treat the bundle as sensitive: share it
> with an assessor, not publicly. The secrets are per-session and grant no
> lasting access to the device.

> catalog: /home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json (290 cases, 1626330 bytes, sha256:eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588); frame attribution: 6648 frames: 5010 attributed to 58 test case(s), 1638 unattributed (background), 0 contested; per-test captures required by the governing document's Reporting Requirements: 33 of 34 written into capture/. NOT WRITTEN: rbac_010.pcap (ssm-conf-v0.8::RBAC-010): NOT WRITTEN — no capture frame is attributed to ssm-conf-v0.8::RBAC-010, so the file would be empty and would claim a session that is not in this run; provenance: DUT build reported fw=1.0.0 build_id=d403552b1056 image_build_id=d403552b1056 image_profile=image

Capture tool output:

```
Capturing on 'wlp2s0'
File: runs/p6-d403552-mbaps-20260909T205229Z/capture/run-20260909-205230.pcapng
Packets captured: 6648
Packets received/dropped on interface 'wlp2s0': 6648/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

## How this run was invoked

```
certify-keylog -campaign mbaps -manifest /home/dmitri/projects/lexa-gw/configs/candidate.json -target 192.168.0.69:802 -pki certs/mbaps -gridsim 192.168.0.188:11113 -gridsim-admin http://192.168.0.188:11114 -modsim 69.0.0.20:5020 -modsim-api http://69.0.0.20:6020 -mbapsdev-api http://69.0.0.20:6031 -gateway-ssh cc93 -metrics-endpoint http://127.0.0.1:9102/metrics -keylog /tmp/bench-shared.keylog -operator 'lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09' -dut-name lexa-gw -dut-build d403552 -iface wlp2s0 -timeout 8m -sign-key '[redacted]' -out runs/p6-d403552-mbaps-20260909T205229Z -v
```

Credential-shaped flag values are replaced with `[redacted]`; every other argument is verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of this table.

The capture itself:

```
/usr/bin/dumpcap -i wlp2s0 -w runs/p6-d403552-mbaps-20260909T205229Z/capture/run-20260909-205230.pcapng -q -p
```

## Result

**41 PASS · 1 FAIL · 3 SKIP · 13 WARN** across 58 in-scope test case(s).

✗ 1 test case(s) FAILED.

| Case | Title | Claim | Verdict | Assertions | Frames |
|------|-------|-------|---------|-----------:|--------|
| ss-1547-test-v1.0::MOD-4 | MOD-4 - Mandatory Points | yes | PASS | 16 | 24–81 |
| ss-1547-test-v1.0::2.4 | Scale Factor Test | yes | PASS | 4 | 105–254 |
| ss-modbus-conf-v1.4::DEV-1 | General Discovery | yes | PASS | 5 | 287–352 |
| ss-modbus-conf-v1.4::DEV-2 | Model 1 Support | yes | PASS | 4 | 378–427 |
| ss-modbus-conf-v1.4::MOD-1 | Model Implementation | yes | PASS | 25 | 459–1030 |
| ss-modbus-conf-v1.4::MOD-2 | Model Read | yes | PASS | 14 | 1055–1136 |
| ss-modbus-conf-v1.4::MB-2 | Modbus Single Register Read | yes | PASS | 3 | 1168–1236 |
| ss-modbus-conf-v1.4::CRV-1 | Curve 1 Support | yes | PASS | 14 | 1264–1324 |
| ss-modbus-conf-v1.4::EXC-3 | Illegal Function Code | yes | PASS | 2 | 1356–1411 |
| ss-modbus-conf-v1.4::EXC-2 | Writing a Read-Only Register | yes | PASS | 2 | 1436–1507 |
| ss-modbus-conf-v1.4::EXC-1 | Invalid Value | yes | PASS | 4 | 1550–1616 |
| ss-modbus-conf-v1.4::MB-1 | Modbus Single/Multiple Register Write | yes | PASS | 3 | 1647–1713 |
| ss-modbus-conf-v1.4::MOD-3 | Point Write | yes | PASS | 5 | 1743–1884 |
| ss-modbus-conf-v1.4::TCP-3 | Multiple TCP Packets | yes | PASS | 3 | 1910–1960 |
| ss-modbus-conf-v1.4::TCP-2 | Partial Request | yes | PASS | 4 | 1996–2218 |
| ss-modbus-conf-v1.4::REV-1 | Reversion Timeout | yes | SKIP | 5 | 2251–2306 |
| ss-modbus-conf-v1.4::REV-2 | Reversion Time Update | yes | SKIP | 4 | 2331–2376 |
| ss-modbus-conf-v1.4::REV-3 | Reversion Cancel | yes | SKIP | 4 | 2408–2456 |
| ss-test-pki::PKI-1 | TLS with digital certificates is mandatory for all CSIP data connections | yes | PASS | 5 | 2466–2481 |
| ss-test-pki::PKI-8 | Test environment topology: DUT configured with a single certificate chain, framework emulates the peer | yes | PASS | 5 | 2492–2578 |
| ss-test-pki::PKI-11 | Device under test should use the mca-mica-dev certificate chain | yes | PASS | 2 | 2584 |
| ss-test-pki::PKI-19 | Certificate authority hierarchy: SERCA, MCA, MICA and the three valid device chains | yes | WARN | 6 | 2601–2720 |
| ss-test-pki::PKI-3 | Separate client and server certificate package types with different intermediate CAs | yes | PASS | 2 | 2713–2758 |
| ss-test-pki::PKI-20 | Error certificates: device certificates on the serca-mica-device chain containing deliberate errors | yes | PASS | 7 | 2753–2854 |
| ssm-conf-v0.8::TLSF-001 | TLS 1.2 Basic Operation [C, S] | yes | PASS | 9 | 2853–3038 |
| ssm-conf-v0.8::TLSF-002 | TLS 1.3 Basic Operation [C, S] (Optional) | yes | PASS | 7 | 3047–3137 |
| ssm-conf-v0.8::TLSF-003 | TLS 1.2 Bad Certificate Detection [S] (Negative Test) | yes | PASS | 9 | 3188–3256 |
| ssm-conf-v0.8::TLSF-004 | Fatal Alert: Missing Certificate [S] (Negative Test) | yes | PASS | 3 | 3263–3277 |
| ssm-conf-v0.8::TLSF-005 | TLSF-005 - Fatal Alert Persistence [S] (Negative Test) | yes | PASS | 2 | 3346–3365 |
| ssm-conf-v0.8::TLSF-006 | TLSF-006 - CertificateRequest Verification [S] | yes | PASS | 4 | 3393–3480 |
| ssm-conf-v0.8::CRYP-001 | CRYP-001 - Mandatory TLS v1.2 Cipher Suites [C, S] | yes | FAIL | 10 | 3488–3540 |
| ssm-conf-v0.8::CRYP-002 | CRYP-002 - TLS v1.3 Cipher Suites [C, S] | yes | PASS | 9 | 3597–3967 |
| ssm-conf-v0.8::CRYP-003 | CRYP-003 - Disable Insecure Ciphers [C, S] | yes | WARN | 3 | 3978–3990 |
| ssm-conf-v0.8::CRYP-004 | CRYP-004 - ECC Curve and Point Format Support [C, S] | yes | WARN | 4 | 4019–4049 |
| ssm-conf-v0.8::CRYP-005 | CRYP-005 - Forbidden Hashes and HMAC Compliance [C, S] | yes | PASS | 3 | 4066–4078 |
| ssm-conf-v0.8::CRYP-006 | CRYP-006 - IANA Registry Compliance [C, S] | yes | WARN | 3 | 4097 |
| ssm-conf-v0.8::CRYP-007 | CRYP-007 - Encryption-Capable Cipher Selection [C, S] (Negative Test) | yes | PASS | 3 | 4118–4129 |
| ssm-conf-v0.8::PKI-001 | PKI-001 - Root Store Capacity [C, S] | yes | WARN | 3 | 4149–4298 |
| ssm-conf-v0.8::PKI-002 | PKI-002 - Certificate Management: Add/Remove [C, S] | yes | WARN | 3 | 4202 |
| ssm-conf-v0.8::PKI-003 | PKI-003 - Public Network Security [C, S] | yes | PASS | 3 | 4376–4399 |
| ssm-conf-v0.8::PKI-004 | PKI-004 - Full Chain Delivery [C, S] | yes | PASS | 3 | 4453 |
| ssm-conf-v0.8::PKI-006 | PKI-006 - Session Resumption and Tickets [C, S] (Optional) | yes | PASS | 2 | 4472–4544 |
| ssm-conf-v0.8::PKI-007 | PKI-007 - RFC 5280 Certificate Compliance [C, S] | yes | PASS | 2 | 4566–4578 |
| ssm-conf-v0.8::PKI-008 | PKI-008 - X.509v3 Identity Authentication [C, S] | yes | PASS | 4 | 4630–4688 |
| ssm-conf-v0.8::PROT-001 | MBAP Integrity | yes | PASS | 2 | 4694–4758 |
| ssm-conf-v0.8::PROT-002 | Fragment Length Negotiation | yes | WARN | 4 | 4767–4786 |
| ssm-conf-v0.8::PROT-004 | Renegotiation Indication | yes | WARN | 3 | 4808 |
| ssm-conf-v0.8::RBAC-001 | Role Extension Extraction | yes | PASS | 3 | 4837–4880 |
| ssm-conf-v0.8::RBAC-002 | Mandatory Roles Support | yes | PASS | 8 | 4907–5149 |
| ssm-conf-v0.8::RBAC-004 | Roles-to-Rights Database Audit | yes | PASS | 1 | — |
| ssm-conf-v0.8::RBAC-005 | Authorization Algorithm Review | yes | WARN | 2 | 5263 |
| ssm-conf-v0.8::RBAC-006 | Role OID Verification | yes | PASS | 5 | 5287–5382 |
| ssm-conf-v0.8::RBAC-007 | Role Encoding and Singular Role Validation | yes | WARN | 6 | 5397–5470 |
| ssm-conf-v0.8::RBAC-008 | Missing Role Handling | yes | PASS | 3 | 5484–5523 |
| ssm-conf-v0.8::RBAC-009 | Information Leakage Prevention | yes | PASS | 1 | 5593 |
| ssm-conf-v0.8::RBAC-010 | Rules Database Configuration | yes | WARN | 2 | — |
| ssm-conf-v0.8::RBAC-012 | Comprehensive Role-to-Rights Consistency Validation | yes | WARN | 9 | 5623–6098 |
| ssm-conf-v0.8::OPS-001 | Cryptographic Export Compliance | yes | WARN | 3 | 6152–6173 |

## Verifying this bundle

This directory is self-checking. Independent checks, in the order a sceptical reader
would run them:

1. `sha256sum -c MANIFEST.sha256` — every file, the capture included, is covered.
2. The evidence verifier re-reads `capture/run-20260909-205230.pcapng` and confirms that every cited frame
   exists and carries the exact bytes each assertion claims. It reads only this
   directory and needs nothing from the bench that produced it.
3. Every case verdict in the table above is re-derived from that case's own printed
   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is
   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be
   edited away from, the evidence underneath it.

Assertions marked *(no digest)* below carry no re-checkable citation: they are
narrative, not proof.

## Test cases

### ✓ ss-1547-test-v1.0::MOD-4 MOD-4 - Mandatory Points — PASS

Reference: SS-1547-TEST-v1.0 1.0 (Approved; Revision History: 1.0 / 07-08-2024). MIGRATION (WP7-T8 / REV0907-E9, 2026-09-08): the doc key and uid prefix were re-keyed from 'SS-1547-TEST-v1.1' to 'SS-1547-TEST-v1.0' to match this line. The prior key was a misparse of the file name 'SunSpec-Modbus-for-1547-Test-Procedures-v1_10-8-24-1.pdf' (= v1, 10-8-24) as a v1.1 document; the PDF cover page has always stated Status: Approved, Version: 1.0 — the doc_version text itself was correct, only the doc/uid keys lagged it. See testdata/catalog/uid_aliases.json for the old-to-new uid mapping (ss-1547-test-v1.1::2.4 -> ss-1547-test-v1.0::2.4, ss-1547-test-v1.1::MOD-4 -> ss-1547-test-v1.0::MOD-4); bundles under runs/ minted before this migration carry the old uid verbatim as immutable evidence and are not rewritten. §2.3.1 MOD-4 - Mandatory Points (under 2.3 General SunSpec Model Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT serves [1 701 702 703 704 705 706 707 708 709 710 711 712]; the IEEE 1547-2018 profile requires [1 701 702 703 704 705 706 707 708 709 710 711 712 713]; conditionally optional and absent: [713]; storage support: the candidate manifest declares topology.role="inverter" and lists no model 713, so it does not support storage (/home/dmitri/projects/lexa-gw/configs/candidate.json)

Frame attribution: 85 frame(s) (1–90), precision connection; 45 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48766 <> 192.168.0.69:802 (MOD-4 IEEE 1547 mandatory points).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256, 192.168.0.188:48766 <> 192.168.0.69:802, 30 request records / 33 response records, 48 ADUs recovered
   - Frames: 24, 30, 32, 33, 34, 35, 36, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81
   - Frames sha256: `aae5da1b061abe0ac197d0b0cd456850fa7c44ef3b5afabf53a28d2ec842df14`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — every SunSpec model the IEEE 1547-2018 profile requires is implemented in the device
   - Method: the complete SunSpec discovery walk, terminated on the end model, compared against the profile's required-model list transcribed in profile1547.go from the SunSpec Modbus IEEE 1547-2018 Profile Specification §3
   - Observed: the discovery walk found [1 701 702 703 704 705 706 707 708 709 710 711 712] and terminated on the end model at 40982; the profile requires [1 701 702 703 704 705 706 707 708 709 710 711 712 713]; model 713 absent — conditionally optional: the profile makes DERStorageCapacity and its SoC point optional for an implementation that does not support storage; storage support: the candidate manifest declares topology.role="inverter" and lists no model 713, so it does not support storage (/home/dmitri/projects/lexa-gw/configs/candidate.json)
   - Frames: 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69
   - Frames sha256: `64068ebe39346d3ee0eb49a433789e3c4dfb53c65f6bade59d540eb3e54be36b`
3. **PASS** — MOD-4.1: every point the IEEE 1547-2018 profile marks mandatory for model 1 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: all 6 profile-required points of model 1 are implemented
   - Frames: 70, 71
   - Frames sha256: `5f0b7a736d416838577fe4dc3dd6b73f019a98f24e6feb30267561f5e9629589`
4. **PASS** — MOD-4.701: every point the IEEE 1547-2018 profile marks mandatory for model 701 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: all 16 profile-required points of model 701 are implemented
   - Frames: 74, 75, 76, 77
   - Frames sha256: `b57fb2229074563489656953611ec6c3f9eb495218c788e11e3909231749a30c`
5. **PASS** — MOD-4.702: every point the IEEE 1547-2018 profile marks mandatory for model 702 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: all 19 profile-required points of model 702 are implemented; not required of this device: WChaRteMaxRtg (INTERPRETATION (profile1547.go's storageConditional, NOT a qualifier printed in Table 18): this point rates a charge axis, and this candidate declares no storage — it serves no model 713, the profile's own marker for storage support, and its manifest (if any) claims no battery role. A DER with no storage behind it has no charge-rate rating to declare, and the not-implemented sentinel is the honest encoding of that; a zero here would be the device positively declaring a rated charge maximum of 0 W), VAChaRteMaxRtg (INTERPRETATION (profile1547.go's storageConditional, NOT a qualifier printed in Table 18): this point rates a charge axis, and this candidate declares no storage — it serves no model 713, the profile's own marker for storage support, and its manifest (if any) claims no battery role. A DER with no storage behind it has no charge-rate rating to declare, and the not-implemented sentinel is the honest encoding of that; a zero here would be the device positively declaring a rated charge maximum of 0 W)
   - Frames: 78, 79
   - Frames sha256: `bf0cd97b27edc9f854f0394fb687f932e048f274ad2984f070e46d7b7d4e7a8b`
6. **PASS** — MOD-4.703: every point the IEEE 1547-2018 profile marks mandatory for model 703 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: all 11 profile-required points of model 703 are implemented
   - Frames: 72, 73
   - Frames sha256: `bb4d8cbb079108582a6247ce8c2db0b92b7ff3c1805dd6805b5e03b95052b9b5`
7. **PASS** — MOD-4.704: every point the IEEE 1547-2018 profile marks mandatory for model 704 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: all 14 profile-required points of model 704 are implemented
   - Frames: 80, 81
   - Frames sha256: `9b095bfc71191cee0ef376ce5534dd4c86f7202cdd2c4c57d50146d9cd8edfb5`
8. **SKIP** — MOD-4.705: every point the IEEE 1547-2018 profile marks mandatory for model 705 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 705's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
9. **SKIP** — MOD-4.706: every point the IEEE 1547-2018 profile marks mandatory for model 706 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 706's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
10. **SKIP** — MOD-4.707: every point the IEEE 1547-2018 profile marks mandatory for model 707 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 707's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
11. **SKIP** — MOD-4.708: every point the IEEE 1547-2018 profile marks mandatory for model 708 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 708's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
12. **SKIP** — MOD-4.709: every point the IEEE 1547-2018 profile marks mandatory for model 709 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 709's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
13. **SKIP** — MOD-4.710: every point the IEEE 1547-2018 profile marks mandatory for model 710 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 710's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
14. **SKIP** — MOD-4.711: every point the IEEE 1547-2018 profile marks mandatory for model 711 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 711's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
15. **SKIP** — MOD-4.712: every point the IEEE 1547-2018 profile marks mandatory for model 712 is implemented
   - Method: FC 3 read of the model's whole register block; each profile-required point compared against its type's not-implemented sentinel, with model 701's voltage points judged against the device's own ACType per the profile's applicability qualifier
   - Observed: this suite carries no transcription of model 712's layout (it is a runtime-geometry curve model), so its required points cannot be located on the wire
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
16. **SKIP** — the device PICS agrees with the profile's mandatory-point list
   - Method: comparison of the PICS workbook against the profile specification
   - Observed: no PICS workbook was supplied; MOD-4 was executed against profile1547.go's transcription of the SunSpec Modbus IEEE 1547-2018 Profile Specification, which is the document the test procedure delegates its list to
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-1547-test-v1.0::2.4 Scale Factor Test — PASS

Reference: SS-1547-TEST-v1.0 1.0 (Approved; Revision History: 1.0 / 07-08-2024). MIGRATION (WP7-T8 / REV0907-E9, 2026-09-08): the doc key and uid prefix were re-keyed from 'SS-1547-TEST-v1.1' to 'SS-1547-TEST-v1.0' to match this line. The prior key was a misparse of the file name 'SunSpec-Modbus-for-1547-Test-Procedures-v1_10-8-24-1.pdf' (= v1, 10-8-24) as a v1.1 document; the PDF cover page has always stated Status: Approved, Version: 1.0 — the doc_version text itself was correct, only the doc/uid keys lagged it. See testdata/catalog/uid_aliases.json for the old-to-new uid mapping (ss-1547-test-v1.1::2.4 -> ss-1547-test-v1.0::2.4, ss-1547-test-v1.1::MOD-4 -> ss-1547-test-v1.0::MOD-4); bundles under runs/ minted before this migration carry the old uid verbatim as immutable evidence and are not rewritten. §2.4 Scale Factor Test

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 25 scale factor(s) read across 13 model(s); not transcribed by this suite: 705, 706, 707, 708, 709, 710, 711, 712

Frame attribution: 122 frame(s) (84–266), precision connection; 182 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48768 <> 192.168.0.69:802 (1547 §2.4 scale factor test).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48768 <> 192.168.0.69:802, 52 request records / 55 response records, 98 ADUs recovered
   - Frames: 105, 108, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 128, 129, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 157, 158, 159, 160, 163, 164, 165, 166, 171, 172, 173, 174, 175, 176, 179, 180, 181, 182, 183, 184, 185, 186, 188, 189, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 207, 208, 209, 210, 217, 218, 219, 220, 229, 230, 238, 241, 245, 246, 247, 248, 249, 250, 252, 253, 254
   - Frames sha256: `d0b1865d97cda4d6a1f3b57e323e84a4fdda2f793c810afabeaf33e58d8cc6cd`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — every scale factor the device implements lies inside the sunssf type's range of -10..10, or reads the defined not-implemented value, and does not change between two reads
   - Method: FC 3 read of every sunssf point in every transcribed model, re-read after the sweep; the range is the sunssf definition in the SunSpec Device Information Model Specification §4.2.4, and the static-value requirement is §4.2.8
   - Observed: 701.A_SF@40202=-1, 701.Hz_SF@40204=-2, 701.PF_SF@40206=-2, 701.Tmp_SF@40211=-1, 701.TotVarh_SF@40210=0, 701.TotWh_SF@40209=0, 701.VA_SF@40207=0, 701.V_SF@40203=-1, 701.Var_SF@40208=0, 701.W_SF@40205=0, 702.A_SF@40294=-1, 702.PF_SF@40290=-2, 702.S_SF@40295=-4, 702.VA_SF@40291=0, 702.V_SF@40293=-1, 702.Var_SF@40292=0, 702.W_SF@40289=0, 703.Hz_SF@40088=-2, 703.V_SF@40087=-1, 704.PF_SF@40349=-2, 704.VarSetPct_SF@40354=-2, 704.VarSet_SF@40353=0, 704.WMaxLimPct_SF@40350=-2, 704.WSetPct_SF@40352=-2, 704.WSet_SF@40351=0
   - Frames: 146, 147, 148, 149, 150, 157, 158, 159, 160, 163, 164, 165, 166, 171, 172, 173, 174, 175, 176, 179, 180, 181, 182, 183, 184, 185, 186, 188, 189, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 207, 208, 209, 210, 217, 218, 219, 220, 229, 230, 238, 241, 245, 246, 247, 248, 249, 250, 252, 253, 254
   - Frames sha256: `2364b180ab14e92e2fd7f64bcb7ea5fed8bf0e36948811a41f86f75f447e8e4b`
3. **PASS** — every scale factor the IEEE 1547-2018 profile lists as required for a model the device implements is itself implemented
   - Method: the profile's per-model required scale-factor list, transcribed in profile1547.go from the profile specification §3, compared against the sunssf values read from the device
   - Observed: every scale factor the profile requires is implemented
   - Frames: 146, 147, 148, 149, 150, 157, 158, 159, 160, 163, 164, 165, 166, 171, 172, 173, 174, 175, 176, 179, 180, 181, 182, 183, 184, 185, 186, 188, 189, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 207, 208, 209, 210, 217, 218, 219, 220, 229, 230, 238, 241, 245, 246, 247, 248, 249, 250, 252, 253, 254
   - Frames sha256: `2364b180ab14e92e2fd7f64bcb7ea5fed8bf0e36948811a41f86f75f447e8e4b`
4. **SKIP** — each scale factor lies in the acceptable range required to meet the IEEE 1547 requirements for its point's data type
   - Method: comparison against the per-point IEEE 1547 accuracy and range requirements
   - Observed: the test procedure does not enumerate those ranges — it delegates them to IEEE 1547-2018 and the device PICS, neither of which was supplied. The assertions above establish the outer bound (the sunssf type's own range, staticness, and the profile's required-scale-factor list); the per-point accuracy envelope is not asserted, and this suite will not invent it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-modbus-conf-v1.4::DEV-1 General Discovery — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.3.1 DEV-1 - General Discovery (under 2.3 General Device Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]

Frame attribution: 75 frame(s) (257–361), precision connection; 199 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48784 <> 192.168.0.69:802 (DEV-1 general discovery).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48784 <> 192.168.0.69:802, 24 request records / 27 response records, 36 ADUs recovered
   - Frames: 287, 302, 305, 308, 309, 310, 311, 312, 313, 314, 315, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 337, 338, 341, 342, 343, 344, 345, 346, 352
   - Frames sha256: `254ef4c0bedaa164c0bc816335e204cd9e0830e89b40d3c78c0e7a3eae5ae6b2`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — the SunSpec content is located at one of the standard start addresses (0, 40000, 50000) and the first two registers there are the SunSpec start marker 0x5375 0x6E53
   - Method: FC 3 read of 2 registers at each of the three standard base addresses
   - Observed: 0: exception 0x01 (illegal function); 40000: 0x5375 0x6e53 (SunS); 50000: exception 0x01 (illegal function)
   - Frames: 305, 308, 309, 310, 311, 312
   - Frames sha256: `8c57338cc2807f844fffa700826b16054e982d2cced65931ca40b7fad4fc420c`
3. **PASS** — every model in the device is located by the standard SunSpec discovery procedure: read the (ID, L) header, skip L registers, repeat
   - Method: successive FC 3 reads of 2-register model headers from base+2, following each declared length
   - Observed: base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]
   - Frames: 313, 314, 315, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 337, 338, 341, 342, 343, 344, 345, 346, 352
   - Frames sha256: `2f494d5f17a5da0252cac2e696c2a8595f7350f01feec6eeb435c83353ded0c1`
4. **PASS** — the model chain is terminated by the SunSpec end model: ID 65535 with length 0
   - Method: FC 3 read of the two-register header at the address the walk arrived at
   - Observed: model ID 0xffff with length 0 at address 40982
   - Frames: 313, 314, 315, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 337, 338, 341, 342, 343, 344, 345, 346, 352
   - Frames sha256: `2f494d5f17a5da0252cac2e696c2a8595f7350f01feec6eeb435c83353ded0c1`
5. **SKIP** — every SunSpec model listed in the device PICS is located by the discovery walk
   - Method: comparison of the discovered chain against the PICS model list
   - Observed: no PICS model list was supplied (-param pics.models=1,701,702,...); the discovered chain is recorded in the assertion above, but a chain cannot be checked against itself
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-modbus-conf-v1.4::DEV-2 Model 1 Support — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.3.2 DEV-2 - Model 1 Support (under 2.3 General Device Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): model 1 at 40002, L=66, Mn="SunSpec Sim" Md="CSIP-Solar-5000" SN="BENCH-MODSIM-01"

Frame attribution: 65 frame(s) (355–436), precision connection; 163 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48794 <> 192.168.0.69:802 (DEV-2 model 1 support).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48794 <> 192.168.0.69:802, 22 request records / 25 response records, 38 ADUs recovered
   - Frames: 378, 380, 382, 384, 385, 386, 387, 388, 389, 391, 392, 393, 394, 395, 396, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 415, 416, 417, 418, 419, 420, 421, 422, 425, 426, 427
   - Frames sha256: `ca7950b57ceec59ffbd0ffe1da2d31fa42aa6866b1c9cfecbf0ed60d2278e534`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — SunSpec model 1 is present in the device model chain, with the length its definition fixes (66)
   - Method: FC 3 read of the two-register model header located by the discovery walk
   - Observed: header at 40002 reads ID=1 L=66 (definition: 66)
   - Frames: 389, 391, 392, 393, 394, 395, 396, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 415, 416, 417, 418, 419, 420, 421, 422, 425
   - Frames sha256: `6ff4660d4574f0b219e52b756063239c7c166ea132ab862e001f8632a621b823`
3. **PASS** — every point the Common Model definition marks mandatory (ID, L, Mn, Md, SN) carries an implemented value in model 1
   - Method: FC 3 read of model 1's whole register block, decoded against this suite's own transcription of the Common Model definition, and each mandatory point compared with its type's not-implemented sentinel
   - Observed: ID=1 [M], L=66 [M], Mn=SunSpec Sim [M], Md=CSIP-Solar-5000 [M], Opt=, Vr=4.2.1, SN=BENCH-MODSIM-01 [M], DA=1, Pad=0x0000
   - Frames: 426, 427
   - Frames sha256: `bf5d44c4120a3b03a88365a2d94ba54d234657497c9c999f35996ef1017e3df8`
4. **SKIP** — the content of model 1 matches what the device PICS declares
   - Method: comparison of the decoded model 1 identity against the PICS workbook
   - Observed: no PICS identity was supplied (-param pics.mn/pics.md/pics.sn); the decoded identity is recorded in the assertion above, but a device cannot be its own conformance statement
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-modbus-conf-v1.4::MOD-1 Model Implementation — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.4.1 MOD-1 - Model Implementation (under 2.4 General SunSpec Model Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 5 model(s) examined, 8 not transcribed by this suite; chain base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]

Frame attribution: 503 frame(s) (430–1041), precision connection; 236 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48796 <> 192.168.0.69:802 (MOD-1 model implementation).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48796 <> 192.168.0.69:802, 238 request records / 241 response records, 464 ADUs recovered
   - Frames: 459, 473, 475, 478, 480, 481, 482, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 540, 541, 542, 543, 544, 545, 547, 548, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 616, 617, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 638, 639, 642, 643, 644, 645, 646, 647, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 670, 671, 674, 675, 676, 677, 678, 679, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 696, 697, 698, 699, 701, 702, 703, 704, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 788, 789, 792, 793, 796, 797, 800, 801, 802, 803, 806, 807, 813, 814, 817, 818, 819, 820, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 861, 862, 863, 864, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 915, 916, 917, 918, 922, 923, 924, 925, 926, 927, 928, 929, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030
   - Frames sha256: `7b30a1f99094b9e892d58cd3f471be74b1fcba5e61e49fd1a0bfc7eff4a6f3b8`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — MOD-1.1 step 2: model 1 declares the length its contents require
   - Method: FC 3 read of the two-register model header, compared against this suite's transcription of the model definition (and, for a variable-length model, the geometry points read from the device)
   - Observed: model 1 declares L=66; its definition requires 66
   - Frames: 516, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 540
   - Frames sha256: `ea2a4b1c526605178d45d6fcaafb15d82860a095a0d412e4b1c3f01b2d1307dd`
3. **PASS** — MOD-1.1 step 3: model 1 implements its mandatory points, ID and L included
   - Method: FC 3 read of the model's whole register block; each mandatory point compared against its type's not-implemented sentinel
   - Observed: ID=1 L=66 and every mandatory point of model 1 carries an implemented value
   - Frames: 516, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 540
   - Frames sha256: `ea2a4b1c526605178d45d6fcaafb15d82860a095a0d412e4b1c3f01b2d1307dd`
4. **PASS** — MOD-1.1 step 5: every point of model 1 can be read as a single point and returns a value inside its datatype range
   - Method: one FC 3 request per point, quantity equal to the point's register width, at the point's offset within the model
   - Observed: all 9 points of model 1 read individually, every value inside its datatype range
   - Frames: 516, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 540
   - Frames sha256: `ea2a4b1c526605178d45d6fcaafb15d82860a095a0d412e4b1c3f01b2d1307dd`
5. **PASS** — MOD-1.703 step 2: model 703 declares the length its contents require
   - Method: FC 3 read of the two-register model header, compared against this suite's transcription of the model definition (and, for a variable-length model, the geometry points read from the device)
   - Observed: model 703 declares L=17; its definition requires 17
   - Frames: 541, 542, 543, 544, 545, 547, 548, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 569, 570, 571, 572, 573
   - Frames sha256: `499c428dd27a70255a386efc43fc653443aec989964831d9d72c6753a827cb50`
6. **PASS** — MOD-1.703 step 3: model 703 implements its mandatory points, ID and L included
   - Method: FC 3 read of the model's whole register block; each mandatory point compared against its type's not-implemented sentinel
   - Observed: ID=703 L=17 and every mandatory point of model 703 carries an implemented value
   - Frames: 541, 542, 543, 544, 545, 547, 548, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 569, 570, 571, 572, 573
   - Frames sha256: `499c428dd27a70255a386efc43fc653443aec989964831d9d72c6753a827cb50`
7. **PASS** — MOD-1.703 step 5: every point of model 703 can be read as a single point and returns a value inside its datatype range
   - Method: one FC 3 request per point, quantity equal to the point's register width, at the point's offset within the model
   - Observed: all 13 points of model 703 read individually, every value inside its datatype range
   - Frames: 541, 542, 543, 544, 545, 547, 548, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 569, 570, 571, 572, 573
   - Frames sha256: `499c428dd27a70255a386efc43fc653443aec989964831d9d72c6753a827cb50`
8. **PASS** — MOD-1.701 step 2: model 701 declares the length its contents require
   - Method: FC 3 read of the two-register model header, compared against this suite's transcription of the model definition (and, for a variable-length model, the geometry points read from the device)
   - Observed: model 701 declares L=153; its definition requires 153
   - Frames: 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 616, 617, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 638, 639, 642, 643, 644, 645, 646, 647, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 670, 671, 674, 675, 676, 677, 678, 679, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 696, 697, 698, 699, 701, 702, 703, 704, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 744, 745, 746, 747, 748, 749, 750, 751, 752
   - Frames sha256: `351bf197038ac2965944de506a3ffe4e9135a3c794602d05c1b3e36b0558be92`
9. **PASS** — MOD-1.701 step 3: model 701 implements its mandatory points, ID and L included
   - Method: FC 3 read of the model's whole register block; each mandatory point compared against its type's not-implemented sentinel
   - Observed: ID=701 L=153 and every mandatory point of model 701 carries an implemented value
   - Frames: 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 616, 617, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 638, 639, 642, 643, 644, 645, 646, 647, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 670, 671, 674, 675, 676, 677, 678, 679, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 696, 697, 698, 699, 701, 702, 703, 704, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 744, 745, 746, 747, 748, 749, 750, 751, 752
   - Frames sha256: `351bf197038ac2965944de506a3ffe4e9135a3c794602d05c1b3e36b0558be92`
10. **PASS** — MOD-1.701 step 5: every point of model 701 can be read as a single point and returns a value inside its datatype range
   - Method: one FC 3 request per point, quantity equal to the point's register width, at the point's offset within the model
   - Observed: all 72 points of model 701 read individually, every value inside its datatype range
   - Frames: 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 616, 617, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 638, 639, 642, 643, 644, 645, 646, 647, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 670, 671, 674, 675, 676, 677, 678, 679, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 696, 697, 698, 699, 701, 702, 703, 704, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 744, 745, 746, 747, 748, 749, 750, 751, 752
   - Frames sha256: `351bf197038ac2965944de506a3ffe4e9135a3c794602d05c1b3e36b0558be92`
11. **PASS** — MOD-1.702 step 2: model 702 declares the length its contents require
   - Method: FC 3 read of the two-register model header, compared against this suite's transcription of the model definition (and, for a variable-length model, the geometry points read from the device)
   - Observed: model 702 declares L=50; its definition requires 50
   - Frames: 753, 754, 755, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 788, 789, 792, 793, 796, 797, 800, 801, 802, 803, 806, 807, 813, 814, 817, 818, 819, 820, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 861, 862, 863, 864, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 882, 883, 884, 885, 886
   - Frames sha256: `c2f13599b905dd5997aa33fccc9fd879dedba3b209ecde4c203587fae4703e9d`
12. **PASS** — MOD-1.702 step 3: model 702 implements its mandatory points, ID and L included
   - Method: FC 3 read of the model's whole register block; each mandatory point compared against its type's not-implemented sentinel
   - Observed: ID=702 L=50 and every mandatory point of model 702 carries an implemented value
   - Frames: 753, 754, 755, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 788, 789, 792, 793, 796, 797, 800, 801, 802, 803, 806, 807, 813, 814, 817, 818, 819, 820, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 861, 862, 863, 864, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 882, 883, 884, 885, 886
   - Frames sha256: `c2f13599b905dd5997aa33fccc9fd879dedba3b209ecde4c203587fae4703e9d`
13. **PASS** — MOD-1.702 step 5: every point of model 702 can be read as a single point and returns a value inside its datatype range
   - Method: one FC 3 request per point, quantity equal to the point's register width, at the point's offset within the model
   - Observed: all 51 points of model 702 read individually, every value inside its datatype range
   - Frames: 753, 754, 755, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 788, 789, 792, 793, 796, 797, 800, 801, 802, 803, 806, 807, 813, 814, 817, 818, 819, 820, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 861, 862, 863, 864, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 882, 883, 884, 885, 886
   - Frames sha256: `c2f13599b905dd5997aa33fccc9fd879dedba3b209ecde4c203587fae4703e9d`
14. **PASS** — MOD-1.704 step 2: model 704 declares the length its contents require
   - Method: FC 3 read of the two-register model header, compared against this suite's transcription of the model definition (and, for a variable-length model, the geometry points read from the device)
   - Observed: model 704 declares L=65; its definition requires 65
   - Frames: 887, 888, 889, 890, 891, 892, 893, 894, 895, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 915, 916, 917, 918, 922, 923, 924, 925, 926, 927, 928, 929, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008
   - Frames sha256: `f393a7cae5446af8e41b48b6ef8c4774d8612f86fdc530deb4a51a6aaf7b2369`
15. **PASS** — MOD-1.704 step 3: model 704 implements its mandatory points, ID and L included
   - Method: FC 3 read of the model's whole register block; each mandatory point compared against its type's not-implemented sentinel
   - Observed: ID=704 L=65 and every mandatory point of model 704 carries an implemented value
   - Frames: 887, 888, 889, 890, 891, 892, 893, 894, 895, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 915, 916, 917, 918, 922, 923, 924, 925, 926, 927, 928, 929, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008
   - Frames sha256: `f393a7cae5446af8e41b48b6ef8c4774d8612f86fdc530deb4a51a6aaf7b2369`
16. **PASS** — MOD-1.704 step 5: every point of model 704 can be read as a single point and returns a value inside its datatype range
   - Method: one FC 3 request per point, quantity equal to the point's register width, at the point's offset within the model
   - Observed: all 53 points of model 704 read individually, every value inside its datatype range
   - Frames: 887, 888, 889, 890, 891, 892, 893, 894, 895, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 915, 916, 917, 918, 922, 923, 924, 925, 926, 927, 928, 929, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008
   - Frames sha256: `f393a7cae5446af8e41b48b6ef8c4774d8612f86fdc530deb4a51a6aaf7b2369`
17. **SKIP** — MOD-1.705: model 705 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 705 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
18. **SKIP** — MOD-1.706: model 706 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 706 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
19. **SKIP** — MOD-1.707: model 707 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 707 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
20. **SKIP** — MOD-1.708: model 708 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 708 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
21. **SKIP** — MOD-1.709: model 709 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 709 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
22. **SKIP** — MOD-1.710: model 710 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 710 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
23. **SKIP** — MOD-1.711: model 711 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 711 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
24. **SKIP** — MOD-1.712: model 712 is implemented correctly
   - Method: per-model examination against this suite's transcription of the model definition
   - Observed: model 712 is a runtime-geometry curve model: its register offsets depend on the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no transcription of its layout, so a per-point sweep would be guessing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
25. **SKIP** — the set of implemented points equals the set the PICS declares (MOD-1 step 4)
   - Method: comparison of the decoded point set against the PICS workbook
   - Observed: no PICS workbook was supplied; the implemented point set is recorded by the assertions above, but a device's own map cannot stand in for the conformance statement it is checked against
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-modbus-conf-v1.4::MOD-2 Model Read — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.4.2 MOD-2 - Model Read (under 2.4 General SunSpec Model Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 13 model(s) read; chain base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]

Frame attribution: 92 frame(s) (1035–1145), precision connection; 171 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48812 <> 192.168.0.69:802 (MOD-2 model read).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48812 <> 192.168.0.69:802, 37 request records / 40 response records, 68 ADUs recovered
   - Frames: 1055, 1057, 1059, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1134, 1135, 1136
   - Frames sha256: `9136beb3f1b50f9bba95d325b721dedf7cb6741fa2c3aac1efd5678189ecf686`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — MOD-2.1: model 1 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 1 read in 1 request(s) covering 68 registers
   - Frames: 1099, 1100
   - Frames sha256: `4dd2e174237e2a3094f35344b7d08b9ab1580026f2f6ab2d68f45271a5977c93`
3. **PASS** — MOD-2.703: model 703 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 703 read in 1 request(s) covering 19 registers
   - Frames: 1101, 1102
   - Frames sha256: `ff2c44dd34c9a8ff3f3b849f707ced1ea40fd6af2a64fbb94ed29c398bab008f`
4. **PASS** — MOD-2.701: model 701 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 701 read in 2 request(s) covering 155 registers
   - Frames: 1103, 1104, 1105, 1108
   - Frames sha256: `f16e679fa87e5de4a09997d640234550582108e9e8b1a1e95839ab41b31a5684`
5. **PASS** — MOD-2.702: model 702 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 702 read in 1 request(s) covering 52 registers
   - Frames: 1109, 1110
   - Frames sha256: `1a10294dd172b3c2c2db3adf746ca271af7fa7af1ce56e31586e45b00286e1cc`
6. **PASS** — MOD-2.704: model 704 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 704 read in 1 request(s) covering 67 registers
   - Frames: 1111, 1112
   - Frames sha256: `b14ddbf3f1ce6953ad554894c9d9b8ce927a4606ff43dca7b10908f242865716`
7. **PASS** — MOD-2.705: model 705 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 705 read in 1 request(s) covering 45 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1113, 1114
   - Frames sha256: `e9afed27b0a8a30b0d8a25b38a71cc2d2c041fac5469caa3f37f436651a0e6f8`
8. **PASS** — MOD-2.706: model 706 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 706 read in 1 request(s) covering 40 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1115, 1118
   - Frames sha256: `e04aaced3e0977e8353e7fa1cd1a2abe771d3a7b5b1b8a71f645dc05c8ffec82`
9. **PASS** — MOD-2.707: model 707 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 707 read in 1 request(s) covering 103 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1119, 1120
   - Frames sha256: `e75d68f8be9b6b9e1114dd31068c14e87275b522bb1f02deef3e01275d0d47b4`
10. **PASS** — MOD-2.708: model 708 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 708 read in 1 request(s) covering 103 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1121, 1122
   - Frames sha256: `b38f64ac50aeb31d01da5b353b0f3d1d66e4486d93bc3a85ee46347cdd3e5c3f`
11. **PASS** — MOD-2.709: model 709 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 709 read in 2 request(s) covering 133 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1123, 1124, 1125, 1126
   - Frames sha256: `bf8d1dc054514126ad8fbcb956420069ac15ff5b9fa3c822e0865202246252c3`
12. **PASS** — MOD-2.710: model 710 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 710 read in 2 request(s) covering 133 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1127, 1128, 1129, 1130
   - Frames sha256: `c2b7bba6fc1d4a0fe58378e54676bc19d84ae1d1a42a836934221b9fb2beaa70`
13. **PASS** — MOD-2.711: model 711 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 711 read in 1 request(s) covering 24 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1131, 1134
   - Frames sha256: `4e140ca6fbf31dd6f139ac6ea69667e9ffb71c8c873e0de483c1a90ec7bf4dca`
14. **PASS** — MOD-2.712: model 712 reads in a single Modbus request, or in consecutive requests of at most 125 registers when it is longer than that
   - Method: FC 3 request(s) at the model's start address with quantity equal to its full span (header included), each within the 125-register application-protocol maximum
   - Observed: model 712 read in 1 request(s) covering 38 registers; this suite has no transcription of the model, so the returned values were not range-checked
   - Frames: 1135, 1136
   - Frames sha256: `d816580fc8bc8e4dc478f0f26a4496b1b6cadb1e080f2a07064134a542b7e29c`

### ✓ ss-modbus-conf-v1.4::MB-2 Modbus Single Register Read — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.7.10 MB-2 - Modbus Single Register Read (under 2.7 Modbus Protocol Tests / General Modbus Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): three single-register reads: 1.ID, 1.L, 1.DA

Frame attribution: 84 frame(s) (1139–1248), precision connection; 125 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48814 <> 192.168.0.69:802 (MB-2 single register read).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48814 <> 192.168.0.69:802, 30 request records / 33 response records, 48 ADUs recovered
   - Frames: 1168, 1176, 1178, 1184, 1185, 1186, 1187, 1190, 1191, 1192, 1193, 1194, 1195, 1196, 1197, 1198, 1199, 1200, 1201, 1202, 1203, 1206, 1207, 1210, 1211, 1212, 1213, 1214, 1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223, 1224, 1225, 1228, 1229, 1230, 1231, 1232, 1233, 1234, 1235, 1236
   - Frames sha256: `c15bb74ea5fdc10d2f1587305f3b4e98762c901b7fdbb0ef2cb71e5f2f9b1fe9`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — three distinct registers are each read correctly by an FC 3 request with quantity 1
   - Method: FC 3 with the quantity field set to 0x0001 at three 16-bit point addresses, each result compared against the value the same register returned inside a whole-model read
   - Observed: 1.ID@40002: 0x0001 (block read: 0x0001); 1.L@40003: 0x0042 (block read: 0x0042); 1.DA@40068: 0x0001 (block read: 0x0001)
   - Frames: 1229, 1230, 1231, 1232, 1233, 1234
   - Frames sha256: `7cc24540d11802a5ae4f2a700080dfa2b92ec83dd554b332a279ebd2bb4cc295`
3. **PASS** — the DUT's handling of a single-register read aimed inside a value longer than 16 bits is recorded; both answering and rejecting are compliant under the v1.4 carve-out
   - Method: FC 3 with quantity 1 at the second register of a 32-bit point
   - Observed: reading 703.ESHzHi (second half of a 32-bit point) at 40076 returned 0x177a, matching the block read — the DUT allows a partial-value read
   - Frames: 1235, 1236
   - Frames sha256: `13647235f46dcfe4a12f147da669392132e915dd7d78b19b5ee8b4d927bf285f`

### ✓ ss-modbus-conf-v1.4::CRV-1 Curve 1 Support — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.5.1 CRV-1 - Curve 1 Support (under 2.5 Curve Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): chain: 1, 703, 701, 702, 704, 705, 706, 707, 708, 709, 710, 711, 712; curve-based models present: 705, 706, 707, 708, 709, 710, 712; curve-family models present that are not curve-based (CTP §2.5's precondition does not reach them): 711. Legacy 12x sweep: 0 model(s) verified read-only, 0 failed, 0 inconclusive, of the 126-134/160 range. Steps 2 and 3 were not asserted at curve-1 granularity: this suite carries no transcription of either curve generation's bank layout. Models 705-712 size their repeating blocks from the NPt / NCrv / NCrvSet / NCtl geometry points read out of the device; the legacy 12x models' banks are flat but are transcribed here to one probe point each and no further. Either way curve 1's sub-block, its read-only indicator point (which the source document does not name) and the registers a curve-1-specific write attempt would target cannot be located, and computing them from a guessed geometry would yield a verdict about whichever registers the guess landed on. What CAN be asserted is the MODEL-level read-only posture of the legacy family, and the per-model CRV-1.126 .. CRV-1.160 assertions in this same test case do exactly that. Closing the rest needs the flattened curve layouts transcribed into models.go, the same gap MOD-4's per-point sweep reports for these models.; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 63 frame(s) (1239–1333), precision connection; 140 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48816 <> 192.168.0.69:802 (CRV-1 curve 1 support).

1. **SKIP** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48816 <> 192.168.0.69:802, 21 request records / 24 response records, 36 ADUs recovered
   - Frames: 1264, 1266, 1268, 1271, 1272, 1275, 1276, 1277, 1278, 1279, 1280, 1283, 1284, 1285, 1286, 1289, 1290, 1291, 1292, 1300, 1301, 1302, 1303, 1304, 1305, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315, 1322, 1323, 1324
   - Frames sha256: `ca0d9783d6c04865f16ed9eac5f5882ca1f8099e137b29f969dc3e80c0378902`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs; recorded as context; this test case was not exercised, so nothing here is claimed as a conformance result
2. **PASS** — a curve-based model — of the 7xx range, or of the legacy 12x family the DUT's Stage-6 read-only projection serves as itself — is present in the DUT's northbound projection, which is CTP §2.5's precondition for performing the curve tests at all
   - Method: the SunSpec model chain walked from the standard base address
   - Observed: chain: 1, 703, 701, 702, 704, 705, 706, 707, 708, 709, 710, 711, 712; curve-based models present: 705, 706, 707, 708, 709, 710, 712; curve-family models present that are not curve-based (CTP §2.5's precondition does not reach them): 711
   - Frames: 1278, 1279, 1280, 1283, 1284, 1285, 1286, 1289, 1290, 1291, 1292, 1300, 1301, 1302, 1303, 1304, 1305, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315, 1322, 1323, 1324
   - Frames sha256: `a67d80a48c5799049691f648c0cae7ac55a22b9e66a8f256b3e90bdbb5140437`
3. **SKIP** — curve 1 is present in the model's curve repeating block and is declared read-only by the device
   - Method: read of the curve repeating block
   - Observed: this suite carries no transcription of either curve generation's bank layout. Models 705-712 size their repeating blocks from the NPt / NCrv / NCrvSet / NCtl geometry points read out of the device; the legacy 12x models' banks are flat but are transcribed here to one probe point each and no further. Either way curve 1's sub-block, its read-only indicator point (which the source document does not name) and the registers a curve-1-specific write attempt would target cannot be located, and computing them from a guessed geometry would yield a verdict about whichever registers the guess landed on. What CAN be asserted is the MODEL-level read-only posture of the legacy family, and the per-model CRV-1.126 .. CRV-1.160 assertions in this same test case do exactly that. Closing the rest needs the flattened curve layouts transcribed into models.go, the same gap MOD-4's per-point sweep reports for these models
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **SKIP** — a write to a point belonging to curve 1 does not take effect: the DUT answers with a Modbus exception (per EXC-2, code 2, 3 or 4) or the value reads back unchanged
   - Method: write attempt to a curve-1 point
   - Observed: this suite carries no transcription of either curve generation's bank layout. Models 705-712 size their repeating blocks from the NPt / NCrv / NCrvSet / NCtl geometry points read out of the device; the legacy 12x models' banks are flat but are transcribed here to one probe point each and no further. Either way curve 1's sub-block, its read-only indicator point (which the source document does not name) and the registers a curve-1-specific write attempt would target cannot be located, and computing them from a guessed geometry would yield a verdict about whichever registers the guess landed on. What CAN be asserted is the MODEL-level read-only posture of the legacy family, and the per-model CRV-1.126 .. CRV-1.160 assertions in this same test case do exactly that. Closing the rest needs the flattened curve layouts transcribed into models.go, the same gap MOD-4's per-point sweep reports for these models
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
5. **SKIP** — CRV-1.126: model 126 (volt_var (Static Volt-VAr Arrays)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 126 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **SKIP** — CRV-1.127: model 127 (freq_watt_param (Parameterized Frequency-Watt)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to WGra of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of WGra at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 127 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
7. **SKIP** — CRV-1.128: model 128 (reactive_current (Dynamic Reactive Current)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ArGraMod of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ArGraMod at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 128 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
8. **SKIP** — CRV-1.129: model 129 (lvrt (LVRT Must Disconnect)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 129 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
9. **SKIP** — CRV-1.130: model 130 (hvrt (HVRT Must Disconnect)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 130 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
10. **SKIP** — CRV-1.131: model 131 (watt_pf (Watt-Power Factor)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 131 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
11. **SKIP** — CRV-1.132: model 132 (volt_watt (Volt-Watt)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 132 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
12. **SKIP** — CRV-1.133: model 133 is not part of the DUT's northbound projection at all, so the procedure has no subject for it on any unit
   - Method: the discovery walk, read against the DUT's registered model set
   - Observed: the DUT's northbound projection registers no layout for model 133 (lexa-gw internal/regmap/chain.go's modelLayouts, chain.go:84-120), and the D4 read-only-verbatim decision that put the legacy family northbound enumerates it as 126/127/128/129/130/131/132/134/160 (internal/regmap/pointgroups.go:264) — 133 is absent from both. Its absence is therefore NOT the device-conditional absence the other eight can have: no unit, of any class, behind any DER, can carry a 133 on this build, so the procedure has no subject for it here and never will on this projection. The discovery walk confirms it: base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
13. **SKIP** — CRV-1.134: model 134 (freq_watt (Curve-Based Frequency-Watt)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to ActCrv of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of ActCrv at model offset 2 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 134 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
14. **SKIP** — CRV-1.160: model 160 (mppt (Multiple MPPT Inverter Extension)) is served READ-ONLY on the DUT's northbound projection — its whole register block reads back, and a write to N of the value that register already holds is REFUSED with a Modbus exception rather than acknowledged
   - Method: FC 3 read of the model's whole register block; FC 3 single-point read of N at model offset 8 (the SunSpec model definition's own point table, transcribed here (not imported from the layout package the DUT encodes with)); FC 6 write of that same value back to it; FC 3 re-read. The graded criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a normal write response is an acknowledgement — not the register's later value
   - Observed: the discovery walk found no model 160 in this unit's chain (base 40000, [1 @40002 L=66] [703 @40070 L=17] [701 @40089 L=153] [702 @40244 L=50] [704 @40296 L=65] [705 @40363 L=43] [706 @40408 L=38] [707 @40448 L=101] [708 @40551 L=101] [709 @40654 L=131] [710 @40787 L=131] [711 @40920 L=22] [712 @40944 L=36] [end 0xffff @40982 L=0]). The gateway chains the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves it southbound — so this is a property of the DER behind the unit and not of the gateway, and the procedure's precondition excludes it. It is reported rather than omitted so a reader checking the 126-134/160 range against this report can see that the model was looked for
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-modbus-conf-v1.4::EXC-3 Illegal Function Code — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.8.3 EXC-3 - Illegal Function Code (under 2.8 Exception Generation Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT answered function code 0x32 at the implemented RW point 704.WMaxLimPct (40311) with function byte 0xb2 and exception code 0x01 (illegal function)

Frame attribution: 73 frame(s) (1327–1420), precision connection; 102 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48826 <> 192.168.0.69:802 (EXC-3 illegal function code).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48826 <> 192.168.0.69:802, 25 request records / 28 response records, 38 ADUs recovered
   - Frames: 1356, 1365, 1368, 1369, 1370, 1371, 1372, 1375, 1376, 1377, 1378, 1379, 1380, 1381, 1382, 1385, 1386, 1387, 1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396, 1397, 1398, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1407, 1411
   - Frames sha256: `02323ee4224b5e4d508514ad47fc6cef963e42ab197a53244ca68649be15dbde`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — a request carrying function code 50 (0x32), which does not exist in the Modbus specification, is answered with function byte 0xB2 and exception code 1 (Illegal Function), echoing the request's transaction identifier
   - Method: one MBAP frame whose PDU begins with 0x32, aimed at the implemented RW point 704.WMaxLimPct; the response ADU is read back out of the capture and its function byte, exception code and transaction id are compared against the request
   - Observed: response pdu on the wire is b2 01: function byte 0xb2, exception code 0x01 (illegal function), transaction id 0x0013
   - Frames: 1407, 1411
   - Frames sha256: `26737d6cf713b3d223280261765510d51c57034821817e7d7281bc6233bb5a97`

### ✓ ss-modbus-conf-v1.4::EXC-2 Writing a Read-Only Register — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.8.2 EXC-2 - Writing a Read-Only Register (under 2.8 Exception Generation Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 1.ID (model header register): FC 6 to 40002 returned exception 0x02 (illegal data address); the register still reads 0x0001; 1.DA (read-only point): FC 6 to 40068 returned exception 0x02 (illegal data address); the register still reads 0x0001; 703.V_SF (scale factor): FC 6 to 40087 returned exception 0x02 (illegal data address); the register still reads 0xffff

Frame attribution: 78 frame(s) (1414–1520), precision connection; 148 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48836 <> 192.168.0.69:802 (EXC-2 write to a read-only register).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48836 <> 192.168.0.69:802, 29 request records / 32 response records, 52 ADUs recovered
   - Frames: 1436, 1438, 1440, 1443, 1444, 1445, 1446, 1447, 1448, 1449, 1450, 1453, 1454, 1455, 1456, 1457, 1458, 1459, 1460, 1463, 1464, 1467, 1468, 1472, 1474, 1475, 1476, 1479, 1480, 1483, 1484, 1485, 1486, 1487, 1488, 1489, 1490, 1491, 1492, 1493, 1494, 1495, 1496, 1497, 1498, 1501, 1502, 1503, 1504, 1505, 1506, 1507
   - Frames sha256: `fb095677372d3e80d860a8a00b4bf653061a9c4e5faddaefc8720d8fb5ea988d`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — every write aimed at a read-only register is answered with Modbus exception 2, 3 or 4, and each targeted register keeps its pre-write value
   - Method: FC 6 write of a changed value to three read-only registers of different kinds (model header, scale factor, rating or measurement), each followed by an FC 3 read-back
   - Observed: 1.ID (model header register): FC 6 to 40002 returned exception 0x02 (illegal data address); the register still reads 0x0001; 1.DA (read-only point): FC 6 to 40068 returned exception 0x02 (illegal data address); the register still reads 0x0001; 703.V_SF (scale factor): FC 6 to 40087 returned exception 0x02 (illegal data address); the register still reads 0xffff
   - Frames: 1494, 1495, 1496, 1497, 1498, 1501, 1502, 1503, 1504, 1505, 1506, 1507
   - Frames sha256: `290b6ccd0cccf70abbe6502b8b0589137a7ef01ed42df89d67a905a87461621c`

### ✓ ss-modbus-conf-v1.4::EXC-1 Invalid Value — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.8.1 EXC-1 - Invalid Value (under 2.8 Exception Generation Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 704.WMaxLimPctEna: writing 255 returned exception 0x03 (illegal data value); the point still reads 1; 704.WMaxLimPct: writing 65534 returned exception 0x03 (illegal data value); the point still reads 6250

Frame attribution: 95 frame(s) (1510–1636), precision connection; 135 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48844 <> 192.168.0.69:802 (EXC-1 invalid value).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48844 <> 192.168.0.69:802, 33 request records / 36 response records, 54 ADUs recovered
   - Frames: 1550, 1554, 1556, 1560, 1561, 1562, 1563, 1564, 1565, 1566, 1567, 1568, 1569, 1570, 1571, 1572, 1573, 1576, 1577, 1578, 1579, 1580, 1581, 1582, 1583, 1584, 1585, 1586, 1587, 1588, 1589, 1592, 1593, 1594, 1595, 1596, 1597, 1598, 1599, 1600, 1601, 1602, 1603, 1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1616
   - Frames sha256: `76b6cbd9c8baa2d0048dfa32f603c4abf155cf4ea1afe521442fe191b60101d7`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — a valid, in-range write to the point EXC-1 targets is accepted, establishing that a refusal of an INVALID value is the exception ladder and not a policy denial
   - Method: FC 6 write of the point's own current value, changing nothing
   - Observed: the control write was accepted
   - Frames: 1597, 1598, 1599, 1600
   - Frames sha256: `18781832acb799842a370301a421156e7b450659fbb8d6d16ae24de4947f70e4`
3. **PASS** — EXC-1: writing the invalid value 255 to 704.WMaxLimPctEna is answered with Modbus exception 2, 3 or 4, and the point is not written
   - Method: FC 6 write of a value outside the point's symbol set or range (the DER model definition gives this enum exactly two values, DISABLED = 0 and ENABLED = 1; 255 is outside the symbol set, and the Device specification requires values outside a point's symbol set to be treated as invalid), followed by an FC 3 read-back of the same point
   - Observed: writing 255 returned exception 0x03 (illegal data value); the point still reads 1
   - Frames: 1597, 1598, 1599, 1600, 1601, 1602, 1603, 1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1616
   - Frames sha256: `d8efff15d3ae46d5d2df32ffafdcebf15bf266dfa7c2c4f6891cc85b54c548b1`
4. **PASS** — EXC-1: writing the invalid value 65534 to 704.WMaxLimPct is answered with Modbus exception 2, 3 or 4, and the point is not written
   - Method: FC 6 write of a value outside the point's symbol set or range (the point's units are percent of maximum active power; 65534 raw is outside the 0..100 % range whatever the reported scale factor, short of the not-implemented sentinel), followed by an FC 3 read-back of the same point
   - Observed: writing 65534 returned exception 0x03 (illegal data value); the point still reads 6250
   - Frames: 1597, 1598, 1599, 1600, 1601, 1602, 1603, 1604, 1605, 1606, 1607, 1608, 1609, 1610, 1611, 1612, 1613, 1616
   - Frames sha256: `d8efff15d3ae46d5d2df32ffafdcebf15bf266dfa7c2c4f6891cc85b54c548b1`

### ✓ ss-modbus-conf-v1.4::MB-1 Modbus Single/Multiple Register Write — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.7.9 MB-1 - Modbus Single/Multiple Register Write (under 2.7 Modbus Protocol Tests / General Modbus Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): one FC 16 request wrote [0x0000 0x186b] to registers 40310..40311 and the read-back returned both; two FC 6 requests restored [0x0001 0x186a] to registers 40310..40311, each echoed and each read back

Frame attribution: 76 frame(s) (1619–1722), precision connection; 174 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48860 <> 192.168.0.69:802 (MB-1 single/multiple register write).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48860 <> 192.168.0.69:802, 29 request records / 32 response records, 52 ADUs recovered
   - Frames: 1647, 1649, 1651, 1653, 1654, 1655, 1656, 1657, 1658, 1661, 1662, 1663, 1664, 1667, 1668, 1669, 1670, 1671, 1672, 1674, 1675, 1678, 1679, 1680, 1681, 1683, 1684, 1685, 1686, 1687, 1688, 1689, 1690, 1691, 1692, 1693, 1694, 1697, 1698, 1699, 1700, 1701, 1702, 1703, 1704, 1705, 1706, 1707, 1708, 1711, 1712, 1713
   - Frames sha256: `c0daabb32cacbcbcbc5fcbdefcfcc55a3901cfdfd672a330a50b8819ca56a27a`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — a Function Code 16 request covering two consecutive read-write points is accepted and both points read back the values it wrote
   - Method: one FC 16 write of two registers at the model 704 WMaxLimPctEna / WMaxLimPct pair, followed by an FC 3 read of the same two registers
   - Observed: one FC 16 request wrote [0x0000 0x186b] to registers 40310..40311 and the read-back returned both
   - Frames: 1698, 1699, 1700, 1701, 1702, 1703, 1704, 1705, 1706, 1707, 1708, 1711, 1712, 1713
   - Frames sha256: `4913d0c2b910817e5317b52aff18f4b6bb1ad8d4b96dd173f1cbff9012fa2027`
3. **PASS** — two Function Code 6 requests, one per point, are each accepted and each point reads back the value it was written
   - Method: two FC 6 writes, each to one register, each response checked for the address-and-value echo, each followed by an FC 3 read of that register
   - Observed: two FC 6 requests restored [0x0001 0x186a] to registers 40310..40311, each echoed and each read back
   - Frames: 1698, 1699, 1700, 1701, 1702, 1703, 1704, 1705, 1706, 1707, 1708, 1711, 1712, 1713
   - Frames sha256: `4913d0c2b910817e5317b52aff18f4b6bb1ad8d4b96dd173f1cbff9012fa2027`

### ✓ ss-modbus-conf-v1.4::MOD-3 Point Write — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.4.3 MOD-3 - Point Write (under 2.4 General SunSpec Model Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): 4 of 4 adjustable point(s) exercised

Frame attribution: 144 frame(s) (1716–1894), precision connection; 181 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48868 <> 192.168.0.69:802 (MOD-3 point write).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48868 <> 192.168.0.69:802, 63 request records / 66 response records, 114 ADUs recovered
   - Frames: 1743, 1748, 1750, 1751, 1752, 1753, 1754, 1755, 1756, 1757, 1758, 1759, 1760, 1761, 1762, 1765, 1766, 1767, 1768, 1769, 1770, 1771, 1772, 1773, 1774, 1777, 1778, 1779, 1780, 1782, 1783, 1784, 1785, 1786, 1787, 1788, 1789, 1790, 1791, 1795, 1796, 1797, 1798, 1801, 1802, 1803, 1804, 1805, 1806, 1807, 1808, 1811, 1812, 1813, 1814, 1815, 1816, 1817, 1818, 1819, 1820, 1821, 1822, 1823, 1824, 1825, 1826, 1827, 1828, 1831, 1832, 1833, 1834, 1835, 1836, 1837, 1838, 1839, 1840, 1843, 1844, 1845, 1846, 1847, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855, 1856, 1857, 1858, 1859, 1860, 1861, 1862, 1865, 1866, 1867, 1868, 1871, 1872, 1873, 1874, 1875, 1876, 1877, 1878, 1882, 1883, 1884
   - Frames sha256: `23cff1a36c448ce08f9d45057a581fd3023475e8281b66afa1a7fd1650f60b8f`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — MOD-3.704: the adjustable point 704.WMaxLimPct accepts every value in its range and reads back exactly what was written
   - Method: FC 6 / FC 16 write of each value followed immediately by an FC 3 read of the same point, with no settling delay allowed (v1.3 removed v1.2's 1000 ms allowance); the value set is the point's minimum, maximum and three intermediates, or its full enumeration
   - Observed: 5 value(s) [0 2500 5000 7500 10000] written and read back exactly; range source: the point's declared units are Pct (percent of maximum active power); the limit-active-power function is defined over 0..100 %, and the bound is converted through the WMaxLimPct_SF the device itself reports
   - Frames: 1791, 1795, 1796, 1797, 1798, 1801, 1802, 1803, 1804, 1805, 1806, 1807, 1808, 1811, 1812, 1813, 1814, 1815, 1816, 1817, 1818, 1819, 1820, 1821, 1822, 1823
   - Frames sha256: `a0a482c4ff498891ae47d051bb4880f908339b738dca8b23bfbc2a5c02e64201`
3. **PASS** — MOD-3.704: the adjustable point 704.WMaxLimPctRvrtTms accepts every value in its range and reads back exactly what was written
   - Method: FC 6 / FC 16 write of each value followed immediately by an FC 3 read of the same point, with no settling delay allowed (v1.3 removed v1.2's 1000 ms allowance); the value set is the point's minimum, maximum and three intermediates, or its full enumeration
   - Observed: 5 value(s) [0 900 1800 2700 3600] written and read back exactly; range source: uint32 seconds with no scale factor; the sweep is bounded at one hour so a conformance run stays finite, and 0 is the defined 'no automatic reversion' value
   - Frames: 1826, 1827, 1828, 1831, 1832, 1833, 1834, 1835, 1836, 1837, 1838, 1839, 1840, 1843, 1844, 1845, 1846, 1847, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855
   - Frames sha256: `54911673bd595c7cdb599c751aef1bce50aa84824206212b69949a45b665493d`
4. **PASS** — MOD-3.704 step 3: the enumerated point 704.WMaxLimPctEna accepts every supported enumeration value
   - Method: FC 6 / FC 16 write of each value followed immediately by an FC 3 read of the same point, with no settling delay allowed (v1.3 removed v1.2's 1000 ms allowance); the value set is the point's minimum, maximum and three intermediates, or its full enumeration
   - Observed: 2 value(s) [0 1] written and read back exactly; range source: the DER model definition's enumeration for every *Ena point: DISABLED = 0, ENABLED = 1
   - Frames: 1858, 1859, 1860, 1861, 1862, 1865, 1866, 1867, 1868, 1871, 1872, 1873, 1874, 1875
   - Frames sha256: `bd6f7204767c1d5193c77573200e2e8e880169320c25891119af9fa5b03fd78d`
5. **PASS** — MOD-3: adjustable points can be written as a group in a single FC 16 request and read back
   - Method: one FC 16 request covering two consecutive adjustable points, followed by an FC 3 read of the same two registers
   - Observed: one FC 16 request wrote WMaxLimPctEna and WMaxLimPct at 40310..40311 and the read-back returned both values exactly
   - Frames: 1876, 1877, 1878, 1882, 1883, 1884
   - Frames sha256: `0bc5adb657bad74a7b9d45f9b524c15598bcf981079b81371c5b7c749503635d`

### ✓ ss-modbus-conf-v1.4::TCP-3 Multiple TCP Packets — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.7.8 TCP-3 - Multiple TCP Packets (under 2.7 Modbus Protocol Tests / Modbus TCP)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT reassembled the two segments and answered FC 3 with 0x5375 0x6e53

Frame attribution: 64 frame(s) (1887–1970), precision connection; 134 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48870 <> 192.168.0.69:802 (TCP-3 request split across two segments).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:48870 <> 192.168.0.69:802, 23 request records / 25 response records, 38 ADUs recovered
   - Frames: 1910, 1913, 1915, 1917, 1918, 1919, 1920, 1921, 1922, 1923, 1924, 1925, 1926, 1929, 1930, 1931, 1932, 1933, 1934, 1935, 1936, 1939, 1940, 1941, 1942, 1943, 1944, 1945, 1946, 1948, 1949, 1950, 1951, 1952, 1953, 1954, 1955, 1957, 1960
   - Frames sha256: `de8b7bd571002b51961822de9e04042fbaefd81da79f478547401284a753cf2c`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — a Modbus request divided across two segments is reassembled by the DUT into one request and answered with a single normal response echoing its transaction identifier
   - Method: one FC 3 request written in two parts split inside the seven-byte MBAP header, with a pause between them; the response is read back out of the capture
   - Observed: one response on the wire, pdu 03 04 53 75 6e 53, transaction id 0x0013
   - Frames: 1955, 1957, 1960
   - Frames sha256: `294728be8055ca30c6b3e7d91704020cc0b28820032d48a5092ed17422acf596`
3. **PASS** — the request genuinely arrived at the DUT in more than one piece, so the reassembly the first claim rests on was actually exercised
   - Method: the request's byte range in the reconstructed application stream is mapped back to the TLS records and capture frames that carried it
   - Observed: the 12-byte request occupied 2 TLS record(s) in 2 capture frame(s)
   - Frames: 1955, 1957, 1960
   - Frames sha256: `294728be8055ca30c6b3e7d91704020cc0b28820032d48a5092ed17422acf596`

### ✓ ss-modbus-conf-v1.4::TCP-2 Partial Request — PASS

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.7.7 TCP-2 - Partial Request (under 2.7 Modbus Protocol Tests / Modbus TCP)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): no usable response on the same connection: mbap: read header: wolfSSL_read returned -1: peer sent close notify alert (err=6); a complete request on a fresh connection was answered normally: 0x5375 0x6e53; waited 2.5s between the two writes

Frame attribution: 110 frame(s) (1964–2230), precision connection; 309 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:48874 <> 192.168.0.69:802 (TCP-2 partial request); tcp 192.168.0.188:54980 <> 192.168.0.69:802 (TCP-2 recovery connection).

1. **PASS** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:48874 <> 192.168.0.69:802, 25 request records / 27 response records, 37 ADUs recovered
   - Frames: 1996, 2001, 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2031, 2032, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2045, 2046, 2183
   - Frames sha256: `8b9a53efa70d1a74b2280f8a07700afb99e52322bbdaee91bbeb96d141a2d553`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs
2. **PASS** — an incomplete Modbus request really was sent: a complete MBAP header whose length field promises more bytes than were written
   - Method: the truncated frame's byte range in the reconstructed request stream, compared against the MBAP length field inside it
   - Observed: 00 13 00 00 00 06 01 03 — the MBAP length field promises 6 bytes after it and only 2 were written
   - Frames: 2046
   - Frames sha256: `753d3842443a518cd239ab210d60eb2926555e6769aa7839f1b03a3c8364205e`
   - Note: 2.5s after the truncated frame (the candidate's declared MBAP frame budget 2s, from /home/dmitri/projects/lexa-gw/configs/candidate.json secure_sunspec.frame_budget_ms, plus a 500ms margin), so the DUT's budget has certainly expired before the follow-up is written and the follow-up cannot be read as the continuation of the truncated frame
3. **PASS** — no Modbus response was returned under the truncated frame's transaction identifier: the DUT did not mis-parse the following request as that frame's missing tail
   - Method: the transaction identifier of the response read back after the follow-up request, compared against the truncated frame's 0x0013
   - Observed: no response arrived under 0x0013
   - Frames: 2046, 2183
   - Frames sha256: `c3e00aa7bcda9ebdb55a047297bfe9e6a6db4860c2f74ed1ee7ce0870894bc12`
4. **PASS** — after an incomplete request the DUT recovers, and a following complete, well-formed request receives a successful response
   - Method: FC 3 request on a second session established after the truncated frame; its own conversation is reconstructed from the capture and cited separately
   - Observed: no usable response on the same connection: mbap: read header: wolfSSL_read returned -1: peer sent close notify alert (err=6); a complete request on a fresh connection was answered normally: 0x5375 0x6e53
   - Frames: 2217, 2218
   - Frames sha256: `739799bf27242c301f866c6562530bd5dd369e4593f8d9101efaf4a6af028aa7`
   - Note: SS-MODBUS-CONF v1.4 §2.7.7 does not state whether the second request may be sent on the same connection, whether the DUT may close the connection after a partial request, or how long the harness should wait — the catalog's own note directs that the connection-close behaviour be recorded as an OBSERVATION rather than as a failure, and it is recorded here as one

### · ss-modbus-conf-v1.4::REV-1 Reversion Timeout — SKIP

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.6.1 REV-1 - Reversion Timeout (under 2.6 Reversion Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)

Frame attribution: 75 frame(s) (2221–2315), precision connection; 142 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:54994 <> 192.168.0.69:802 (REV-1 reversion timeout).

1. **SKIP** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:54994 <> 192.168.0.69:802, 25 request records / 28 response records, 38 ADUs recovered
   - Frames: 2251, 2258, 2260, 2261, 2262, 2264, 2265, 2267, 2268, 2269, 2270, 2271, 2272, 2275, 2276, 2277, 2278, 2279, 2280, 2281, 2282, 2285, 2286, 2289, 2290, 2291, 2292, 2294, 2295, 2298, 2299, 2300, 2301, 2302, 2303, 2304, 2305, 2306
   - Frames sha256: `0e96b3e040057aae3893c1fb4934b73e4b071a4bd47cb3ab797732682fff419d`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs; recorded as context; this test case was not exercised, so nothing here is claimed as a conformance result
2. **SKIP** — every reversion point the timer needs is implemented in the model
   - Method: FC 3 read of model 704's register block; each reversion point compared against its type's not-implemented sentinel
   - Observed: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value) — so no reversion timer is implemented in this model and §2.6's gate applies: these tests are NOT PERFORMED
   - Frames: 2305, 2306
   - Frames sha256: `a700f26bc4a852fed72ee427fddb912dbb111deb773e65d3d303102a3db57f71`
   - Note: SS-MODBUS-CONF-v1.4 §2.6, the section preamble: "Reversion tests verify the reversion timer functionality. IF THIS FUNCTIONALITY IS NOT IMPLEMENTED IN A MODEL, THE TESTS ARE NOT PERFORMED. The following tests must be performed for each reversion timer that is implemented." REV-1 step 1 then scopes itself further — "all reversion points are implemented for the reversion timer SPECIFIED IN THE PICS". With no implemented reversion timer and no PICS declaring one, these tests are not applicable: the finding below is recorded as context, not as a conformance result. Supply -param pics.reversion-timer=1 when the PICS DOES declare this timer, and the same observation becomes a FAIL.
3. **SKIP** — the reversion-time-remaining point tracks the countdown to within two seconds, sampled at least three times
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **SKIP** — the reversion timer expires within two seconds of the programmed reversion time
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
5. **SKIP** — the reversion settings are in effect once the timer has expired
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### · ss-modbus-conf-v1.4::REV-2 Reversion Time Update — SKIP

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.6.2 REV-2 - Reversion Time Update (under 2.6 Reversion Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)

Frame attribution: 62 frame(s) (2309–2385), precision connection; 179 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55000 <> 192.168.0.69:802 (REV-2 reversion time update).

1. **SKIP** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 (resumed) MFL=1, 192.168.0.188:55000 <> 192.168.0.69:802, 22 request records / 25 response records, 38 ADUs recovered
   - Frames: 2331, 2335, 2337, 2338, 2339, 2340, 2341, 2342, 2343, 2344, 2345, 2346, 2347, 2348, 2349, 2350, 2351, 2354, 2355, 2356, 2357, 2358, 2359, 2360, 2361, 2364, 2365, 2366, 2367, 2368, 2369, 2370, 2371, 2372, 2373, 2374, 2375, 2376
   - Frames sha256: `128b026090f87a4b3310ff3ff28b83cf02f35569055aeadba0db3a5fa7b3ceeb`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs; recorded as context; this test case was not exercised, so nothing here is claimed as a conformance result
2. **SKIP** — every reversion point the timer needs is implemented in the model
   - Method: FC 3 read of model 704's register block; each reversion point compared against its type's not-implemented sentinel
   - Observed: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value) — so no reversion timer is implemented in this model and §2.6's gate applies: these tests are NOT PERFORMED
   - Frames: 2375, 2376
   - Frames sha256: `578e2df1ba55670b3bdd06aa3f3e04c7c825570e6d977e2720c0f00c2c2591e1`
   - Note: SS-MODBUS-CONF-v1.4 §2.6, the section preamble: "Reversion tests verify the reversion timer functionality. IF THIS FUNCTIONALITY IS NOT IMPLEMENTED IN A MODEL, THE TESTS ARE NOT PERFORMED. The following tests must be performed for each reversion timer that is implemented." REV-1 step 1 then scopes itself further — "all reversion points are implemented for the reversion timer SPECIFIED IN THE PICS". With no implemented reversion timer and no PICS declaring one, these tests are not applicable: the finding below is recorded as context, not as a conformance result. Supply -param pics.reversion-timer=1 when the PICS DOES declare this timer, and the same observation becomes a FAIL.
3. **SKIP** — rewriting the reversion time mid-countdown restarts the countdown, and the remaining-time readback tracks the updated time to within two seconds
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **SKIP** — the reversion settings are NOT applied at the original timeout instant once the time has been updated
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### · ss-modbus-conf-v1.4::REV-3 Reversion Cancel — SKIP

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.6.3 REV-3 - Reversion Cancel (under 2.6 Reversion Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)

Frame attribution: 72 frame(s) (2379–2468), precision connection; 185 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55006 <> 192.168.0.69:802 (REV-3 reversion cancel).

1. **SKIP** — the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, because the DUT exposes no plain Modbus interface
   - Method: TLS record parse and decryption of the attributed session with the run's NSS key log; the Modbus ADUs cited elsewhere in this test case are the recovered plaintext
   - Observed: TLSv1.3 TLS13-AES128-GCM-SHA256 MFL=1, 192.168.0.188:55006 <> 192.168.0.69:802, 25 request records / 28 response records, 38 ADUs recovered
   - Frames: 2408, 2413, 2415, 2416, 2417, 2419, 2420, 2421, 2422, 2423, 2424, 2425, 2426, 2427, 2428, 2432, 2433, 2434, 2435, 2436, 2437, 2438, 2439, 2440, 2441, 2442, 2443, 2444, 2445, 2448, 2449, 2450, 2451, 2452, 2453, 2454, 2455, 2456
   - Frames sha256: `1409f29a5eef1f7a872c991bfcae9e8e17032d0fcc11252e5508f2523d7bd9fe`
   - Note: TRANSPORT DEVIATION from the source procedure, which specifies Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, so the ADUs are the procedure's ADUs; recorded as context; this test case was not exercised, so nothing here is claimed as a conformance result
2. **SKIP** — every reversion point the timer needs is implemented in the model
   - Method: FC 3 read of model 704's register block; each reversion point compared against its type's not-implemented sentinel
   - Observed: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value) — so no reversion timer is implemented in this model and §2.6's gate applies: these tests are NOT PERFORMED
   - Frames: 2455, 2456
   - Frames sha256: `0d2a86cb803dd6281953a2edbb8020a42b399926a807c294cc78cd5de7d0d17f`
   - Note: SS-MODBUS-CONF-v1.4 §2.6, the section preamble: "Reversion tests verify the reversion timer functionality. IF THIS FUNCTIONALITY IS NOT IMPLEMENTED IN A MODEL, THE TESTS ARE NOT PERFORMED. The following tests must be performed for each reversion timer that is implemented." REV-1 step 1 then scopes itself further — "all reversion points are implemented for the reversion timer SPECIFIED IN THE PICS". With no implemented reversion timer and no PICS declaring one, these tests are not applicable: the finding below is recorded as context, not as a conformance result. Supply -param pics.reversion-timer=1 when the PICS DOES declare this timer, and the same observation becomes a FAIL.
3. **SKIP** — writing 0 to the reversion time takes the reversion-time-remaining point to 0
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **SKIP** — the reversion settings are never applied after the timer has been cancelled, past the instant the original timer would have fired
   - Method: drive the reversion timer and poll its remaining-time readback
   - Observed: the reversion group is incomplete: WMaxLimPctRvrt (reads its type's not-implemented value), WMaxLimPctRvrtRem (reads its type's not-implemented value), WMaxLimPctEnaRvrt (reads its type's not-implemented value)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-test-pki::PKI-1 TLS with digital certificates is mandatory for all CSIP data connections — PASS

Reference: SS-TEST-PKI current §1 Overview

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): connection to 192.168.0.69:802 as read-only: TLS 1.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 25 frame(s) (2459–2491), precision connection; 190 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55016 <> 192.168.0.69:802 (PKI-1 mandatory TLS on the DUT's data port).

1. **PASS** — the bench's data connection to the DUT began with a TLS handshake, not a cleartext application protocol
   - Method: TLS record-layer dissection of the first bytes of the reassembled bench->DUT direction
   - Observed: record type handshake, legacy version TLS 1.0, 202-byte fragment; ClientHello offering 10 cipher suite(s), max version TLS 1.2
   - Frames: 2466
   - Stream: `192.168.0.188:55016 > 192.168.0.69:802` bytes [0,207)
   - Bytes sha256: `7ad82b270748e11717775142701a44a815d6545c51b050e77a998cf87c647515`
2. **PASS** — every byte the bench sent on the data connection was carried inside a TLS record: no cleartext CSIP or Modbus payload appears outside the tunnel
   - Method: TLS record-layer walk over the entire reassembled bench->DUT direction
   - Observed: 1361 byte(s) reassembled into 6 complete TLS record(s), 0 bytes outside the record layer
   - Frames: 2466, 2481
   - Stream: `192.168.0.188:55016 > 192.168.0.69:802` bytes [0,1361)
   - Bytes sha256: `8b1df6c4a8d952018d2272589dec2c53a99a18aa7434f33e4a3b964cf9b738b1`
3. **PASS** — the DUT presented an X.509 certificate chain on the data connection
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: chain of 3 certificate(s): depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2471
   - Stream: `192.168.0.69:802 > 192.168.0.188:55016` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
4. **PASS** — the DUT demanded a certificate from the bench, so the connection is mutually authenticated rather than server-authenticated
   - Method: CertificateRequest handshake message located in the DUT's plaintext handshake flight
   - Observed: the DUT sent CertificateRequest
   - Frames: 2477
   - Frames sha256: `c3beedfee4e1dd18bf84f19fc7d47dfcd3b2ba9eaf739d6c0d6280d285c44da2`
5. **SKIP** — the DUT's own northbound IEEE 2030.5 client connection is likewise carried over TLS
   - Method: frame attribution (time AND connection 4-tuple)
   - Observed: the DUT initiates its northbound 2030.5 connection to the bench's gridsim, so this check never holds that socket and cannot claim its 4-tuple; asserting it here would mean attributing frames this check did not cause. The csip-client suite covers that leg
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ss-test-pki::PKI-8 Test environment topology: DUT configured with a single certificate chain, framework emulates the peer — PASS

Reference: SS-TEST-PKI current §3 Using Test Certificates

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT presented one chain across 3 connections

Frame attribution: 77 frame(s) (2492–2578), precision connection; 209 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55018 <> 192.168.0.69:802 (PKI-8 connection 1 of 3 as grid-service); tcp 192.168.0.188:55034 <> 192.168.0.69:802 (PKI-8 connection 2 of 3 as lexavolt-read-only); tcp 192.168.0.188:55040 <> 192.168.0.69:802 (PKI-8 connection 3 of 3 as net-admin).

1. **PASS** — on connection 1 of 3 the DUT presented chain sha256 00ba3ca537cc7b11
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2499
   - Stream: `192.168.0.69:802 > 192.168.0.188:55018` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
2. **PASS** — on connection 2 of 3 the DUT presented chain sha256 00ba3ca537cc7b11
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2530
   - Stream: `192.168.0.69:802 > 192.168.0.188:55034` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
3. **PASS** — on connection 3 of 3 the DUT presented chain sha256 00ba3ca537cc7b11
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2557
   - Stream: `192.168.0.69:802 > 192.168.0.188:55040` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
4. **PASS** — the DUT presented the same device certificate and chain on every connection in this run
   - Method: sha256 of the concatenated chain DER from each connection's Certificate message, compared
   - Observed: the DUT presented chain sha256 00ba3ca537cc7b11 on all 3 connections
   - Frames: 2492, 2494, 2495, 2496, 2497, 2498, 2499, 2500, 2501, 2502, 2505, 2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513, 2514, 2515, 2516, 2517, 2518, 2519, 2520, 2521, 2522, 2523, 2524, 2525, 2528, 2529, 2530, 2531, 2532, 2533, 2534, 2535, 2536, 2537, 2538, 2539, 2540, 2541, 2542, 2543, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2552, 2555, 2556, 2557, 2558, 2559, 2560, 2561, 2562, 2563, 2564, 2565, 2566, 2567, 2568, 2569, 2570, 2571, 2575, 2576, 2577, 2578
   - Frames sha256: `0b071f09eee6167f5a18940c11ac9c2e4bac9440b08517263552c3876bec55a4`
5. **PASS** — the test framework, not the DUT, is what varied the certificate material across connections
   - Method: sha256 of the bench's own chain from each connection's Certificate message, compared
   - Observed: the bench presented 3 distinct chains across 3 connections
   - Frames: 2492, 2494, 2495, 2496, 2497, 2498, 2499, 2500, 2501, 2502, 2505, 2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513, 2514, 2515, 2516, 2517, 2518, 2519, 2520, 2521, 2522, 2523, 2524, 2525, 2528, 2529, 2530, 2531, 2532, 2533, 2534, 2535, 2536, 2537, 2538, 2539, 2540, 2541, 2542, 2543, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2552, 2555, 2556, 2557, 2558, 2559, 2560, 2561, 2562, 2563, 2564, 2565, 2566, 2567, 2568, 2569, 2570, 2571, 2575, 2576, 2577, 2578
   - Frames sha256: `0b071f09eee6167f5a18940c11ac9c2e4bac9440b08517263552c3876bec55a4`

### ✓ ss-test-pki::PKI-11 Device under test should use the mca-mica-dev certificate chain — PASS

Reference: SS-TEST-PKI current §3.1 Test Certificate Package

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT presented the 3-certificate mca-mica-dev chain

Frame attribution: 25 frame(s) (2572–2605), precision connection; 165 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55044 <> 192.168.0.69:802 (PKI-11 provisioned chain depth).

1. **PASS** — the DUT is provisioned on the mca-mica-dev chain — device certificate issued by a MICA, itself issued by an MCA — which is the most complex compliant chain and therefore the best demonstration of compliant chain support
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: the Certificate message carries 3 certificates: depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2584
   - Stream: `192.168.0.69:802 > 192.168.0.188:55044` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
2. **PASS** — every link of the chain the DUT presented holds: the issuer DN, the authority/subject key identifier pair, and the signature
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: "CN=lexa-gw-nb-mbaps-server" <- "CN=csip-tls-test bench mbaps Intermediate CA": issuer DN true, key id true, signature true; "CN=csip-tls-test bench mbaps Intermediate CA" <- "CN=csip-tls-test bench mbaps Root CA": issuer DN true, key id true, signature true
   - Frames: 2584
   - Stream: `192.168.0.69:802 > 192.168.0.188:55044` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`

### ⚠ ss-test-pki::PKI-19 Certificate authority hierarchy: SERCA, MCA, MICA and the three valid device chains — WARN

Reference: SS-TEST-PKI current §3.1.2 Certificate Authorities

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's own chain was dissected from the capture; the DUT accepted all 3 chain depths anchored at its own trust anchor; VERDICT RECONCILED — the live phase declared PASS from what the socket saw; the citation phase re-derived the criteria from the capture and the case is WARN. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 103 frame(s) (2601–2720), precision connection; 144 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55046 <> 192.168.0.69:802 (PKI-19 chain the DUT presents); tcp 192.168.0.188:55052 <> 192.168.0.69:802 (PKI-19 present a serca-device chain); tcp 192.168.0.188:55054 <> 192.168.0.69:802 (PKI-19 present a serca-mica-device chain); tcp 192.168.0.188:55068 <> 192.168.0.69:802 (PKI-19 present a serca-mca-mica-device chain).

1. **WARN** — the chain the DUT presents is one of the three valid IEEE 2030.5 chains (serca-device, serca-mica-device, serca-mca-mica-device) and each CA in it is issued by the CA above it
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: presented shape serca-mca-mica-device at depth 3: depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA — the top certificate (CN=csip-tls-test bench mbaps Root CA) is self-issued: the sender included its trust anchor in-band, so the presented depth 3 is one more than the chain's issuing depth
   - Frames: 2611
   - Stream: `192.168.0.69:802 > 192.168.0.188:55046` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
2. **PASS** — every link of the chain the DUT presented holds: the issuer DN, the authority/subject key identifier pair, and the signature
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: "CN=lexa-gw-nb-mbaps-server" <- "CN=csip-tls-test bench mbaps Intermediate CA": issuer DN true, key id true, signature true; "CN=csip-tls-test bench mbaps Intermediate CA" <- "CN=csip-tls-test bench mbaps Root CA": issuer DN true, key id true, signature true
   - Frames: 2611
   - Stream: `192.168.0.69:802 > 192.168.0.188:55046` bytes [96,1494)
   - Bytes sha256: `a8ba31492d74aaeb0abf3cee41440e6debad4c526bdd38f9b8ff98d840634ab0`
3. **PASS** — the bench presented a serca-device chain to the DUT
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 1 (serca-device): CN=suitepki serca-device client
   - Frames: 2653
   - Stream: `192.168.0.188:55052 > 192.168.0.69:802` bytes [207,695)
   - Bytes sha256: `7abc6223bf4df76539cb08a5e9788c2275e4d22af7d26863905a271d277441cc`
4. **PASS** — the bench presented a serca-mica-device chain to the DUT
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 2 (serca-mica-device): CN=suitepki serca-mica-device client <- CN=suitepki chain-depth MICA (SERCA-issued)
   - Frames: 2680
   - Stream: `192.168.0.188:55054 > 192.168.0.69:802` bytes [207,1164)
   - Bytes sha256: `bd34fc8afa1a860f43dad05e4ed6a0c96378fb64c142d7b127d4b1600ee58009`
5. **PASS** — the bench presented a serca-mca-mica-device chain to the DUT
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: depth 3 (serca-mca-mica-device): CN=suitepki serca-mca-mica-device client <- CN=suitepki chain-depth MICA <- CN=suitepki chain-depth MCA
   - Frames: 2706
   - Stream: `192.168.0.188:55068 > 192.168.0.69:802` bytes [207,1570)
   - Bytes sha256: `959588e947238bc2d1c957310951a4b0bbe9c219564817c451896b7f8f007005`
6. **PASS** — the DUT validates device certificates at all three IEEE 2030.5 chain depths when they are anchored at the trust anchor it is configured with
   - Method: a leaf presented at each of the three IEEE 2030.5 chain depths, all anchored at the bench root the DUT's trust domain is configured with; the handshake outcome is the observable
   - Observed: serca-device (depth 1 (serca-device): CN=suitepki serca-device client): accepted; serca-mica-device (depth 2 (serca-mica-device): CN=suitepki serca-mica-device client <- CN=suitepki chain-depth MICA (SERCA-issued)): accepted; serca-mca-mica-device (depth 3 (serca-mca-mica-device): CN=suitepki serca-mca-mica-device client <- CN=suitepki chain-depth MICA <- CN=suitepki chain-depth MCA): accepted
   - Frames: 2601, 2606, 2607, 2608, 2609, 2610, 2611, 2612, 2613, 2614, 2615, 2616, 2617, 2618, 2619, 2620, 2621, 2626, 2627, 2628, 2629, 2630, 2633, 2634, 2635, 2636, 2637, 2638, 2639, 2640, 2641, 2642, 2643, 2644, 2645, 2646, 2647, 2648, 2649, 2650, 2651, 2652, 2653, 2656, 2657, 2658, 2659, 2660, 2661, 2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670, 2671, 2672, 2673, 2674, 2675, 2676, 2677, 2678, 2679, 2680, 2681, 2682, 2683, 2684, 2685, 2687, 2688, 2689, 2690, 2691, 2692, 2693, 2694, 2695, 2696, 2697, 2698, 2699, 2700, 2701, 2702, 2703, 2704, 2705, 2706, 2707, 2708, 2709, 2710, 2711, 2712, 2716, 2717, 2718, 2720
   - Frames sha256: `6e6b9dbefd025dde7ee4547321d1b24272a56241484e71c7b55760839ff6d3f1`

### ✓ ss-test-pki::PKI-3 Separate client and server certificate package types with different intermediate CAs — PASS

Reference: SS-TEST-PKI current §2.1 Device Type

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT completed a mutually-authenticated handshake with a peer whose chain is anchored at the bench root but issued by a second, freshly minted intermediate CA

Frame attribution: 26 frame(s) (2713–2758), precision connection; 154 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55082 <> 192.168.0.69:802 (PKI-3 peer chain under a second intermediate).

1. **PASS** — the bench's chain and the DUT's chain were issued by different intermediate CAs
   - Method: the peer's X.509 leaf lifted out of the TLS Certificate handshake message in the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS records carrying that message in the reassembled direction
   - Observed: bench intermediate 86c5b04fbf5210da, DUT intermediate 4ece7491aac2e57a — different certificates; bench chain depth 2 (serca-mica-device): CN=suitepki cross-issuer client <- CN=suitepki cross-issuer MICA; DUT chain depth 3 (serca-mca-mica-device): CN=lexa-gw-nb-mbaps-server <- CN=csip-tls-test bench mbaps Intermediate CA <- CN=csip-tls-test bench mbaps Root CA
   - Frames: 2735
   - Stream: `192.168.0.188:55082 > 192.168.0.69:802` bytes [207,1132)
   - Bytes sha256: `fefd17eefd4e3bbdfe99d8f10fc0ae3b789ba8b7f375f3f285717f400239e58c`
2. **PASS** — the DUT validates a peer certificate chain issued by an intermediate CA that is not the one that issued its own certificate
   - Method: outcome of the mutually-authenticated handshake, read from the capture's handshake flight and alert records
   - Observed: the handshake completed: the DUT accepted the chain
   - Frames: 2713, 2719, 2721, 2722, 2723, 2724, 2725, 2726, 2727, 2728, 2729, 2730, 2731, 2732, 2733, 2734, 2735, 2748, 2749, 2750, 2751, 2752, 2754, 2755, 2756, 2758
   - Frames sha256: `161c7cee6acba90b9cf1605c3c97013c2ff81721caead5bd5724d4c54a21f7c7`
   - Note: SHOULD-strength: the test-PKI document itself notes that IEEE 2030.5 draws no client/server certificate distinction and that separate intermediates are a SunSpec test-PKI convention adopted because it is desirable for testing

### ✓ ss-test-pki::PKI-20 Error certificates: device certificates on the serca-mica-device chain containing deliberate errors — PASS

Reference: SS-TEST-PKI current §3.1.2 Certificate Authorities

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT refused all 4 error certificates presented

Frame attribution: 84 frame(s) (2753–2854), precision connection; 133 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55084 <> 192.168.0.69:802 (PKI-20 present the expired fixture); tcp 192.168.0.188:55088 <> 192.168.0.69:802 (PKI-20 present the wrong-ca fixture); tcp 192.168.0.188:55096 <> 192.168.0.69:802 (PKI-20 present the minted expired fixture); tcp 192.168.0.188:55102 <> 192.168.0.69:802 (PKI-20 present the minted not-yet-valid fixture).

1. **PASS** — the DUT refused the expired error certificate (validity window ended in the past)
   - Method: present the fixture as the bench's client certificate and observe the handshake outcome and any TLS alert in the capture
   - Observed: refused: remote error: tls: expired certificate — server sent fatal certificate_expired in frame(s) [2777]
   - Frames: 2760, 2762, 2763, 2768, 2770, 2771, 2774, 2777
   - Frames sha256: `4b823f20fd0e9c7b3ff434be5ea249a1e8db2d11174282006934276325e0ff67`
   - Note: material: committed fixture certs/mbaps/negative/expired-cert.pem
2. **PASS** — the DUT refused the wrong-ca error certificate (issued by a root outside the DUT's trust domain)
   - Method: present the fixture as the bench's client certificate and observe the handshake outcome and any TLS alert in the capture
   - Observed: refused: remote error: tls: unknown certificate authority — server sent fatal unknown_ca in frame(s) [2800]
   - Frames: 2784, 2785, 2787, 2789, 2790, 2791, 2797, 2800
   - Frames sha256: `ca55e492d32492193eb81ceeaf1d3df29bcde3ca97be27f5d681bea643edb424`
   - Note: material: committed fixture certs/mbaps/negative/wrong-ca-cert.pem
3. **PASS** — the DUT refused the minted expired error certificate (validity window ended in the past)
   - Method: present the fixture as the bench's client certificate and observe the handshake outcome and any TLS alert in the capture
   - Observed: refused: remote error: tls: expired certificate — server sent fatal certificate_expired in frame(s) [2822]
   - Frames: 2807, 2809, 2810, 2813, 2815, 2816, 2819, 2822
   - Frames sha256: `73bf6443f38c5702ba01e0b12b4d785f022295eee9b39e49adf6ef431a12f85a`
   - Note: material: minted on a serca-mica-device chain under the bench root
4. **PASS** — the DUT refused the minted not-yet-valid error certificate (validity window begins in the future)
   - Method: present the fixture as the bench's client certificate and observe the handshake outcome and any TLS alert in the capture
   - Observed: refused: remote error: tls: unknown certificate — server sent fatal certificate_unknown in frame(s) [2847]
   - Frames: 2830, 2834, 2836, 2837, 2838, 2839, 2846, 2847
   - Frames sha256: `63f6cba26c67e45dbc2d59099801bfae7d1509bb6e9d4d82da24bc1e66709d6e`
   - Note: material: minted on a serca-mica-device chain under the bench root
5. **PASS** — the DUT refuses a device certificate carrying a deliberate error, terminating the handshake rather than completing it
   - Method: each deliberate-error certificate presented in turn as the bench's client certificate; the handshake outcome and any fatal alert are the observables
   - Observed: expired (validity window ended in the past): refused: remote error: tls: expired certificate — server sent fatal certificate_expired in frame(s) [2777]; wrong-ca (issued by a root outside the DUT's trust domain): refused: remote error: tls: unknown certificate authority — server sent fatal unknown_ca in frame(s) [2800]; minted expired (validity window ended in the past): refused: remote error: tls: expired certificate — server sent fatal certificate_expired in frame(s) [2822]; minted not-yet-valid (validity window begins in the future): refused: remote error: tls: unknown certificate — server sent fatal certificate_unknown in frame(s) [2847]
   - Frames: 2753, 2757, 2759, 2760, 2761, 2762, 2763, 2764, 2765, 2768, 2769, 2770, 2771, 2772, 2773, 2774, 2777, 2778, 2779, 2780, 2781, 2782, 2783, 2784, 2785, 2786, 2787, 2788, 2789, 2790, 2791, 2792, 2793, 2794, 2795, 2796, 2797, 2800, 2801, 2802, 2803, 2804, 2805, 2806, 2807, 2808, 2809, 2810, 2811, 2812, 2813, 2814, 2815, 2816, 2817, 2818, 2819, 2822, 2823, 2824, 2825, 2826, 2827, 2828, 2829, 2830, 2831, 2834, 2835, 2836, 2837, 2838, 2839, 2840, 2841, 2842, 2843, 2844, 2845, 2846, 2847, 2848, 2849, 2854
   - Frames sha256: `4f54240f00eccd3fbdd1492fe80552b056c8ee8d5ba532ccef864265a42e3cd3`
6. **PASS** — deliberate-error device certificates were available to present to the DUT
   - Method: inventory of the deliberate-error material this run presented
   - Observed: 4 fixture(s): expired, wrong-ca, minted expired, minted not-yet-valid
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: certs/mbaps/negative (committed, generated by `make gen-mbaps-certs`) and material minted in memory under the bench root for this run
7. **SKIP** — the DUT's rejection used the specific TLS alert the applicable test procedure requires
   - Method: TLS alert records in the capture, read in the clear
   - Observed: the SunSpec Test PKI document defines neither which errors are injected nor the alert a conformant device must answer with; that criterion belongs to the SunSpec CSIP 2030.5 Test Procedures and is not gradeable from this document. Alerts observed, for the record: expired: certificate_expired, wrong-ca: unknown_ca, minted expired: certificate_expired, minted not-yet-valid: certificate_unknown
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ssm-conf-v0.8::TLSF-001 TLS 1.2 Basic Operation [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.1 TLSF-001 - TLS 1.2 Basic Operation [C, S] (under 2.4 Tests for Transport Layer Security Fundamentals (TLSF))

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS iteration 1: reversed mandated order: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2 · ✓ PASS iteration 2: GCM withheld: ServerHello.cipher_suite = 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.2 · ✓ PASS iteration 3: CCM-8 only: ServerHello.cipher_suite = 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, negotiated version TLS 1.2 · ✓ PASS iteration 4: mandated order: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2 · ✓ PASS Model 1 read on unit 1 (chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]): normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing 

Frame attribution: 140 frame(s) (2850–3045), precision connection; 250 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55106 <> 192.168.0.69:802 (SSM probe: iteration 1: reversed mandated order); tcp 192.168.0.188:55114 <> 192.168.0.69:802 (SSM probe: iteration 2: GCM withheld); tcp 192.168.0.188:55128 <> 192.168.0.69:802 (SSM probe: iteration 3: CCM-8 only); tcp 192.168.0.188:55136 <> 192.168.0.69:802 (SSM probe: iteration 4: mandated order); tcp 192.168.0.188:55144 <> 192.168.0.69:802 (TLSF-001 completing TLS 1.2 mutual-auth session).

1. **PASS** — SunSpecTCP-17/19: offered [0xC0AE, 0xCCA9, 0xC02B], the EUT-S selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   - Method: TLS 1.2 ServerHello.cipher_suite, parsed from the capture (iteration 1: reversed mandated order)
   - Observed: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2
   - Frames: 2855
   - Frames sha256: `0ccd31e7292afa1b682c3b1805b36f4bd6c02ffdfbdf94145405c65c3840e221`
2. **PASS** — SunSpecTCP-17/19: offered [0xC0AE, 0xCCA9], the EUT-S selected 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
   - Method: TLS 1.2 ServerHello.cipher_suite, parsed from the capture (iteration 2: GCM withheld)
   - Observed: ServerHello.cipher_suite = 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.2
   - Frames: 2878
   - Frames sha256: `203d679d3ceece96ffedc8abfdd831be1a3b864c072f41f5c34f955a0acf7bef`
3. **PASS** — SunSpecTCP-17/19: offered [0xC0AE], the EUT-S selected 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
   - Method: TLS 1.2 ServerHello.cipher_suite, parsed from the capture (iteration 3: CCM-8 only)
   - Observed: ServerHello.cipher_suite = 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, negotiated version TLS 1.2
   - Frames: 2900
   - Frames sha256: `05e0bb46e9391c35e1ef44db42e31e4523e0bb7bc974610568461bc82d8ee836`
4. **PASS** — SunSpecTCP-17/19: offered [0xC02B, 0xCCA9, 0xC0AE], the EUT-S selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   - Method: TLS 1.2 ServerHello.cipher_suite, parsed from the capture (iteration 4: mandated order)
   - Observed: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2
   - Frames: 2922
   - Frames sha256: `7dfb6ba8669e04a871b31334db153baf243d4b91a0aa901613b1891157914586`
5. **PASS** — SunSpecTCP-4: the ClientHello offered legacy_version 0x0303 with an empty session_id and no supported_versions extension, and the EUT-S negotiated TLS 1.2
   - Method: ClientHello and ServerHello fields, parsed from the capture
   - Observed: ClientHello legacy_version 0x0303, session_id 0 byte(s), supported_versions ABSENT; ServerHello version 0x0303 (TLS 1.2)
   - Frames: 2921, 2922
   - Frames sha256: `cc77cd8d86035ddf320a7bbb5f56d65e909b12bbf09bcb99629e5c8a2dce50f3`
6. **PASS** — SunSpecTCP-1: the mbaps exchange took place on TCP port 802
   - Method: the destination port of the TCP conversation this check opened, from the capture
   - Observed: the bench dialled 192.168.0.69:802 and the conversation in the capture is 192.168.0.69:802 <> 192.168.0.188:55106
   - Frames: 2853, 2855, 2857, 2859, 2860, 2861
   - Frames sha256: `31a8a70e366449b3f88bbdbe36558611fda97a20ab967cd322f60055a6e4da06`
7. **PASS** — SunSpecTCP-6/10/12/13: the TLS 1.2 mutual-authentication handshake flight was exchanged in full
   - Method: handshake message types of both directions, parsed from the capture
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 2944, 2946, 2947, 2950, 2952, 2953, 2956, 2957, 2958, 2960, 2996, 2997, 2998, 2999, 3002, 3003, 3004, 3005, 3006, 3008, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3038
   - Frames sha256: `01b4805522c596f56d7bb13cdc81ce18ff63142ecb22e5700d2df5b1cfca0afa`
8. **PASS** — a SunSpec Common Model (Model 1) read was carried inside the established TLS session and answered
   - Method: TLS decryption of this session's records with the run's key log, then MBAP framing
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 2996
   - Frames sha256: `0888a389ab34e15ed8552942772f1962eab8997a0bbf8509c5803734ec80faa3`
9. **N/A** — SunSpecTCP-17/19 [C]: the gateway's own southbound ClientHello offers 0xC02B, 0xCCA9 and 0xC0AE in that relative order
   - Method: cipher_suites list of the gateway's ClientHello to the bench device sim, parsed from the capture
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::TLSF-002 TLS 1.3 Basic Operation [C, S] (Optional) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.2 TLSF-002 - TLS 1.3 Basic Operation [C, S] (Optional) (under 2.4 Tests for Transport Layer Security Fundamentals (TLSF))

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS iteration 1: reversed mandated order: ServerHello.cipher_suite = 0x1301 TLS_AES_128_GCM_SHA256, negotiated version TLS 1.3 · ✓ PASS iteration 2: AES-GCM withheld: ServerHello.cipher_suite = 0x1303 TLS_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.3 · ✓ PASS iteration 3: CCM only: ServerHello.cipher_suite = 0x1304 TLS_AES_128_CCM_SHA256, negotiated version TLS 1.3 · ✓ PASS Model 1 read on unit 1 (chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]): normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing 

Frame attribution: 129 frame(s) (3035–3185), precision connection; 143 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55150 <> 192.168.0.69:802 (SSM probe: iteration 1: reversed mandated order); tcp 192.168.0.188:55154 <> 192.168.0.69:802 (SSM probe: iteration 2: AES-GCM withheld); tcp 192.168.0.188:55158 <> 192.168.0.69:802 (SSM probe: iteration 3: CCM only); tcp 192.168.0.188:55160 <> 192.168.0.69:802 (TLSF-002 completing TLS 1.3 mutual-auth session).

1. **PASS** — SunSpecTCP-18/19: offered [0x1304, 0x1303, 0x1301] over TLS 1.3, the EUT-S selected 0x1301 TLS_AES_128_GCM_SHA256
   - Method: TLS 1.3 ServerHello.cipher_suite, parsed from the capture (iteration 1: reversed mandated order)
   - Observed: ServerHello.cipher_suite = 0x1301 TLS_AES_128_GCM_SHA256, negotiated version TLS 1.3
   - Frames: 3049
   - Frames sha256: `d26bfac0e517db77eb199103f4c722484a16ea528c53f3d901422ae940347965`
2. **PASS** — SunSpecTCP-18/19: offered [0x1304, 0x1303] over TLS 1.3, the EUT-S selected 0x1303 TLS_CHACHA20_POLY1305_SHA256
   - Method: TLS 1.3 ServerHello.cipher_suite, parsed from the capture (iteration 2: AES-GCM withheld)
   - Observed: ServerHello.cipher_suite = 0x1303 TLS_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.3
   - Frames: 3072
   - Frames sha256: `3bc48ba1f38b549788b0fcb083ee25c973ecfd628ced084a2b97f9d8dae1063a`
3. **PASS** — SunSpecTCP-18/19: offered [0x1304] over TLS 1.3, the EUT-S selected 0x1304 TLS_AES_128_CCM_SHA256
   - Method: TLS 1.3 ServerHello.cipher_suite, parsed from the capture (iteration 3: CCM only)
   - Observed: ServerHello.cipher_suite = 0x1304 TLS_AES_128_CCM_SHA256, negotiated version TLS 1.3
   - Frames: 3096
   - Frames sha256: `1925281cd33e25c9a4846d5f179783e20b3601616fb65afcaa97b9878e4c6db2`
4. **PASS** — SunSpecTCP-5: the ClientHello carried legacy_version 0x0303 with supported_versions 0x0304, and the EUT-S negotiated TLS 1.3 through the supported_versions extension
   - Method: ClientHello and ServerHello supported_versions extensions, parsed from the capture
   - Observed: ClientHello legacy_version 0x0303, supported_versions [772], session_id 0 byte(s); ServerHello legacy_version 0x0303, supported_versions 0x0304
   - Frames: 3047, 3049
   - Frames sha256: `20097ff59147a5984cc4a46db276dc2fe6cb38871f5324a64b35d3ecd1b74667`
5. **PASS** — under TLS 1.3 only ClientHello and ServerHello are cleartext; EncryptedExtensions, Certificate, CertificateVerify and Finished appear as opaque records
   - Method: record-type and cleartext-handshake scan of the DUT→bench direction
   - Observed: cleartext handshake messages from the DUT: [server_hello]; 5 opaque record(s) followed
   - Frames: 3047, 3049, 3051, 3052, 3053, 3054, 3055, 3056
   - Frames sha256: `447083244ea28bac247cfd175a86577f8ddee2309141fd59c87fc82f928f4c32`
6. **PASS** — a SunSpec Common Model (Model 1) read was carried inside the established TLS 1.3 session and answered
   - Method: TLS 1.3 decryption of this session's records with the run's key log, then MBAP framing
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 3137
   - Frames sha256: `7844ac0fcb40205917e1be41aab0c366a0a97de2523800ff5b37996c3905a5b9`
7. **N/A** — SunSpecTCP-18 [C]: the gateway's own southbound ClientHello offers 0x1301, 0x1303 and 0x1304 in that relative order
   - Method: cipher_suites list of the gateway's ClientHello to the bench device sim, parsed from the capture
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::TLSF-003 TLS 1.2 Bad Certificate Detection [S] (Negative Test) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.3 TLSF-003 - TLS 1.2 Bad Certificate Detection [S] (Negative Test) (under 2.4 Tests for Transport Layer Security Fundamentals (TLSF))

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS expired: the DUT rejected a client certificate whose validity period has passed — remote error: tls: expired certificate · ✓ PASS badsig: the DUT rejected a client certificate whose signature does not verify — remote error: tls: unknown certificate authority · ✓ PASS untrusted: the DUT rejected a client certificate issued by a CA outside the DUT's trust store — remote error: tls: unknown certificate authority

Frame attribution: 67 frame(s) (3178–3262), precision connection; 234 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55168 <> 192.168.0.69:802 (TLSF-003 negative: expired); tcp 192.168.0.188:55180 <> 192.168.0.69:802 (TLSF-003 negative: badsig); tcp 192.168.0.188:55192 <> 192.168.0.69:802 (TLSF-003 negative: untrusted).

1. **PASS** — SunSpecTCP-6/7/13/52: the EUT-S detected a client certificate whose validity period has passed and terminated the connection with a fatal TLS alert
   - Method: TLS record and alert scan of the DUT→bench direction of this connection
   - Observed: the DUT refused a client certificate whose validity period has passed with a fatal alert: level 2 (fatal), description 45 (certificate_expired)
   - Frames: 3202
   - Frames sha256: `cda7eee6db537a871a1883e3770b65bbba753f9f5045f319993d12f64b426055`
2. **PASS** — the EUT-S sent a CertificateRequest in the server flight of the expired handshake
   - Method: handshake message types of the DUT→bench direction
   - Observed: CertificateRequest: certificate_types [1 (rsa_sign), 64 (ecdsa_sign)], supported_signature_algorithms [0x0403 (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0501 (rsa_pkcs1_sha384), 0x0401 (rsa_pkcs1_sha256)], 3 certificate_authorities DN(s)
   - Frames: 3196
   - Frames sha256: `8150b48ba67210f447eab1a6280159e093b770520bd4211ba4c7f6ebbfae9380`
3. **PASS** — no TLS application_data record was exchanged after the EUT-S refused a client certificate whose validity period has passed
   - Method: record-type scan of the DUT→bench direction of this check's own conversation
   - Observed: the DUT→bench direction holds 6 TLS record(s) and none is application_data
   - Frames: 3188, 3189, 3191, 3195, 3196, 3197, 3201, 3202
   - Frames sha256: `76663fb13facb7d2353964b5f260797f251ffda4d2016c94ea835c8fb42c5802`
4. **PASS** — SunSpecTCP-6/7/13/52: the EUT-S detected a client certificate whose signature does not verify and terminated the connection with a fatal TLS alert
   - Method: TLS record and alert scan of the DUT→bench direction of this connection
   - Observed: the DUT refused a client certificate whose signature does not verify with a fatal alert: level 2 (fatal), description 48 (unknown_ca)
   - Frames: 3232
   - Frames sha256: `a0b453791f95e16a4354408bde7e7214f3bf1af126c4e45eaa93cc7505875a99`
5. **PASS** — the EUT-S sent a CertificateRequest in the server flight of the badsig handshake
   - Method: handshake message types of the DUT→bench direction
   - Observed: CertificateRequest: certificate_types [1 (rsa_sign), 64 (ecdsa_sign)], supported_signature_algorithms [0x0403 (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0501 (rsa_pkcs1_sha384), 0x0401 (rsa_pkcs1_sha256)], 3 certificate_authorities DN(s)
   - Frames: 3222
   - Frames sha256: `b1c233d2217e9237eb10f4f85a63148ae5314de93fa235813f2093675ad21847`
6. **PASS** — no TLS application_data record was exchanged after the EUT-S refused a client certificate whose signature does not verify
   - Method: record-type scan of the DUT→bench direction of this check's own conversation
   - Observed: the DUT→bench direction holds 6 TLS record(s) and none is application_data
   - Frames: 3209, 3215, 3218, 3221, 3222, 3223, 3229, 3232
   - Frames sha256: `87b7947d6eac2430498e1b837de3c4b14324cb9d3b735d96b45d29a2b9d55dd7`
7. **PASS** — SunSpecTCP-6/7/13/52: the EUT-S detected a client certificate issued by a CA outside the DUT's trust store and terminated the connection with a fatal TLS alert
   - Method: TLS record and alert scan of the DUT→bench direction of this connection
   - Observed: the DUT refused a client certificate issued by a CA outside the DUT's trust store with a fatal alert: level 2 (fatal), description 48 (unknown_ca)
   - Frames: 3256
   - Frames sha256: `d585287907ae120f476fad829f1661d4697763ffceb8e98953ab3b8d933f5e04`
8. **PASS** — the EUT-S sent a CertificateRequest in the server flight of the untrusted handshake
   - Method: handshake message types of the DUT→bench direction
   - Observed: CertificateRequest: certificate_types [1 (rsa_sign), 64 (ecdsa_sign)], supported_signature_algorithms [0x0403 (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0501 (rsa_pkcs1_sha384), 0x0401 (rsa_pkcs1_sha256)], 3 certificate_authorities DN(s)
   - Frames: 3249
   - Frames sha256: `c9539b532697421be0fcbec2f7900f1c0f60fa2a6dcf8de89577168f4497e720`
9. **PASS** — no TLS application_data record was exchanged after the EUT-S refused a client certificate issued by a CA outside the DUT's trust store
   - Method: record-type scan of the DUT→bench direction of this check's own conversation
   - Observed: the DUT→bench direction holds 6 TLS record(s) and none is application_data
   - Frames: 3240, 3241, 3243, 3247, 3249, 3251, 3253, 3256
   - Frames sha256: `c0fafb09b667e37b07d91a32202690ea49eba5475142eb0c0de36abcffa3466c`

### ✓ ssm-conf-v0.8::TLSF-004 Fatal Alert: Missing Certificate [S] (Negative Test) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.4 TLSF-004 - Fatal Alert: Missing Certificate [S] (Negative Test) (under 2.4 Tests for Transport Layer Security Fundamentals (TLSF))

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the DUT rejected the certless handshake: remote error: tls: handshake failure

Frame attribution: 22 frame(s) (3259–3285), precision connection; 147 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55198 <> 192.168.0.69:802 (TLSF-004: empty client Certificate message).

1. **PASS** — SunSpecTCP-11/14/45/48: the EUT-S sent a CertificateRequest and the bench answered it with an empty Certificate message
   - Method: handshake message types and Certificate message contents of both directions
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange]; the bench's Certificate message carried 0 certificate(s)
   - Frames: 3272, 3276
   - Frames sha256: `2cf440827caa0a65208a6830f37608ab3b0c2a394e6f9a169cef7ac7b7441c88`
2. **PASS** — SunSpecTCP-13/14: the EUT-S terminated the certless handshake with a fatal TLS alert
   - Method: TLS alert scan of the DUT→bench direction
   - Observed: the DUT refused a client that answered the CertificateRequest with no certificate with a fatal alert: level 2 (fatal), description 40 (handshake_failure)
   - Frames: 3277
   - Frames sha256: `9b88042b966242c64450e6038e1b4a1da496c9f268fa9272f4e2358de2f4490d`
3. **PASS** — no TLS application_data record was exchanged after the EUT-S refused a client that answered the CertificateRequest with no certificate
   - Method: record-type scan of the DUT→bench direction of this check's own conversation
   - Observed: the DUT→bench direction holds 6 TLS record(s) and none is application_data
   - Frames: 3263, 3264, 3266, 3270, 3272, 3273, 3276, 3277
   - Frames sha256: `b1ab76e70f5796833ced00f80e1dc7646708255e4d3e082f675a002390a59120`

### ✓ ssm-conf-v0.8::TLSF-005 TLSF-005 - Fatal Alert Persistence [S] (Negative Test) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.5 TLSF-005 - Fatal Alert Persistence [S] (Negative Test)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the session carried a clean Model 1 exchange before the corruption · ✓ PASS the DUT tore the session down after the corrupted record: read MBAP header: remote error: tls: bad record MAC · ✓ PASS the DUT refused to resume the aborted session and performed a full handshake

Frame attribution: 91 frame(s) (3281–3391), precision connection; 182 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55214 <> 192.168.0.69:802 (TLSF-005: session that will be aborted by a corrupted record); tcp 192.168.0.188:55224 <> 192.168.0.69:802 (TLSF-005: resumption attempt after the fatal alert).

1. **PASS** — SunSpecTCP-14 / RFC 5246 §7.2.2: the EUT-S answered a corrupted TLS record with a fatal alert
   - Method: TLS alert scan of the DUT→bench direction of the aborted session, decrypted with the run's key log
   - Observed: fatal alert level 2 description 20 (bad_record_mac), recovered from the capture with the run's key log
   - Frames: 3346
   - Frames sha256: `7ab2ce5f95bbb89ff1978bae4995bfbfa0357ed55d02bd02cb6618941263f2dd`
2. **PASS** — SunSpecTCP-14: the EUT-S did not resume the session that had ended in a fatal alert
   - Method: ServerHello session_id and handshake message types of the resumption attempt
   - Observed: resumption attempt: ServerHello session_id , flight [server_hello certificate server_key_exchange certificate_request server_hello_done new_session_ticket] — a FULL handshake: Certificate and CertificateRequest were re-exchanged
   - Frames: 3365
   - Frames sha256: `fc33058715c8ae4e53b9c254fb106164a5f6ee2aa382f96f38deec5221851845`

### ✓ ssm-conf-v0.8::TLSF-006 TLSF-006 - CertificateRequest Verification [S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.4.6 TLSF-006 - CertificateRequest Verification [S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS CertificateRequest: certificate_types [1 (rsa_sign), 64 (ecdsa_sign)], supported_signature_algorithms [0x0403 (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0501 (rsa_pkcs1_sha384), 0x0401 (rsa_pkcs1_sha256)], 3 certificate_authorities DN(s) · ✓ PASS EUT-S cleartext flight: [server_hello, certificate, server_key_exchange, certificate_request, server_hello_done] · ✓ PASS Model 1 read on unit 1 (chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]): normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing 

Frame attribution: 79 frame(s) (3386–3485), precision connection; 197 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55234 <> 192.168.0.69:802 (SSM probe: TLSF-006 conformant TLS 1.2 hello); tcp 192.168.0.188:55250 <> 192.168.0.69:802 (TLSF-006 completing session answering the CertificateRequest).

1. **PASS** — SunSpecTCP-11: the EUT-S sent a CertificateRequest (handshake type 13) with a non-empty certificate_types and supported_signature_algorithms
   - Method: CertificateRequest message, parsed from the capture
   - Observed: CertificateRequest: certificate_types [1 (rsa_sign), 64 (ecdsa_sign)], supported_signature_algorithms [0x0403 (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0501 (rsa_pkcs1_sha384), 0x0401 (rsa_pkcs1_sha256)], 3 certificate_authorities DN(s)
   - Frames: 3404
   - Frames sha256: `41ef2c8983aa5e599e0fc548f7dff241dd82a3e2e0de779ae45ba47636308ca8`
2. **PASS** — SunSpecTCP-11: the EUT-S flight was ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone, in that order
   - Method: ordered handshake message types of the DUT→bench direction
   - Observed: EUT-S cleartext flight: [server_hello, certificate, server_key_exchange, certificate_request, server_hello_done]
   - Frames: 3393, 3396, 3398, 3402, 3404, 3405
   - Frames sha256: `9050ce7ce1ccb7c709d7e2541f0363358ee64f157474711d9ab5d2ecb52575b3`
3. **PASS** — the bench answered the CertificateRequest with a Certificate, ClientKeyExchange, CertificateVerify and Finished, and the handshake completed
   - Method: handshake message types of the bench→DUT direction
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 3414, 3415, 3417, 3421, 3423, 3424, 3427, 3430, 3431, 3433, 3434, 3435, 3438, 3439, 3440, 3441, 3444, 3445, 3448, 3449, 3450, 3451, 3452, 3453, 3454, 3455, 3456, 3457, 3458, 3459, 3460, 3461, 3464, 3465, 3466, 3467, 3470, 3471, 3472, 3473, 3474, 3475, 3480
   - Frames sha256: `d061340f9da8c2109bc09b3f0da473032b0df233c5c201afaf558d188b20594a`
4. **PASS** — a SunSpec Model 1 read was carried inside the session the CertificateRequest gated, and answered
   - Method: TLS decryption with the run's key log, then MBAP framing
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 3434
   - Frames sha256: `60d4c3312f8085ca8e9049dd79cbc4fec3d2a724b2a4aefffd13a9c35729b479`

### ✗ ssm-conf-v0.8::CRYP-001 CRYP-001 - Mandatory TLS v1.2 Cipher Suites [C, S] — FAIL

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.1 CRYP-001 - Mandatory TLS v1.2 Cipher Suites [C, S] (under 2.5 Cryptography (CRYP) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS iteration 1: only 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 → ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2 · ✓ PASS iteration 2: only 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 → ServerHello.cipher_suite = 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.2 · ✓ PASS iteration 3: only 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 → ServerHello.cipher_suite = 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, negotiated version TLS 1.2 · ✗ FAIL no session could be established on 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: tlsprobe: the handshake to 192.168.0.69:802 offering only 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 did not complete: wolfSSL_connect failed: ret=-1 err=-308 (error state on socket); the peer closed or reset the TCP connection during the handshake WITHOUT sending a TLS alert — it aborted at the transport layer, not with a protocol rejection (so the cause is a socket/record-level mismatch, not a cipher or certificate the peer named) · ✗ FAIL no session could be established on 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: tlsprobe: the handshake to 192.168.0.69:802 offering only 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 did not complete: wolfSSL_connect failed: ret=-1 err=-308 (error state on socket); the peer closed or reset the TCP connection during the handshake WITHOUT sending a TLS alert — it aborted at the transport layer, not with a protocol rejection (so the cause is a socket/record-level mismatch, not a cipher or certificate the peer named) · ✗ FAIL no session could be established on 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: tlsprobe: the handshake to 192.168.0.69:802 offering only 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 did not complete: wolfSSL_connect failed: ret=-1 err=-308 (error state on socket); the peer closed or reset the TCP connection during the handshake WITHOUT sending a TLS alert — it aborted at the transport layer, not with a protocol rejection (so the cause is a socket/record-level mismatch, not a cipher or certificate the peer named)

Frame attribution: 99 frame(s) (3477–3598), precision connection; 158 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55256 <> 192.168.0.69:802 (SSM probe: iteration 1: only 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); tcp 192.168.0.188:55270 <> 192.168.0.69:802 (SSM probe: iteration 2: only 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256); tcp 192.168.0.188:55286 <> 192.168.0.69:802 (SSM probe: iteration 3: only 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8); tcp 192.168.0.188:55296 <> 192.168.0.69:802 (CRYP-001 completing session on 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); tcp 192.168.0.188:55308 <> 192.168.0.69:802 (CRYP-001 completing session on 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256); tcp 192.168.0.188:55316 <> 192.168.0.69:802 (CRYP-001 completing session on 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8).

1. **PASS** — SunSpecTCP-17: offered ONLY 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, the EUT-S accepted it and answered with a ServerHello selecting it
   - Method: single-suite TLS 1.2 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2
   - Frames: 3489
   - Frames sha256: `f757de8a553865b5be8c52dea6732734f787212ccf4c6d1f703da034c802b7c4`
2. **PASS** — SunSpecTCP-19: with only 0xC02B offered, the EUT-S proceeded through its whole server flight rather than aborting
   - Method: ordered handshake message types of the DUT→bench direction
   - Observed: EUT-S cleartext flight: [server_hello, certificate, server_key_exchange, certificate_request, server_hello_done]
   - Frames: 3488, 3489, 3492, 3496, 3498, 3499
   - Frames sha256: `7502cb7b536364497fcb2ddf007adc39dca0c5036d790b2a4f0715240313ee3a`
3. **SKIP** — SunSpecTCP-17 / §2.5.1.3: the EUT-S ESTABLISHED a secure session on 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: no session was established, so it produced no wire evidence
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **PASS** — SunSpecTCP-17: offered ONLY 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, the EUT-S accepted it and answered with a ServerHello selecting it
   - Method: single-suite TLS 1.2 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.2
   - Frames: 3512
   - Frames sha256: `78a25838581f7dccca35ef32f70763dba056855e52265b150528621e8d0e66f3`
5. **PASS** — SunSpecTCP-19: with only 0xCCA9 offered, the EUT-S proceeded through its whole server flight rather than aborting
   - Method: ordered handshake message types of the DUT→bench direction
   - Observed: EUT-S cleartext flight: [server_hello, certificate, server_key_exchange, certificate_request, server_hello_done]
   - Frames: 3509, 3512, 3514, 3516, 3517, 3518
   - Frames sha256: `12d2489980b886561e2047f1c54492b24f76751fe541f1ed3e0a6785fc2dd9da`
6. **SKIP** — SunSpecTCP-17 / §2.5.1.3: the EUT-S ESTABLISHED a secure session on 0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: no session was established, so it produced no wire evidence
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
7. **PASS** — SunSpecTCP-17: offered ONLY 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, the EUT-S accepted it and answered with a ServerHello selecting it
   - Method: single-suite TLS 1.2 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, negotiated version TLS 1.2
   - Frames: 3533
   - Frames sha256: `b251e708eb3d7ac93da279e030b4baed49dabfc6fa8ff559742d55a23aa8e0d9`
8. **PASS** — SunSpecTCP-19: with only 0xC0AE offered, the EUT-S proceeded through its whole server flight rather than aborting
   - Method: ordered handshake message types of the DUT→bench direction
   - Observed: EUT-S cleartext flight: [server_hello, certificate, server_key_exchange, certificate_request, server_hello_done]
   - Frames: 3530, 3533, 3534, 3537, 3539, 3540
   - Frames sha256: `2d4fb14109c4b9843267f5434a3a60ebac6cbcda7a5b0ccd818b79c438522e38`
9. **SKIP** — SunSpecTCP-17 / §2.5.1.3: the EUT-S ESTABLISHED a secure session on 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: no session was established, so it produced no wire evidence
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
10. **N/A** — SunSpecTCP-17 [C]: the gateway's own southbound ClientHello offers all three mandatory TLS 1.2 suites
   - Method: cipher_suites list of the gateway's ClientHello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::CRYP-002 CRYP-002 - TLS v1.3 Cipher Suites [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.2 CRYP-002 - TLS v1.3 Cipher Suites [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS iteration 1: only 0x1301 TLS_AES_128_GCM_SHA256 → ServerHello.cipher_suite = 0x1301 TLS_AES_128_GCM_SHA256, negotiated version TLS 1.3 · ✓ PASS iteration 2: only 0x1303 TLS_CHACHA20_POLY1305_SHA256 → ServerHello.cipher_suite = 0x1303 TLS_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.3 · ✓ PASS iteration 3: only 0x1304 TLS_AES_128_CCM_SHA256 → ServerHello.cipher_suite = 0x1304 TLS_AES_128_CCM_SHA256, negotiated version TLS 1.3 · ✓ PASS Model 1 read on unit 1 (chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]): normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing  · ✓ PASS an mbaps session was ESTABLISHED on 0x1301 TLS_AES_128_GCM_SHA256 (TLSv1.3, 0x1301 TLS13-AES128-GCM-SHA256, via the wolfSSL probe client); SunSpec Model 1 read on unit 1: FC 0x03 at 40004 for 66 register(s), answered with a conformant 141-byte ADU — Mn SunSpec Sim, Md CSIP-Solar-5000, SN BENCH-MODSIM-01 · ✓ PASS an mbaps session was ESTABLISHED on 0x1303 TLS_CHACHA20_POLY1305_SHA256 (TLSv1.3, 0x1303 TLS13-CHACHA20-POLY1305-SHA256, via the wolfSSL probe client); SunSpec Model 1 read on unit 1: FC 0x03 at 40004 for 66 register(s), answered with a conformant 141-byte ADU — Mn SunSpec Sim, Md CSIP-Solar-5000, SN BENCH-MODSIM-01 · ✓ PASS an mbaps session was ESTABLISHED on 0x1304 TLS_AES_128_CCM_SHA256 (TLSv1.3, 0x1304 TLS13-AES128-CCM-SHA256, via the wolfSSL probe client); SunSpec Model 1 read on unit 1: FC 0x03 at 40004 for 66 register(s), answered with a conformant 141-byte ADU — Mn SunSpec Sim, Md CSIP-Solar-5000, SN BENCH-MODSIM-01

Frame attribution: 253 frame(s) (3594–3977), precision connection; 276 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55332 <> 192.168.0.69:802 (SSM probe: iteration 1: only 0x1301 TLS_AES_128_GCM_SHA256); tcp 192.168.0.188:55348 <> 192.168.0.69:802 (SSM probe: iteration 2: only 0x1303 TLS_CHACHA20_POLY1305_SHA256); tcp 192.168.0.188:55358 <> 192.168.0.69:802 (SSM probe: iteration 3: only 0x1304 TLS_AES_128_CCM_SHA256); tcp 192.168.0.188:55366 <> 192.168.0.69:802 (CRYP-002 TLS 1.3 session for the Model 1 read); tcp 192.168.0.188:55378 <> 192.168.0.69:802 (CRYP-002 completing session on 0x1301 TLS_AES_128_GCM_SHA256); tcp 192.168.0.188:55388 <> 192.168.0.69:802 (CRYP-002 completing session on 0x1303 TLS_CHACHA20_POLY1305_SHA256); tcp 192.168.0.188:55398 <> 192.168.0.69:802 (CRYP-002 completing session on 0x1304 TLS_AES_128_CCM_SHA256).

1. **PASS** — SunSpecTCP-18: offered ONLY 0x1301 TLS_AES_128_GCM_SHA256 over TLS 1.3, the EUT-S selected it
   - Method: single-suite TLS 1.3 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1301 TLS_AES_128_GCM_SHA256, negotiated version TLS 1.3
   - Frames: 3600
   - Frames sha256: `e70a43cfcb0f9e543205b2efa5fdd1ad04ae5fc5acf78abfb2ea7d05a71f8a9f`
2. **PASS** — SunSpecTCP-18 / §2.5.2.3: the EUT-S ESTABLISHED a TLS 1.3 session on 0x1301 TLS_AES_128_GCM_SHA256 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1301 TLS_AES_128_GCM_SHA256; EUT-S flight [server_hello]; bench flight [client_hello] — under TLS 1.3 the Certificate/CertificateVerify/Finished exchange is encrypted; both directions carry opaque records and the session went on to exchange application data (established by the wolfSSL probe)
   - Frames: 3830, 3832, 3834, 3835, 3836, 3840, 3842, 3844, 3846, 3847, 3848, 3849, 3850, 3858, 3859, 3861, 3863, 3864, 3865, 3866, 3870
   - Frames sha256: `55580a98771bf4a23559d1d3ccf9048f0f6a7b8d810685acd13fa39a78a719fb`
3. **PASS** — SunSpecTCP-18: offered ONLY 0x1303 TLS_CHACHA20_POLY1305_SHA256 over TLS 1.3, the EUT-S selected it
   - Method: single-suite TLS 1.3 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1303 TLS_CHACHA20_POLY1305_SHA256, negotiated version TLS 1.3
   - Frames: 3624
   - Frames sha256: `faccd64c50b23d0539f4313bf1848cbd7d768876f0f6e746d7eaacdce2750fa4`
4. **PASS** — SunSpecTCP-18 / §2.5.2.3: the EUT-S ESTABLISHED a TLS 1.3 session on 0x1303 TLS_CHACHA20_POLY1305_SHA256 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1303 TLS_CHACHA20_POLY1305_SHA256; EUT-S flight [server_hello]; bench flight [client_hello] — under TLS 1.3 the Certificate/CertificateVerify/Finished exchange is encrypted; both directions carry opaque records and the session went on to exchange application data (established by the wolfSSL probe)
   - Frames: 3878, 3880, 3882, 3883, 3886, 3887, 3888, 3892, 3894, 3895, 3896, 3897, 3898, 3903, 3904, 3906, 3908, 3909, 3914, 3915, 3918
   - Frames sha256: `d5f344af86be6c7d415fb1a68ca8cc7a94ef60a4376ea9a03e7dc4a7ab7c229b`
5. **PASS** — SunSpecTCP-18: offered ONLY 0x1304 TLS_AES_128_CCM_SHA256 over TLS 1.3, the EUT-S selected it
   - Method: single-suite TLS 1.3 ClientHello; ServerHello.cipher_suite parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1304 TLS_AES_128_CCM_SHA256, negotiated version TLS 1.3
   - Frames: 3646
   - Frames sha256: `6f37883dd7d70806acb25819ff38b762bedd28459e4ae3fd29c8d46cc78d1629`
6. **PASS** — SunSpecTCP-18 / §2.5.2.3: the EUT-S ESTABLISHED a TLS 1.3 session on 0x1304 TLS_AES_128_CCM_SHA256 — the handshake completed, not merely the selection
   - Method: the conversation's ServerHello and its full handshake flight, both directions, re-parsed from the capture
   - Observed: ServerHello.cipher_suite = 0x1304 TLS_AES_128_CCM_SHA256; EUT-S flight [server_hello]; bench flight [client_hello] — under TLS 1.3 the Certificate/CertificateVerify/Finished exchange is encrypted; both directions carry opaque records and the session went on to exchange application data (established by the wolfSSL probe)
   - Frames: 3926, 3927, 3929, 3930, 3933, 3934, 3939, 3941, 3943, 3944, 3945, 3946, 3949, 3952, 3954, 3956, 3957, 3959, 3960, 3967
   - Frames sha256: `5a6f0ffa026ba64f27adcd28fcb7b1904c4e78fd491e229cdddcb0f161aca1ec`
7. **PASS** — CRYP-002 client-hello shape: legacy_version 0x0303 with a supported_versions extension containing 0x0304
   - Method: ClientHello legacy_version and supported_versions, parsed from the capture
   - Observed: legacy_version 0x0303, supported_versions [772]
   - Frames: 3597
   - Frames sha256: `61f4a4f7ad6144d90796056bb5bd1e780f7a6bcf9d123e61eead8f9ddd387cfc`
8. **PASS** — a SunSpec Model 1 read was carried inside the TLS 1.3 session and answered
   - Method: TLS 1.3 decryption with the run's key log, then MBAP framing
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 3791
   - Frames sha256: `40d780b4331644b328ed321c17740f712b3bcdcf7fa6f1672c56aa1de67d6af7`
9. **N/A** — SunSpecTCP-18 [C]: the gateway's own southbound ClientHello offers 0x1301, 0x1303 and 0x1304 in that exact order
   - Method: cipher_suites list of the gateway's ClientHello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ⚠ ssm-conf-v0.8::CRYP-003 CRYP-003 - Disable Insecure Ciphers [C, S] — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.3 CRYP-003 - Disable Insecure Ciphers [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the EUT-S refused a ClientHello offering only IANA-discouraged cipher suites [0x000A, 0xC013, 0x0067, 0xC009, 0x0035] with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure) · ✓ PASS control: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2 · ⚠ WARN the suite-disable MECHANISM (steps 4 and 9) was not exercised on the wire: toggling a cipher suite is a configuration change to a shared DUT. The DUT's mbaps configuration (1057 bytes) is cited off-wire as evidence that the mechanism exists.

Frame attribution: 31 frame(s) (3964–4006), precision connection; 258 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55410 <> 192.168.0.69:802 (SSM probe: CRYP-003: IANA-discouraged suites only); tcp 192.168.0.188:55422 <> 192.168.0.69:802 (SSM probe: CRYP-003 control: mandated suites).

1. **PASS** — SunSpecTCP-20: the EUT-S refused a handshake offering only IANA-discouraged cipher suites [0x000A, 0xC013, 0x0067, 0xC009, 0x0035]
   - Method: raw ClientHello probe; the DUT's answer read off the socket and re-parsed from the capture
   - Observed: the EUT-S refused a ClientHello offering only IANA-discouraged cipher suites with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure)
   - Frames: 3978
   - Frames sha256: `c51edf8bf4ea936465dea7e662dd3f0b468a551b99888d172a80695e544091f7`
2. **PASS** — control: the same probe offering the SunSpecTCP-17 suites was accepted, so the refusal above is attributable to the suites and not to an unreachable DUT
   - Method: ServerHello.cipher_suite of the control conversation
   - Observed: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2
   - Frames: 3990
   - Frames sha256: `0f8180a4cced4a02c4b30ff78d0910105544be8bdad8e42fac4343cd21b784da`
3. **PASS** — SunSpecTCP-20: the EUT provides a mechanism to disable specific cipher suites
   - Method: read of the DUT's mbaps configuration over the read-only gateway client
   - Observed: the DUT's mbaps configuration carries a cipher-suite selector: "suites12": "default",
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the DUT's own /etc/lexa/mbaps.json, read over the read-only gateway client; the disable/re-enable steps themselves were NOT performed, because this suite may not reconfigure a shared bench DUT

### ⚠ ssm-conf-v0.8::CRYP-004 CRYP-004 - ECC Curve and Point Format Support [C, S] — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.4 CRYP-004 - ECC Curve and Point Format Support [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS ServerKeyExchange curve_type=named_curve(3) named_curve=0x0017 (secp256r1) · ⚠ WARN negative iteration: the EUT-S ACCEPTED a ClientHello whose supported_groups offered only secp384r1, without the mandatory P-256: ServerHello selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 over TLS 1.2 — which SunSpecTCP-42 permits: it requires support for "at least" P-256, not the refusal of anything else. See this assertion's note.

Frame attribution: 38 frame(s) (4016–4062), precision connection; 162 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55436 <> 192.168.0.69:802 (SSM probe: CRYP-004: P-256 offered); tcp 192.168.0.188:55446 <> 192.168.0.69:802 (SSM probe: CRYP-004 negative: only secp384r1 offered).

1. **PASS** — CRYP-004 steps 3-4 (test-client setup): the ClientHello carried extension 0x000A supported_groups containing NamedCurve 0x0017 (secp256r1) and extension 0x000B ec_point_formats
   - Method: ClientHello extensions of the bench→DUT direction, parsed from the capture
   - Observed: the bench's ClientHello: extension 0x000A supported_groups present = [0x0017 (secp256r1)]; extension 0x000B ec_point_formats present
   - Frames: 4019
   - Frames sha256: `94b00085bb80257268208cabbb02bb310a22b20a71b4f1a0aec10eef9aeeec25`
2. **PASS** — SunSpecTCP-42/43/44: the EUT-S performed the ECDHE key exchange over the P-256 curve
   - Method: ServerKeyExchange ECParameters (RFC 4492 §5.4), parsed from the capture
   - Observed: ServerKeyExchange curve_type=named_curve(3) named_curve=0x0017 (secp256r1)
   - Frames: 4029
   - Frames sha256: `f9114fa0092e3c74a3089a3af8a3c10e78a52db00c9a9df2a49615de4a599b43`
3. **WARN** — CRYP-004 step 7 (procedure-defect deviation, see note): offered only the non-mandatory secp384r1 curve, the EUT-S did not complete an ECDHE handshake
   - Method: raw ClientHello probe; the DUT's answer read off the socket and re-parsed from the capture
   - Observed: the EUT-S ACCEPTED a ClientHello whose supported_groups omitted the mandatory P-256 curve: ServerHello selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 over TLS 1.2 — which SunSpecTCP-42 permits: it requires support for "at least" P-256, not the refusal of anything else. See this assertion's note.
   - Frames: 4041, 4042, 4044, 4046, 4048, 4049
   - Frames sha256: `62541566b559d7fc69037bcfd609057617db691108148348475cadfc446db2c1`
   - Note: DOCUMENTED DEVIATION — this step is a defect in the test procedure, not a criterion the EUT-S can fail. The only normative requirements §2.5.4 traces to are SunSpecTCP-42/43/44, and TCP-42 reads "mbaps Devices using ECC technology MUST support AT LEAST P-256 NIST curve" (MBR-61). "At least" explicitly contemplates supporting more, and nothing anywhere in the Secure SunSpec Modbus Specification obliges a server to REFUSE a client that offers a different curve. §2.5.4.1 step 7's "EUT-S must reject the connection or select a different key exchange method" also contradicts RFC 4492 §5.1, which runs the other way — a server declines an ECC suite only when it supports NONE of the offered curves — and its "select a different key exchange method" alternative would mean falling back to RSA or static DH, strictly worse security required by nothing. A device that completes ECDHE over P-384 has demonstrated MORE than TCP-42 asks, provided P-256 support is proven separately, which the positive iteration of this same case does. Recorded as WARN so the observation survives in the bundle; raise it with SunSpec as a defect in a document still at TEST (draft) status.
4. **N/A** — SunSpecTCP-43/44 [C]: the gateway's own southbound ClientHello carries supported_groups with secp256r1 and the ec_point_formats extension
   - Method: ClientHello extensions of the gateway's hello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::CRYP-005 CRYP-005 - Forbidden Hashes and HMAC Compliance [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.5 CRYP-005 - Forbidden Hashes and HMAC Compliance [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the EUT-S refused a ClientHello offering 0x002F TLS_RSA_WITH_AES_128_CBC_SHA with (sha1, ecdsa) and (md5, rsa) signature algorithms with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure) · ✓ PASS the control handshake selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, a SHA-256-PRF suite

Frame attribution: 31 frame(s) (4055–4093), precision connection; 183 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55460 <> 192.168.0.69:802 (SSM probe: CRYP-005: SHA-1 suite with md5/sha1 signature algorithms); tcp 192.168.0.188:55466 <> 192.168.0.69:802 (SSM probe: CRYP-005 control: SHA-256 suites).

1. **PASS** — SunSpecTCP-54/55: the EUT-S rejected a handshake offering an MD5/SHA-1 signature algorithm set and a SHA-1 MAC cipher suite
   - Method: raw ClientHello probe; the DUT's answer read off the socket and re-parsed from the capture
   - Observed: the EUT-S refused a ClientHello with cipher suite 0x002F and signature_algorithms (sha1, ecdsa) and (md5, rsa) with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure)
   - Frames: 4066
   - Frames sha256: `60d053ed5fc52e1ef81da128648dea05d0c4ec921aef898d075314ad12bc19e3`
2. **PASS** — SunSpecTCP-56/57: the EUT-S negotiated a SHA-256-PRF cipher suite, so key derivation uses HMAC-SHA-256 (RFC 5246 §5)
   - Method: ServerHello.cipher_suite of the control conversation, mapped to its PRF hash
   - Observed: negotiated 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 over TLS 1.2 — RFC 5246 §5 fixes this suite's PRF at SHA-256, from which HMAC-SHA-256 key derivation follows
   - Frames: 4078
   - Frames sha256: `93d76d4911a5e100ac21f36b1b531456f9376b66a8546ff3bb8927467106e8f6`
3. **N/A** — SunSpecTCP-54/55 [C]: the gateway's own southbound ClientHello offers no MD5 or SHA-1 signature algorithm and no SHA-1 MAC cipher suite
   - Method: signature_algorithms and cipher_suites of the gateway's ClientHello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ⚠ ssm-conf-v0.8::CRYP-006 CRYP-006 - IANA Registry Compliance [C, S] — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.6 CRYP-006 - IANA Registry Compliance [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the EUT-S selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 — IANA-registered and certificate-based key exchange in the suite name: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 · ⚠ WARN the vendor PICS cross-reference (steps 4-6) was not performed: no Protocol Implementation Conformance Statement was supplied to this run, and the suite will not manufacture a cross-reference table from the codepoints it happened to observe

Frame attribution: 19 frame(s) (4091–4112), precision connection; 189 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55476 <> 192.168.0.69:802 (SSM probe: CRYP-006: mandated offer).

1. **PASS** — SunSpecTCP-15/16: the cipher suite the EUT-S selected is registered in the IANA TLS Cipher Suite Registry and accommodates X.509v3 certificate authentication
   - Method: ServerHello.cipher_suite cross-referenced against the bench's own transcription of the IANA registry
   - Observed: selected 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256; IANA-registered: true; certificate-based key exchange in the suite name: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   - Frames: 4097
   - Frames sha256: `67d818c3d464b5cc975e9d0d2b84710ba5f6570fe5ca1bb915963eb83c917431`
2. **SKIP** — SunSpecTCP-15/16: every cipher suite in the vendor's PICS is IANA-registered and not marked discouraged or prohibited
   - Method: cross-reference of the vendor PICS against the IANA TLS Cipher Suite Registry
   - Observed: no Protocol Implementation Conformance Statement was supplied to this run. The suites the DUT was OBSERVED to offer and select are asserted above; the PICS covers suites the DUT supports but did not use here, and no capture can evidence those.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
3. **N/A** — SunSpecTCP-15/16 [C]: every cipher suite the gateway offers is IANA-registered and certificate-based
   - Method: every codepoint in the gateway's ClientHello cipher_suites, cross-referenced against the bench's IANA transcription
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::CRYP-007 CRYP-007 - Encryption-Capable Cipher Selection [C, S] (Negative Test) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.5.7 CRYP-007 - Encryption-Capable Cipher Selection [C, S] (Negative Test)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the EUT-S refused a ClientHello offering only the 19 registered NULL-encryption cipher suites with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure) · ✓ PASS control: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2

Frame attribution: 32 frame(s) (4110–4148), precision connection; 179 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55486 <> 192.168.0.69:802 (SSM probe: CRYP-007: NULL-encryption suites only); tcp 192.168.0.188:55492 <> 192.168.0.69:802 (SSM probe: CRYP-007 control: SunSpecTCP-17 suites).

1. **PASS** — SunSpecTCP-53: the EUT-S rejected a handshake offering only NULL-encryption cipher suites (all 19 registered codepoints, not only the four the procedure names)
   - Method: raw ClientHello probe; the DUT's answer read off the socket and re-parsed from the capture
   - Observed: the EUT-S refused a ClientHello offering only NULL-encryption cipher suites with a fatal TLS alert: level 2 (fatal), description 40 (handshake_failure)
   - Frames: 4118
   - Frames sha256: `23cbfb7ea38f70c8e4b4563f5dd5fc8382764d202277ea29fd62674d9f47cdc6`
2. **PASS** — SunSpecTCP-17/53: the same probe offering the mandatory encrypting suites was accepted and the handshake proceeded
   - Method: ServerHello.cipher_suite of the control conversation
   - Observed: ServerHello.cipher_suite = 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2
   - Frames: 4129
   - Frames sha256: `4d658612c172cb57bd31b4b60ff91a9a055061ae22b4949701c90961f441c83d`
3. **N/A** — SunSpecTCP-53 [C]: the gateway's own southbound ClientHello offers no NULL-encryption cipher suite
   - Method: every codepoint in the gateway's ClientHello, checked against the registered NULL-encryption set
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ⚠ ssm-conf-v0.8::PKI-001 PKI-001 - Root Store Capacity [C, S] — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.1 PKI-001 - Root Store Capacity [C, S] (under 2.6 Public Key Infrastructure (PKI) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS a leaf issued by a root in the DUT's trust store completed the handshake · ✓ PASS the DUT rejected a leaf issued by a CA outside its trust store: remote error: tls: unknown certificate authority · ⚠ WARN the CAPACITY criterion (ten distinct roots, ten successful handshakes) was not exercised: loading roots means ten writes to the DUT's trust store through certmgr's SO_PEERCRED socket (scripts/bench-certctl), and this run shares the bench with other agents and may not mutate DUT state

Frame attribution: 47 frame(s) (4142–4214), precision connection; 168 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55498 <> 192.168.0.69:802 (PKI-001 control: a leaf from a root the DUT holds); tcp 192.168.0.188:55514 <> 192.168.0.69:802 (PKI-001: a leaf from a root outside the DUT's trust store).

1. **PASS** — SunSpecTCP-2: a client certificate chaining to a root in the EUT-S trust store completed the mutual-auth handshake
   - Method: handshake message types and the bench's Certificate chain, parsed from the capture
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 4149, 4151, 4155, 4157, 4158, 4159, 4165, 4166, 4167, 4189, 4298
   - Frames sha256: `6280bd9a6c59c69fbe77a0b425583c6eb034651646163a3adee3030fb8d51246`
   - Note: cited as part of a TLS conversation this check owns whose establishing handshake landed just before the window opened (a long-lived connection the DUT kept alive into it); the same "a TLS session is indivisible evidence" rule the attributor applies to a split conversation
2. **PASS** — SunSpecTCP-2: a client certificate chaining to a root the EUT-S does NOT hold was rejected with a TLS alert
   - Method: TLS alert scan of the DUT→bench direction of the unknown-root connection
   - Observed: the DUT refused a client certificate issued by an untrusted CA with a fatal alert: level 2 (fatal), description 48 (unknown_ca)
   - Frames: 4187
   - Frames sha256: `cd018b3b14cb9734e34cbd41ea3e3e7142fc0c58dcbaafc85251bc4f8c4ad159`
3. **SKIP** — SunSpecTCP-2: the EUT-S trust store holds at least ten distinct root certificates and completes a handshake against each
   - Method: ten certificate installs through the DUT's certificate-management interface, then ten handshakes
   - Observed: installing roots is a WRITE to a shared DUT's trust store (certmgr over its SO_PEERCRED unix socket, driven by scripts/bench-certctl). This run is read-only against the bench by constraint, and would leave the trust store altered for every other agent. The rejection of an out-of-store root IS asserted above, which is the half that a capture can show.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ssm-conf-v0.8::PKI-002 PKI-002 - Certificate Management: Add/Remove [C, S] — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.2 PKI-002 - Certificate Management: Add/Remove [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ⚠ WARN PKI-002's procedure is entirely add/remove operations against the DUT's certificate-management interface. Every step is a WRITE to a shared DUT (certmgr over its SO_PEERCRED unix socket), which this run may not perform. The plaintext-management-traffic criterion IS asserted, from a scan of the whole capture.

Frame attribution: 61 frame(s) (4191–4351), precision connection; 347 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:55530 <> 192.168.0.69:802 (PKI-002: observation of the installed server chain).

1. **PASS** — PKI-002 (observation): the server certificate and intermediate chain the EUT-S currently presents
   - Method: the EUT-S Certificate message, parsed from the capture
   - Observed: the chain installed at the time of this run: the EUT-S delivered leaf + 2 intermediate CA certificate(s): 3 certificate(s), leaf first: [0] subject "CN=lexa-gw-nb-mbaps-server" issuer "CN=csip-tls-test bench mbaps Intermediate CA" ca=false sha256=955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497; [1] subject "CN=csip-tls-test bench mbaps Intermediate CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=4ece7491aac2e57a4b0be034d8111f39136fa32df7e50eede3020d948a743cb6; [2] subject "CN=csip-tls-test bench mbaps Root CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=2478d56be07777c9ae5d8ae0e196c9b27086d9a66fae1ed951ce313a78705e5d
   - Frames: 4202
   - Frames sha256: `4d2c317e769cb6dc30f8c598f857f13cdea0b9eccd53ff46286a8875d09c48e9`
2. **PASS** — SunSpecTCP-3: no certificate-management or Modbus traffic involving the DUT crossed the wire in the clear
   - Method: whole-capture scan for TCP streams to or from the DUT on cleartext management ports
   - Observed: scanned all 123 conversation(s) in the capture: no TCP stream to or from the DUT on a cleartext management port (80/HTTP, 502/Modbus, 23/telnet) carried any bytes
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: a scan of every conversation in the run's capture, not only this test case's own frames — an ABSENCE claim is only meaningful at capture scope, and the framework forbids citing frames this check does not own, so this assertion carries no frame citation by design
3. **SKIP** — SunSpecTCP-3: root certificates and the server certificate can be securely added to and removed from the EUT, and a removed root's leaf is subsequently rejected
   - Method: add/remove operations through the EUT's certificate-management interface, then handshake attempts
   - Observed: every step of PKI-002 is a WRITE to a shared DUT's certificate store through certmgr's SO_PEERCRED unix socket. This run is read-only against the bench by constraint. Running it would also leave the DUT's trust store and server identity altered for the other agents using the bench.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ssm-conf-v0.8::PKI-003 PKI-003 - Public Network Security [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.3 PKI-003 - Public Network Security [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the DUT rejected the self-signed client certificate: remote error: tls: unknown certificate authority · ✓ PASS the CA-signed client certificate completed the handshake and carried a Model 1 read

Frame attribution: 82 frame(s) (4345–4450), precision connection; 134 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59758 <> 192.168.0.69:802 (PKI-003: self-signed client certificate); tcp 192.168.0.188:59772 <> 192.168.0.69:802 (PKI-003: CA-signed client certificate).

1. **PASS** — SunSpecTCP-50: the EUT-S rejected a self-signed client certificate (issuer == subject, chaining to no CA)
   - Method: the bench's Certificate message and the DUT's alert, parsed from the capture
   - Observed: the bench presented a self-signed leaf and the DUT refused a self-signed client certificate with a fatal alert: level 2 (fatal), description 48 (unknown_ca)
   - Frames: 4376
   - Frames sha256: `0b04e54eb05b8b888349717d266c52105529e51c6b32bf4b9007d7b58597da10`
2. **PASS** — SunSpecTCP-50: a CA-signed client certificate (issuer != subject, chaining to a trusted root) completed the handshake
   - Method: the bench's Certificate message and the completed flight, parsed from the capture
   - Observed: the bench leaf is CA-signed: subject "CN=mbaps-client-grid-service", issuer "CN=csip-tls-test bench mbaps Intermediate CA", 2 certificate(s) in the chain (sha256 d260a871e8763e60e98f04f8abdb0068059efca25d259f929c73a18a82fe6c6b); EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 4399
   - Frames sha256: `54d2c526ba85ae723f7929ea690750d6591dd039aa3696e3332511ba06d26a9c`
3. **PASS** — SunSpecTCP-50: the EUT-S's own server certificate is CA-signed, not self-signed
   - Method: the EUT-S Certificate message, parsed from the capture
   - Observed: the EUT-S leaf is CA-signed: subject "CN=lexa-gw-nb-mbaps-server", issuer "CN=csip-tls-test bench mbaps Intermediate CA", 3 certificate(s) in the chain (sha256 955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497)
   - Frames: 4387
   - Frames sha256: `3d7a05498bb991d20f1327034dc2381f732af2a9b9bc50a799b38aa0c8c86829`

### ✓ ssm-conf-v0.8::PKI-004 PKI-004 - Full Chain Delivery [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.4 PKI-004 - Full Chain Delivery [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the EUT-S delivered leaf + 2 intermediate CA certificate(s): 3 certificate(s), leaf first: [0] subject "CN=lexa-gw-nb-mbaps-server" issuer "CN=csip-tls-test bench mbaps Intermediate CA" ca=false sha256=955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497; [1] subject "CN=csip-tls-test bench mbaps Intermediate CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=4ece7491aac2e57a4b0be034d8111f39136fa32df7e50eede3020d948a743cb6; [2] subject "CN=csip-tls-test bench mbaps Root CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=2478d56be07777c9ae5d8ae0e196c9b27086d9a66fae1ed951ce313a78705e5d

Frame attribution: 19 frame(s) (4441–4471), precision connection; 189 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59774 <> 192.168.0.69:802 (SSM probe: PKI-004: chain delivery observation).

1. **PASS** — SunSpecTCP-51: the EUT-S Certificate message delivers the leaf followed by every intermediate CA needed to build a path to the root
   - Method: the EUT-S Certificate message's certificate_list, parsed from the capture
   - Observed: the EUT-S delivered leaf + 2 intermediate CA certificate(s): 3 certificate(s), leaf first: [0] subject "CN=lexa-gw-nb-mbaps-server" issuer "CN=csip-tls-test bench mbaps Intermediate CA" ca=false sha256=955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497; [1] subject "CN=csip-tls-test bench mbaps Intermediate CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=4ece7491aac2e57a4b0be034d8111f39136fa32df7e50eede3020d948a743cb6; [2] subject "CN=csip-tls-test bench mbaps Root CA" issuer "CN=csip-tls-test bench mbaps Root CA" ca=true sha256=2478d56be07777c9ae5d8ae0e196c9b27086d9a66fae1ed951ce313a78705e5d
   - Frames: 4453
   - Frames sha256: `079f6f55a8aff970819a3a44281fdc04c70ecb1984e765298ab5270af64c706a`
2. **PASS** — SunSpecTCP-51: no AIA/caIssuers fetch was required to complete the chain — the delivered chain was sufficient
   - Method: whole-capture scan for outbound HTTP traffic during this conversation, plus the AIA extension of the delivered leaf
   - Observed: the delivered chain is 3 certificate(s) deep; the leaf does not carry an AuthorityInformationAccess extension. The bench built the path from the delivered chain alone and dereferenced nothing.
   - Frames: 4453
   - Frames sha256: `079f6f55a8aff970819a3a44281fdc04c70ecb1984e765298ab5270af64c706a`
3. **N/A** — SunSpecTCP-51 [C]: the gateway's own southbound client delivers a full chain (leaf + intermediates)
   - Method: the gateway's Certificate message to the bench device sim, parsed from the capture
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::PKI-006 PKI-006 - Session Resumption and Tickets [C, S] (Optional) — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.6 PKI-006 - Session Resumption and Tickets [C, S] (Optional)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the DUT resumed the session (abbreviated handshake), which SunSpecTCP-46/47 permits

Frame attribution: 81 frame(s) (4464–4571), precision connection; 241 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59790 <> 192.168.0.69:802 (PKI-006: initial full handshake); tcp 192.168.0.188:59804 <> 192.168.0.69:802 (PKI-006: resumption attempt).

1. **PASS** — PKI-006: the initial handshake was a FULL mutual-auth exchange and offered resumable state (a non-empty session_id and/or a NewSessionTicket)
   - Method: ServerHello.session_id and handshake message types of the initial conversation
   - Observed: ServerHello.session_id =  (0 byte(s)); NewSessionTicket present; flight [server_hello certificate server_key_exchange certificate_request server_hello_done new_session_ticket]
   - Frames: 4472
   - Frames sha256: `7199200d11af79801b899fb9f007f065e7f4e369cdad0a3249b1f5d4a8815722`
2. **PASS** — SunSpecTCP-46/47: the second handshake was either a correct abbreviated resumption or a clean fall back to a full mutual handshake
   - Method: handshake message types and session_id of both conversations
   - Observed: initial handshake: ServerHello.session_id 0 byte(s) (), NewSessionTicket present; resumption attempt: ClientHello.session_id 32 byte(s) (107c0b5098ca3728e597ae7b81d80cc9a2131e3a99ee2bbe85da3e4a294eabfb), ServerHello.session_id 32 byte(s) (107c0b5098ca3728e597ae7b81d80cc9a2131e3a99ee2bbe85da3e4a294eabfb), Certificate ABSENT — the EUT-S performed an ABBREVIATED handshake: it echoed the session id offered in the resumption ClientHello (RFC 5077 §3.4) and re-sent no Certificate or CertificateRequest
   - Frames: 4539, 4544
   - Frames sha256: `3f72e0c6867d60976cf09754e73a5fec977b5eaf78561b8a129665b35e5d7849`

### ✓ ssm-conf-v0.8::PKI-007 PKI-007 - RFC 5280 Certificate Compliance [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.7 PKI-007 - RFC 5280 Certificate Compliance [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS all 3 of the DUT's chain certificates conform to the RFC 5280 v3 profile

Frame attribution: 60 frame(s) (4554–4632), precision connection; 198 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59820 <> 192.168.0.69:802 (PKI-007: certificate profile observation).

1. **PASS** — SunSpecTCP-52: every certificate the EUT-S sent conforms to the RFC 5280 X.509v3 profile — v3, positive serial, signatureAlgorithm, validity, issuer, subjectPublicKeyInfo, KeyUsage, BasicConstraints, SubjectKeyIdentifier and AuthorityKeyIdentifier
   - Method: each certificate in the EUT-S Certificate message parsed from the capture and checked field by field against RFC 5280 §4.1-§4.2
   - Observed: [0] "CN=lexa-gw-nb-mbaps-server" (sha256 955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497) conforms: v3 serial 70A141F21B72C2D6187B9C523AE81492762A77E2 sigalg ECDSA-SHA256 validity 2026-07-18..2028-10-21 key ECDSA/256 P-256 keyUsage [DigitalSignature] basicConstraints cA=false SKI+AKI present \| [1] "CN=csip-tls-test bench mbaps Intermediate CA" (sha256 4ece7491aac2e57a4b0be034d8111f39136fa32df7e50eede3020d948a743cb6) conforms: v3 serial B3D708C8489C329AC77E87353BE2F93D sigalg ECDSA-SHA256 validity 2026-07-19..2033-07-17 key ECDSA/256 P-256 keyUsage [DigitalSignature,CertSign,CRLSign] basicConstraints cA=true SKI+AKI present \| [2] "CN=csip-tls-test bench mbaps Root CA" (sha256 2478d56be07777c9ae5d8ae0e196c9b27086d9a66fae1ed951ce313a78705e5d) conforms: v3 serial 852645A1E345E0A54A803BC066FDFFDC sigalg ECDSA-SHA256 validity 2026-07-19..2036-07-16 key ECDSA/256 P-256 keyUsage [DigitalSignature,CertSign,CRLSign] basicConstraints cA=true SKI+AKI present
   - Frames: 4566
   - Frames sha256: `cf33d8b6ef564d7165e6091af97036d74502af514249522ff31d79f175c31b7a`
2. **PASS** — bench self-check (NOT a DUT verdict): the Test Client certificate this bench presented also conforms to the RFC 5280 X.509v3 profile
   - Method: each certificate in the BENCH's Certificate message parsed from the capture and checked against RFC 5280
   - Observed: [0] "CN=mbaps-client-grid-service" (sha256 d260a871e8763e60e98f04f8abdb0068059efca25d259f929c73a18a82fe6c6b) conforms: v3 serial 5CCA9ABA0633D49BF5D5E4DAD1EBDFD1 sigalg ECDSA-SHA256 validity 2026-08-07..2029-08-06 key ECDSA/256 P-256 keyUsage [DigitalSignature] basicConstraints cA=false SKI+AKI present \| [1] "CN=csip-tls-test bench mbaps Intermediate CA" (sha256 4ece7491aac2e57a4b0be034d8111f39136fa32df7e50eede3020d948a743cb6) conforms: v3 serial B3D708C8489C329AC77E87353BE2F93D sigalg ECDSA-SHA256 validity 2026-07-19..2033-07-17 key ECDSA/256 P-256 keyUsage [DigitalSignature,CertSign,CRLSign] basicConstraints cA=true SKI+AKI present
   - Frames: 4578
   - Frames sha256: `02998e623f53fbf0a1cce3114d063b2a901b9d10fb73a8cf93b077deab779755`
   - Note: scope: SSM-CONF-v0.8 §2.6.7.1 step 3 inspects the EUT-S Certificate message. With the DUT as the server the bench is the Test Client, so this row is recorded for completeness and is capped at WARN — it cannot be a verdict on the device under test.

### ✓ ssm-conf-v0.8::PKI-008 PKI-008 - X.509v3 Identity Authentication [C, S] — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.6.8 PKI-008 - X.509v3 Identity Authentication [C, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS Model 1 read on unit 1 (chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]): normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing 

Frame attribution: 60 frame(s) (4623–4696), precision connection; 249 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59836 <> 192.168.0.69:802 (PKI-008: X.509v3 mutual authentication).

1. **PASS** — SunSpecTCP-7: the EUT-S identified itself with an X.509v3 certificate carrying subjectKeyIdentifier, authorityKeyIdentifier and keyUsage
   - Method: the EUT-S Certificate message, parsed from the capture
   - Observed: v3 leaf, subject "CN=lexa-gw-nb-mbaps-server", sha256 955e7f093d2180b34fd32717e9f18b0981051e3ea754e9f54810e829bc282497; subjectKeyIdentifier present; authorityKeyIdentifier present; keyUsage [DigitalSignature]
   - Frames: 4635
   - Frames sha256: `58984bbbebadf23f82641a1582ac9f7311d8fd83a48f6999af0af2643b93b194`
2. **PASS** — bench self-check (NOT a DUT verdict): the Test Client certificate this bench presented is X.509v3 and carries subjectKeyIdentifier, authorityKeyIdentifier and keyUsage
   - Method: the bench client Certificate message, parsed from the capture
   - Observed: v3 leaf, subject "CN=mbaps-client-grid-service", sha256 d260a871e8763e60e98f04f8abdb0068059efca25d259f929c73a18a82fe6c6b; subjectKeyIdentifier present; authorityKeyIdentifier present; keyUsage [DigitalSignature]
   - Frames: 4645
   - Frames sha256: `2523f926ee92d5af95b1bb24112d7de124bf3f08497c5cf0116a9eec98521617`
   - Note: scope: SSM-CONF-v0.8 §2.6.8.1 step 3 inspects the EUT-S Certificate message. With the DUT as the server the bench is the Test Client, so this row is recorded for completeness and is capped at WARN.
3. **PASS** — SunSpecTCP-7: mutual authentication completed — both Certificate messages were exchanged and the bench sent a CertificateVerify
   - Method: handshake message types of both directions, parsed from the capture
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 4630, 4633, 4635, 4639, 4640, 4641, 4645, 4646, 4647, 4649, 4652, 4653, 4654, 4655, 4656, 4657, 4658, 4659, 4660, 4661, 4662, 4663, 4664, 4665, 4666, 4667, 4668, 4669, 4670, 4671, 4672, 4673, 4674, 4675, 4678, 4679, 4680, 4681, 4682, 4683, 4684, 4685, 4688
   - Frames sha256: `32b1d4cfb5e51e9275278d578c9db7f654d007061e9e496be8831d8452bdab73`
4. **PASS** — a SunSpec Model 1 read followed the mutual X.509v3 authentication and was answered
   - Method: TLS decryption with the run's key log, then MBAP framing
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 4652
   - Frames sha256: `414975fd285d7f63ff1d152b0a8045e999c7065b7271179552c2570fb26096ef`

### ✓ ssm-conf-v0.8::PROT-001 MBAP Integrity — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.8.1 PROT-001 - MBAP Integrity [C, S] (under 2.8 Protocol Integrity (PROT) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS unit 1, chain models [1 703 701 702 704 705 706 707 708 709 710 711 712]: request MBAP header 00 10 00 00 00 06 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 6 | Unit ID 1; PDU 03 9c 44 00 42 (5 byte(s)); trailing  || response MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing 

Frame attribution: 60 frame(s) (4687–4766), precision connection; 245 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59840 <> 192.168.0.69:802 (PROT-001: MBAP integrity inside the tunnel).

1. **PASS** — SunSpecTCP-9: inside the secure transport the Modbus ADU is unchanged — a 7-byte MBAP header (Transaction ID, Protocol ID 0x0000, Length, Unit ID) followed by the unmodified PDU
   - Method: TLS decryption of this session's records with the run's key log, then field-by-field decoding of the recovered MBAP frames
   - Observed: request MBAP header 00 01 00 00 00 06 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 6 \| Unit ID 1; PDU 03 9c 40 00 02 (5 byte(s)); trailing  \|\| response MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 4717
   - Frames sha256: `74807f55505a86e13f07e5348aa6cb3aa0e5f31eb6d97869106bfa4a1c49dd8d`
2. **PASS** — SunSpecTCP-9: the Modbus exchange was carried entirely inside TLS application_data records — no Modbus byte appeared on the wire in the clear
   - Method: record-type scan of both directions of this session's conversation
   - Observed: bench→DUT: 23 record(s), 16 application_data, 0 trailing byte(s) outside record framing; DUT→bench: 24 record(s), 16 application_data, 0 trailing byte(s) outside record framing — every byte of the exchange is inside TLS record framing
   - Frames: 4694, 4697, 4699, 4703, 4705, 4706, 4709, 4713, 4714, 4716, 4717, 4718, 4719, 4720, 4721, 4722, 4723, 4724, 4727, 4728, 4730, 4731, 4732, 4733, 4734, 4735, 4736, 4737, 4739, 4740, 4741, 4742, 4743, 4744, 4745, 4746, 4748, 4749, 4750, 4751, 4754, 4755, 4758
   - Frames sha256: `79fbb2e1733fc876ca3fa3d5fd42ee96ec9e123daab6d99ebeb39ebd0b65f313`

### ⚠ ssm-conf-v0.8::PROT-002 Fragment Length Negotiation — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.8.2 PROT-002 - Fragment Length Negotiation [C, S] (under 2.8 Protocol Integrity (PROT) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the ServerHello echoed max_fragment_length code 1 = 512 bytes, matching the ClientHello request · ✓ PASS the control ServerHello carries no max_fragment_length, so the echo above is a genuine negotiation · ⚠ WARN the fragment-SIZE criterion (a >512-byte Modbus response split into records of at most 512 plaintext bytes) was not exercised: Go's crypto/tls, this bench's TLS stack, does not implement RFC 6066 max_fragment_length, so it cannot establish a session under the negotiated limit. The negotiation itself is asserted from the ServerHello.

Frame attribution: 38 frame(s) (4757–4805), precision connection; 217 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59854 <> 192.168.0.69:802 (SSM probe: PROT-002: max_fragment_length code 1 (512 bytes)); tcp 192.168.0.188:59864 <> 192.168.0.69:802 (SSM probe: PROT-002 control: no max_fragment_length offered).

1. **PASS** — SunSpecTCP-59/60: offered the RFC 6066 max_fragment_length extension with code 1 (512 bytes), the EUT-S echoed it in its ServerHello
   - Method: ServerHello extension 0x0001, parsed from the capture
   - Observed: the ServerHello echoed max_fragment_length code 1 = 512 bytes, matching the ClientHello request
   - Frames: 4767
   - Frames sha256: `e8ddf0b50ce4a858c6032954a92042ca4b20fc7b1b2c7185b46d4fa71fab4ce2`
2. **PASS** — SunSpecTCP-59: the extension is genuinely NEGOTIATED — with no max_fragment_length in the ClientHello, the EUT-S echoes none
   - Method: ServerHello extension list of the control conversation, parsed from the capture
   - Observed: control ServerHello extensions: [renegotiation_info, extended_master_secret, ec_point_formats] — no max_fragment_length, as expected when none is requested
   - Frames: 4786
   - Frames sha256: `c10abdc834013c02c4a5a1031195795219734977687000341715d715e506a223`
3. **SKIP** — SunSpecTCP-59/60: with a 512-byte fragment length negotiated, every TLS record of a >512-byte Modbus response carries at most 512 plaintext bytes
   - Method: record-length measurement of a multi-register read inside a session with MFL 512 negotiated
   - Observed: this bench's TLS stack (Go crypto/tls) does not implement RFC 6066 max_fragment_length, so it cannot ESTABLISH a session under the negotiated limit — only offer the extension and observe the echo, which is asserted above. Measuring the resulting record sizes needs a client that honours the limit it negotiated.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **N/A** — SunSpecTCP-59 [C]: the gateway's own southbound ClientHello carries the max_fragment_length extension
   - Method: ClientHello extension 0x0001 of the gateway's hello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ⚠ ssm-conf-v0.8::PROT-004 Renegotiation Indication — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.8.4 PROT-004 - Renegotiation Indication [C, S] (under 2.8 Protocol Integrity (PROT) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the ServerHello carries the RFC 5746 renegotiation_info extension (type 0xFF01) with an empty renegotiated_connection, as required on an initial handshake · ⚠ WARN the RENEGOTIATION itself (a second handshake inside the established session, whose renegotiation_info carries the previous Finished messages' verify_data) was not attempted: Go's crypto/tls, this bench's TLS stack, cannot INITIATE renegotiation as a client — it can only accept a server-initiated one. The RFC 5746 indication, which is what SunSpecTCP-62 requires, is asserted from the wire.

Frame attribution: 18 frame(s) (4799–4821), precision connection; 231 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59874 <> 192.168.0.69:802 (SSM probe: PROT-004: TLS 1.2 hello carrying renegotiation_info).

1. **PASS** — SunSpecTCP-62 / RFC 5746: the EUT-S ServerHello carries the renegotiation_info extension (type 0xFF01)
   - Method: ServerHello extension 0xFF01, parsed from the capture
   - Observed: the ServerHello carries the RFC 5746 renegotiation_info extension (type 0xFF01) with an empty renegotiated_connection, as required on an initial handshake
   - Frames: 4808
   - Frames sha256: `16b2f7006c47993ef67c2cee83af5ccecb10e4b4897d31bad27ea187493d5fce`
2. **SKIP** — SunSpecTCP-62: a renegotiation handshake inside the established session carries the previous handshake's Finished verify_data in renegotiation_info, and Modbus data continues to flow afterwards
   - Method: a client-initiated renegotiation inside an established mbaps session
   - Observed: Go's crypto/tls — this bench's TLS stack — cannot initiate renegotiation as a client, only accept a server-initiated one, so this bench cannot provoke the second handshake. The RFC 5746 indication extension itself, which is SunSpecTCP-62's requirement, IS asserted above. TLS 1.3 removes renegotiation entirely, so this criterion applies only to the DUT's TLS 1.2 sessions.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
3. **N/A** — SunSpecTCP-62 [C]: the gateway's own southbound ClientHello provides the RFC 5746 secure-renegotiation indication in one of the two forms §3.4 admits — the empty renegotiation_info extension, or TLS_EMPTY_RENEGOTIATION_INFO_SCSV in cipher_suites
   - Method: ClientHello extension 0xFF01 and cipher_suites of the gateway's hello to the bench device sim
   - Observed: this criterion is a [C] step of the procedure — it is about the candidate as a Secure SunSpec Modbus CLIENT — and candidate profile "one-to-one-7xx-tcp" does not claim that direction: secure_sunspec.roles declares [server]. There is no client direction on this candidate to measure, so no outcome about it exists to report
   - _(no digest — narrative, not re-checkable)_
   - Note: NOT APPLICABLE — declared by: manifest; declaration: secure_sunspec.roles = [server] (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622…)

### ✓ ssm-conf-v0.8::RBAC-001 Role Extension Extraction — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.1 RBAC-001 - Role Extension Extraction [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS Model 1 read: normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing  · ✓ PASS control write to model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op: exception response: function code 0x90, exception code 1 (Illegal Function). MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 90 01 (2 byte(s)); trailing 

Frame attribution: 64 frame(s) (4819–4894), precision connection; 233 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59876 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec).

1. **PASS** — SunSpecTCP-8/21/26/39: the client presented a certificate carrying the role ReadOnlySunSpec in the extension at OID 1.3.6.1.4.1.50316.802.1
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "ReadOnlySunSpec" (DER value 0c0f526561644f6e6c7953756e53706563)
   - Frames: 4837
   - Frames sha256: `2daeaa7676ddd1d9a1567608b43dc7fb8f413e73e15b680c1e127ec37cf0067e`
2. **PASS** — SunSpecTCP-21/26: a Read Holding Registers request for the Common Model was answered normally for the ReadOnlySunSpec role
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 4844
   - Frames sha256: `49af96c07f75caf05c21ad0b156902c987aae235e8d2d5593d1fa34bf23a791b`
3. **PASS** — SunSpecTCP-39: a Write Multiple Registers request to a control point was answered with Modbus exception code 01 (Illegal Function) for the ReadOnlySunSpec role — model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; exception response: function code 0x90, exception code 1 (Illegal Function). MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 90 01 (2 byte(s)); trailing 
   - Frames: 4880
   - Frames sha256: `1af72338025efbedcf387723ddf2543f490a496084ac1dc87bc15fd59a15b8b6`

### ✓ ssm-conf-v0.8::RBAC-002 Mandatory Roles Support — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.2 RBAC-002 - Mandatory Roles Support [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS GridServiceSunSpec: write to model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op — AUTHORIZED and performed — normal (non-exception) response: MBAP header 00 12 00 00 00 06 01 = Transaction ID 0x0012 | Protocol ID 0x0000 | Length 6 | Unit ID 1; PDU 10 9d 6a 00 01 (5 byte(s)); trailing  · · SKIP NetworkAdministratorSunSpec: the write step was not performed — this DUT's chain on unit 1 holds no model that is a network configuration point (models [1 703 701 702 704 705 706 707 708 709 710 711 712]), so §2.7.2.1's "if one exists" condition is not met and the step is not performed · ✓ PASS SuperAdministratorSunSpec: write to model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op — AUTHORIZED and performed — normal (non-exception) response: MBAP header 00 12 00 00 00 06 01 = Transaction ID 0x0012 | Protocol ID 0x0000 | Length 6 | Unit ID 1; PDU 10 9d 6a 00 01 (5 byte(s)); trailing 

Frame attribution: 254 frame(s) (4883–5187), precision connection; 200 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59878 <> 192.168.0.69:802 (RBAC session: GridServiceSunSpec); tcp 192.168.0.188:59890 <> 192.168.0.69:802 (RBAC session: NetworkAdministratorSunSpec); tcp 192.168.0.188:59892 <> 192.168.0.69:802 (RBAC session: SuperAdministratorSunSpec); tcp 192.168.0.188:59908 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec (contrast)).

1. **PASS** — SunSpecTCP-22: a client certificate carrying the mandatory role GridServiceSunSpec was presented and accepted
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "GridServiceSunSpec" (DER value 0c12477269645365727669636553756e53706563)
   - Frames: 4907
   - Frames sha256: `48ee8cc3cf2763268f454e755809100d9e7553ae66a554f6b4630d466f238b96`
2. **PASS** — SunSpecTCP-22/40: the EUT-S AUTHORIZED a Write Multiple Registers request as GridServiceSunSpec — model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; AUTHORIZED and performed — normal (non-exception) response: MBAP header 00 12 00 00 00 06 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 6 \| Unit ID 1; PDU 10 9d 6a 00 01 (5 byte(s)); trailing 
   - Frames: 4954
   - Frames sha256: `d29cc2c8f2e1c9845c52b0ff89f4aaf6a8b7474e9b536e34d7c6cbab381381b1`
3. **PASS** — SunSpecTCP-22: a client certificate carrying the mandatory role NetworkAdministratorSunSpec was presented and accepted
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "NetworkAdministratorSunSpec" (DER value 0c1b4e6574776f726b41646d696e6973747261746f7253756e53706563)
   - Frames: 4973
   - Frames sha256: `a39797d9c3c2e76e18f0ec513d83864089344ce6f24a627117aa5ce44bbfc7ee`
4. **SKIP** — SunSpecTCP-22/40: the EUT-S AUTHORIZED a Write Multiple Registers request as NetworkAdministratorSunSpec — model 0 register 0 (current value 0x0000, written back unchanged) — 
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: this step is conditioned on "if one exists" and no such point exists on this DUT: this DUT's chain on unit 1 holds no model that is a network configuration point (models [1 703 701 702 704 705 706 707 708 709 710 711 712]), so §2.7.2.1's "if one exists" condition is not met and the step is not performed
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
5. **PASS** — SunSpecTCP-22: a client certificate carrying the mandatory role SuperAdministratorSunSpec was presented and accepted
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "SuperAdministratorSunSpec" (DER value 0c19537570657241646d696e6973747261746f7253756e53706563)
   - Frames: 5034
   - Frames sha256: `67a93832d642cd857f9653cedc3ae2639714e7d25f1c6f188cb6813597e714fa`
6. **PASS** — SunSpecTCP-22/40: the EUT-S AUTHORIZED a Write Multiple Registers request as SuperAdministratorSunSpec — model 704 register 40298 (current value 0x0000, written back unchanged) — Model 704, a control point the RBAC procedures name; register 40298 holds 0x0000, a real value, so writing it back is both legal and a no-op
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; AUTHORIZED and performed — normal (non-exception) response: MBAP header 00 12 00 00 00 06 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 6 \| Unit ID 1; PDU 10 9d 6a 00 01 (5 byte(s)); trailing 
   - Frames: 5080
   - Frames sha256: `5eab60411f0417d453857fe74f8018c5dcfe1e60468d0dc97c36163f1eb0c73f`
7. **PASS** — contrast: the SAME write as ReadOnlySunSpec was denied with exception code 01, so the grants above are role-specific and not a blanket allow
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; exception response: function code 0x90, exception code 1 (Illegal Function). MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 90 01 (2 byte(s)); trailing 
   - Frames: 5149
   - Frames sha256: `29a57c15c70647eed4a2860fb62cc45571e324066a104305a5df401c64b9f95e`
8. **PASS** — SunSpecTCP-22 (context): the DUT's roles-to-rights database as configured at the time of this run
   - Method: read of the DUT's RBAC rules over the read-only gateway client
   - Observed: the DUT's rules database (3147 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the DUT's own /etc/lexa/rbac/rules.json, read over the read-only gateway client

### ✓ ssm-conf-v0.8::RBAC-004 Roles-to-Rights Database Audit — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.4 RBAC-004 - Roles-to-Rights Database Audit [T] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's rules database (3147 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]; off-wire criterion: RBAC-004 is a documentation audit. Its own observables begin "No wire traffic — this is a documentation audit", so there is nothing in any capture that could evidence it. The artefact is read off the DUT instead, over the read-only gateway client.

Frame attribution: 0 frame(s) (—), precision none; 132 frame(s) inside the window belonged to other conversations and were excluded.

1. **PASS** — SunSpecTCP-24/25/34: the vendor supplies a roles-to-rights rules database covering the mandatory SunSpec roles
   - Method: read of the DUT's RBAC rules database over the read-only gateway client
   - Observed: the DUT's rules database (3147 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the DUT's own /etc/lexa/rbac/rules.json. Whether the mapping is COMPLETE with respect to every implemented SunSpec point is a document review a human performs against the vendor's model documentation; this assertion establishes only that the database exists on the device and which roles it names.

### ⚠ ssm-conf-v0.8::RBAC-005 Authorization Algorithm Review — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.5 RBAC-005 - Authorization Algorithm Review [T] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the behavioural corollary: exception response: function code 0x90, exception code 1 (Illegal Function). MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 90 01 (2 byte(s)); trailing  · ⚠ WARN the AuthZ Algorithm Description itself is a vendor document. None was supplied to this run (-param ssm.authz_algorithm=<path>), and no capture can evidence a document; the corollary the procedure names — exception code 01 on an unauthorised request — is asserted from the wire instead.

Frame attribution: 63 frame(s) (5198–5272), precision connection; 147 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59920 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec).

1. **PASS** — SunSpecTCP-25/33 (behavioural corollary): an unauthorised request was answered with Modbus exception code 01 (Illegal Function), which is what the vendor's authorization algorithm must produce
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; exception response: function code 0x90, exception code 1 (Illegal Function). MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 90 01 (2 byte(s)); trailing 
   - Frames: 5263
   - Frames sha256: `eb4ef93f0536c91acdaed73455e99a05d5d69e9c3da224a7ddef1d1842c208d6`
2. **SKIP** — SunSpecTCP-25/33: the vendor has defined and supplied the authorization enforcement algorithm
   - Method: review of a vendor-supplied AuthZ Algorithm Description
   - Observed: no AuthZ Algorithm Description was supplied to this run (-param ssm.authz_algorithm=<path>). It is a paper artefact; no capture can evidence it, and the suite will not assert a document it has not been given.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ssm-conf-v0.8::RBAC-006 Role OID Verification — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.6 RBAC-006 - Role OID Verification [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS compliant OID: Model 1 read normal (non-exception) response: MBAP header 00 10 00 00 00 87 01 = Transaction ID 0x0010 | Protocol ID 0x0000 | Length 135 | Unit ID 1; PDU 03 84 53 75 6e 53 70 65 63 20 53 69 6d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 43 53 49 50 2d 53 6f 6c 61 72 2d 35 30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 34 2e 32 2e 31 00 00 00 00 00 00 00 00 00 00 00 42 45 4e 43 48 2d 4d 4f 44 53 49 4d 2d 30 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 (134 byte(s)); trailing  · ✓ PASS non-compliant OID: first Modbus request exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 09 00 00 00 03 01 = Transaction ID 0x0009 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 83 01 (2 byte(s)); trailing 

Frame attribution: 112 frame(s) (5266–5395), precision connection; 174 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59930 <> 192.168.0.69:802 (RBAC session: role at OID 1.3.6.1.4.1.50316.802.1); tcp 192.168.0.188:59936 <> 192.168.0.69:802 (RBAC session: role at OID 1.3.6.1.4.1.50316.802.99).

1. **PASS** — SunSpecTCP-29: session 1 presented the role in the extension at the mandatory Modbus.org PEN OID 1.3.6.1.4.1.50316.802.1
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "ReadOnlySunSpec" (DER value 0c0f526561644f6e6c7953756e53706563)
   - Frames: 5287
   - Frames sha256: `6c85ec44eb8bc8e3bb270d721456884e534e566413453b85c596e71c1a2e82a5`
2. **PASS** — SunSpecTCP-29: session 2 presented the role under a NON-COMPLIANT OID (1.3.6.1.4.1.50316.802.99) and nothing at 1.3.6.1.4.1.50316.802.1
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; every custom extension OID enumerated
   - Observed: custom extension OIDs on the presented leaf: [1.3.6.1.4.1.50316.802.99]; extension at 1.3.6.1.4.1.50316.802.1 ABSENT
   - Frames: 5348
   - Frames sha256: `a8922e3fc6eea5b116b34beed56eaa5c5fa3f6e52010948f79777362678be767`
3. **PASS** — SunSpecTCP-29: the non-compliant-OID handshake reached Finished — the DUT rejected it at the APPLICATION layer, not with a TLS alert
   - Method: handshake message types and alert scan of the non-compliant-OID conversation
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec — and no fatal TLS alert was sent
   - Frames: 5336, 5338, 5339, 5340, 5341, 5342, 5348, 5352, 5354, 5356, 5359, 5360, 5361, 5362, 5363, 5364, 5365, 5366, 5367, 5368, 5369, 5370, 5371, 5372, 5373, 5374, 5375, 5378, 5382
   - Frames sha256: `190e8928c680e53850f0b27013776e0244445a765b802404372006a7e84d087c`
4. **PASS** — SunSpecTCP-29: with the role at the mandatory OID, the Model 1 read was answered with data
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; normal (non-exception) response: MBAP header 00 01 00 00 00 07 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 7 \| Unit ID 1; PDU 03 04 53 75 6e 53 (6 byte(s)); trailing 
   - Frames: 5294
   - Frames sha256: `0c35537b0f7b6ed9ec9fccab1306ce1a90e1204d2a7494551ace6477c5ec2c30`
5. **PASS** — SunSpecTCP-29: with the role under a non-compliant OID, the FIRST Modbus request was answered with exception code 01 (Illegal Function)
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 01 00 00 00 03 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 83 01 (2 byte(s)); trailing 
   - Frames: 5359
   - Frames sha256: `0b8f907fbce8f491752dc3a743935559ee2dd54e16c7a6d3c0bbe96c311c806c`

### ⚠ ssm-conf-v0.8::RBAC-007 Role Encoding and Singular Role Validation — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.7 RBAC-007 - Role Encoding and Singular Role Validation [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS role encoded as IA5String, not UTF8String: exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 09 00 00 00 03 01 = Transaction ID 0x0009 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 83 01 (2 byte(s)); trailing  · ⚠ WARN certificate carrying two role values: the session completed but issued no readable request: read MBAP header: EOF

Frame attribution: 79 frame(s) (5380–5481), precision connection; 210 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59948 <> 192.168.0.69:802 (RBAC session: role encoded as IA5String, not UTF8String); tcp 192.168.0.188:59954 <> 192.168.0.69:802 (RBAC session: certificate carrying two role values).

1. **PASS** — SunSpecTCP-30: the client certificate carried the role at OID 1.3.6.1.4.1.50316.802.1 with the ASN.1 tag IA5String instead of the required UTF8String
   - Method: the bench's Certificate message, parsed from the capture; the extension's DER value quoted verbatim
   - Observed: the extension at 1.3.6.1.4.1.50316.802.1 carries ASN.1 tag 0x16 (IA5String); DER value 1612477269645365727669636553756e53706563
   - Frames: 5410
   - Frames sha256: `e81ab9b5a491026b927d629d2de5553625b160cd44ae416aeb5d8aae702bf57b`
2. **PASS** — SunSpecTCP-30: the IA5String-encoded role was rejected at the application layer with Modbus exception code 01
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 01 00 00 00 03 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 83 01 (2 byte(s)); trailing 
   - Frames: 5418
   - Frames sha256: `25454544e48d89deb6ba01a903e854c2c19b56dd2fa3075308ce6da3304adb67`
3. **PASS** — SunSpecTCP-31: the client certificate carried more than one role value
   - Method: the bench's Certificate message, parsed from the capture; the role extension's DER value quoted verbatim
   - Observed: extension at 1.3.6.1.4.1.50316.802.1: present true, DER value 0c12477269645365727669636553756e53706563, decode: tlsdis: certificate carries multiple role extensions
   - Frames: 5455
   - Frames sha256: `e0381e9927da7701684cc18e6ffe6ee005c300116fd13892fb61ba59a0609f35`
4. **PASS** — SunSpecTCP-30/31: the handshake presenting role encoded as IA5String, not UTF8String completed — the non-compliant role was judged at the application layer, with no TLS alert
   - Method: handshake message types and alert scan of this conversation
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 5397, 5399, 5400, 5404, 5406, 5407, 5410, 5412, 5413, 5415, 5418, 5419, 5420, 5421, 5422, 5423, 5424, 5425, 5428, 5429, 5430, 5431, 5432, 5433, 5434, 5435, 5436, 5465, 5470
   - Frames sha256: `592d9501c5225af2e90827c5436fa87f397e03daebd38c7e23a1a8dae7454f65`
5. **PASS** — SunSpecTCP-30/31: the handshake presenting certificate carrying two role values completed — the non-compliant role was judged at the application layer, with no TLS alert
   - Method: handshake message types and alert scan of this conversation
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 5440, 5442, 5443, 5449, 5451, 5452, 5455, 5456, 5457, 5459, 5460, 5461, 5463, 5464, 5466, 5468
   - Frames sha256: `3818621663d2960b11ff86c2f7544d0e2be5e8ec1aaa193ea9726e09c12c1477`
6. **SKIP** — SunSpecTCP-31: the two-role certificate's first Modbus request was answered — either denied with exception 01, or answered normally with the concatenation treated as one unknown role; the procedure's expected results permit both
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: the recovered plaintext does not contain what this claim rests on: the request 00 01 00 00 00 06 01 03 9c 40 00 02 was recovered but no matching response appears in the 0 decrypted DUT→bench byte(s)
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ ssm-conf-v0.8::RBAC-008 Missing Role Handling — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.8 RBAC-008 - Missing Role Handling [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS the handshake completed with a role-less certificate, as required · ✓ PASS the Model 1 read was then exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 09 00 00 00 03 01 = Transaction ID 0x0009 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 83 01 (2 byte(s)); trailing 

Frame attribution: 45 frame(s) (5469–5528), precision connection; 186 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59966 <> 192.168.0.69:802 (RBAC session: certificate with no role extension).

1. **PASS** — SunSpecTCP-32: the client certificate carried NO extension at OID 1.3.6.1.4.1.50316.802.1
   - Method: the bench's Certificate message, parsed from the capture; every custom extension OID enumerated
   - Observed: custom extension OIDs on the presented leaf: []; extension at 1.3.6.1.4.1.50316.802.1 ABSENT
   - Frames: 5498
   - Frames sha256: `2419beb45149ef7f26b15730043f35a66b797270f9ac997680fcf6db38e2151c`
2. **PASS** — SunSpecTCP-32/40: mutual authentication COMPLETED with the role-less certificate — CertificateVerify and Finished were exchanged and no TLS alert was sent
   - Method: handshake message types and alert scan of this conversation
   - Observed: EUT-S flight [server_hello certificate server_key_exchange certificate_request server_hello_done]; bench flight [client_hello certificate client_key_exchange certificate_verify] — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec
   - Frames: 5484, 5486, 5487, 5492, 5494, 5495, 5498, 5499, 5500, 5502, 5503, 5504, 5505, 5506, 5507, 5508, 5509, 5510, 5511, 5512, 5513, 5514, 5515, 5516, 5517, 5518, 5519, 5520, 5523
   - Frames sha256: `319a57102af1d249fe021facd1cb5d4c840b03fb026a3a03135b18fb980bfe4d`
3. **PASS** — SunSpecTCP-40: the Read Holding Registers request on the role-less session was answered with Modbus exception code 01 (Illegal Function)
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 01 00 00 00 06 01 03 9c 40 00 02; exception response: function code 0x83, exception code 1 (Illegal Function). MBAP header 00 01 00 00 00 03 01 = Transaction ID 0x0001 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 83 01 (2 byte(s)); trailing 
   - Frames: 5503
   - Frames sha256: `efa61dc7bb6edbfdbeb798cfbcc7ef9268f32556b3449ab7878b17337ccf2eda`

### ✓ ssm-conf-v0.8::RBAC-009 Information Leakage Prevention — PASS

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.9 RBAC-009 - Information Leakage Prevention [S] (Negative Test) (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS 9-byte denial response 00 12 00 00 00 03 01 90 01. MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 | Protocol ID 0x0000 | Length 3 | Unit ID 1; PDU 90 01 (2 byte(s)); trailing  — no register values, no diagnostic text, nothing after the exception code

Frame attribution: 64 frame(s) (5522–5599), precision connection; 142 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59976 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec).

1. **PASS** — SunSpecTCP-33/34/41: the denied Write Multiple Registers request was answered by exactly nine bytes — a 7-byte MBAP header with Length 3, the error function code, and exception code 01 — with no register values, diagnostic text or trailing bytes
   - Method: TLS decryption of this session's records with the run's key log, then MBAP decoding of the recovered request/response pair
   - Observed: request 00 12 00 00 00 09 01 10 9d 6a 00 01 02 00 00; 9-byte denial response 00 12 00 00 00 03 01 90 01. MBAP header 00 12 00 00 00 03 01 = Transaction ID 0x0012 \| Protocol ID 0x0000 \| Length 3 \| Unit ID 1; PDU 90 01 (2 byte(s)); trailing  — no register values, no diagnostic text, nothing after the exception code
   - Frames: 5593
   - Frames sha256: `c51a76f70c161d0c58eba14a48896f168a4a166a2cd7f3da6c4c08150efd9d5d`

### ⚠ ssm-conf-v0.8::RBAC-010 Rules Database Configuration — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.10 RBAC-010 - Rules Database Configuration [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ⚠ WARN RBAC-010 requires creating a role (SecureSunSpecTestRole), modifying its rights, exercising them and deleting it — four WRITES to the DUT's roles-to-rights database. This run shares the bench and may not change DUT configuration. The underlying criterion — that the database is configuration and not hardcoded — is evidenced off-wire from the DUT's own rules file. · ✓ PASS the DUT's roles-to-rights database is a configuration file on the device (3147 bytes)

Frame attribution: 0 frame(s) (—), precision none; 189 frame(s) inside the window belonged to other conversations and were excluded.

1. **SKIP** — SunSpecTCP-36/37: a role can be created in the EUT's rules database, granted rights that are then honoured on the wire, and deleted again
   - Method: role creation, rights modification and deletion through the EUT's management interface, with handshakes between each step
   - Observed: every step is a WRITE to a shared DUT's roles-to-rights database, and the procedure would leave a SecureSunSpecTestRole behind on failure. This run may not change DUT configuration.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **PASS** — SunSpecTCP-36: the EUT's roles-to-rights database is configurable data, not compiled-in behaviour
   - Method: read of the DUT's RBAC rules database over the read-only gateway client
   - Observed: the roles-to-rights database is a 3147-byte file on the device, reloadable without a rebuild: the DUT's rules database (3147 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the DUT's own /etc/lexa/rbac/rules.json, read over the read-only gateway client

### ⚠ ssm-conf-v0.8::RBAC-012 Comprehensive Role-to-Rights Consistency Validation — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.12 RBAC-012 - Comprehensive Role-to-Rights Consistency Validation [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS swept 52 role×model cell(s): GridServiceSunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=allow, m705 r=allow w=deny(3), m706 r=allow w=deny(3), m707 r=allow w=deny(3), m708 r=allow w=deny(3), m709 r=allow w=deny(3), m710 r=allow w=deny(3), m711 r=allow w=deny(3), m712 r=allow w=deny(3) | NetworkAdministratorSunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=deny(1), m705 r=allow w=deny(1), m706 r=allow w=deny(1), m707 r=allow w=deny(1), m708 r=allow w=deny(1), m709 r=allow w=deny(1), m710 r=allow w=deny(1), m711 r=allow w=deny(1), m712 r=allow w=deny(1) | ReadOnlySunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=deny(1), m705 r=allow w=deny(1), m706 r=allow w=deny(1), m707 r=allow w=deny(1), m708 r=allow w=deny(1), m709 r=allow w=deny(1), m710 r=allow w=deny(1), m711 r=allow w=deny(1), m712 r=allow w=deny(1) | SuperAdministratorSunSpec: m1 r=allow w=deny(2), m703 r=allow w=allow, m701 r=allow w=deny(2), m702 r=allow w=deny(2), m704 r=allow w=allow, m705 r=allow w=deny(3), m706 r=allow w=deny(3), m707 r=allow w=deny(3), m708 r=allow w=deny(3), m709 r=allow w=deny(3), m710 r=allow w=deny(3), m711 r=allow w=deny(3), m712 r=allow w=deny(3) · ✓ PASS 3 distinct write-permission profiles were observed across the four mandatory roles; VERDICT RECONCILED — the live phase declared PASS from what the socket saw; the citation phase re-derived the criteria from the capture and the case is WARN. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 454 frame(s) (5608–6150), precision connection; 172 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:59980 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec); tcp 192.168.0.188:59986 <> 192.168.0.69:802 (RBAC session: GridServiceSunSpec); tcp 192.168.0.188:60000 <> 192.168.0.69:802 (RBAC session: NetworkAdministratorSunSpec); tcp 192.168.0.188:60010 <> 192.168.0.69:802 (RBAC session: SuperAdministratorSunSpec).

1. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value ReadOnlySunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "ReadOnlySunSpec" (DER value 0c0f526561644f6e6c7953756e53706563)
   - Frames: 5623
   - Frames sha256: `d81bbb68529d390f2c2199c23131870b8971c718abb8142ae6ca30000ac3b18d`
2. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value GridServiceSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "GridServiceSunSpec" (DER value 0c12477269645365727669636553756e53706563)
   - Frames: 5757
   - Frames sha256: `475e875d341a7ff870c43ccd706d52dc2cc47b2bfc40291914ec13873b324c20`
3. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value NetworkAdministratorSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "NetworkAdministratorSunSpec" (DER value 0c1b4e6574776f726b41646d696e6973747261746f7253756e53706563)
   - Frames: 5874
   - Frames sha256: `0053b574d707a6df4f54ec9dd0ddd8844cc92fc9550ff5dc86ef56c9fe7b67ba`
4. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value SuperAdministratorSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "SuperAdministratorSunSpec" (DER value 0c19537570657241646d696e6973747261746f7253756e53706563)
   - Frames: 5996
   - Frames sha256: `94c6081ced01feac2720f8336de5da68b1ce9a63a9027ac0c018450faba592c5`
5. **PASS** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role ReadOnlySunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: ReadOnlySunSpec: model 1 at register 40004 — read allow, write deny(1); model 703 at register 40072 — read allow, write deny(1); model 701 at register 40091 — read allow, write deny(1); model 702 at register 40246 — read allow, write deny(1); model 704 at register 40298 — read allow, write deny(1); model 705 at register 40365 — read allow, write deny(1); model 706 at register 40410 — read allow, write deny(1); model 707 at register 40450 — read allow, write deny(1); model 708 at register 40553 — read allow, write deny(1); model 709 at register 40656 — read allow, write deny(1); model 710 at register 40789 — read allow, write deny(1); model 711 at register 40922 — read allow, write deny(1); model 712 at register 40946 — read allow, write deny(1)
   - Frames: 5628, 5632, 5634, 5636, 5638, 5642, 5644, 5646, 5648, 5650, 5652, 5654, 5658, 5660, 5670, 5672, 5674, 5676, 5679, 5682, 5687, 5689, 5691, 5693, 5695, 5699, 5701, 5703, 5705, 5707, 5709, 5712, 5714, 5716, 5720, 5722, 5724, 5726, 5728, 5734, 5736, 5738
   - Frames sha256: `30f2215c4bb8409e66767f54d1b5f026df7671257fd3ab9f33cae0d737633c0e`
6. **PASS** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role GridServiceSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: GridServiceSunSpec: model 1 at register 40004 — read allow, write deny(1); model 703 at register 40072 — read allow, write deny(1); model 701 at register 40091 — read allow, write deny(1); model 702 at register 40246 — read allow, write deny(1); model 704 at register 40298 — read allow, write allow; model 705 at register 40365 — read allow, write deny(3); model 706 at register 40410 — read allow, write deny(3); model 707 at register 40450 — read allow, write deny(3); model 708 at register 40553 — read allow, write deny(3); model 709 at register 40656 — read allow, write deny(3); model 710 at register 40789 — read allow, write deny(3); model 711 at register 40922 — read allow, write deny(3); model 712 at register 40946 — read allow, write deny(3)
   - Frames: 5764, 5766, 5770, 5772, 5774, 5776, 5778, 5780, 5782, 5784, 5786, 5788, 5792, 5794, 5796, 5798, 5800, 5802, 5804, 5808, 5810, 5812, 5814, 5816, 5818, 5820, 5824, 5826, 5828, 5830, 5832, 5834, 5836, 5838, 5840, 5842, 5844, 5846, 5848, 5852, 5854, 5856
   - Frames sha256: `cce8c41fa177a9b54dedca6b02425d1b2be2a1628a363729304ee684e947f2e8`
7. **PASS** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role NetworkAdministratorSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: NetworkAdministratorSunSpec: model 1 at register 40004 — read allow, write deny(1); model 703 at register 40072 — read allow, write deny(1); model 701 at register 40091 — read allow, write deny(1); model 702 at register 40246 — read allow, write deny(1); model 704 at register 40298 — read allow, write deny(1); model 705 at register 40365 — read allow, write deny(1); model 706 at register 40410 — read allow, write deny(1); model 707 at register 40450 — read allow, write deny(1); model 708 at register 40553 — read allow, write deny(1); model 709 at register 40656 — read allow, write deny(1); model 710 at register 40789 — read allow, write deny(1); model 711 at register 40922 — read allow, write deny(1); model 712 at register 40946 — read allow, write deny(1)
   - Frames: 5884, 5886, 5890, 5892, 5894, 5896, 5898, 5900, 5902, 5904, 5907, 5911, 5913, 5915, 5917, 5919, 5922, 5924, 5926, 5928, 5930, 5932, 5936, 5938, 5940, 5944, 5946, 5948, 5950, 5954, 5956, 5958, 5960, 5962, 5964, 5968, 5970, 5972, 5974, 5976, 5978, 5980
   - Frames sha256: `50ae118a8f22a5243f9886986f48694fa7743b42e9099c0d4a3e47d7e455ba63`
8. **PASS** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role SuperAdministratorSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: SuperAdministratorSunSpec: model 1 at register 40004 — read allow, write deny(2); model 703 at register 40072 — read allow, write allow; model 701 at register 40091 — read allow, write deny(2); model 702 at register 40246 — read allow, write deny(2); model 704 at register 40298 — read allow, write allow; model 705 at register 40365 — read allow, write deny(3); model 706 at register 40410 — read allow, write deny(3); model 707 at register 40450 — read allow, write deny(3); model 708 at register 40553 — read allow, write deny(3); model 709 at register 40656 — read allow, write deny(3); model 710 at register 40789 — read allow, write deny(3); model 711 at register 40922 — read allow, write deny(3); model 712 at register 40946 — read allow, write deny(3)
   - Frames: 6004, 6006, 6008, 6012, 6014, 6016, 6018, 6020, 6022, 6024, 6026, 6029, 6033, 6036, 6038, 6040, 6042, 6044, 6046, 6048, 6052, 6054, 6056, 6058, 6060, 6064, 6066, 6068, 6070, 6072, 6074, 6076, 6078, 6080, 6082, 6084, 6086, 6088, 6090, 6094, 6096, 6098
   - Frames sha256: `8c69f0a7ee689c30a128915f1e7ba285e59050417b57095d98f852aef5e5ade2`
9. **WARN** — SunSpecTCP-38: the observed permission matrix is consistent with the vendor's roles-to-rights database
   - Method: cross-reference of the observed matrix against the DUT's own rules database
   - Observed: observed matrix: GridServiceSunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=allow, m705 r=allow w=deny(3), m706 r=allow w=deny(3), m707 r=allow w=deny(3), m708 r=allow w=deny(3), m709 r=allow w=deny(3), m710 r=allow w=deny(3), m711 r=allow w=deny(3), m712 r=allow w=deny(3) \| NetworkAdministratorSunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=deny(1), m705 r=allow w=deny(1), m706 r=allow w=deny(1), m707 r=allow w=deny(1), m708 r=allow w=deny(1), m709 r=allow w=deny(1), m710 r=allow w=deny(1), m711 r=allow w=deny(1), m712 r=allow w=deny(1) \| ReadOnlySunSpec: m1 r=allow w=deny(1), m703 r=allow w=deny(1), m701 r=allow w=deny(1), m702 r=allow w=deny(1), m704 r=allow w=deny(1), m705 r=allow w=deny(1), m706 r=allow w=deny(1), m707 r=allow w=deny(1), m708 r=allow w=deny(1), m709 r=allow w=deny(1), m710 r=allow w=deny(1), m711 r=allow w=deny(1), m712 r=allow w=deny(1) \| SuperAdministratorSunSpec: m1 r=allow w=deny(2), m703 r=allow w=allow, m701 r=allow w=deny(2), m702 r=allow w=deny(2), m704 r=allow w=allow, m705 r=allow w=deny(3), m706 r=allow w=deny(3), m707 r=allow w=deny(3), m708 r=allow w=deny(3), m709 r=allow w=deny(3), m710 r=allow w=deny(3), m711 r=allow w=deny(3), m712 r=allow w=deny(3) \|\| database: the DUT's rules database (3147 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]. A full clause-by-clause cross-reference requires interpreting the vendor's rules language, including its deployment-mode overlays, which this suite does not re-implement; the matrix and the database are both recorded here so a reviewer can perform it.
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the observed sweep above plus the DUT's own /etc/lexa/rbac/rules.json

### ⚠ ssm-conf-v0.8::OPS-001 Cryptographic Export Compliance — WARN

Reference: SSM-CONF-v0.8 v0.8-TEST §2.9.1 OPS-001 - Cryptographic Export Compliance [C, S] (under 2.9 Operational Security (OPS) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✓ PASS OPS-001: TLS 1.2 observation: negotiated 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 over TLS 1.2 · ✓ PASS OPS-001: TLS 1.3 observation: negotiated 0x1301 TLS_AES_128_GCM_SHA256 over TLS 1.3 · ⚠ WARN no Cryptographic Export Declaration was supplied (-param ssm.export_declaration=<path>), so the vendor attestation SunSpecTCP-58 requires could not be reviewed; the observed cryptography is cited below as the cross-reference input for that review

Frame attribution: 40 frame(s) (6115–6189), precision connection; 88 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:60020 <> 192.168.0.69:802 (SSM probe: OPS-001: TLS 1.2 observation); tcp 192.168.0.188:60028 <> 192.168.0.69:802 (SSM probe: OPS-001: TLS 1.3 observation).

1. **PASS** — SunSpecTCP-58 (cross-reference input): the cryptography the EUT actually used on the wire — OPS-001: TLS 1.2 observation
   - Method: ServerKeyExchange curve and ServerHello.cipher_suite, parsed from the capture
   - Observed: cipher suite 0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, negotiated version TLS 1.2 — this is the observation an export declaration must be consistent with
   - Frames: 6152
   - Frames sha256: `aff800a20b37f4cd3d93901c54400f03dfcd84e781062a42586b2b5c815ea044`
2. **PASS** — SunSpecTCP-58 (cross-reference input): the cryptography the EUT actually used on the wire — OPS-001: TLS 1.3 observation
   - Method: ServerKeyExchange curve and ServerHello.cipher_suite, parsed from the capture
   - Observed: cipher suite 0x1301 TLS_AES_128_GCM_SHA256, negotiated version TLS 1.3 — this is the observation an export declaration must be consistent with
   - Frames: 6173
   - Frames sha256: `103df01e0f24f0f52614eeb065c942d0143c2d46b0720c7d2db260bffa5159ea`
3. **SKIP** — SunSpecTCP-58: the vendor's Cryptographic Export Declaration lists every implemented cipher suite and key exchange, attests to jurisdictional compliance, and matches the CRYP-category observations
   - Method: clause-by-clause review of a vendor-supplied declaration against the observed suites
   - Observed: no Cryptographic Export Declaration was supplied to this run (-param ssm.export_declaration=<path>). This is a paper artefact a vendor provides; no packet capture can evidence it, and the suite will not assert a document it has not been given.
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

