# Conformance evidence bundle

**Device under test:** lexa-gw at `192.168.0.69:802`

| | |
|---|---|
| Tool | csip-certify eb2c71acf25f |
| Source commit | 13a76b6fb0dfdc5962d366c826be081cf61bbeb4 |
| Operator | lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09 |
| Host | dmitri-HP-ENVY-TE01-1xxx |
| Started | 2026-09-09T20:48:22Z |
| Finished | 2026-09-09T20:48:28Z |
| DUT build | d403552 |
| Capture | `capture/run-20260909-204823.pcapng` — 275 packets, 48752 bytes, pcapng |
| Capture tool | dumpcap Dumpcap (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). |
| Interface | wlp2s0 |
| Capture hygiene | 275 frame(s) captured; no filter was requested, so every frame the tool wrote is in this bundle |
| Key log | capture/bench-shared.keylog |

> **This bundle contains TLS session secrets.** `capture/bench-shared.keylog` is an NSS key log for the
> capture above: anyone holding this directory can decrypt every session it
> records. It is included on purpose — the application-layer citations below
> cannot be re-derived without it — and it is covered by the manifest, so it
> cannot be quietly dropped either. Treat the bundle as sensitive: share it
> with an assessor, not publicly. The secrets are per-session and grant no
> lasting access to the device.

> catalog: /home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json (290 cases, 1626330 bytes, sha256:eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588); frame attribution: 275 frames: 245 attributed to 2 test case(s), 30 unattributed (background), 0 contested; per-test captures required by the governing document's Reporting Requirements: 1 of 1 written into capture/; provenance: DUT build reported fw=1.0.0 build_id=d403552b1056 image_build_id=d403552b1056 image_profile=image; EXPLORATORY, NOT GATING: no -campaign was declared: this is an EXPLORATORY selection, and its result is evidence about the implementation rather than a campaign anything may rest on

Capture tool output:

```
Capturing on 'wlp2s0'
File: runs/p6-d403552-rbac-zero-principals-20260909T204822Z/capture/run-20260909-204823.pcapng
Packets captured: 275
Packets received/dropped on interface 'wlp2s0': 275/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

## How this run was invoked

```
certify-keylog -uid ssm-conf-v0.8::RBAC-012 -uid ss-modbus-conf-v1.4::MB-1 -manifest /home/dmitri/projects/lexa-gw/configs/candidate.json -target 192.168.0.69:802 -pki certs/mbaps -gridsim 192.168.0.188:11113 -gridsim-admin http://192.168.0.188:11114 -modsim 69.0.0.20:5020 -modsim-api http://69.0.0.20:6020 -mbapsdev-api http://69.0.0.20:6031 -gateway-ssh cc93 -metrics-endpoint http://127.0.0.1:9102/metrics -keylog /tmp/bench-shared.keylog -operator 'lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09' -dut-name lexa-gw -dut-build d403552 -iface wlp2s0 -timeout 6m -out runs/p6-d403552-rbac-zero-principals-20260909T204822Z -v
```

Credential-shaped flag values are replaced with `[redacted]`; every other argument is verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of this table.

The capture itself:

```
/usr/bin/dumpcap -i wlp2s0 -w runs/p6-d403552-rbac-zero-principals-20260909T204822Z/capture/run-20260909-204823.pcapng -q -p
```

## Result

**0 PASS · 2 FAIL · 0 SKIP · 0 WARN** across 2 in-scope test case(s).

✗ 2 test case(s) FAILED.

| Case | Title | Claim | Verdict | Assertions | Frames |
|------|-------|-------|---------|-----------:|--------|
| ss-modbus-conf-v1.4::MB-1 | Modbus Single/Multiple Register Write | yes | FAIL | 1 | — |
| ssm-conf-v0.8::RBAC-012 | Comprehensive Role-to-Rights Consistency Validation | yes | FAIL | 9 | 88–221 |

## Verifying this bundle

This directory is self-checking. Independent checks, in the order a sceptical reader
would run them:

1. `sha256sum -c MANIFEST.sha256` — every file, the capture included, is covered.
2. The evidence verifier re-reads `capture/run-20260909-204823.pcapng` and confirms that every cited frame
   exists and carries the exact bytes each assertion claims. It reads only this
   directory and needs nothing from the bench that produced it.
3. Every case verdict in the table above is re-derived from that case's own printed
   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is
   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be
   edited away from, the evidence underneath it.

Assertions marked *(no digest)* below carry no re-checkable citation: they are
narrative, not proof.

## Test cases

### ✗ ss-modbus-conf-v1.4::MB-1 Modbus Single/Multiple Register Write — FAIL

Reference: SS-MODBUS-CONF-v1.4 v1.4 §2.7.9 MB-1 - Modbus Single/Multiple Register Write (under 2.7 Modbus Protocol Tests / General Modbus Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): check could not be carried out: suitemodbusserver: no unit in 1..16 answered the SunSpec identifier at 40000

Frame attribution: 69 frame(s) (1–71), precision connection; 75 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:39800 <> 192.168.0.69:802 (MB-1 single/multiple register write).

1. **FAIL** — the test case was carried out
   - Method: runner
   - Observed: suitemodbusserver: no unit in 1..16 answered the SunSpec identifier at 40000
   - _(no digest — narrative, not re-checkable)_
   - Note: no conformance conclusion about the DUT can be drawn from this row

### ✗ ssm-conf-v0.8::RBAC-012 Comprehensive Role-to-Rights Consistency Validation — FAIL

Reference: SSM-CONF-v0.8 v0.8-TEST §2.7.12 RBAC-012 - Comprehensive Role-to-Rights Consistency Validation [S] (under 2.7 Role-Based Access Control (RBAC) Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): ✗ FAIL no role could discover a SunSpec chain, so no permission matrix could be swept

Frame attribution: 176 frame(s) (72–251), precision connection; 54 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp 192.168.0.188:39816 <> 192.168.0.69:802 (RBAC session: ReadOnlySunSpec); tcp 192.168.0.188:39830 <> 192.168.0.69:802 (RBAC session: GridServiceSunSpec); tcp 192.168.0.188:39832 <> 192.168.0.69:802 (RBAC session: NetworkAdministratorSunSpec); tcp 192.168.0.188:39834 <> 192.168.0.69:802 (RBAC session: SuperAdministratorSunSpec).

1. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value ReadOnlySunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "ReadOnlySunSpec" (DER value 0c0f526561644f6e6c7953756e53706563)
   - Frames: 88
   - Frames sha256: `27ddee0dc4b1f88a38d1a4221368982d8813c939553c1e2cedba3de4b2a506e7`
2. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value GridServiceSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "GridServiceSunSpec" (DER value 0c12477269645365727669636553756e53706563)
   - Frames: 125
   - Frames sha256: `33cc81a691c2005d285f1b296c1dae9e36be030b67258805622be2797c21e58b`
3. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value NetworkAdministratorSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "NetworkAdministratorSunSpec" (DER value 0c1b4e6574776f726b41646d696e6973747261746f7253756e53706563)
   - Frames: 161
   - Frames sha256: `57bbc45b0473c57bb9d764423437ddb4aff58914d61173ec2e2cea83011a7744`
4. **PASS** — SunSpecTCP-35: the certificate presented for the sweep carries the role value SuperAdministratorSunSpec, which must appear in the vendor's roles-to-rights database
   - Method: the bench's TLS 1.2 Certificate message, parsed from the capture; the extension at OID 1.3.6.1.4.1.50316.802.1 decoded with the bench's own ASN.1 rule
   - Observed: extension at OID 1.3.6.1.4.1.50316.802.1 decodes as the single UTF8String "SuperAdministratorSunSpec" (DER value 0c19537570657241646d696e6973747261746f7253756e53706563)
   - Frames: 201
   - Frames sha256: `1e11ff22bda7592671ef004bb18b0a93630671b2c42a0853a919254d8cd4f6fd`
5. **FAIL** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role ReadOnlySunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: this role completed no sweep cells
   - Frames: 94, 96, 98, 100, 102, 104, 106, 108
   - Frames sha256: `fb2de4ae0b2f8b1b9ea352a49c2b29c0ec89df4c323e0112feb8b7c372280943`
6. **FAIL** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role GridServiceSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: this role completed no sweep cells
   - Frames: 131, 133, 135, 137, 139, 141, 143, 145
   - Frames sha256: `705758b5282524ec5e436bc2403894e550c0282385b86faead2e66cbec69f0e5`
7. **FAIL** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role NetworkAdministratorSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: this role completed no sweep cells
   - Frames: 170, 172, 174, 176, 178, 180, 182, 184
   - Frames sha256: `efafc6664dccd72a1964720de32071f80bc2552bc11c9aeaf1cc0b1ba5661df4`
8. **FAIL** — SunSpecTCP-35/38: the permission profile the EUT-S applied to role SuperAdministratorSunSpec across every model in its chain
   - Method: a read and a read-back write per model per role, recovered by decrypting this session's records with the run's key log. NOTE: the sweep is per MODEL, not per point — a per-point sweep of every model across four roles is several thousand authenticated round trips against a shared gateway, and the DUT's authorization decision is made per point-group, so a per-model probe exercises the same decision path
   - Observed: this role completed no sweep cells
   - Frames: 207, 209, 211, 213, 215, 217, 219, 221
   - Frames sha256: `020b09ad0e76915e71d3930c2b2b65220c80895976aad13cde8b700a24c70466`
9. **WARN** — SunSpecTCP-38: the observed permission matrix is consistent with the vendor's roles-to-rights database
   - Method: cross-reference of the observed matrix against the DUT's own rules database
   - Observed: observed matrix: (empty) \|\| database: the DUT's rules database (1231 bytes) names 4 of the 4 mandatory SunSpec roles: [ReadOnlySunSpec, GridServiceSunSpec, NetworkAdministratorSunSpec, SuperAdministratorSunSpec]. A full clause-by-clause cross-reference requires interpreting the vendor's rules language, including its deployment-mode overlays, which this suite does not re-implement; the matrix and the database are both recorded here so a reviewer can perform it.
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the observed sweep above plus the DUT's own /etc/lexa/rbac/rules.json

