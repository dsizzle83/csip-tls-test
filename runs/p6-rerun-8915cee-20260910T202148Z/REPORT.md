# Conformance evidence bundle

**Device under test:** lexa-gw at `192.168.0.69:802`

| | |
|---|---|
| Tool | csip-certify eb2c71acf25f |
| Source commit | f69a8ce598df7d655c12fc317b6e0e442f934759 |
| Operator | lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09 |
| Host | dmitri-HP-ENVY-TE01-1xxx |
| Started | 2026-09-10T20:21:48Z |
| Finished | 2026-09-10T20:46:42Z |
| DUT build | 8915cee |
| Capture | `capture/run-20260910-202149.pcapng` — 44498 packets, 24777856 bytes, pcapng |
| Capture tool | dumpcap Dumpcap (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). |
| Interface | wlp2s0 |
| Capture hygiene | 44498 frame(s) captured; no filter was requested, so every frame the tool wrote is in this bundle |
| Key log | capture/bench-shared.keylog |

> **This bundle contains TLS session secrets.** `capture/bench-shared.keylog` is an NSS key log for the
> capture above: anyone holding this directory can decrypt every session it
> records. It is included on purpose — the application-layer citations below
> cannot be re-derived without it — and it is covered by the manifest, so it
> cannot be quietly dropped either. Treat the bundle as sensitive: share it
> with an assessor, not publicly. The secrets are per-session and grant no
> lasting access to the device.

> catalog: /home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json (290 cases, 1626330 bytes, sha256:eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588); frame attribution: 44498 frames: 5242 attributed to 5 test case(s), 39256 unattributed (background), 0 contested; provenance: DUT build reported fw=1.0.0 build_id=8915cee2fd56 image_build_id=8915cee2fd56 image_profile=image; EXPLORATORY, NOT GATING: no -campaign was declared: this is an EXPLORATORY selection, and its result is evidence about the implementation rather than a campaign anything may rest on

Capture tool output:

```
Capturing on 'wlp2s0'
File: runs/p6-rerun-8915cee-20260910T202148Z/capture/run-20260910-202149.pcapng
Packets captured: 44498
Packets received/dropped on interface 'wlp2s0': 44498/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

## How this run was invoked

```
certify-keylog -uid local-ext-v1::EXT-005 -uid local-ext-v1::EXT-006 -uid local-ext-v1::EXT-008 -uid csip-conf-v1.3::BASIC-009 -uid csip-conf-v1.3::CORE-022 -manifest /home/dmitri/projects/lexa-gw/configs/candidate.json -target 192.168.0.69:802 -pki certs/mbaps -gridsim 192.168.0.188:11113 -gridsim-admin http://192.168.0.188:11114 -modsim 69.0.0.20:5020 -modsim-api http://69.0.0.20:6020 -mbapsdev-api http://69.0.0.20:6031 -gateway-ssh cc93 -metrics-endpoint http://127.0.0.1:9102/metrics -keylog /tmp/bench-shared.keylog -operator 'lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09' -dut-name lexa-gw -dut-build 8915cee -iface wlp2s0 -timeout 12m -param CORE-022:csip.wait=8m -sign-key '[redacted]' -out runs/p6-rerun-8915cee-20260910T202148Z -v
```

Credential-shaped flag values are replaced with `[redacted]`; every other argument is verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of this table.

The capture itself:

```
/usr/bin/dumpcap -i wlp2s0 -w runs/p6-rerun-8915cee-20260910T202148Z/capture/run-20260910-202149.pcapng -q -p
```

## Result

**3 PASS · 2 FAIL · 0 SKIP · 0 WARN** across 5 in-scope test case(s).

- **Applicable to the claim:** 2 PASS · 0 FAIL · 0 SKIP · 0 WARN (2 in-scope case(s))
- **Informative** — implemented but not bearing on the claim, marked `info` (not applicable to the claimed profile) or `local-ext` (covered by no published procedure) in the table below: 1 PASS · 2 FAIL · 0 SKIP · 0 WARN (3 in-scope case(s))

✗ 2 test case(s) FAILED — 0 applicable to the claim, 2 informative. Only the applicable failures bear on the certification claim.

| Case | Title | Claim | Verdict | Assertions | Frames |
|------|-------|-------|---------|-----------:|--------|
| csip-conf-v1.3::BASIC-009 | Basic Inverter Control (Connect/Disconnect) [C, A, S] | yes | PASS | 9 | 7362–12618 |
| csip-conf-v1.3::CORE-022 | Responses [C, A, S] | yes | PASS | 4 | 17627–18278 |
| local-ext-v1::EXT-005 | EXT-005 - envelope refusal: an mbaps WMaxLimPct write above the CSIP envelope draws exception 03; within it, it is acked | local-ext | PASS | 3 | 36275 |
| local-ext-v1::EXT-006 | EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default | local-ext | FAIL | 4 | — |
| local-ext-v1::EXT-008 | EXT-008 - envelope tightening / ownership take: a standing mbaps WSet stands, CSIP taking the axis drops it, release restores the device default | local-ext | FAIL | 4 | — |

## Verifying this bundle

This directory is self-checking. Independent checks, in the order a sceptical reader
would run them:

1. `sha256sum -c MANIFEST.sha256` — every file, the capture included, is covered.
2. The evidence verifier re-reads `capture/run-20260910-202149.pcapng` and confirms that every cited frame
   exists and carries the exact bytes each assertion claims. It reads only this
   directory and needs nothing from the bench that produced it.
3. Every case verdict in the table above is re-derived from that case's own printed
   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is
   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be
   edited away from, the evidence underneath it.

Assertions marked *(no digest)* below carry no re-checkable citation: they are
narrative, not proof.

## Test cases

### ✓ csip-conf-v1.3::BASIC-009 Basic Inverter Control (Connect/Disconnect) [C, A, S] — PASS

Reference: CSIP-CONF-v1.3 V1.3 §BASIC-009 - Basic Inverter Control (Connect/Disconnect) [C, A, S] (no numeric section number printed; test-ID heading only)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): published a DERControl (CERT-BASIC-009-f1953fac) carrying opModConnect and waited 1m54s for the DUT to fetch it; independent southbound oracle: PASS — the DER did NOT hold the commanded value before this row published its control (GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads true against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads true against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 1 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead) and DOES hold it after the DUT's poll cycle (GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads false against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads false against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 0 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead) — the reading MOVED, so the match is evidence this control was applied, not a register an earlier run left behind; poll-cycle window: 2m30s, derived from the bench 2030.5 server's advertised pollRate of 1m0s (poll_rate_s from http://192.168.0.188:11114/admin/status), which is the rate a client in poll_rate_mode "honor" — the product default — paces its walk at, the configured interval being only a floor beneath it — it is the slower of that and the DUT's own IEEE 2030.5 discovery interval floor of 1m0s (discovery_interval_s in /etc/lexa/northbound.json), and the slower governs: 2 periods plus 30s of slack, so a period that had just elapsed still leaves a whole one inside the window; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 403 frame(s) (862–17601), precision endpoint; 13150 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized).

1. **PASS** — the DUT issued GET /dcap and the server answered 200 with a conformant DeviceCapability
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the request line, status line and sep+xml body of the first /dcap exchange in the session
   - Observed: GET /dcap -> 200 <DeviceCapability pollRate=60> TimeLink×1 ResponseSetListLink×1 EndDeviceListLink×1 MirrorUsagePointListLink×1 SelfDeviceLink×1; root element in the 2030.5 namespace with an EndDeviceListLink. These bytes are from 192.168.0.69:41068 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:52258 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 12523, 12524
   - Stream: `192.168.0.188:11113 > 192.168.0.69:41068` bytes [1283,1841)
   - Bytes sha256: `e4af22728309f681b34d32e645596918d92324effad01719a70198a7c98beafa`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
2. **PASS** — the DUT fetched the DERProgramList reached through FunctionSetAssignments and the server answered 200 with a conformant DERProgramList
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the first exchange in the session whose response body is a DERProgramList in the 2030.5 namespace, located by root element rather than by URI because 2030.5 URIs are server-defined
   - Observed: GET /edev/2/fsa/0/derp -> 200 <DERProgramList all=3 results=3 pollRate=60> DERProgram×3; 3 DERProgram(s), primacy 1,5,10 in ascending primacy order
   - Frames: 7362, 7363, 7364
   - Stream: `192.168.0.188:11113 > 192.168.0.69:52258` bytes [6347,8139)
   - Bytes sha256: `9f03bf75e362df5a6ad83fb153d86a34891bd92001e81c195139d7b3df398705`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
3. **PASS** — the DUT fetched a DERControl carrying a connect/disconnect command
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — a <opModConnect> element inside the DERControlBase of the DERControl with THIS ROW's own mRID (CERT-BASIC-009-f1953fac), in a DERControlList the DUT fetched during the session
   - Observed: DERControl mRID=CERT-BASIC-009-f1953fac carries <opModConnect>false</opModConnect>
   - Frames: 7369, 7370
   - Stream: `192.168.0.188:11113 > 192.168.0.69:52258` bytes [8610,9588)
   - Bytes sha256: `3785ccf47c6b41e7b34ea199fbeca74054ba4556ec04fbca7298df075e08776d`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
4. **PASS** — the DUT fetched the DefaultDERControl of a DERProgram and the server answered 200 with a conformant DefaultDERControl
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the first exchange in the session whose response body is a DefaultDERControl in the 2030.5 namespace, located by root element rather than by URI because 2030.5 URIs are server-defined
   - Observed: GET /derp/0/dderc -> 200 <DefaultDERControl> mRID×1 description×1 DERControlBase×1; DERControlBase modes: opModExpLimW
   - Frames: 7366
   - Stream: `192.168.0.188:11113 > 192.168.0.69:52258` bytes [8139,8610)
   - Bytes sha256: `e4e21bc2af58dcf34b075be00f2265f9ab28c51856f954157e3cc751a17b3280`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
5. **PASS** — the DER's own southbound registers hold the a connect/disconnect command this row commanded
   - Method: independent live read of the DER's own SunSpec registers (simapi sidecar), taken during the run and carried into this phase — an independent read of the DER's raw SunSpec register image (internal/invariant, which shares only the register-offset tables with the product and none of its CSIP/derbase interpretation), taken BEFORE this row published its control and again after the DUT's poll cycle, and compared against what this row itself published — not against what the DUT reports the DER received. opModConnect's register home is model 123's Conn point and opModEnergize's is model 703's enter-service permission (ES) — the OPPOSITE-generation homes of a legacy and a 7xx DER. Which one this row GRADES is chosen from the candidate manifest's declared models (123-only -> M123 Conn, 703-only -> M703 ES) or an explicit -param connect-home, read here through this referee's own transcription of the published models (internal/invariant's legacyctl.go, lexa-proto's Parse703), not through the product's; the OTHER home and model 701's ConnSt are REPORTED alongside the graded axis, never graded.
   - Observed: the DER did NOT hold the commanded value before this row published its control (GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads true against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads true against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 1 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead) and DOES hold it after the DUT's poll cycle (GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads false against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads false against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 0 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead) — the reading MOVED, so the match is evidence this control was applied, not a register an earlier run left behind
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
6. **PASS** — the DUT did not report DERControlResponse Started(2) for the connect control unless the graded connect home (model 123 Conn or model 703 ES) measurably reached the commanded state
   - Method: cleartext TLS handshake in the capture — the DERControlResponse statuses the DUT POSTed for this control — recovered from the session (tier 2) or from gridsim's own record (tier 3) — cross-checked against the independent connect-home read the connect oracle graded: a Started(2) the graded home does not back is a FAIL, and a correct withhold (no Started(2), CannotComply at receipt) is a PASS
   - Observed: the DUT reported Started(2) for the connect control AND the graded connect home MOVED to the commanded state: before, GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads true against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads true against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 1 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead; after, GRADED (opModConnect via model 123, the declared connect home): model 123 Conn reads false against a commanded connect=false. REPORTED, not graded: model 703 ES (enter-service permission) reads false against the energize=false published alongside — REPORTED, not graded on this run: the connect home graded here is M123 Conn; the DER's own model 701 ConnSt reads 0 — its account of its connection state, REPORTED and not graded; the candidate manifest declares model 123, so the graded connect home is one it claims. Connect home: the candidate manifest declares BOTH model 123 and model 703; per the product's M123-first precedence (opModConnect actuates model 123 Conn only; 703 EnterService is a future home) BASIC-009 grades model 123 Conn — pass -param connect-home=M703 to grade the 703 enter-service path instead. These bytes are from 192.168.0.69:52268 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:52258 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 12618
   - Stream: `192.168.0.69:52268 > 192.168.0.188:11113` bytes [2743,3126)
   - Bytes sha256: `60168fc4eee793f14c85c233a444443a594c6a7a22f043b2930b729b558a2f63`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
7. **PASS** — the DUT POSTed a DERControlResponse with status=1 (Event received) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-BASIC-009-f1953fac status=1, answered 201 Created. These bytes are from 192.168.0.69:52268 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:52258 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 7463
   - Stream: `192.168.0.69:52268 > 192.168.0.188:11113` bytes [1728,2111)
   - Bytes sha256: `c6599c392b4545f4ddca71e413fca3b0be3385f19eeb4db27e9ac2d1f94d55a0`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
8. **PASS** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-BASIC-009-f1953fac status=2, answered (none). These bytes are from 192.168.0.69:52268 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:52258 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 12618
   - Stream: `192.168.0.69:52268 > 192.168.0.188:11113` bytes [2743,3126)
   - Bytes sha256: `60168fc4eee793f14c85c233a444443a594c6a7a22f043b2930b729b558a2f63`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
9. **SKIP** — no DERControlResponse the DUT POSTed for this control carries status 8 (PartialOptOut) or 10 (NoParticipation) before the EARLIEST EffectiveEndTime the control's own randomizeStart/randomizeDuration (§10.2.3.2/§10.2.4.2.2/.3) permit
   - Method: not observed — every Response-family POST in the session whose <subject> is this row's own mRID, filtered to <status> in {8,10}, each one's own capture timestamp compared against the BAND of EffectiveEndTime values this control's own randomizeStart/randomizeDuration (§10.2.3.2/§10.2.4.2.2/.3) permit its SpecifiedEndTime (<interval><start> + <interval><duration>) to move to: FAIL only strictly before the band's earliest edge (IEEE 2030.5-2018 Table 27 p.74-76 — SD-02); a Response landing inside the band is reported as a disclosed non-verdict rather than guessed at, since which point in it the DUT's own random draw selected is not recoverable from the wire
   - Observed: no Response for subject CERT-BASIC-009-f1953fac carried status 8 or 10 in this window, so this criterion has nothing to grade
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ✓ csip-conf-v1.3::CORE-022 Responses [C, A, S] — PASS

Reference: CSIP-CONF-v1.3 V1.3 §6 Core Function Tests (implied) - CORE-022 - Responses [C, A, S]

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): published an immediate DERControl (CERT-CORE022-f1953fac, opModMaxLimW) and waited 10m55s for its natural 1/2/3 lifecycle; statuses received: [1 2 3]. A second control (CERT-CORE022-CANCEL-f1953fac) was published alongside it on a different program AND A DIFFERENT AXIS (opModGenLimW — IEEE Std 2030.5-2018 §10.2.3.3 t) keeps differing controls independent, so the two coexist instead of one superseding the other, which is what leaves a live event for the server to cancel) and then CANCELLED server-side mid-flight; statuses received: [1 2 6]; poll-cycle window: 8m0s, set explicitly with -param csip.wait=8m. An operator's own value is used verbatim: it is neither raised to the 1m30s floor, nor capped at 5m0s, nor trimmed to fit the check's -timeout; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 2132 frame(s) (17276–37363), precision endpoint; 20367 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized).

1. **PASS** — the DUT POSTed a DERControlResponse with status=1 (Event received) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-CORE022-f1953fac status=1, answered 201 Created. These bytes are from 192.168.0.69:43278 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:43272 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 17627
   - Stream: `192.168.0.69:43278 > 192.168.0.188:11113` bytes [1729,2110)
   - Bytes sha256: `e47a961159740506c6027a6ba3932949f0fb53641e8e0f3cb773780bb245ca5a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
2. **PASS** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-CORE022-f1953fac status=2, answered 201 Created. These bytes are from 192.168.0.69:43278 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:43272 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 18278
   - Stream: `192.168.0.69:43278 > 192.168.0.188:11113` bytes [3130,3511)
   - Bytes sha256: `05461106c02adebb77591ba2000d49f3798484007ba4f66010b6579d09b6a719`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
3. **PASS** — the DUT POSTs its Responses to the replyTo URI the event carried, not to a hard-coded path
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the request target of each Response POST FOR THE COMPLETING CONTROL (mrid) compared with the replyTo attribute of the DERControl it acknowledges
   - Observed: Response for CERT-CORE022-f1953fac POSTed to /rsps/0/r; the event's replyTo is /rsps/0/r. These bytes are from 192.168.0.69:43278 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:43272 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 17627
   - Stream: `192.168.0.69:43278 > 192.168.0.188:11113` bytes [1729,2110)
   - Bytes sha256: `e47a961159740506c6027a6ba3932949f0fb53641e8e0f3cb773780bb245ca5a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
4. **PASS** — the DUT reports the event lifecycle: statuses 1 (received), 2 (started) and 3 (completed), and 6 (cancelled) for an event the server cancels
   - Method: gridsim server-side observation (admin API) — the set of Response statuses received for a control this check lets run its full natural lifecycle, and separately for a second control this check cancels server-side mid-flight (audit 2026-08-01 — see coreResponsesSpec's doc), each status gated against its own control's responseRequired (#17/F2)
   - Observed: completing control CERT-CORE022-f1953fac: statuses [1 2 3]; server-cancelled control CERT-CORE022-CANCEL-f1953fac: statuses [1 2 6] — the full 1/2/3/6 event lifecycle was observed
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: gridsim admin API at http://192.168.0.188:11114; this is the SERVER's record of the DUT's behaviour, not the wire, and cannot be re-derived from the pcap

### ✓ local-ext-v1::EXT-005 EXT-005 - envelope refusal: an mbaps WMaxLimPct write above the CSIP envelope draws exception 03; within it, it is acked — PASS

**LOCAL EXTENSION — certifiable under no standard.** No published procedure covers this case: its Test Values are the harness's own and its verdict is supplementary PRODUCT EVIDENCE, not a conformance result. It is run, bundled and re-verified like any other row, and it is excluded from every applicable-FAIL tally and from the clean-run criterion. A FAIL here is a finding about the implementation; it is not a certification failure.

Reference: LOCAL-EXT-v1 v1 (local extension family; not a published specification) §1.5 EXT-005 - an above-envelope mbaps ceiling write draws exception 03 (under 1 Local product-evidence extensions)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): published a CSIP opModMaxLimW control (CERT-EXT005-ENVELOPE-CEILING-f1953fac) at 50.00% and waited 12s for it to be Started, then over a role-bound mbaps GridServiceSunSpec session wrote WMaxLimPct first ABOVE it (80.00%) and then WITHIN it (30.00%) — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Active-power ceiling row), §3.2; poll-cycle window: 2m30s, derived from the bench 2030.5 server's advertised pollRate of 1m0s (poll_rate_s from http://192.168.0.188:11114/admin/status), which is the rate a client in poll_rate_mode "honor" — the product default — paces its walk at, the configured interval being only a floor beneath it — it is the slower of that and the DUT's own IEEE 2030.5 discovery interval floor of 1m0s (discovery_interval_s in /etc/lexa/northbound.json), and the slower governs: 2 periods plus 30s of slack, so a period that had just elapsed still leaves a whole one inside the window; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 255 frame(s) (36055–37111), precision endpoint; 195 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized); tcp 192.168.0.188:58280 <> 192.168.0.69:802 (REV0907-D2-IMPL P5 envelope session: grid-service).

1. **PASS** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-EXT005-ENVELOPE-CEILING-f1953fac status=2, answered 201 Created. These bytes are from 192.168.0.69:54530 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:47354 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 36275
   - Stream: `192.168.0.69:54530 > 192.168.0.188:11113` bytes [2756,3153)
   - Bytes sha256: `c3be3a09f0cfe306b087ba72208a6c705ed0c59e5f23baa63bfe6503535c5f4b`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
2. **PASS** — an mbaps GridServiceSunSpec write to 704 WMaxLimPct ABOVE the CSIP envelope (50.00%, control CERT-EXT005-ENVELOPE-CEILING-f1953fac) draws Modbus exception 03 (illegal data value) and the DER's own ceiling register does not move — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §1.4/§2/§3.2, owner answer A ("reject with exception 03"): no clamp-and-ack
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — this row's own mbaps GridServiceSunSpec write to WMaxLimPct (80.00% > the 50.00% envelope), decoded from the raw MBAP response; the DER's own active-power ceiling register read independently before and after the write, through the same southbound oracle path localext_eventstatus.go's EXT-004 uses
   - Observed: the above-envelope write drew Modbus exception 03 (illegal data value) as docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §1.4/§3.2 requires, and the DER's own WMaxLimPct register did not move: enabled=true value=50.0000 before and after
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
3. **PASS** — the same mbaps GridServiceSunSpec client's write WITHIN the envelope (30.00%) is acked (no Modbus exception) and the DER reads it back within this row's window — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §1.4/§2: "a write within the envelope is acked and applied"
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — this row's own mbaps GridServiceSunSpec write to WMaxLimPct within the envelope, decoded from the raw MBAP response; the DER's own resolved active-power ceiling, read through the same effect-based oracle BASIC-010 uses (oracleMaxLimW), polled across this row's poll-cycle window
   - Observed: the within-envelope write was ACKED (no Modbus exception), and the DER's own ceiling register came to hold it: the DER's own WMaxLimPct resolves to a 2400.0 W active-power ceiling (commanded 30.00% of its own 8000.0 W WMax, read from its own M702 = 2400.0 W)
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact

### ✗ local-ext-v1::EXT-006 EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default — FAIL

**LOCAL EXTENSION — certifiable under no standard.** No published procedure covers this case: its Test Values are the harness's own and its verdict is supplementary PRODUCT EVIDENCE, not a conformance result. It is run, bundled and re-verified like any other row, and it is excluded from every applicable-FAIL tally and from the clean-run criterion. A FAIL here is a finding about the implementation; it is not a certification failure.

Reference: LOCAL-EXT-v1 v1 (local extension family; not a published specification) §1.6 EXT-006 - a CSIP-owned value axis refuses mbaps (01) and releases to the device default (under 1 Local product-evidence extensions)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): published a CSIP opModFixedPFInjectW control (CERT-EXT006-VALUE-AXIS-f1953fac, PF 0.9 injecting) and waited 5m1s for it to be Started, attempted an mbaps GridServiceSunSpec PFWInj_PF write (PF 0.85) while it was in effect, then cancelled it and attempted the same write again — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Fixed PF row); poll-cycle window: 2m30s, derived from the bench 2030.5 server's advertised pollRate of 1m0s (poll_rate_s from http://192.168.0.188:11114/admin/status), which is the rate a client in poll_rate_mode "honor" — the product default — paces its walk at, the configured interval being only a floor beneath it — it is the slower of that and the DUT's own IEEE 2030.5 discovery interval floor of 1m0s (discovery_interval_s in /etc/lexa/northbound.json), and the slower governs: 2 periods plus 30s of slack, so a period that had just elapsed still leaves a whole one inside the window; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is FAIL. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 1121 frame(s) (36981–40896), precision endpoint; 2791 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized); tcp 192.168.0.188:35936 <> 192.168.0.69:802 (REV0907-D2-IMPL P5 envelope session: grid-service).

1. **FAIL** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: gridsim server-side observation (admin API) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: gridsim received 2 Response(s) for subject CERT-EXT006-VALUE-AXIS-f1953fac but none with status=2: CERT-EXT006-VALUE-AXIS-f1953fac/status=1, CERT-EXT006-VALUE-AXIS-f1953fac/status=6
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: gridsim admin API at http://192.168.0.188:11114; this is the SERVER's record of the DUT's behaviour, not the wire, and cannot be re-derived from the pcap
2. **PASS** — while the CSIP opModFixedPFInjectW control (CERT-EXT006-VALUE-AXIS-f1953fac) is in effect, an mbaps GridServiceSunSpec write to 704 PFWInj_PF draws Modbus exception 01 (illegal function) and the DER's own PF register does not move — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Fixed PF: "refused (01) while CSIP-owned")
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — this row's own mbaps write to PFWInj_PF/_Ext, decoded from the raw MBAP response; the DER's own model 704 PF sync group read independently before and after the write
   - Observed: the write drew Modbus exception 01 (illegal function) as docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 requires, and the DER's own PF register did not move: ena=true pf=0.9 ext=0 before and after
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
3. **PASS** — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2's release rule (owner answer B, "device default"): immediately after CSIP releases the axis (before this row's second mbaps write), the DER's own PF register reads the SAME value this row observed before the CSIP control was ever published — never a value mbaps held
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — the DER's own model 704 PF sync group, read once before this row published its CSIP control (the device-default baseline) and again immediately after the control's cancellation was served and this row's settle window elapsed, both through the same southbound oracle path
   - Observed: at release PFWInjEna reads false, matching this row's own pre-publication baseline (also false) — the axis is no longer in force, the device default docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 owner answer B requires (reported, not asserted: raw PF register reads pf=0.9 ext=0, baseline was pf=0 ext=0 — a 704 DER's value register keeps its last-written contents after Ena clears, which is not what this claim is about)
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
4. **PASS** — after the control ends, the same mbaps write is acked and the DER's own PF register moves to the mbaps-commanded value (PF 0.85) — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 ("else mbaps")
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — this row's own second mbaps write to PFWInj_PF/_Ext, issued after the CSIP control's cancellation, decoded from the raw MBAP response; the DER's own model 704 PF sync group read independently afterward
   - Observed: the write was ACKED, and the DER's own PF register moved to it: pf=0.8500000000000001 ext=0
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact

### ✗ local-ext-v1::EXT-008 EXT-008 - envelope tightening / ownership take: a standing mbaps WSet stands, CSIP taking the axis drops it, release restores the device default — FAIL

**LOCAL EXTENSION — certifiable under no standard.** No published procedure covers this case: its Test Values are the harness's own and its verdict is supplementary PRODUCT EVIDENCE, not a conformance result. It is run, bundled and re-verified like any other row, and it is excluded from every applicable-FAIL tally and from the clean-run criterion. A FAIL here is a finding about the implementation; it is not a certification failure.

Reference: LOCAL-EXT-v1 v1 (local extension family; not a published specification) §1.8 EXT-008 - CSIP takes a value axis mbaps held: contribution dropped, journaled, restored to default at release (under 1 Local product-evidence extensions)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): wrote a standing mbaps WSet setpoint (500.0 W), published a CSIP opModFixedW control (CERT-EXT008-OWNERSHIP-TAKE-f1953fac, 40.00%) and waited 5m1s for it to be Started, attempted a further mbaps WSet write (-300.0 W) while it was in effect, then cancelled it — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Setpoint row); poll-cycle window: 2m30s, derived from the bench 2030.5 server's advertised pollRate of 1m0s (poll_rate_s from http://192.168.0.188:11114/admin/status), which is the rate a client in poll_rate_mode "honor" — the product default — paces its walk at, the configured interval being only a floor beneath it — it is the slower of that and the DUT's own IEEE 2030.5 discovery interval floor of 1m0s (discovery_interval_s in /etc/lexa/northbound.json), and the slower governs: 2 periods plus 30s of slack, so a period that had just elapsed still leaves a whole one inside the window; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is FAIL. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 1331 frame(s) (40322–44463), precision endpoint; 2822 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized); tcp 192.168.0.188:60666 <> 192.168.0.69:802 (REV0907-D2-IMPL P5 envelope session: grid-service).

1. **FAIL** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: gridsim server-side observation (admin API) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: gridsim received 2 Response(s) for subject CERT-EXT008-OWNERSHIP-TAKE-f1953fac but none with status=2: CERT-EXT008-OWNERSHIP-TAKE-f1953fac/status=1, CERT-EXT008-OWNERSHIP-TAKE-f1953fac/status=6
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: gridsim admin API at http://192.168.0.188:11114; this is the SERVER's record of the DUT's behaviour, not the wire, and cannot be re-derived from the pcap
2. **PASS** — an mbaps GridServiceSunSpec 704 WSet write made BEFORE any CSIP opModFixedW control is in effect stands: it is acked and the DER's own WSet register reads it (500.0 W) — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 ("else mbaps")
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — this row's own mbaps write to WSet, decoded from the raw MBAP response; the DER's own model 704 WSet register read independently afterward
   - Observed: the write was ACKED and the DER's own WSet register holds it: ena=true 500.0 W
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
3. **PASS** — once the CSIP opModFixedW control (CERT-EXT008-OWNERSHIP-TAKE-f1953fac) starts, the DER's own WSet register follows CSIP's commanded value (40.00%), not the standing mbaps value, and a further mbaps WSet write (-300.0 W) draws Modbus exception 01 (illegal function) — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §1.1/§2: CSIP taking a value axis mbaps held drops the mbaps contribution
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — the DER's own model 704 WSet register, read through the same effect-based oracle BASIC-013 uses (oracleFixedW); this row's own further mbaps write, decoded from the raw MBAP response
   - Observed: the DER's own WSet register followed the CSIP control (the DER actuated this command as a SETPOINT: its own WSet resolves to 3200.0 W (commanded 40.00% of its own WMax (this device implements no WDisChaRteMaxRtg) = 8000.0 W, so 3200.0 W)), and the further mbaps WSet write correctly drew Modbus exception 01 (illegal function)
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact
4. **PASS** — when the control ends, the DER's own WSet register returns to the device default captured at this row's own pre-publication baseline, not to the prior mbaps value (500.0 W) — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 owner answer B
   - Method: this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, and any product parser (suitessm.DialEnvelopeRole) — the DER's own model 704 WSet register, read once before this row published anything (the device-default baseline) and again after the CSIP control's cancellation was served and this row's settle window elapsed
   - Observed: at release WSetEna reads false, matching this row's own pre-publication baseline (also false) — the axis is no longer in force, the device default docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 owner answer B requires (reported, not asserted: raw WSet register reads 3200.0 W, baseline was 0.0 W, standing mbaps write was 500.0 W — a 704 DER's value register keeps its last-written contents after Ena clears, which is not what this claim is about)
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: the run's capture, but the evaluator did not record which frames carried the fact

