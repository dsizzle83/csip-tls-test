# Conformance evidence bundle

**Device under test:** lexa-gw at `192.168.0.69:802`

| | |
|---|---|
| Tool | csip-certify eb2c71acf25f |
| Source commit | 045ba8fd234a6e82b6162402ac2a4d817f9a0db0 |
| Operator | lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09 |
| Host | dmitri-HP-ENVY-TE01-1xxx |
| Started | 2026-09-09T20:54:16Z |
| Finished | 2026-09-09T21:01:30Z |
| DUT build | d403552 |
| Capture | `capture/run-20260909-205418.pcapng` — 1755 packets, 895616 bytes, pcapng |
| Capture tool | dumpcap Dumpcap (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). |
| Interface | enp1s0 |
| Capture hygiene | 1755 frame(s) captured; no filter was requested, so every frame the tool wrote is in this bundle |
| Key log | capture/bench-shared.keylog |

> **This bundle contains TLS session secrets.** `capture/bench-shared.keylog` is an NSS key log for the
> capture above: anyone holding this directory can decrypt every session it
> records. It is included on purpose — the application-layer citations below
> cannot be re-derived without it — and it is covered by the manifest, so it
> cannot be quietly dropped either. Treat the bundle as sensitive: share it
> with an assessor, not publicly. The secrets are per-session and grant no
> lasting access to the device.

> catalog: /home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json (290 cases, 1626330 bytes, sha256:eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588); frame attribution: 1755 frames: 880 attributed to 14 test case(s), 871 unattributed (background), 4 contested; provenance: DUT build reported fw=1.0.0 build_id=d403552b1056 image_build_id=d403552b1056 image_profile=image

Capture tool output:

```
Capturing on 'enp1s0'
File: runs/p6-d403552-modbus-client-20260909T205416Z/capture/run-20260909-205418.pcapng
Packets captured: 1755
Packets received/dropped on interface 'enp1s0': 1755/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

## How this run was invoked

```
certify-keylog -campaign modbus-client -manifest /home/dmitri/projects/lexa-gw/configs/candidate.json -target 192.168.0.69:802 -pki certs/mbaps -gridsim 192.168.0.188:11113 -gridsim-admin http://192.168.0.188:11114 -modsim 69.0.0.20:5020 -modsim-api http://69.0.0.20:6020 -mbapsdev-api http://69.0.0.20:6031 -gateway-ssh cc93 -metrics-endpoint http://127.0.0.1:9102/metrics -keylog /tmp/bench-shared.keylog -operator 'lead (Claude) for owner dsizzle83, P6 bench campaign 2026-09-09' -dut-name lexa-gw -dut-build d403552 -iface enp1s0 -timeout 8m -sign-key '[redacted]' -out runs/p6-d403552-modbus-client-20260909T205416Z -v
```

Credential-shaped flag values are replaced with `[redacted]`; every other argument is verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of this table.

The capture itself:

```
/usr/bin/dumpcap -i enp1s0 -w runs/p6-d403552-modbus-client-20260909T205416Z/capture/run-20260909-205418.pcapng -q -p
```

## Result

**1 PASS · 0 FAIL · 0 SKIP · 13 WARN** across 14 in-scope test case(s).

1 further case(s) are **NOT APPLICABLE** to this candidate and were not run: each carries a reason and the declaration it rests on, in its own section below. They are neither passes nor failures and bear on nothing.

✓ No failures.

| Case | Title | Claim | Verdict | Assertions | Frames |
|------|-------|-------|---------|-----------:|--------|
| ss-modbus-client-conf-v1.1::WR-1 | Write Single Point | yes | N/A | 1 | — |
| ss-modbus-client-conf-v1.1::READ-2 | Multiple Point Reads | yes | PASS | 10 | 1–108 |
| ss-modbus-client-conf-v1.1::READ-1 | Single Point Reads | yes | WARN | 2 | — |
| ss-modbus-client-conf-v1.1::CLI-2 | General Discovery for SunSpec Servers at Different Ports | yes | WARN | 10 | 117–139 |
| ss-modbus-client-conf-v1.1::CLI-1 | General Discovery for SunSpec Servers at Different IPv4 Addresses | yes | WARN | 10 | 148–172 |
| ss-modbus-client-conf-v1.1::CLI-3 | General Discovery for SunSpec Servers with Different Unit IDs | yes | WARN | 13 | 179–224 |
| ss-modbus-client-conf-v1.1::CLI-4 | General Discovery for SunSpec Servers with Different Starting Register Values | yes | WARN | 10 | 231–337 |
| ss-modbus-client-conf-v1.1::PROT-2 | TCP Segmentation (Only for Modbus TCP Clients) | yes | WARN | 3 | — |
| ss-modbus-client-conf-v1.1::ERR-3 | Unknown Model ID Test | yes | WARN | 5 | 347–589 |
| ss-modbus-client-conf-v1.1::ERR-1 | Noncompliant Server | yes | WARN | 4 | 724 |
| ss-modbus-client-conf-v1.1::INFO-1 | SunSpec Type Interpretations | yes | WARN | 7 | 960–1180 |
| ss-modbus-client-conf-v1.1::ERR-2 | Exception Tests | yes | WARN | 8 | 1190–1233 |
| ss-modbus-client-conf-v1.1::INFO-2 | Unimplemented Point Interpretations | yes | WARN | 5 | — |
| ss-modbus-client-conf-v1.1::PROT-1 | Partial Response | yes | WARN | 8 | — |
| ss-modbus-client-conf-v1.1::WR-2 | Write Multiple Points | yes | WARN | 8 | — |

## Verifying this bundle

This directory is self-checking. Independent checks, in the order a sceptical reader
would run them:

1. `sha256sum -c MANIFEST.sha256` — every file, the capture included, is covered.
2. The evidence verifier re-reads `capture/run-20260909-205418.pcapng` and confirms that every cited frame
   exists and carries the exact bytes each assertion claims. It reads only this
   directory and needs nothing from the bench that produced it.
3. Every case verdict in the table above is re-derived from that case's own printed
   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is
   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be
   edited away from, the evidence underneath it.

Assertions marked *(no digest)* below carry no re-checkable citation: they are
narrative, not proof.

## Test cases

### — ss-modbus-client-conf-v1.1::WR-1 Write Single Point — N/A

**NOT APPLICABLE — not run.** this row requires the candidate to have claimed FC 6 for modbus_client.write_function_codes, and the candidate's manifest does not: it declares FC 16

- Declared by: `manifest`
- Declaration: modbus_client.write_function_codes: candidate declares FC 16; ss-modbus-client-conf-v1.1::WR-1 requires FC 6 (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622); the candidate's PICS declares this axis in PICS_SUNSPEC_MODBUS.md §4.2 ("Read and write capability")

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.6.1 WR-1 – Write Single Point (under 2.6 Write Tests)

this row requires the candidate to have claimed FC 6 for modbus_client.write_function_codes, and the candidate's manifest does not: it declares FC 16

1. **N/A** — the test case is in scope for the candidate under test
   - Method: scope declaration (manifest)
   - Observed: this row requires the candidate to have claimed FC 6 for modbus_client.write_function_codes, and the candidate's manifest does not: it declares FC 16
   - _(no digest — narrative, not re-checkable)_
   - Note: modbus_client.write_function_codes: candidate declares FC 16; ss-modbus-client-conf-v1.1::WR-1 requires FC 6 (/home/dmitri/projects/lexa-gw/configs/candidate.json, sha256 24653c0eac0fa622); the candidate's PICS declares this axis in PICS_SUNSPEC_MODBUS.md §4.2 ("Read and write capability")

### ✓ ss-modbus-client-conf-v1.1::READ-2 Multiple Point Reads — PASS

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.5.2 READ-2 – Multiple Point Reads (under 2.5 Read Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's southbound read pattern was observed over a forced rediscovery and then one COMPLETE poll cycle, both held on the simulator rather than on a clock after its southbound connection was severed at epoch 6, so that its reconnect would perform discovery inside this test case's window. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 5 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 6 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside READ-2's observation window); VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 96 frame(s) (1–111), precision endpoint; 5 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 2 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:49214 <> 69.0.0.20:5020, 69.0.0.2:44996 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 1
   - Frames sha256: `f24541fb7e95bed4d5e7e19008c479fa569f8119b1771fce046e6097055eed29`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — no register read the DUT issued exceeded the Modbus maximum of 125 registers
   - Method: quantity field of every FC 0x03 / 0x04 request in the reassembled DUT→server direction
   - Observed: 37 read request(s), largest quantity 125 (limit 125). Largest request cited: txid=23 unit=1 FC=0x03 read start=40256(0x9d40) quantity=125 [00 17 00 00 00 06 01 03 9d 40 00 7d]
   - Frames: 61
   - Stream: `69.0.0.2:44996 > 69.0.0.20:5020` bytes [264,276)
   - Bytes sha256: `351687888d78e4a9d35436a2b9f00c8103a2efd2aecd8a80e8f14f44fd48cb2f`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — all points after the ID and L points of the Common Model (model 1) were read in a single request
   - Method: the smallest set of FC 0x03 requests covering model 1's body, from the DUT→server direction
   - Observed: one FC 0x03 request covered model 1's whole body: start 40004, quantity 66, for a body of 66 register(s) at 40004..40069. Request cited in full: [00 16 00 00 00 06 01 03 9c 44 00 42]
   - Frames: 59
   - Stream: `69.0.0.2:44996 > 69.0.0.20:5020` bytes [252,264)
   - Bytes sha256: `f3533a8a499ba3ac813e5b1ce0d07d97de1312da8f3121c93bde2dfc753e1b9f`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **PASS** — a model longer than 125 registers was read in multiple reads that maximise the registers retrieved per request
   - Method: the quantity field of each FC 0x03 request covering a model body longer than the 125-register Modbus limit, scoped to the DUT's first complete sweep of the body when the window spans more than one of its poll cycles
   - Observed: model 701's 153-register body was read as start=40256 qty=125, start=40381 qty=28 — every request but the last asked for the full 125-register maximum, so the body was retrieved in the fewest reads the limit allows. (this window observed 5 read(s) total across more than one DUT poll cycle; graded against the first 2 that complete one full sweep of the body) First request cited in full: [00 17 00 00 00 06 01 03 9d 40 00 7d]
   - Frames: 61
   - Stream: `69.0.0.2:44996 > 69.0.0.20:5020` bytes [264,276)
   - Bytes sha256: `351687888d78e4a9d35436a2b9f00c8103a2efd2aecd8a80e8f14f44fd48cb2f`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
5. **PASS** — the DUT's register reads were whole-block reads rather than one request per point
   - Method: distribution of the quantity field over every FC 0x03 / 0x04 request in the window
   - Observed: 37 read request(s) fetching 1208 register(s): quantities from 2 to 125; 20 request(s) asked for 4 registers or fewer (a model-header probe or a single point) and 1168 register(s) — 96% of the total — arrived in wider block reads. The traffic is block-oriented
   - Frames: 15
   - Stream: `69.0.0.2:44996 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
6. **SKIP** — the DUT logged every point of every PICS model, with the log data represented as hex strings
   - Method: inspection of the client's own log output
   - Observed: the criterion is about the CLIENT's log, not about the wire: it requires the CUT to render every point of every model as a hex string. The DUT is an autonomous gateway, not a point browser — it decodes the measurement and identity points its reconcilers consume and journals those, and emits no per-point hex dump. The bytes themselves ARE in this bundle (every response is in the capture, and the cited assertions quote the ADUs verbatim in hex), but that is the bench's rendering, not the DUT's, and the two must not be confused. Promoting this row to full requires a diagnostic mode on the DUT's Modbus client that dumps each decoded point with its raw registers
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
7. **PASS** — every Modbus/TCP request the DUT emitted carried a well-formed MBAP header
   - Method: independent MBAP decode of the reassembled DUT→server direction (protocol id == 0; length field == 1 + PDU length; unit id in 1..247)
   - Observed: all 39 request(s) carried protocol id 0, a length field consistent with the delivered PDU, and a unit id in 1..247. First request cited in full: txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 15
   - Stream: `69.0.0.2:44996 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT matched every response to its request by MBAP transaction identifier
   - Method: pairing of requests and responses by (transaction id, unit id, function code), with no positional fallback
   - Observed: 39 request(s) with transaction ids 1…39; 38 advanced monotonically; every response was matched to the request bearing its id (1 request(s) unanswered)
   - Frames: 15, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 93, 96, 98, 108
   - Frames sha256: `c554e0b3be4042ca75a9be1a4e312cc77aeb3cb518b573fa9fc19ad98c84a7ba`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
9. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 6 and it issued 3 transaction(s) afterwards across 10 session(s) — 3 transaction(s) (3 answered) — starting at seq 927, epoch 6, poll 0, conn 10: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
10. **PASS** — the read pattern asserted above was observed over a COMPLETE poll cycle, not a fragment of one
   - Method: the simulator's poll barrier: it counts the client's cycles from the server side of the wire and returns only once a cycle has closed and every transaction of it has resolved
   - Observed: a complete poll cycle closed inside this test case's window before any read assertion was graded. the sim counted 2 completed poll cycle(s) over 10 session(s) (0 abandoned mid-cycle by a reconnect), using anchor FC 0x03 at 40411×50, learned. Its rule: a poll cycle is the interval between two consecutive arrivals of the cycle anchor (the read request the client repeats every cycle); cycle N is COMPLETE when the anchor opening cycle N+1 has arrived and every transaction of cycle N has been resolved at the sim's wire layer
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs

### ⚠ ss-modbus-client-conf-v1.1::READ-1 Single Point Reads — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.5.1 READ-1 – Single Point Reads (under 2.5 Read Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT exposes no way to request an individual SunSpec point, so the one-request-per-point pattern this row requires cannot be provoked. What the DUT does instead was observed over one complete poll cycle — held on the simulator's own poll barrier, not on a sleep — and is cited.; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.; PASS downgraded to WARN: no assertion carries a digest the bundle's verifier can re-derive from the capture

Frame attribution: 0 frame(s) (—), precision endpoint; 5 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **SKIP** — the DUT read every point of the Common Model individually, one request per point
   - Method: frame attribution (time AND flow)
   - Observed: no capture frame was attributed to this test case: the DUT sent no southbound Modbus traffic to 69.0.0.20:5020 during its observation window, or the capture did not see it. nothing was injected: the DUT was observed in its steady state
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **PASS** — the read pattern asserted above was observed over a COMPLETE poll cycle, not a fragment of one
   - Method: the simulator's poll barrier: it counts the client's cycles from the server side of the wire and returns only once a cycle has closed and every transaction of it has resolved
   - Observed: a complete poll cycle closed inside this test case's window before any read assertion was graded. the sim counted 2 completed poll cycle(s) over 10 session(s) (0 abandoned mid-cycle by a reconnect), using anchor FC 0x03 at 40482×65, learned. Its rule: a poll cycle is the interval between two consecutive arrivals of the cycle anchor (the read request the client repeats every cycle); cycle N is COMPLETE when the anchor opening cycle N+1 has arrived and every transaction of cycle N has been resolved at the sim's wire layer
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs

### ⚠ ss-modbus-client-conf-v1.1::CLI-2 General Discovery for SunSpec Servers at Different Ports — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.4.2 CLI-2 – General Discovery for SunSpec Servers at Different Ports (under 2.4 General Client Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's two southbound servers are on non-standard ports 5020 and 8021; the rediscovery this row observes was held on the simulator's transaction ledger rather than on a poll interval. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 8 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 9 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-2's observation window); VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is WARN. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 26 frame(s) (117–142), precision endpoint; 10 frame(s) inside the window belonged to other conversations and were excluded.

1 frame(s) were claimed by more than one test case and attributed to none: [133]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes); tcp *:* <> 69.0.0.20:8021 (69.0.0.20:8021 is the bench's Secure SunSpec Modbus (mbaps) device sim — the DUT's second southbound server. The DUT dials it, so again no 4-tuple is knowable to the bench; the endpoint is single-purpose and the run is serialized. Only the connection-level facts of this endpoint are used: its Modbus payload is inside TLS and this suite holds no key material for it).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: exactly one conversation was attributed: 69.0.0.2:34026 <> 69.0.0.20:5020. The endpoint claim this suite relies on — 'all traffic to 69.0.0.20:5020 during my interval is the DUT's' — therefore held for this test case
   - Frames: 117
   - Frames sha256: `1e07ce5fedceb03bc63c4c73e7f0f2386e44302855cedc244c98d5761a4f2995`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT connected to a SunSpec server on a non-standard TCP port and completed discovery
   - Method: destination TCP port of the DUT's southbound connection, from the capture
   - Observed: the DUT dialled 69.0.0.20:5020 — destination port 5020, which is not the Modbus default 502 — and exchanged 17 Modbus message(s) there after its southbound connection was severed at epoch 9, so that its reconnect would perform discovery inside this test case's window
   - Frames: 120, 124, 126, 128, 130, 132, 134, 136, 139
   - Frames sha256: `5abd31cf283720101ddab5c50bb58403b698c7253ffd2e9a236f3c3205c4b10e`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the DUT probed a standard SunSpec base address and read the 'SunS' identifier
   - Method: FC 0x03 request address + the identifier registers in the matching response, decoded independently from the reassembled byte stream
   - Observed: registers 40000..40001 read by the DUT hold 0x5375 0x6e53 = "SunS" — the SunSpec identifier at base 40000
   - Frames: 122
   - Stream: `69.0.0.20:5020 > 69.0.0.2:34026` bytes [9,13)
   - Bytes sha256: `32f1b60b22f544bbf85105f54628052d81fe4505c4395545068b0c012197a3e3`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **WARN** — the DUT walked the server's complete SunSpec model chain
   - Method: reconstruction of the model chain from the register image the DUT was observed to read: each ID/length header pair from base+2 to the 0xFFFF end marker
   - Observed: 7 model header(s) were observed but the chain did not reach the 0xFFFF end marker within this test case's frames: the chain walk reached the model header at 40409, which this test case did not observe the DUT read. Observed: ID 1 @40002 L=66 (header only — stepped over by length), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length), ID 701 @40254 L=153 (header only — stepped over by length)
   - Frames: 122, 125, 127, 129, 131, 133, 135, 137
   - Frames sha256: `9abddb0686fdd1107af1128206d68c0701cb0b5d1f139acfbb82f1c11716c6b6`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
5. **SKIP** — the DUT read the complete Common Model (model ID 1) block
   - Method: coverage of model 1's body by the DUT's read requests, with the identity points decoded independently from the response bytes
   - Observed: model 1 (header at 40002, length 66) was found in the chain but this test case did not observe the DUT read its whole body
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **PASS** — every Modbus/TCP request the DUT emitted carried a well-formed MBAP header
   - Method: independent MBAP decode of the reassembled DUT→server direction (protocol id == 0; length field == 1 + PDU length; unit id in 1..247)
   - Observed: all 9 request(s) carried protocol id 0, a length field consistent with the delivered PDU, and a unit id in 1..247. First request cited in full: txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 120
   - Stream: `69.0.0.2:34026 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
7. **PASS** — the DUT matched every response to its request by MBAP transaction identifier
   - Method: pairing of requests and responses by (transaction id, unit id, function code), with no positional fallback
   - Observed: 9 request(s) with transaction ids 1…9; 8 advanced monotonically; every response was matched to the request bearing its id (1 request(s) unanswered)
   - Frames: 120, 124, 126, 128, 130, 132, 134, 136, 139
   - Frames sha256: `5abd31cf283720101ddab5c50bb58403b698c7253ffd2e9a236f3c3205c4b10e`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 9 and it issued 3 transaction(s) afterwards across 11 session(s) — 3 transaction(s) (3 answered) — starting at seq 965, epoch 9, poll 0, conn 11: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
9. **SKIP** — the DUT logged the contents of all the Common Model points
   - Method: observation of the DUT reading model 1's BODY — not merely its ID/length header — inside a test case's window
   - Observed: lexa-gw reads model 1's body EXACTLY ONCE, during admission, on a separate short-lived connection at boot (internal/southbound/admission/identify.go's identifyNow calls sunspec.ReadCommon there and nowhere else). Its steady-state poll reads only the measurement model, and even a full reconnect rediscovery walks the chain's HEADERS and then goes straight to that model — lexa-proto/sunspec/reader.go caches the block layout per session and never re-reads model 1's body. So no provocation available to this bench can make the DUT re-read the Common Model inside a window: it would take a process restart, which a shared-bench conformance run must not perform. THIS IS A DUT-SIDE OBSERVABILITY GAP, not a missing sim verb. Closing it needs either a re-identify diagnostic on the DUT that a read-only client can trigger, or a run whose capture begins before the DUT's own boot so the admission connection falls inside it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
10. **SKIP** — the DUT connected to a SECOND SunSpec server on a DIFFERENT non-standard TCP port
   - Method: destination TCP port of the DUT's second southbound connection, from the capture
   - Observed: no conversation with the second server 69.0.0.20:8021 was attributed to this test case: certify: ss-modbus-client-conf-v1.1::CLI-2: no attributed conversation on port 8021 (attributed streams: 69.0.0.2:34026 <> 69.0.0.20:5020). The DUT polls it on its own schedule, which need not fall inside this observation window
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::CLI-1 General Discovery for SunSpec Servers at Different IPv4 Addresses — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.4.1 CLI-1 – General Discovery for SunSpec Servers at Different IPv4 Addresses (under 2.4 General Client Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): discovery against server 1 at 69.0.0.20:5020 was observed after a forced rediscovery, held on the simulator's transaction ledger rather than on a poll interval; a SECOND server at a different IPv4 address needs a DUT configuration change this read-only run must not make (see the assertion). injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 11 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 12 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-1's observation window)

Frame attribution: 26 frame(s) (148–173), precision endpoint; 5 frame(s) inside the window belonged to other conversations and were excluded.

1 frame(s) were claimed by more than one test case and attributed to none: [133]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: exactly one conversation was attributed: 69.0.0.2:56042 <> 69.0.0.20:5020. The endpoint claim this suite relies on — 'all traffic to 69.0.0.20:5020 during my interval is the DUT's' — therefore held for this test case
   - Frames: 148
   - Frames sha256: `94c8c9f1b98970d3d4c97db3347c414e5dbd613b7ca8e14de13fba4607ffaf8d`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT performed SunSpec discovery against a server at a given IPv4 address
   - Method: destination IPv4 address of the DUT's southbound TCP connection, from the capture
   - Observed: the DUT dialled 69.0.0.20:5020 from 69.0.0.2:56042 and exchanged 19 Modbus message(s) there after its southbound connection was severed at epoch 12, so that its reconnect would perform discovery inside this test case's window
   - Frames: 151, 155, 157, 159, 161, 163, 165, 167, 169, 172
   - Frames sha256: `1876847b2cdabc7b516c055c321fe668402fa9a27ce15d41b920bf443b3fbbfa`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the DUT probed a standard SunSpec base address and read the 'SunS' identifier
   - Method: FC 0x03 request address + the identifier registers in the matching response, decoded independently from the reassembled byte stream
   - Observed: registers 40000..40001 read by the DUT hold 0x5375 0x6e53 = "SunS" — the SunSpec identifier at base 40000
   - Frames: 153
   - Stream: `69.0.0.20:5020 > 69.0.0.2:56042` bytes [9,13)
   - Bytes sha256: `32f1b60b22f544bbf85105f54628052d81fe4505c4395545068b0c012197a3e3`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **WARN** — the DUT walked the server's complete SunSpec model chain
   - Method: reconstruction of the model chain from the register image the DUT was observed to read: each ID/length header pair from base+2 to the 0xFFFF end marker
   - Observed: 8 model header(s) were observed but the chain did not reach the 0xFFFF end marker within this test case's frames: the chain walk reached the model header at 40461, which this test case did not observe the DUT read. Observed: ID 1 @40002 L=66 (header only — stepped over by length), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length), ID 701 @40254 L=153 (header only — stepped over by length), ID 702 @40409 L=50 (header only — stepped over by length)
   - Frames: 153, 156, 158, 160, 162, 164, 166, 168, 170
   - Frames sha256: `15149936c7362ac349515c2e6d24ef05bb355f299f5726129ec453c62d9eb890`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
5. **SKIP** — the DUT read the complete Common Model (model ID 1) block
   - Method: coverage of model 1's body by the DUT's read requests, with the identity points decoded independently from the response bytes
   - Observed: model 1 (header at 40002, length 66) was found in the chain but this test case did not observe the DUT read its whole body
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **PASS** — every Modbus/TCP request the DUT emitted carried a well-formed MBAP header
   - Method: independent MBAP decode of the reassembled DUT→server direction (protocol id == 0; length field == 1 + PDU length; unit id in 1..247)
   - Observed: all 10 request(s) carried protocol id 0, a length field consistent with the delivered PDU, and a unit id in 1..247. First request cited in full: txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 151
   - Stream: `69.0.0.2:56042 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
7. **PASS** — the DUT matched every response to its request by MBAP transaction identifier
   - Method: pairing of requests and responses by (transaction id, unit id, function code), with no positional fallback
   - Observed: 10 request(s) with transaction ids 1…10; 9 advanced monotonically; every response was matched to the request bearing its id (1 request(s) unanswered)
   - Frames: 151, 155, 157, 159, 161, 163, 165, 167, 169, 172
   - Frames sha256: `1876847b2cdabc7b516c055c321fe668402fa9a27ce15d41b920bf443b3fbbfa`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 12 and it issued 3 transaction(s) afterwards across 12 session(s) — 3 transaction(s) (3 answered) — starting at seq 973, epoch 12, poll 0, conn 12: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
9. **SKIP** — the DUT logged the contents of all the Common Model points
   - Method: observation of the DUT reading model 1's BODY — not merely its ID/length header — inside a test case's window
   - Observed: lexa-gw reads model 1's body EXACTLY ONCE, during admission, on a separate short-lived connection at boot (internal/southbound/admission/identify.go's identifyNow calls sunspec.ReadCommon there and nowhere else). Its steady-state poll reads only the measurement model, and even a full reconnect rediscovery walks the chain's HEADERS and then goes straight to that model — lexa-proto/sunspec/reader.go caches the block layout per session and never re-reads model 1's body. So no provocation available to this bench can make the DUT re-read the Common Model inside a window: it would take a process restart, which a shared-bench conformance run must not perform. THIS IS A DUT-SIDE OBSERVABILITY GAP, not a missing sim verb. Closing it needs either a re-identify diagnostic on the DUT that a read-only client can trigger, or a run whose capture begins before the DUT's own boot so the admission connection falls inside it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
10. **SKIP** — the DUT performed SunSpec discovery against a second server at a DIFFERENT IPv4 address
   - Method: present the single simulated device at a second IPv4 address and have the DUT discover it there, per §2.4.1 steps 1-3
   - Observed: THE BENCH HALF IS READY AND THE DUT HALF IS NOT. modsim binds one address with -bind, so presenting the same device at a second IPv4 address is a launch argument. What cannot be done from inside a conformance run is the other half of §2.4.1 step 2 — 'share the server IP addresses … with the CUT operator' — because this DUT reads its southbound endpoint from /etc/lexa/modbus.json EXACTLY ONCE, at process start, and offers no runtime path to change it: no SIGHUP handler (it installs SIGINT/SIGTERM only), no config file watch, and its only HTTP listener serves /metrics. The supported change is an operator write to lexa-api's POST /config/modbus, which stages the file and then requests `systemctl restart lexa-modbus` — and this harness's gateway client is READ-ONLY BY CONSTRUCTION (its allowlist admits observation commands only and restricts systemctl to reporting subcommands), because the bench is shared and a conformance run must not change the DUT it is measuring. PROMOTING THIS ROW therefore takes an operator procedure rather than a bench capability: prepare the second address's modsim and the matching device entry BEFORE the run, and record the two discoveries as two runs of this row correlated in the bundle's DUT metadata. Note also that the DUT is not commissioned-locked for this to work: the config write API refuses outright once /etc/lexa/commissioned exists. Server 1 in this run was 69.0.0.20:5020
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::CLI-3 General Discovery for SunSpec Servers with Different Unit IDs — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.4.3 CLI-3 – General Discovery for SunSpec Servers with Different Unit IDs (under 2.4 General Client Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's unit-id handling was observed against server 1 after its southbound connection was severed at epoch 15, so that its reconnect would perform discovery inside this test case's window, and the served device was then RE-ADDRESSED at runtime to unit id 247 — a capability this bench did not have before — to show what the DUT does when a server's unit id changes under it. Two servers with different unit ids, both of which the DUT is configured for, still needs a DUT configuration change this run must not make. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 14 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 15 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-3's observation window); POST http://69.0.0.20:6020/fault {"kind":unit_id "unit_id":247} → epoch 16 (re-address the served device to unit id 247, so a client still addressing its previously configured id is answered 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND — §2.4.3 step 1's 'different Unit IDs', as a runtime lever); POST http://69.0.0.20:6020/fault {"clear":true "kind":unit_id}; POST http://69.0.0.20:6020/fault {"clear":true "kind":unit_id} → epoch 18 (restore the device's original addressing so the DUT's recovery can be observed)

Frame attribution: 42 frame(s) (179–225), precision endpoint; 10 frame(s) inside the window belonged to other conversations and were excluded.

1 frame(s) were claimed by more than one test case and attributed to none: [215]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 2 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:55144 <> 69.0.0.20:5020, 69.0.0.2:54504 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 179
   - Frames sha256: `8480d94aaafea40861019b89929126eba7ee234eb62a342f4fd45ec727906ab4`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — every Modbus request the DUT emitted carried the server's configured unit identifier, in the legal range 1..247
   - Method: unit identifier field of every MBAP header in the reassembled DUT→server direction, and of every response
   - Observed: all 8 request(s) addressed unit id 1 (legal range 1..247) and every response echoed it. First request cited in full: [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 207
   - Stream: `69.0.0.2:54504 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the DUT probed a standard SunSpec base address and read the 'SunS' identifier
   - Method: FC 0x03 request address + the identifier registers in the matching response, decoded independently from the reassembled byte stream
   - Observed: registers 40000..40001 read by the DUT hold 0x5375 0x6e53 = "SunS" — the SunSpec identifier at base 40000
   - Frames: 209
   - Stream: `69.0.0.20:5020 > 69.0.0.2:54504` bytes [9,13)
   - Bytes sha256: `32f1b60b22f544bbf85105f54628052d81fe4505c4395545068b0c012197a3e3`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **WARN** — the DUT walked the server's complete SunSpec model chain
   - Method: reconstruction of the model chain from the register image the DUT was observed to read: each ID/length header pair from base+2 to the 0xFFFF end marker
   - Observed: 6 model header(s) were observed but the chain did not reach the 0xFFFF end marker within this test case's frames: the chain walk reached the model header at 40254, which this test case did not observe the DUT read. Observed: ID 1 @40002 L=66 (header only — stepped over by length), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length)
   - Frames: 209, 212, 214, 216, 218, 220, 222
   - Frames sha256: `422f60ee3acd25da11313a029bea371d93e79072abdfa15d48c8aa2c5de26704`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
5. **SKIP** — the DUT read the complete Common Model (model ID 1) block
   - Method: coverage of model 1's body by the DUT's read requests, with the identity points decoded independently from the response bytes
   - Observed: model 1 (header at 40002, length 66) was found in the chain but this test case did not observe the DUT read its whole body
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **PASS** — every Modbus/TCP request the DUT emitted carried a well-formed MBAP header
   - Method: independent MBAP decode of the reassembled DUT→server direction (protocol id == 0; length field == 1 + PDU length; unit id in 1..247)
   - Observed: all 8 request(s) carried protocol id 0, a length field consistent with the delivered PDU, and a unit id in 1..247. First request cited in full: txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 207
   - Stream: `69.0.0.2:54504 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
7. **PASS** — the DUT matched every response to its request by MBAP transaction identifier
   - Method: pairing of requests and responses by (transaction id, unit id, function code), with no positional fallback
   - Observed: 8 request(s) with transaction ids 1…8; 7 advanced monotonically; every response was matched to the request bearing its id (1 request(s) unanswered)
   - Frames: 207, 211, 213, 215, 217, 219, 221, 224
   - Frames sha256: `3bccfb6a6080580d370adb85a69998d9041f1a63e87bb8436681f99a11c87493`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 15 and it issued 3 transaction(s) afterwards across 13 session(s) — 3 transaction(s) (3 answered) — starting at seq 982, epoch 15, poll 0, conn 13: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
9. **PASS** — every Modbus request the DUT emitted carried one unit identifier, in the legal range 1..247, and the server echoed it
   - Method: the MBAP unit identifier of every request in the simulator's own transaction ledger since the DUT's connection was severed
   - Observed: all 3 transaction(s) the simulator recorded addressed unit id 1, in the legal range 1..247. First: seq 982, epoch 15, poll 0, conn 13: unit 1, FC 0x03 at 40000×2 → answered
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
10. **SKIP** — the served device was re-addressed to a different unit id and the DUT's requests to its previously configured id were answered as a gateway-target failure
   - Method: arm modsim's unit_id gate at unit 247 and read, from the simulator's own ledger, how the DUT's requests were resolved
   - Observed: OBSERVATION, not the criterion: with the served device re-addressed to unit id 247 at epoch 16, 1 of the DUT's request(s) — still carrying unit id 1 — were answered 0x0B GATEWAY TARGET DEVICE FAILED TO RESPOND, and the device behind the gate never saw them. First: seq 987, epoch 16, poll 0, conn 13: unit 1, FC 0x03 at 40176×2 → exception 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND. This shows the DUT genuinely ADDRESSES the unit id it is configured with rather than ignoring the field, and that this bench can now present a server at a different unit id at all — neither of which is §2.4.3's criterion, which is that the CUT DISCOVERS a server whose unit id differs. That needs the DUT told the new id; see the assertion below
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
11. **PASS** — the DUT resumed normal operation once the server answered its configured unit id again
   - Method: a transaction that completed normally AFTER the unit-id gate was cleared, held on the simulator's transaction ledger rather than on a clock
   - Observed: with the device's original addressing restored at epoch 18, 1 of the DUT's transaction(s) completed normally — first: seq 988, epoch 18, poll 0, conn 14: unit 1, FC 0x03 at 40000×2 → answered. The client recovered from a server that stopped answering its unit id
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
12. **SKIP** — the DUT logged the contents of all the Common Model points
   - Method: observation of the DUT reading model 1's BODY — not merely its ID/length header — inside a test case's window
   - Observed: lexa-gw reads model 1's body EXACTLY ONCE, during admission, on a separate short-lived connection at boot (internal/southbound/admission/identify.go's identifyNow calls sunspec.ReadCommon there and nowhere else). Its steady-state poll reads only the measurement model, and even a full reconnect rediscovery walks the chain's HEADERS and then goes straight to that model — lexa-proto/sunspec/reader.go caches the block layout per session and never re-reads model 1's body. So no provocation available to this bench can make the DUT re-read the Common Model inside a window: it would take a process restart, which a shared-bench conformance run must not perform. THIS IS A DUT-SIDE OBSERVABILITY GAP, not a missing sim verb. Closing it needs either a re-identify diagnostic on the DUT that a read-only client can trigger, or a run whose capture begins before the DUT's own boot so the admission connection falls inside it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
13. **SKIP** — the DUT interacted with two servers carrying DIFFERENT unit identifiers
   - Method: present the single simulated device at a second unit id and have the DUT discover it there, per §2.4.3 steps 1-3
   - Observed: THE BENCH HALF IS READY AND THE DUT HALF IS NOT. modsim can re-address the served device at runtime — the preceding assertion drove it — so a server at a different unit id is no longer something this bench lacks. What cannot be done from inside a conformance run is §2.4.3 step 2, sharing the new unit id with the CUT: this DUT reads devices[].unit_id from /etc/lexa/modbus.json EXACTLY ONCE, at process start, applies it to the session with a single SetUnitID at connect, and offers no runtime path to change it — no SIGHUP handler (it installs SIGINT/SIGTERM only), no config watch, and its only HTTP listener serves /metrics. The supported change is an operator write to lexa-api's POST /config/modbus followed by `systemctl restart lexa-modbus`, and this harness's gateway client is READ-ONLY BY CONSTRUCTION (its allowlist admits observation commands only and restricts systemctl to reporting subcommands) because the bench is shared and a conformance run must not change the DUT it is measuring. PROMOTING THIS ROW takes an operator procedure, not a bench capability: prepare the second unit id in the DUT's config before the run and record the two discoveries as two runs of this row correlated in the bundle's DUT metadata
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::CLI-4 General Discovery for SunSpec Servers with Different Starting Register Values — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.4.4 CLI-4 – General Discovery for SunSpec Servers with Different Starting Register Values (under 2.4 General Client Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the server's SunSpec map was re-homed to each of §2.4.4's three canonical starting registers in turn — [0 50000 40000] — and the DUT's rediscovery at each was held on the simulator's own transaction ledger rather than on a poll interval, so each base's evidence is the traffic that happened while THAT base was in force. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 20 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 21 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-4 (default base)'s observation window); POST http://69.0.0.20:6020/fault {"base":0 "kind":relocate} → epoch 22 (re-home the server's SunSpec map to base 0, one of §2.4.4's three canonical starting registers, so discovery can be observed there too); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 23 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-4 (base 0)'s observation window); POST http://69.0.0.20:6020/fault {"base":50000 "kind":relocate} → epoch 24 (re-home the server's SunSpec map to base 50000, one of §2.4.4's three canonical starting registers, so discovery can be observed there too); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 25 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-4 (base 50000)'s observation window); POST http://69.0.0.20:6020/fault {"base":40000 "kind":relocate} → epoch 26 (re-home the server's SunSpec map to base 40000, one of §2.4.4's three canonical starting registers, so discovery can be observed there too); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 27 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside CLI-4 (base 40000)'s observation window)

Frame attribution: 88 frame(s) (231–338), precision endpoint; 26 frame(s) inside the window belonged to other conversations and were excluded.

2 frame(s) were claimed by more than one test case and attributed to none: [215 328]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 4 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:45902 <> 69.0.0.20:5020, 69.0.0.2:43956 <> 69.0.0.20:5020, 69.0.0.2:37592 <> 69.0.0.20:5020, 69.0.0.2:38410 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 231
   - Frames sha256: `1d010eed71f500bebf18ba11c179c8ed8d25b8536479dda2cc45e58bca67185a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT probed only standard SunSpec base addresses, and read the map from the one that answered
   - Method: start addresses of the DUT's FC 0x03 requests, compared against the three standard SunSpec base addresses 0, 40000 and 50000
   - Observed: the DUT issued 1 read(s) at standard base address(es) [40000] (of the legal set [40000 0 50000]) and none at any other candidate base. The probe at 40000 returned the SunSpec identifier, and the model-chain walk continued from 40002. First probe cited in full: [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 314
   - Stream: `69.0.0.2:38410 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the DUT probed a standard SunSpec base address and read the 'SunS' identifier
   - Method: FC 0x03 request address + the identifier registers in the matching response, decoded independently from the reassembled byte stream
   - Observed: registers 40000..40001 read by the DUT hold 0x5375 0x6e53 = "SunS" — the SunSpec identifier at base 40000
   - Frames: 316
   - Stream: `69.0.0.20:5020 > 69.0.0.2:38410` bytes [9,13)
   - Bytes sha256: `32f1b60b22f544bbf85105f54628052d81fe4505c4395545068b0c012197a3e3`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **WARN** — the DUT walked the server's complete SunSpec model chain
   - Method: reconstruction of the model chain from the register image the DUT was observed to read: each ID/length header pair from base+2 to the 0xFFFF end marker
   - Observed: 9 model header(s) were observed but the chain did not reach the 0xFFFF end marker within this test case's frames: the chain walk reached the model header at 40480, which this test case did not observe the DUT read. Observed: ID 1 @40002 L=66 (header only — stepped over by length), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length), ID 701 @40254 L=153 (header only — stepped over by length), ID 702 @40409 L=50 (header only — stepped over by length), ID 703 @40461 L=17 (header only — stepped over by length)
   - Frames: 316, 319, 321, 323, 325, 327, 329, 331, 333, 335
   - Frames sha256: `9da3a1592873221fcee232980d292148f9678b702ef46772e2279d54c0af9c7b`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
5. **SKIP** — the DUT read the complete Common Model (model ID 1) block
   - Method: coverage of model 1's body by the DUT's read requests, with the identity points decoded independently from the response bytes
   - Observed: model 1 (header at 40002, length 66) was found in the chain but this test case did not observe the DUT read its whole body
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **PASS** — every Modbus/TCP request the DUT emitted carried a well-formed MBAP header
   - Method: independent MBAP decode of the reassembled DUT→server direction (protocol id == 0; length field == 1 + PDU length; unit id in 1..247)
   - Observed: all 11 request(s) carried protocol id 0, a length field consistent with the delivered PDU, and a unit id in 1..247. First request cited in full: txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 [00 01 00 00 00 06 01 03 9c 40 00 02]
   - Frames: 314
   - Stream: `69.0.0.2:38410 > 69.0.0.20:5020` bytes [0,12)
   - Bytes sha256: `9cb3adc3dd65786f65c5b72dc763d11e5754e1d71397a091df164d04c48d836a`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
7. **PASS** — the DUT matched every response to its request by MBAP transaction identifier
   - Method: pairing of requests and responses by (transaction id, unit id, function code), with no positional fallback
   - Observed: 11 request(s) with transaction ids 1…11; 10 advanced monotonically; every response was matched to the request bearing its id (1 request(s) unanswered)
   - Frames: 314, 318, 320, 322, 324, 326, 328, 330, 332, 334, 337
   - Frames sha256: `8f2af5ce7a6b7e6a4fa81f82588a0b48799eef2464aa3f39f4bc01901b3f94bf`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 21 and it issued 3 transaction(s) afterwards across 15 session(s) — 3 transaction(s) (3 answered) — starting at seq 995, epoch 21, poll 0, conn 15: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
9. **PASS** — the DUT completed SunSpec discovery with the server's map at each of the three canonical starting registers 0, 40000 and 50000
   - Method: re-home the server's map to each base, sever the DUT's connection, and read from the simulator's ledger — fenced at that leg's own epoch — whether the DUT probed the new base and read the identifier there
   - Observed: 3 of 3 base(s) completed: base 0: probed and the identifier read back, then 2 further transaction(s) walking the map; base 50000: probed and the identifier read back, then 2 further transaction(s) walking the map; base 40000: probed and the identifier read back, then 2 further transaction(s) walking the map
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
10. **SKIP** — the DUT logged the contents of all the Common Model points
   - Method: observation of the DUT reading model 1's BODY — not merely its ID/length header — inside a test case's window
   - Observed: lexa-gw reads model 1's body EXACTLY ONCE, during admission, on a separate short-lived connection at boot (internal/southbound/admission/identify.go's identifyNow calls sunspec.ReadCommon there and nowhere else). Its steady-state poll reads only the measurement model, and even a full reconnect rediscovery walks the chain's HEADERS and then goes straight to that model — lexa-proto/sunspec/reader.go caches the block layout per session and never re-reads model 1's body. So no provocation available to this bench can make the DUT re-read the Common Model inside a window: it would take a process restart, which a shared-bench conformance run must not perform. THIS IS A DUT-SIDE OBSERVABILITY GAP, not a missing sim verb. Closing it needs either a re-identify diagnostic on the DUT that a read-only client can trigger, or a run whose capture begins before the DUT's own boot so the admission connection falls inside it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::PROT-2 TCP Segmentation (Only for Modbus TCP Clients) — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.8.2 PROT-2 – TCP-Segmentation (under 2.8 Modbus Protocol Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's MBAP-length framing of the server's byte stream was asserted over a reconnect's discovery burst, held on the simulator's own transaction ledger rather than on a clock; a genuinely segmented ADU was NOT compelled (certify: POST http://69.0.0.20:6020/fault: HTTP 400: segment/truncate framing faults need an interposed relay: restart the sim with -protofault (kinds: segment_response, short_response)). injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 29 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 30 (sever the DUT's southbound connection so its reconnect's discovery burst — many responses in quick succession — falls inside this test case's window); VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.; PASS downgraded to WARN: no assertion carries a digest the bundle's verifier can re-derive from the capture

Frame attribution: 0 frame(s) (—), precision endpoint; 76 frame(s) inside the window belonged to other conversations and were excluded.

2 frame(s) were claimed by more than one test case and attributed to none: [328 363]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **SKIP** — the DUT parsed a Modbus response delivered across more than one TCP segment
   - Method: frame attribution (time AND flow)
   - Observed: no capture frame was attributed to this test case: the DUT sent no southbound Modbus traffic to 69.0.0.20:5020 during its observation window, or the capture did not see it. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 29 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 30 (sever the DUT's southbound connection so its reconnect's discovery burst — many responses in quick succession — falls inside this test case's window); POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 31
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **SKIP** — the server delivered a Modbus response across more than one TCP segment and the DUT parsed it correctly
   - Method: arm modsim's segment_response fault (one ADU, two socket writes, split after the MBAP header) and confirm from the simulator's own ledger that the DUT's transactions under it completed normally
   - Observed: the server could not be made to segment: certify: POST http://69.0.0.20:6020/fault: HTTP 400: segment/truncate framing faults need an interposed relay: restart the sim with -protofault (kinds: segment_response, short_response). modsim serves this fault only with a second framing relay interposed (-protofault); it refuses the kind BY NAME when that flag was not given, which is why this reads as a launch-flag gap rather than as 'segmentation cannot be compelled'. Add -protofault to the bench's modsim invocation and this row's headline criterion becomes drivable
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
3. **PASS** — the DUT re-established its connection and issued a discovery burst the framing assertions above are drawn from
   - Method: the transactions the simulator recorded after the DUT's connection was severed at a named epoch
   - Observed: after its connection was severed at epoch 30 the DUT reconnected and issued 3 transaction(s) — 3 transaction(s) (3 answered) — over 19 session(s) as the simulator counted them
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs

### ⚠ ss-modbus-client-conf-v1.1::ERR-3 Unknown Model ID Test — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.9.3 ERR-3 – Unknown Model ID Test (under 2.9 Error Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): a model with an ID unknown to any client (65000) was spliced into the server's chain immediately before the end marker (spliced=true), and the DUT's rediscovery over it was held on the simulator's transaction ledger rather than on a poll interval after its southbound connection was severed at epoch 34, so that its reconnect would perform discovery inside this test case's window. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 32 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/inject {"insert_model":map[id:65000 len:4]} → epoch 33 (splice a model with an unregistered ID (65000) into the server's chain immediately before the end marker, per §2.9.3 step 1); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 34 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside ERR-3's observation window)

Frame attribution: 162 frame(s) (347–718), precision endpoint; 195 frame(s) inside the window belonged to other conversations and were excluded.

1 frame(s) were claimed by more than one test case and attributed to none: [363]

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 2 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:51148 <> 69.0.0.20:5020, 69.0.0.2:44668 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 347
   - Frames sha256: `c355ea4b519eefa18f53d01330534e68e248c3c965b2f2623c9bc5c3c98395de`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT stepped over a model it did not consume by using its length header, and continued the chain walk to the end marker
   - Method: model chain reconstruction: a model whose ID and length registers the DUT read but whose body it never requested, followed by a header read at exactly HeaderAddr + 2 + Length
   - Observed: the DUT read the header of model 120 at 40070 (length 26) but never requested any of its body registers at 40072..40097, and its next header read was at 40098 = 40070 + 2 + 26 — the address the length header dictates. 12 of the chain's 19 model(s) were stepped over this way: ID 1 @40002 L=66 (body read), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length), ID 701 @40254 L=153 (body read), ID 702 @40409 L=50 (body read), ID 703 @40461 L=17 (header only — stepped over by length), ID 704 @40480 L=65 (body read), ID 705 @40547 L=73 (body read), ID 706 @40622 L=63 (body read), ID 711 @40687 L=32 (header only — stepped over by length), ID 712 @40721 L=60 (body read), ID 707 @40783 L=159 (header only — stepped over by length), ID 708 @40944 L=159 (header only — stepped over by length), ID 709 @41105 L=207 (header only — stepped over by length), ID 710 @41314 L=207 (header only — stepped over by length), ID 65000 @41523 L=4 (header only — stepped over by length).
   - Frames: 515, 518, 520, 522, 524, 526, 528, 530, 532, 534, 536, 538, 540, 542, 544, 546, 548, 550, 552, 554, 556, 561, 565, 567, 569, 571, 573, 575, 577, 579, 581, 583, 585, 587, 589
   - Frames sha256: `602c19e3849425ffbcfab0936544742cd17dfbb42c12576bb37d7fac07f1b583`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 34 and it issued 3 transaction(s) afterwards across 20 session(s) — 3 transaction(s) (3 answered) — starting at seq 1057, epoch 34, poll 0, conn 20: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
4. **PASS** — the DUT's list of discovered models does not include the unknown model ID
   - Method: the DUT's own admission journal (/var/lib/lexa/journal/modbus/journal.ndjson), read over the read-only gateway client, for a fresh admission event naming the device that appeared after the unregistered model was spliced
   - Observed: the freshly-journaled admission event for device "inv-plain" reports its discovered models as [1 120 121 122 103 123 701 702 703 704 705 706 711 712 707 708 709 710] — the unregistered ID 65000 this test case spliced into the chain is absent
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: cat /var/lib/lexa/journal/modbus/journal.ndjson on the device under test
5. **PASS** — a model whose ID is absent from the DUT's model definition directory was present in the server's chain, and the DUT stepped over it using its length header
   - Method: splice a model with an unregistered ID into the server's SunSpec map (modsim's insert_model verb, sim/southbound/modelsplice.go), per §2.9.3 step 1, then reconstruct the model chain from the register image the DUT was observed to read
   - Observed: the server's chain carried a genuinely unregistered model (ID 65000, header at 41523, length 4, spliced by this test case immediately before the end marker), and the DUT read only its header — stepping over the body by length exactly as it does for a registered model it simply does not consume
   - Frames: 515, 518, 520, 522, 524, 526, 528, 530, 532, 534, 536, 538, 540, 542, 544, 546, 548, 550, 552, 554, 556, 561, 565, 567, 569, 571, 573, 575, 577, 579, 581, 583, 585, 587, 589
   - Frames sha256: `602c19e3849425ffbcfab0936544742cd17dfbb42c12576bb37d7fac07f1b583`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes

### ⚠ ss-modbus-client-conf-v1.1::ERR-1 Noncompliant Server — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.9.1 ERR-1 – Noncompliant Server (under 2.9 Error Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the server's SunSpec map was moved to holding register 40001 — the deliberately noncompliant off-by-one base §2.9.1 calls for — and the DUT's reconnect was observed against it, then against the restored legal map. This row previously reported 'the server cannot be made noncompliant on this bench'; modsim's relocate verb closes that, and no step of it waits on a clock. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 36 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"base":40001 "kind":relocate} → epoch 37 (re-home the server's SunSpec map to holding register 40001 — one register off the legal 40000, which is §2.9.1's noncompliant server); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 38 (sever the DUT's southbound connection so its reconnect performs the base probe against the noncompliant map, inside this test case's window); POST http://69.0.0.20:6020/fault {"base":40000 "kind":relocate} → epoch 39 (put the server's SunSpec map back at the legal base 40000 so the DUT's recovery can be observed)

Frame attribution: 102 frame(s) (724–835), precision endpoint; 253 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 2 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:59728 <> 69.0.0.20:5020, 69.0.0.2:60902 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 724
   - Frames sha256: `a32b3b939e95c6b4f007d2027fda985319acc11c51b86e1a8c3fddc12fba6c34`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT probed only legal SunSpec base addresses against a server whose map begins at holding register 40001, and found no identifier at any of them
   - Method: the start address of every read the DUT issued after the server's map was re-homed to 40001, from the simulator's own transaction ledger, cross-checked against the identifier registers the responses actually carried
   - Observed: with the server's map at holding register 40001, the DUT issued 3 read(s), at standard base address(es) [0 40000 50000] and nowhere else. None returned the SunSpec identifier 0x5375 0x6e53, so discovery correctly failed rather than finding a map at the noncompliant offset. First transaction: seq 1092, epoch 38, poll 0, conn 21: unit 1, FC 0x03 at 40000×2 → answered
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
3. **PASS** — the DUT logged the noncompliant server
   - Method: the DUT's own lexa-modbus journal, read over the read-only gateway client, restricted to lines added after the server's map was moved off a legal base
   - Observed: 3 journal line(s) added while the server's map sat at holding register 40001 report the failure to identify "inv-plain". First: 2026-09-09T16:56:49-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:56:49.275-04:00 level=INFO msg="lexa-modbus: device inv-plain poll error: inverter: read model 701: sunspec: read model 701 at 40256+153: EOF" svc=lexa-modbus \| 2026-09-09T16:56:59-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:56:59.277-04:00 level=INFO msg="lexa-modbus: device inv-plain poll error: inverter: scan SunSpec blocks: sunspec scan: no SunS header at bases [40000 0 50000]" svc=lexa-modbus \| 2026-09-09T16:57:09-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:57:09.291-04:00 level=INFO msg="lexa-modbus: device inv-plain poll error: inverter: malformed device: model 701 declares 2 registers, spec layout requires 153 (fixed measurement model is shorter than its SunSpec layout)" svc=lexa-modbus
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: journalctl -u lexa-modbus on the device under test
4. **PASS** — the DUT recovered — did not hang or crash — after being connected to the noncompliant server
   - Method: a transaction with the server AFTER its map was restored to the legal base 40000, held on the simulator's transaction ledger rather than on a clock
   - Observed: with the server's map restored to the legal base 40000 at epoch 39, the DUT issued 1 transaction(s) that completed normally — it kept probing through the noncompliant interval and resumed discovery the moment the server became compliant. First: seq 1095, epoch 39, poll 0, conn 22: unit 1, FC 0x03 at 40000×2 → answered
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs

### ⚠ ss-modbus-client-conf-v1.1::INFO-1 SunSpec Type Interpretations — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.7.1 INFO-1 – SunSpec Type Interpretations (under 2.7 Information Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT's read coverage and its scale-factor interpretation were asserted over a forced rediscovery and one complete poll cycle, both held on the simulator rather than on a clock; the per-datatype rendering criteria (a)-(i) are about the client's own log and are not wire facts. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 41 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/control {"cmd":"pause"} (freeze the server's animated registers so the value the DUT reads and the value it reports are the same instant); POST http://69.0.0.20:6020/fault {"kind":tcp_drop} → epoch 43 (sever the DUT's southbound connection so its reconnect performs the full SunSpec discovery sequence inside INFO-1's observation window)

Frame attribution: 86 frame(s) (960–1184), precision endpoint; 254 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: exactly one conversation was attributed: 69.0.0.2:42478 <> 69.0.0.20:5020. The endpoint claim this suite relies on — 'all traffic to 69.0.0.20:5020 during my interval is the DUT's' — therefore held for this test case
   - Frames: 960
   - Frames sha256: `1ff264cae363148e4099c7eabe5099d106ccb4cb5695bd429ebafe7cbeab597c`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT read the register blocks of the server's models, scale-factor registers included
   - Method: coverage of each model body by the DUT's FC 0x03 requests, from the reconstructed chain
   - Observed: base 40000, 18 model(s) in the chain; the DUT read into 7 of them and fully covered 7. Because a model body is read as a contiguous block, every scale-factor register inside a covered body was read with its value. Chain: ID 1 @40002 L=66 (body read), ID 120 @40070 L=26 (header only — stepped over by length), ID 121 @40098 L=30 (header only — stepped over by length), ID 122 @40130 L=44 (header only — stepped over by length), ID 103 @40176 L=50 (header only — stepped over by length), ID 123 @40228 L=24 (header only — stepped over by length), ID 701 @40254 L=153 (body read), ID 702 @40409 L=50 (body read), ID 703 @40461 L=17 (header only — stepped over by length), ID 704 @40480 L=65 (body read), ID 705 @40547 L=73 (body read), ID 706 @40622 L=63 (body read), ID 711 @40687 L=32 (header only — stepped over by length), ID 712 @40721 L=60 (body read), ID 707 @40783 L=159 (header only — stepped over by length), ID 708 @40944 L=159 (header only — stepped over by length), ID 709 @41105 L=207 (header only — stepped over by length), ID 710 @41314 L=207 (header only — stepped over by length)
   - Frames: 965, 968, 970, 972, 974, 976, 978, 980, 982, 984, 986, 988, 990, 992, 994, 996, 998, 1000, 1002, 1004, 1006, 1008, 1010, 1012, 1014, 1016, 1018, 1020, 1022, 1024, 1026, 1028, 1030, 1032, 1164, 1172, 1180
   - Frames sha256: `443d6f6e51dc2bb2fd431cc76221a7578d7dafe2c6fb0be7d0215ae2e6541359`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
3. **PASS** — the value the DUT reported for the device is the value its raw register reads decode to under the SunSpec scale-factor convention
   - Method: search of the register image the DUT was observed to read for a (value, sunssf) pair satisfying reported = raw × 10^sunssf, with the server's animation frozen so both refer to the same instant
   - Observed: the DUT reported 8000 W for device "inv-plain"; register 40264, whose raw value 0x1f40 = 8000 the DUT read in the cited response bytes, scaled by the sunssf register at 40010 (value 0) gives 8000 — matching in 1221 ways (the register image contains several pairs that agree, so this corroborates the conversion rather than pinning the exact point). The raw register alone already equals the reported value, so the scale factor is 10^0 and is trivially applied
   - Frames: 1010
   - Stream: `69.0.0.20:5020 > 69.0.0.2:42478` bytes [535,537)
   - Bytes sha256: `befce9dfa709699a5f20d1b01095f6460dd1ac61b7a56b6fda475794d1b801a2`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
4. **PASS** — the DUT re-established its southbound connection and performed a fresh SunSpec discovery inside this test case's window
   - Method: sever the DUT's connection at a named control-plane epoch, then wait on the simulator's own transaction ledger — not on a poll interval — for the rediscovery burst
   - Observed: the DUT's connection was severed at epoch 43 and it issued 3 transaction(s) afterwards across 23 session(s) — 3 transaction(s) (3 answered) — starting at seq 1135, epoch 43, poll 0, conn 23: unit 1, FC 0x03 at 40000×2 → answered. The discovery assertions in this row are about that conversation
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
5. **PASS** — the read pattern asserted above was observed over a COMPLETE poll cycle, not a fragment of one
   - Method: the simulator's poll barrier: it counts the client's cycles from the server side of the wire and returns only once a cycle has closed and every transaction of it has resolved
   - Observed: a complete poll cycle closed inside this test case's window before any read assertion was graded. the sim counted 2 completed poll cycle(s) over 23 session(s) (0 abandoned mid-cycle by a reconnect), using anchor FC 0x03 at 40482×65, learned. Its rule: a poll cycle is the interval between two consecutive arrivals of the cycle anchor (the read request the client repeats every cycle); cycle N is COMPLETE when the anchor opening cycle N+1 has arrived and every transaction of cycle N has been resolved at the sim's wire layer
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
6. **SKIP** — the DUT logged every point of every PICS model in human-readable form, with each datatype rendered as §2.7.1 step 2 (a)–(i) prescribes
   - Method: inspection of the client's own human-readable point log
   - Observed: criteria (a)–(i) prescribe a RENDERING — dotted-quad for ipaddr, RFC-4291 hextets for ipv6addr, uppercase colon-separated octets for eui48, hex strings for bitfields, base-10 for enums — and a rendering exists only in the client's output, never on the wire. The DUT is an autonomous gateway: it decodes the measurement and identity points its reconcilers consume and journals those, and has no point-browser mode that prints every point of every model. Nine of the datatypes in §2.3's list (ipv6addr, eui48, float64, int64, uint64, acc64 among them) do not occur at all in the models this server serves, so even a point browser would leave them unexercised here. Promoting this row to full needs both a diagnostic dump mode on the DUT and a server whose models span every datatype in the list
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
7. **SKIP** — the DUT applied the appropriate scale factor to every numerical point
   - Method: per-point comparison of the DUT's reported values against the raw registers
   - Observed: the DUT reports one derived quantity per device per poll (its watt readback), which the preceding assertion tests. A per-POINT sweep needs the DUT to publish every decoded point; see the rendering assertion above for the same missing capability
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::ERR-2 Exception Tests — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.9.2 ERR-2 – Exception Tests (under 2.9 Error Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): all five exception classes §2.9.2 is about — 0x01, 0x02, 0x03, 0x04 and 0x0B — were provoked on the server in turn, each armed at a named epoch and held until the SIMULATOR'S OWN transaction ledger showed the DUT had met it, then cleared. Recovery was held the same way. No step of this row waits on a clock. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 46 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"code":1 "kind":exception_code "on_fc":3} → epoch 47 (answer every FC 0x03 read with exception 0x01 ILLEGAL FUNCTION (ILLEGAL FUNCTION — the server declines the function code entirely)); POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code}; POST http://69.0.0.20:6020/fault {"code":2 "kind":exception_code "on_fc":3} → epoch 49 (answer every FC 0x03 read with exception 0x02 ILLEGAL DATA ADDRESS (ILLEGAL DATA ADDRESS — the register range is not one the server serves)); POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code}; POST http://69.0.0.20:6020/fault {"code":3 "kind":exception_code "on_fc":3} → epoch 51 (answer every FC 0x03 read with exception 0x03 ILLEGAL DATA VALUE (ILLEGAL DATA VALUE — the request's own parameters are refused)); POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code}; POST http://69.0.0.20:6020/fault {"code":4 "kind":exception_code "on_fc":3} → epoch 53 (answer every FC 0x03 read with exception 0x04 SERVER DEVICE FAILURE (SERVER DEVICE FAILURE — the right device, internally broken)); POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code}; POST http://69.0.0.20:6020/fault {"code":11 "kind":exception_code "on_fc":3} → epoch 55 (answer every FC 0x03 read with exception 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND (GATEWAY TARGET DEVICE FAILED TO RESPOND — the addressing failure, which is what a Modbus gateway answers for a unit it cannot reach)); POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code}; POST http://69.0.0.20:6020/fault {"clear":true "kind":exception_code} → epoch 57 (clear every exception class so the DUT's recovery can be observed)

Frame attribution: 256 frame(s) (1190–1754), precision endpoint; 282 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **PASS** — every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint
   - Method: every attributed TCP conversation with the bench's Modbus server endpoint is WITH that endpoint — the endpoint claim itself, re-checked against the capture rather than assumed
   - Observed: 3 conversations with 69.0.0.20:5020 were attributed (69.0.0.2:54776 <> 69.0.0.20:5020, 69.0.0.2:45540 <> 69.0.0.20:5020, 69.0.0.2:46120 <> 69.0.0.20:5020), some of them overlapping in time or not — that distinction does not matter here. 69.0.0.20:5020 is a dedicated, single-purpose, SERIALIZED listener (see the endpoint claim above): no other client can ever dial it during this run, whether one conversation's teardown races the next one's SYN or a check provokes several sequential reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim held for all of them
   - Frames: 1190
   - Frames sha256: `0949095ca0f4f6efa3030d38758ff04583668e1e8653f1be7bdf6861346d7e1e`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
2. **PASS** — the DUT received exception code 0x01 ILLEGAL FUNCTION from the server
   - Method: the exception code of the response the server returned to the DUT's own FC 0x03 read, after that class was armed at a named control-plane epoch and held until the simulator's transaction ledger recorded the DUT meeting it
   - Observed: the server delivered 1 exception 0x01 ILLEGAL FUNCTION to the DUT while the class was armed at epoch 47 — first: seq 1169, epoch 47, poll 0, conn 23: unit 1, FC 0x03 at 40256×125 → exception 0x01 ILLEGAL FUNCTION. No frame carrying one was attributed to this test case, so this rests on the simulator's record rather than on a citation into the capture; the DUT's own reconnect-with-backoff can place the exchange outside this window even when the provocation lands perfectly
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
3. **PASS** — the DUT received exception code 0x02 ILLEGAL DATA ADDRESS from the server
   - Method: the exception code of the response the server returned to the DUT's own FC 0x03 read, after that class was armed at a named control-plane epoch and held until the simulator's transaction ledger recorded the DUT meeting it
   - Observed: the server delivered 1 exception 0x02 ILLEGAL DATA ADDRESS to the DUT while the class was armed at epoch 49 — first: seq 1170, epoch 49, poll 0, conn 23: unit 1, FC 0x03 at 40256×125 → exception 0x02 ILLEGAL DATA ADDRESS. No frame carrying one was attributed to this test case, so this rests on the simulator's record rather than on a citation into the capture; the DUT's own reconnect-with-backoff can place the exchange outside this window even when the provocation lands perfectly
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
4. **PASS** — the DUT received exception code 0x03 ILLEGAL DATA VALUE from the server
   - Method: the exception code of the response the server returned to the DUT's own FC 0x03 read, after that class was armed at a named control-plane epoch and held until the simulator's transaction ledger recorded the DUT meeting it
   - Observed: the server delivered 1 exception 0x03 ILLEGAL DATA VALUE to the DUT while the class was armed at epoch 51 — first: seq 1171, epoch 51, poll 3, conn 23: unit 1, FC 0x03 at 40256×125 → exception 0x03 ILLEGAL DATA VALUE. No frame carrying one was attributed to this test case, so this rests on the simulator's record rather than on a citation into the capture; the DUT's own reconnect-with-backoff can place the exchange outside this window even when the provocation lands perfectly
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
5. **PASS** — the DUT received exception code 0x04 SERVER DEVICE FAILURE from the server
   - Method: the exception code of the response the server returned to the DUT's own FC 0x03 read, after that class was armed at a named control-plane epoch and held until the simulator's transaction ledger recorded the DUT meeting it
   - Observed: the server delivered 1 exception 0x04 SERVER DEVICE FAILURE to the DUT while the class was armed at epoch 53 — first: seq 1172, epoch 53, poll 0, conn 24: unit 1, FC 0x03 at 40000×2 → exception 0x04 SERVER DEVICE FAILURE. No frame carrying one was attributed to this test case, so this rests on the simulator's record rather than on a citation into the capture; the DUT's own reconnect-with-backoff can place the exchange outside this window even when the provocation lands perfectly
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
6. **PASS** — the DUT received exception code 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND from the server
   - Method: the exception code of the response the server returned to the DUT's own FC 0x03 read, after that class was armed at a named control-plane epoch and held until the simulator's transaction ledger recorded the DUT meeting it
   - Observed: the server delivered 1 exception 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND to the DUT while the class was armed at epoch 55 — first: seq 1175, epoch 55, poll 0, conn 25: unit 1, FC 0x03 at 40000×2 → exception 0x0b GATEWAY TARGET DEVICE FAILED TO RESPOND. No frame carrying one was attributed to this test case, so this rests on the simulator's record rather than on a citation into the capture; the DUT's own reconnect-with-backoff can place the exchange outside this window even when the provocation lands perfectly
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
7. **PASS** — the DUT continued to operate normally after each Modbus exception
   - Method: a complete, non-exception transaction with the server AFTER every exception class was cleared, held on the simulator's transaction ledger rather than on a clock so the DUT's own reconnect-with-backoff has as long as it needs
   - Observed: after every exception class was cleared at epoch 57 the DUT issued txid=1 unit=1 FC=0x03 read start=40000(0x9c40) quantity=2 and the server answered it normally — the client neither abandoned the connection nor stopped polling. The simulator's own ledger independently records 1 completed transaction(s) after that epoch, first: seq 1178, epoch 57, poll 0, conn 26: unit 1, FC 0x03 at 40000×2 → answered. Recovery response cited: txid=1 unit=1 FC=0x03 response bytecount=4(0x04) registers=2
   - Frames: 1233
   - Stream: `69.0.0.20:5020 > 69.0.0.2:46120` bytes [0,13)
   - Bytes sha256: `10dbc843f67b6fbb5e53a756a113f677522543a7aba9238a3f1c8179f8ee0312`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes
8. **PASS** — the DUT logged each Modbus exception it received
   - Method: the DUT's own lexa-modbus journal, read over the read-only gateway client, restricted to lines added after the first class was armed
   - Observed: 17 journal line(s) added during the fault report the failure of "inv-plain", 12 of them naming an exception class by name. First: 2026-09-09T16:57:29-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:57:29.275-04:00 level=WARN msg="lexa-modbus: device answered a Modbus exception" svc=lexa-modbus device=inv-plain unit_id=1 fc=0x03 address=40256 count=125 code=1 code_name="illegal function" policy=refused attempt=1 rediscover=false \| 2026-09-09T16:57:29-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:57:29.276-04:00 level=INFO msg="lexa-modbus: device inv-plain poll error: inverter: read model 701: sunspec: read model 701 at 40256+153: modbus: unit 1 fc 0x03 at 40256+125: exception 0x01 illegal function" svc=lexa-modbus \| 2026-09-09T16:57:39-04:00 ccimx93-dvk lexa-modbus[817]: time=2026-09-09T16:57:39.275-04:00 level=WARN msg="lexa-modbus: device answered a Modbus exception" svc=lexa-modbus device=inv-plain unit_id=1 fc=0x03 address=40256 count=125 code=2 code_name="illegal data address" policy=refused attempt=2 rediscover=false
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: journalctl -u lexa-modbus on the device under test

### ⚠ ss-modbus-client-conf-v1.1::INFO-2 Unimplemented Point Interpretations — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.7.2 INFO-2 – Unimplemented Point Interpretations (under 2.7 Information Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the int16 not-implemented sentinel was served for every register, and then 22 point(s) — one per SunSpec datatype — were seeded with their OWN not-implemented values inside the block the simulator observed the DUT reading every cycle. Both phases were held on the simulator's transaction ledger rather than on a poll interval. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 59 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":nan_sentinel} → epoch 60 (make every register read return the SunSpec not-implemented sentinel 0x8000 (int16 -32768), which is §2.7.2 step 2's 'configure points to the unimplemented value' applied to the whole register bank); POST http://69.0.0.20:6020/fault {"clear":true "kind":nan_sentinel}; POST http://69.0.0.20:6020/control {"cmd":"pause"} (freeze the animation so a seeded sentinel is not overwritten before the DUT reads it); POST http://69.0.0.20:6020/inject {"unimplemented":[map[addr:40258 type:int16] map[addr:40259 type:uint16] map[addr:40260 type:count] map[addr:40261 type:acc16] map[addr:40262 type:enum16] map[addr:40263 type:bitfield16] map[addr:40264 type:sunssf] map[addr:40265 type:pad] map[addr:40266 type:int32] map[addr:40268 type:uint32] map[addr:40270 type:acc32] map[addr:40272 type:enum32] map[addr:40274 type:bitfield32] map[addr:40276 type:ipaddr] map[addr:40278 type:float32] map[addr:40280 type:eui48] map[addr:40283 type:int64] map[addr:40287 type:uint64] map[addr:40291 type:acc64] map[addr:40295 type:float64] map[addr:40299 len:4 type:string] map[addr:40303 len:8 type:ipv6addr]]} → epoch 63 (seed 22 point(s) — one per SunSpec datatype — inside FC 0x03 at 40256×125, the block the simulator observed the DUT reading every poll cycle, each with its OWN not-implemented value per the Device Information Model)

Frame attribution: 0 frame(s) (—), precision endpoint; 219 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **SKIP** — the server returned the not-implemented sentinel and the DUT did not report it as a measurement
   - Method: frame attribution (time AND flow)
   - Observed: no capture frame was attributed to this test case: the DUT sent no southbound Modbus traffic to 69.0.0.20:5020 during its observation window, or the capture did not see it. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 59 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"kind":nan_sentinel} → epoch 60 (make every register read return the SunSpec not-implemented sentinel 0x8000 (int16 -32768), which is §2.7.2 step 2's 'configure points to the unimplemented value' applied to the whole register bank); POST http://69.0.0.20:6020/fault {"clear":true "kind":nan_sentinel}; POST http://69.0.0.20:6020/control {"cmd":"pause"} (freeze the animation so a seeded sentinel is not overwritten before the DUT reads it); POST http://69.0.0.20:6020/inject {"unimplemented":[map[addr:40258 type:int16] map[addr:40259 type:uint16] map[addr:40260 type:count] map[addr:40261 type:acc16] map[addr:40262 type:enum16] map[addr:40263 type:bitfield16] map[addr:40264 type:sunssf] map[addr:40265 type:pad] map[addr:40266 type:int32] map[addr:40268 type:uint32] map[addr:40270 type:acc32] map[addr:40272 type:enum32] map[addr:40274 type:bitfield32] map[addr:40276 type:ipaddr] map[addr:40278 type:float32] map[addr:40280 type:eui48] map[addr:40283 type:int64] map[addr:40287 type:uint64] map[addr:40291 type:acc64] map[addr:40295 type:float64] map[addr:40299 len:4 type:string] map[addr:40303 len:8 type:ipv6addr]]} → epoch 63 (seed 22 point(s) — one per SunSpec datatype — inside FC 0x03 at 40256×125, the block the simulator observed the DUT reading every poll cycle, each with its OWN not-implemented value per the Device Information Model); POST http://69.0.0.20:6020/inject {"clear_unimplemented":true} → epoch 64 (restore every seeded point); POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 66
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **PASS** — the server served the not-implemented sentinel for every register and the DUT read it
   - Method: arm the whole-bank sentinel at a named epoch, then read from the simulator's ledger what the DUT was actually served under it
   - Observed: with the whole-bank sentinel armed at epoch 60, the DUT read 125 register(s) at 40256 and every one of them carried a not-implemented value. Transaction: seq 1212, epoch 60, poll 0, conn 26: unit 1, FC 0x03 at 40256×125 → answered
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
3. **PASS** — the DUT identified the sentinel-valued points as unimplemented rather than reporting the sentinel as a measurement
   - Method: the DUT's own readback values while the server served the sentinel, from its journal
   - Observed: while the server returned the sentinel for every register, the DUT journalled no readback value at all for device "inv-plain" in 1 line(s) — it did not report the sentinel as a measurement
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: journalctl -u lexa-modbus on the device under test
4. **WARN** — at least one point of EVERY SunSpec datatype was configured to its own not-implemented value and the DUT read it back
   - Method: seed one point per datatype inside the block the simulator observed the DUT reading every poll cycle, each with the Device Information Model's value for that type, then confirm from the simulator's ledger that the DUT's own read returned exactly those words
   - Observed: 6 of 22 datatype(s) were confirmed on the wire, and 16 came back with values other than the ones seeded: int16@40258 served [4], wanted [32768]; uint16@40259 served [1], wanted [65535]; count@40260 served [0], wanted [65535]; sunssf@40264 served [1536], wanted [32768]; pad@40265 served [1564], wanted [32768]; int32@40266 served [297 9818], wanted [32768 0]; uint32@40268 served [6 4164], wanted [65535 65535]; acc32@40270 served [2404 0], wanted [0 0]; enum32@40272 served [6002 0], wanted [65535 65535]; bitfield32@40274 served [0 0], wanted [65535 65535]; ipaddr@40276 served [3139 0], wanted [0 0]; float32@40278 served [0 0], wanted [32704 0]; eui48@40280 served [0 65535 65535], wanted [65535 65535 65535]; uint64@40287 served [65535 65535 65535 388], wanted [65535 65535 65535 65535]; float64@40295 served [512 521 99 9818], wanted [32760 0 0 0]; string@40299 served [2 4164 2404 0], wanted [0 0 0 0]. That is a disagreement between this suite's sentinel table and the simulator's — a bench defect, not a DUT finding. Confirmed: acc16@40261, enum16@40262, bitfield16@40263, int64@40283, acc64@40291, ipv6addr@40303
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
5. **SKIP** — the DUT logged each unimplemented point AS unimplemented rather than reporting its sentinel as a value
   - Method: inspection of the client's own per-point output
   - Observed: §2.7.2's criterion is about the CLIENT'S RENDERING, and this DUT has no per-point output to inspect: it journals reconciler decisions and a decoded measurement, not a point browser. The wire half — that the server really did serve each datatype's not-implemented value and that the DUT really did read it — is asserted above from the simulator's own record. Closing the rest needs a point-browser diagnostic on the DUT, and no sim work promotes it. Note also that the specification makes three of these types genuinely ambiguous: acc16, acc32, acc64, ipaddr and string all have ZERO as their not-implemented value, which is also an ordinary reading, so even a perfect client cannot distinguish them on the wire — that ambiguity is the Information Model's, not this bench's
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::PROT-1 Partial Response — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.8.1 PROT-1 – Partial Response (under 2.8 Modbus Protocol Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): all three readings of §2.8.1's undefined 'partial response' were driven as ONE-SHOTS armed against the next matching request, so each landed inside a transaction this bundle can name rather than in the gap between two of them — which is where a blanket fault spent every previous campaign. The DUT's recovery from each was held on the simulator's own transaction ledger, not on a clock. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 67 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"action":drop "kind":next_response "on_addr":[40256 40381] "on_fc":3} → epoch 68 (a response the server never sent — the server received the request, composed an answer, and delivered none of it while leaving the connection OPEN. This is the reading closest to §2.8.1's words: the client is left holding an incomplete transaction rather than a dead socket, so its own read timeout is what has to save it, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 69 (confirm no one-shot is left armed after the a response the server never sent reading, and fence the DUT's recovery from it); POST http://69.0.0.20:6020/fault {"action":short "kind":next_response "on_addr":[40256 40381] "on_fc":3 "truncate_bytes":2} → epoch 70 (a structurally truncated response — the MBAP header promises the full PDU and the socket write stops after the function code and byte count. A client that frames by length waits for bytes that are not coming; one that reads whatever is next splices the following response onto this value and decodes a number that was never sent, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 71 (confirm no one-shot is left armed after the a structurally truncated response reading, and fence the DUT's recovery from it); POST http://69.0.0.20:6020/fault {"action":delay "delay_ms":9000 "kind":next_response "on_addr":[40256 40381] "on_fc":3} → epoch 72 (a response too late to be an answer — the answer is complete and correct and arrives after the client's own per-request deadline. lexa-gw bounds every transaction at 5 s (cmd/modbus/transport_factory.go:52), so a 9 s hold is decided by the client's timeout rather than by this bench's patience, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 73 (confirm no one-shot is left armed after the a response too late to be an answer reading, and fence the DUT's recovery from it)

Frame attribution: 0 frame(s) (—), precision endpoint; 30 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **SKIP** — the DUT remained functional after a Modbus response failed to complete
   - Method: frame attribution (time AND flow)
   - Observed: no capture frame was attributed to this test case: the DUT sent no southbound Modbus traffic to 69.0.0.20:5020 during its observation window, or the capture did not see it. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 67 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/fault {"action":drop "kind":next_response "on_addr":[40256 40381] "on_fc":3} → epoch 68 (a response the server never sent — the server received the request, composed an answer, and delivered none of it while leaving the connection OPEN. This is the reading closest to §2.8.1's words: the client is left holding an incomplete transaction rather than a dead socket, so its own read timeout is what has to save it, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 69 (confirm no one-shot is left armed after the a response the server never sent reading, and fence the DUT's recovery from it); POST http://69.0.0.20:6020/fault {"action":short "kind":next_response "on_addr":[40256 40381] "on_fc":3 "truncate_bytes":2} → epoch 70 (a structurally truncated response — the MBAP header promises the full PDU and the socket write stops after the function code and byte count. A client that frames by length waits for bytes that are not coming; one that reads whatever is next splices the following response onto this value and decodes a number that was never sent, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 71 (confirm no one-shot is left armed after the a structurally truncated response reading, and fence the DUT's recovery from it); POST http://69.0.0.20:6020/fault {"action":delay "delay_ms":9000 "kind":next_response "on_addr":[40256 40381] "on_fc":3} → epoch 72 (a response too late to be an answer — the answer is complete and correct and arrives after the client's own per-request deadline. lexa-gw bounds every transaction at 5 s (cmd/modbus/transport_factory.go:52), so a 9 s hold is decided by the client's timeout rather than by this bench's patience, aimed at the DUT's own measurement read at 40256×125 — the block the sim observed it repeating every poll cycle); POST http://69.0.0.20:6020/fault {"clear":true "kind":next_response} → epoch 73 (confirm no one-shot is left armed after the a response too late to be an answer reading, and fence the DUT's recovery from it); POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 74
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **WARN** — the DUT received a response the server never sent and did not hang on it
   - Method: a one-shot armed against the NEXT matching request ({"action":drop "kind":next_response "on_addr":[40256 40381] "on_fc":3}), so the provocation lands inside a transaction the bench can name; graded from the simulator's own record of what it delivered for that transaction
   - Observed: the one-shot was armed at epoch 68 and the DUT issued 1 transaction(s) under it, but the simulator recorded none resolved as "dropped": 1 transaction(s) (1 answered). That is a disagreement between the one-shot's contract and its wire behaviour — a bench defect, not a DUT finding
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
3. **PASS** — the DUT remained functional after a response the server never sent and transacted normally again
   - Method: a transaction with the server AFTER the one-shot was spent, held on the simulator's transaction ledger rather than on a clock, so the DUT's own reconnect-with-backoff has as long as it needs
   - Observed: after a response the server never sent the DUT issued 1 transaction(s) that completed normally — first: seq 1233, epoch 69, poll 4, conn 26: unit 1, FC 0x03 at 40256×125 → answered. The client neither hung on the incomplete answer nor stopped polling
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
4. **WARN** — the DUT received a structurally truncated response and did not hang on it
   - Method: a one-shot armed against the NEXT matching request ({"action":short "kind":next_response "on_addr":[40256 40381] "on_fc":3 "truncate_bytes":2}), so the provocation lands inside a transaction the bench can name; graded from the simulator's own record of what it delivered for that transaction
   - Observed: the one-shot was armed at epoch 70 and the DUT issued 1 transaction(s) under it, but the simulator recorded none resolved as "truncated": 1 transaction(s) (1 answered). That is a disagreement between the one-shot's contract and its wire behaviour — a bench defect, not a DUT finding
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
5. **PASS** — the DUT remained functional after a structurally truncated response and transacted normally again
   - Method: a transaction with the server AFTER the one-shot was spent, held on the simulator's transaction ledger rather than on a clock, so the DUT's own reconnect-with-backoff has as long as it needs
   - Observed: after a structurally truncated response the DUT issued 1 transaction(s) that completed normally — first: seq 1237, epoch 71, poll 5, conn 26: unit 1, FC 0x03 at 40256×125 → answered. The client neither hung on the incomplete answer nor stopped polling
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
6. **WARN** — the DUT received a response too late to be an answer and did not hang on it
   - Method: a one-shot armed against the NEXT matching request ({"action":delay "delay_ms":9000 "kind":next_response "on_addr":[40256 40381] "on_fc":3}), so the provocation lands inside a transaction the bench can name; graded from the simulator's own record of what it delivered for that transaction
   - Observed: the one-shot was armed at epoch 72 and the DUT issued 1 transaction(s) under it, but the simulator recorded none resolved as "delayed": 1 transaction(s) (1 answered). That is a disagreement between the one-shot's contract and its wire behaviour — a bench defect, not a DUT finding
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
7. **PASS** — the DUT remained functional after a response too late to be an answer and transacted normally again
   - Method: a transaction with the server AFTER the one-shot was spent, held on the simulator's transaction ledger rather than on a clock, so the DUT's own reconnect-with-backoff has as long as it needs
   - Observed: after a response too late to be an answer the DUT issued 1 transaction(s) that completed normally — first: seq 1240, epoch 73, poll 6, conn 26: unit 1, FC 0x03 at 40256×125 → answered. The client neither hung on the incomplete answer nor stopped polling
   - _(no digest — narrative, not re-checkable)_
   - Note: not wire-cited; source: GET http://69.0.0.20:6020/ledger — the simulator's own append-only record of every Modbus transaction, written by its wire layer as the bytes crossed it, independently of anything the DUT logs
8. **SKIP** — the DUT logged the Common Model read values as expected after the server returned to normal
   - Method: §2.8.1 steps 6-7: read the Common Model again once the server is behaving, and check the decoded values
   - Observed: lexa-gw reads model 1's BODY exactly once, during admission, on a separate short-lived connection at boot (internal/southbound/admission/identify.go's identifyNow → sunspec.ReadCommon). Its steady-state poll and its post-reconnect rediscovery read the model chain's HEADERS and then only the measurement model — lexa-proto/sunspec/reader.go caches the block layout per session and never re-reads model 1's body. So no provocation available to this bench can make the DUT re-read the Common Model inside a test case's window: it would take a process restart, which a shared-bench conformance run must not perform. This is a DUT-side observability gap, not a missing sim verb, and it is the same gap CLI-1..CLI-4 report against the identical criterion
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

### ⚠ ss-modbus-client-conf-v1.1::WR-2 Write Multiple Points — WARN

Reference: SS-MODBUS-CLIENT-CONF-v1.1 v1.1 §2.6.2 WR-2 – Write Multiple Points (under 2.6 Write Tests)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): the DUT was provoked into writing rather than commanded to, and the register diverged was LEARNED from the DUT's own write in the simulator's transaction ledger rather than guessed — so the provocation reached the cell the product owns instead of a legacy mirror the sim re-derives each tick, which is why every previous campaign's divergence lever produced nothing. the DUT issued no write, and the northbound lever was NOT used (-param modbus-client.dercontrol=on). injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 75 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting)

Frame attribution: 0 frame(s) (—), precision endpoint; 45 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 69.0.0.20:5020 (the DUT is the Modbus CLIENT under test and 69.0.0.20:5020 is the bench's plain-text SunSpec Modbus server, so the bench never learns the DUT's ephemeral source port and cannot make a 4-tuple claim; the endpoint is a dedicated single-purpose listener and this conformance run is serialized, so no other client dials it during this test case's interval — a claim the citation phase re-derives from the capture rather than assumes).

1. **SKIP** — the DUT wrote an adjustable point using Modbus function code 0x10
   - Method: frame attribution (time AND flow)
   - Observed: no capture frame was attributed to this test case: the DUT sent no southbound Modbus traffic to 69.0.0.20:5020 during its observation window, or the capture did not see it. injected: POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 75 (cleared: relocation → base 40000, targeted exception, not-implemented sentinels, spliced model, poked registers, device faults (register, lying, legacy-curve, reversion timers), wire-tap faults (next_response, unit_id), poll-cycle accounting); POST http://69.0.0.20:6020/reset {"baseline":"as-built"} → epoch 76
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
2. **SKIP** — the DUT wrote an adjustable point using Modbus function code 0x10 (Write Multiple Registers), with a quantity and byte count that agree
   - Method: the function code, address, quantity, byte count and values of the DUT's own write request, taken from the simulator's transaction ledger and cited into the capture where this test case owns the frame
   - Observed: no write was observed, and the northbound lever was NOT used: the DUT emits a southbound write only when a northbound command gives its reconciler something to enforce, and posting one reaches outside this suite's surface, so it is opt-in. Re-run with -param modbus-client.dercontrol=on
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
3. **SKIP** — the server's write operation was validated: a control register the DUT had written was moved out from under it and the DUT re-asserted the value
   - Method: move the EXACT register the DUT was observed writing (learned from the simulator's ledger, not from any model definition directory), then wait on the ledger for a write covering that address
   - Observed: no write was observed to learn a register from, so nothing could be diverged. no write was observed, and the northbound lever was NOT used: the DUT emits a southbound write only when a northbound command gives its reconciler something to enforce, and posting one reaches outside this suite's surface, so it is opt-in. Re-run with -param modbus-client.dercontrol=on
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
4. **SKIP** — the value the DUT wrote was present in the server's register image when the DUT read the block back
   - Method: the DUT's own next read covering the written address, from the simulator's ledger, decoded against the values its write carried
   - Observed: no re-assert was observed, so there is no written value to read back
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
5. **SKIP** — every implemented adjustable point was written to its minimum, maximum and three intermediate values using FC 0x10
   - Method: a five-value sweep per adjustable point, driven from the server's PICS
   - Observed: the procedure assumes an operator console the test engineer can hand five values per point to. The DUT has no such interface: its southbound writes are emitted by reconcilers acting on a northbound command, so the VALUE written is a function of the command, not of anything this suite can dictate, and only the points its reconcilers drive are reachable at all. What IS now demonstrated is that the client can write a point with FC 0x10 and re-assert it against a diverging device — the mechanism the sweep would repeat. Promoting the row to full needs either a diagnostic write verb on the DUT's Modbus client, or a driver that sweeps five northbound setpoints per reconciled axis and correlates each with the resulting register write. The latter is buildable on this bench now — the ledger already correlates a northbound command with the exact register the DUT writes — but it is a campaign, not a single test case
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
6. **SKIP** — every supported value of each adjustable enumerated point was written using FC 0x10
   - Method: a per-enumerated-value sweep, driven from the server's PICS
   - Observed: same constraint as the five-value sweep: the DUT chooses the enumerated values it writes from the northbound command it is enforcing
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
7. **SKIP** — the write sweep was repeated with unit id 0, the broadcast address, using FC 0x10
   - Method: repeat §2.6 step 3 over an RTU server interface with unit id 0
   - Observed: §2.6 step 3 is explicitly conditional on the CUT supporting RTU SERVER interfaces, and unit id 0 is the RTU broadcast address — it has no meaning over Modbus/TCP, where every request is addressed to a unit on a specific connection. The DUT's southbound servers on this bench are all TCP, so the step is out of scope here and would remain so even with a full write sweep
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run
8. **SKIP** — the DUT logged every write operation, with the log data represented as hex strings
   - Method: inspection of the client's own log output
   - Observed: the same client-side-log criterion as READ-1/READ-2: the DUT journals reconciler decisions, not per-write hex. Where a write DID occur this bundle quotes the request ADU verbatim in hex — but that is the bench's rendering of the bytes, not the DUT's log. This is a DUT diagnostic gap, not a bench gap: no sim work promotes it
   - _(no digest — narrative, not re-checkable)_
   - Note: not asserted in this run

