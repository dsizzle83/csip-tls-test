# Conformance evidence bundle

**Device under test:** lexa-gw at `192.168.0.69:802`

| | |
|---|---|
| Tool | csip-certify eb2c71acf25f |
| Source commit | f69a8ce598df7d655c12fc317b6e0e442f934759 |
| Operator | lead reseed probe |
| Host | dmitri-HP-ENVY-TE01-1xxx |
| Started | 2026-09-10T20:50:40Z |
| Finished | 2026-09-10T20:54:53Z |
| DUT build | 8915cee |
| Capture | `capture/run-20260910-205042.pcapng` — 19558 packets, 13606016 bytes, pcapng |
| Capture tool | dumpcap Dumpcap (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). |
| Interface | wlp2s0 |
| Capture hygiene | 19558 frame(s) captured; no filter was requested, so every frame the tool wrote is in this bundle |
| Key log | capture/bench-shared.keylog |

> **This bundle contains TLS session secrets.** `capture/bench-shared.keylog` is an NSS key log for the
> capture above: anyone holding this directory can decrypt every session it
> records. It is included on purpose — the application-layer citations below
> cannot be re-derived without it — and it is covered by the manifest, so it
> cannot be quietly dropped either. Treat the bundle as sensitive: share it
> with an assessor, not publicly. The secrets are per-session and grant no
> lasting access to the device.

> catalog: /home/dmitri/projects/csip-tls-test/testdata/catalog/catalog.json (290 cases, 1626330 bytes, sha256:eb2c71acf25fe8b26876d5fd0783cfdd1fb74a3efb21885ebaafa4b67a285588); frame attribution: 19558 frames: 937 attributed to 1 test case(s), 18621 unattributed (background), 0 contested; provenance: DUT build reported fw=1.0.0 build_id=8915cee2fd56 image_build_id=8915cee2fd56 image_profile=image; EXPLORATORY, NOT GATING: no -campaign was declared: this is an EXPLORATORY selection, and its result is evidence about the implementation rather than a campaign anything may rest on

Capture tool output:

```
Capturing on 'wlp2s0'
File: runs/p6-ext006probe-8915cee-20260910T205040Z/capture/run-20260910-205042.pcapng
Packets captured: 19558
Packets received/dropped on interface 'wlp2s0': 19558/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

## How this run was invoked

```
certify-keylog -uid local-ext-v1::EXT-006 -manifest /home/dmitri/projects/lexa-gw/configs/candidate.json -target 192.168.0.69:802 -pki certs/mbaps -gridsim 192.168.0.188:11113 -gridsim-admin http://192.168.0.188:11114 -modsim 69.0.0.20:5020 -modsim-api http://69.0.0.20:6020 -mbapsdev-api http://69.0.0.20:6031 -gateway-ssh cc93 -metrics-endpoint http://127.0.0.1:9102/metrics -keylog /tmp/bench-shared.keylog -operator 'lead reseed probe' -dut-name lexa-gw -dut-build 8915cee -iface wlp2s0 -timeout 10m -out runs/p6-ext006probe-8915cee-20260910T205040Z -v
```

Credential-shaped flag values are replaced with `[redacted]`; every other argument is verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of this table.

The capture itself:

```
/usr/bin/dumpcap -i wlp2s0 -w runs/p6-ext006probe-8915cee-20260910T205040Z/capture/run-20260910-205042.pcapng -q -p
```

## Result

**1 PASS · 0 FAIL · 0 SKIP · 0 WARN** across 1 in-scope test case(s).

- **Applicable to the claim:** 0 PASS · 0 FAIL · 0 SKIP · 0 WARN (0 in-scope case(s))
- **Informative** — implemented but not bearing on the claim, marked `info` (not applicable to the claimed profile) or `local-ext` (covered by no published procedure) in the table below: 1 PASS · 0 FAIL · 0 SKIP · 0 WARN (1 in-scope case(s))

✓ No failures.

| Case | Title | Claim | Verdict | Assertions | Frames |
|------|-------|-------|---------|-----------:|--------|
| local-ext-v1::EXT-006 | EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default | local-ext | PASS | 4 | 2627 |

## Verifying this bundle

This directory is self-checking. Independent checks, in the order a sceptical reader
would run them:

1. `sha256sum -c MANIFEST.sha256` — every file, the capture included, is covered.
2. The evidence verifier re-reads `capture/run-20260910-205042.pcapng` and confirms that every cited frame
   exists and carries the exact bytes each assertion claims. It reads only this
   directory and needs nothing from the bench that produced it.
3. Every case verdict in the table above is re-derived from that case's own printed
   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is
   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be
   edited away from, the evidence underneath it.

Assertions marked *(no digest)* below carry no re-checkable citation: they are
narrative, not proof.

## Test cases

### ✓ local-ext-v1::EXT-006 EXT-006 - CSIP-owned value axis: mbaps refused (01) while owned; acked and applied after release; release restores the device default — PASS

**LOCAL EXTENSION — certifiable under no standard.** No published procedure covers this case: its Test Values are the harness's own and its verdict is supplementary PRODUCT EVIDENCE, not a conformance result. It is run, bundled and re-verified like any other row, and it is excluded from every applicable-FAIL tally and from the clean-run criterion. A FAIL here is a finding about the implementation; it is not a certification failure.

Reference: LOCAL-EXT-v1 v1 (local extension family; not a published specification) §1.6 EXT-006 - a CSIP-owned value axis refuses mbaps (01) and releases to the device default (under 1 Local product-evidence extensions)

Live-phase observation (what the check's own socket saw; the numbered assertions below are re-derived from the capture and are the verdict): published a CSIP opModFixedPFInjectW control (CERT-EXT006-VALUE-AXIS-b99e2753, PF 0.9 injecting) and waited 3m0s for it to be Started, attempted an mbaps GridServiceSunSpec PFWInj_PF write (PF 0.85) while it was in effect, then cancelled it and attempted the same write again — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Fixed PF row); poll-cycle window: 2m30s, derived from the bench 2030.5 server's advertised pollRate of 1m0s (poll_rate_s from http://192.168.0.188:11114/admin/status), which is the rate a client in poll_rate_mode "honor" — the product default — paces its walk at, the configured interval being only a floor beneath it — it is the slower of that and the DUT's own IEEE 2030.5 discovery interval floor of 1m0s (discovery_interval_s in /etc/lexa/northbound.json), and the slower governs: 2 periods plus 30s of slack, so a period that had just elapsed still leaves a whole one inside the window; VERDICT RECONCILED — the live phase declared SKIP from what the socket saw; the citation phase re-derived the criteria from the capture and the case is PASS. The capture-derived verdict is the one that stands: it is the only one a reader of this bundle can repeat.

Frame attribution: 937 frame(s) (924–19473), precision endpoint; 18536 frame(s) inside the window belonged to other conversations and were excluded.

Connections claimed: tcp *:* <> 192.168.0.188:11113 (the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized); tcp 192.168.0.188:52682 <> 192.168.0.69:802 (REV0907-D2-IMPL P5 envelope session: grid-service).

1. **PASS** — the DUT POSTed a DERControlResponse with status=2 (Event started) for the control under test
   - Method: decrypted HTTP/2030.5 transcript from the capture (NSS key log) — the sep+xml body of a POST in the session whose root element is a Response family member, matched on <subject> and <status>
   - Observed: POST /rsps/0/r carrying Response subject=CERT-EXT006-VALUE-AXIS-b99e2753 status=2, answered 201 Created. These bytes are from 192.168.0.69:40868 <> 192.168.0.188:11113, a SECOND conversation this test case wholly owns: the DUT opened it alongside the discovery walk recovered as this window's session (192.168.0.69:40856 <> 192.168.0.188:11113), and a frame of it is a frame this case may cite
   - Frames: 2627
   - Stream: `192.168.0.69:40868 > 192.168.0.188:11113` bytes [2751,3142)
   - Bytes sha256: `658fd1368f4f85b5ca2a2af2c4767475a967f8df7bde9d58a9c56e1ae95efc37`
   - Note: frames attributed by remote endpoint and time, not by connection 4-tuple: the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame to or from the CSIP server endpoint during this check's interval. That is sound on this bench because the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be sound if a second conformance run were driving the same simulator concurrently, which is why live runs in this campaign are serialized
2. **PASS** — while the CSIP opModFixedPFInjectW control (CERT-EXT006-VALUE-AXIS-b99e2753) is in effect, an mbaps GridServiceSunSpec write to 704 PFWInj_PF draws Modbus exception 01 (illegal function) and the DER's own PF register does not move — docs/design/AUTHORITY_ENVELOPE_2026-09-08.md §2 (Fixed PF: "refused (01) while CSIP-owned")
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

