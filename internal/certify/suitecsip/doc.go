// Package suitecsip implements the SunSpec CSIP Conformance Test Procedures
// V1.3 (catalog document CSIP-CONF-v1.3) against the LEXA gateway's IEEE
// 2030.5 client.
//
// # What is being certified, and what is not
//
// The gateway is a 2030.5 CLIENT in the DER-client profile: it dials the
// utility server, walks /dcap, registers itself, polls DERPrograms, executes
// DERControls, PUTs its DER state and POSTs Responses. It is NOT a 2030.5
// server, NOT an aggregator client, and it does not subscribe. The V1.3 §4
// profile matrix is already resolved per row in the catalog, and this suite
// honours it exactly: the twelve AGG-* rows, the four 2030.5-server rows
// (CORE-001/002/004, UTIL-001), the two subscription rows (CORE-018/019) plus
// ERR-002, the five MAINT-* rows, COMM-001 (xmDNS discovery, optional for all
// device types) and the three remaining UTIL-* rows are registered and report
// NOT APPLICABLE quoting the catalog's own reason. They are registered rather
// than omitted because an unregistered uid reads as an oversight, while a
// registered SKIP carrying the extraction's reason reads as an engineering
// judgment a reviewer can audit.
//
// # Why gridsim is the driver
//
// The DUT dials OUT. Nothing in this suite can make the gateway do anything by
// connecting to it — the gateway's only externally reachable port is :802
// (mbaps), which belongs to a different suite entirely. What this suite CAN do
// is change what the DUT finds when it next walks: post a DERControl, warp the
// 2030.5 clock, arm a redirect, delete the program list. So every check here
// has the same shape:
//
//  1. claim the gridsim endpoint for the window (the DUT's local port is not
//     knowable, so this is necessarily an endpoint claim with a reason);
//  2. drive gridsim's admin API to create the condition the procedure needs;
//  3. WAIT for the DUT's own poll cycle to reach the condition, observing the
//     server side to know when it has;
//  4. in the citation phase, recover the session from the capture and assert
//     the wire facts the pass criteria rest on.
//
// Step 3 is why this suite is slow and why its timeouts are generous. It is
// also why every check that waits reports how long it waited: a reader of the
// bundle needs to be able to tell "the DUT did the right thing" from "the DUT
// had not polled yet when we gave up".
//
// # The three evidence tiers, and the honesty rule that ranks them
//
// A CSIP test case's pass criteria live at three different depths, and this
// suite is explicit about which depth it reached:
//
//	TIER 1 — HANDSHAKE. TLS version, offered and negotiated cipher suites,
//	the certificate chains both directions, CertificateRequest, alerts. All of
//	this is CLEARTEXT on the wire and needs no secrets, so COMM-002/003/004*
//	produce fully re-checkable frame and byte citations from any capture of the
//	session. This tier is always available.
//
//	TIER 2 — DECRYPTED TRANSCRIPT. The HTTP methods, paths, status codes and
//	sep+xml payloads. Recoverable only when the run exports the bench server's
//	TLS secrets to an NSS key log (-keylog) AND the log contains this session's
//	client random. gridsim is the SERVER, so those are the bench's own secrets
//	to export — but see the note below. When the transcript is available every
//	payload criterion is cited to the TLS record that carried it and the
//	frames that record occupied.
//
//	TIER 3 — SERVER-SIDE OBSERVATION. gridsim's admin API (/admin/responses,
//	/admin/derputs, /admin/logevents, /admin/status) and its request log
//	(/admin/logs). These are real observations of the DUT's behaviour, made by
//	the peer it was talking to — but they are NOT the wire, so they become
//	Narrative assertions naming gridsim as the source, never citations. A test
//	case whose verdict rests only on tier 3 therefore reaches WARN, not PASS,
//	under the runner's uncited-PASS rule. That downgrade is correct and it is
//	deliberate: "the server says the device did the right thing" is weaker
//	evidence than "here are the bytes", and the bundle should say so.
//
// Checks are written to produce the best tier available and to state, in the
// assertion itself, which tier that was. A criterion that reached no tier is a
// SKIP carrying the reason — never a PASS.
//
// # Where a SKIP is not honest: the release-enforcing criteria
//
// That rule holds for criteria about the WIRE, where "the capture could not
// show me this" is a fact about the run. It does NOT hold for the criteria that
// carry a row's whole subject, and the difference is verdict arithmetic: Skip is
// severity 0 in the roll-up (bundle.Verdict.Severity) while every roll-up in the
// runner raises only, so a Skip cannot dent a case verdict and cannot hold a
// release. A row whose only "did the DUT actually do it" criterion skips reports
// the SAME verdict as a row that tested everything and passed — absence of
// measurement reading as success.
//
// Three families of criterion are therefore written with NO Skip path at all,
// and every shape their live phase can leave behind — including an unreachable
// bench — comes back as a decided verdict:
//
//   - the SCALAR southbound oracle (IW13-001/IW14-003 —
//     critDEREffectViaSouthboundOracle, BASIC-010/013): the DER's own register
//     holds the value this row commanded;
//   - the CURVE southbound oracle and the REFUSED-axis oracle (IW15-008 —
//     curve.go, BASIC-006/011/012/015 and BASIC-014): the DER's own curve model
//     adopted and enabled this row's breakpoints, or — for an axis the product
//     refuses — the DUT answered cannot-comply and nothing of that axis moved.
//     A row whose Figure prescribes more than breakpoints (curve plan #32:
//     BASIC-006's openLoopTms, BASIC-012's inline opModFreqDroop) measures
//     every part of it the DER's generation stores in a register — BOTH halves
//     must hold — and NAMES, on every verdict, the authored content that
//     generation stores nowhere, so a PASS is never read as covering something
//     nothing looked at;
//   - the RIDE-THROUGH southbound oracle (curve plan #32 — ridethrough.go,
//     BASIC-004/005): one DERControl carrying the several ride-through curves
//     its Figure prescribes, and per curve, the SUB-CURVE of the DER's own
//     1547 trip bank that curve names — MustTrip, MayTrip or MomCess — read for
//     the breakpoints the row published, adopted and enabled. The worst answer
//     decides and every answer is carried, because a DUT that adopted the
//     must-trip curves and ignored the momentary-cessation ones has executed
//     half of one control. It carries a second, separate claim: no protective
//     trip boundary that was up before the row published is down after it.
//   - the AUTHORING-GAP criteria (IW15-008 — critModeUnauthorable, BASIC-007):
//     this bench has no lever for the mode, so the row was not tested, and an
//     untested row must not roll up as a passing one. BASIC-004 and BASIC-005
//     were here until curve plan #32 built the ride-through lever, the 707-710
//     decode and the sim's NPt; they are measured rows now.
//
// The last of those is a BENCH gap rather than a DUT defect, and its Observed
// text says so in its first sentence; it is still a FAIL, because the
// consequence — a conformance bundle claiming a row was exercised when it was
// not — is the same either way.
//
// # The key-log prerequisite (read this before running the suite live)
//
// As of this writing the bench's CSIP server (sim/server over sim/tlsserver
// and internal/wolfssl) does NOT wire up NSS key-log export; only
// internal/mbtls does. Until it does, every tier-2 assertion in this suite
// SKIPs with that exact reason and the payload-level rows settle at WARN on
// tier 3. Nothing here fabricates a tier it did not reach, and nothing here
// needs changing when the export is added: the transcript recovery already
// runs, finds no secret for the session's client random, and says so.
//
// # Timing is measured from capture timestamps
//
// Poll intervals, retry backoff and response deadlines are measured from the
// pcap's frame timestamps — the same clock a reviewer would read in Wireshark —
// never from wall clock inside the harness, which measures the harness's own
// scheduling as much as the DUT's. Where a deadline cannot be measured from the
// capture (no frames attributed), the criterion SKIPs rather than falling back
// to the harness clock.
//
// A related trap this suite is built to avoid: the gateway backs off to a
// 15-minute retry interval after sustained northbound failure. A check that
// injects a fault and then expects a prompt reconnect is measuring backoff
// state, not conformance. Checks that inject a fault therefore (a) bound the
// fault's duration so the DUT sees at most one or two failed walks, (b) clear
// the fault before waiting for recovery, and (c) report the observed recovery
// latency rather than asserting a bound on it, unless the procedure states one.
//
// # Referee independence
//
// Nothing here imports lexa-platform or anything from the product tree. The
// 2030.5 XML is inspected by this package's own namespace-aware reader
// (sepxml.go) rather than by unmarshalling into the shared model, so a shared
// struct definition cannot hide a shared bug; the SFDI/LFDI/PIN arithmetic is
// implemented here from IEEE 2030.5 §6.3 (identity.go) and unit-tested against
// the standard's own worked example. The only shared code in the whole suite is
// the TLS and TCP dissection in internal/evidence, which is the bench's.
package suitecsip
