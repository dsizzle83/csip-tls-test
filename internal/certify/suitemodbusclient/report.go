package suitemodbusclient

// report.go is this suite's own account of what it can and cannot demonstrate
// on the bench as it stands today.
//
// The framework already prints coverage — which catalog uids have an
// implementation — but coverage cannot distinguish a row that was fully driven
// from a row whose check ran, told the truth, and skipped every criterion. That
// distinction is the whole value of this suite's output, so it is stated here
// as data rather than left to be reconstructed from the bundle's assertion
// texts, and the gaps carry the specific capability that would close them.
//
// The table is hand-maintained and deliberately so: it is an engineering
// judgement about a bench, not something derivable from the code. GapsTest
// keeps it honest by requiring every row to name a uid the suite registers.

import (
	"fmt"
	"sort"
	"strings"
)

// Depth is how far a catalog row can be driven on this bench.
type Depth string

const (
	// DepthFull — every operative criterion of the row is exercised and cited.
	DepthFull Depth = "full"
	// DepthPartial — some criteria are exercised and cited; the rest carry a
	// SKIP naming what is missing.
	DepthPartial Depth = "partial"
	// DepthObservationOnly — no criterion can be exercised; the check cites
	// adjacent wire facts under SKIP so the bundle still shows what the DUT
	// does, and states why the criterion itself is out of reach.
	DepthObservationOnly Depth = "observation only"
	// DepthNotApplicable — the row does not apply to this DUT or this bench.
	DepthNotApplicable Depth = "not applicable"
)

// Row describes one catalog row's reach.
type Row struct {
	ID    string
	UID   string
	Depth Depth
	// Demonstrated is what the suite actually asserts, cited, for this row.
	Demonstrated string
	// Gap is what it cannot assert, and Capability is the specific thing that
	// would close the gap — a sim verb, a DUT diagnostic, a bench topology
	// change. Both are empty for a DepthFull row.
	Gap        string
	Capability string
}

// Rows is the suite's self-assessment, in catalog order.
var Rows = []Row{
	{ID: "CLI-1", UID: "ss-modbus-client-conf-v1.1::CLI-1", Depth: DepthPartial,
		Demonstrated: "discovery against a server at a named IPv4 address: identifier probe, full model-chain walk, complete Common Model read, MBAP framing",
		Gap:          "a SECOND server at a DIFFERENT IPv4 address — both of the DUT's southbound servers are on the capture host's single address",
		Capability:   "a second modsim instance on a second address plus a matching device entry in the DUT's /etc/lexa/modbus.json, prepared before the run"},
	{ID: "CLI-2", UID: "ss-modbus-client-conf-v1.1::CLI-2", Depth: DepthFull,
		Demonstrated: "two servers on two distinct non-502 ports, full discovery on the plain one, connection-level evidence on the secure one",
		Gap:          "the second server's model discovery is inside TLS and not decodable here",
		Capability:   "none needed for the criterion; the second server's payload would need the DUT's client-side key log"},
	{ID: "CLI-3", UID: "ss-modbus-client-conf-v1.1::CLI-3", Depth: DepthPartial,
		Demonstrated: "every request carries the configured unit id, in 1..247, echoed by every response",
		Gap:          "two servers with DIFFERENT unit ids — both configured devices declare unit id 1",
		Capability:   "a second modsim started with a different unit id plus a matching DUT device entry"},
	{ID: "CLI-4", UID: "ss-modbus-client-conf-v1.1::CLI-4", Depth: DepthPartial,
		Demonstrated: "the DUT probes only legal base addresses and reads the map from the one that answers, " +
			"at the default base 40000 and — modsim's relocate verb (sim/southbound/relocate.go) landed and " +
			"is now driven at runtime, no launch flag needed — after the map is re-homed to base 0 and to " +
			"base 50000 in turn, each with its own forced reconnect. A live-hardware run confirmed the " +
			"DUT genuinely rediscovers the map at each relocated base (runs/warnmeas-mc-ssm-20260802T134537); " +
			"each reconnect is now HELD until the DUT's own journal confirms a complete poll cycle " +
			"(awaitJournalEvidence), not a fixed cycle count, since the DUT polls on its own independent " +
			"~10s cadence",
		Gap: "the SAME live run also showed the Common Model's full-body read specifically (as opposed to " +
			"the header-only chain walk) can still miss a fixed-length window even when the base-relocation " +
			"itself succeeds — the hold above is this row's fix for that; full confidence still wants " +
			"another live run's bundle to confirm the body-coverage assertion PASSes at every base, not " +
			"just the base-probe one",
		Capability: "none further on the sim side; promoting to full needs a real-bench run whose bundle " +
			"shows all three bases' discovery AND full Common Model body coverage complete"},
	{ID: "CLI-5", UID: "ss-modbus-client-conf-v1.1::CLI-5", Depth: DepthNotApplicable,
		Demonstrated: "nothing; the row is the optional Modbus RTU baud-rate sweep",
		Gap:          "there is no RS-485 SunSpec server on the bench and no serial line to capture",
		Capability:   "an RS-485 SunSpec server on the DUT's /dev/lexa/rs485-1 and a line analyser — evidence that would not live in a pcap at all"},
	{ID: "READ-1", UID: "ss-modbus-client-conf-v1.1::READ-1", Depth: DepthObservationOnly,
		Demonstrated: "the DUT's actual read granularity, cited under SKIP",
		Gap:          "one FC 0x03 request per point — the DUT reads whole model blocks and exposes no way to request a single point",
		Capability:   "a diagnostic point-read mode on the DUT's Modbus client. This is a device capability gap, not a bench gap: no sim work promotes it"},
	{ID: "READ-2", UID: "ss-modbus-client-conf-v1.1::READ-2", Depth: DepthFull,
		Demonstrated: "the 125-register ceiling on every read, the Common Model body in one request, and a " +
			">125-register model read in maximal chunks — graded against the DUT's FIRST complete sweep " +
			"of a long model's body (firstSweep) since a window spanning more than one of the DUT's own " +
			"~10s poll cycles legitimately observes the same maximal-chunk pattern several times over " +
			"(a live-hardware finding, runs/warnmeas-mc-ssm-20260802T134537)",
		Gap:        "the client-side 'log every point as hex strings' criterion",
		Capability: "a diagnostic dump mode on the DUT; the bytes themselves are already in the bundle"},
	{ID: "WR-1", UID: "ss-modbus-client-conf-v1.1::WR-1", Depth: DepthObservationOnly,
		Demonstrated: "the framing of any FC 0x06 write the provocation elicits — function code, address, value, and the server's echo",
		Gap:          "the five-values-per-point sweep, the enumerated-value sweep, and the RTU broadcast step",
		Capability:   "a driver that sweeps northbound setpoints per reconciled axis and correlates each with the resulting register write (-param modbus-client.dercontrol=on is its first step); the broadcast step is RTU-only and out of scope for a TCP DUT"},
	{ID: "WR-2", UID: "ss-modbus-client-conf-v1.1::WR-2", Depth: DepthObservationOnly,
		Demonstrated: "the framing of any FC 0x10 write the provocation elicits — quantity, byte count, values, and the server's acknowledgement",
		Gap:          "as WR-1",
		Capability:   "as WR-1"},
	{ID: "INFO-1", UID: "ss-modbus-client-conf-v1.1::INFO-1", Depth: DepthPartial,
		Demonstrated: "model-block read coverage including the scale-factor registers, and that the value the DUT reports is the value its raw reads decode to under the scale-factor convention (with the server's animation frozen so both refer to one instant)",
		Gap:          "the per-datatype rendering criteria (a)–(i), which exist only in the client's own log",
		Capability:   "a point-browser diagnostic on the DUT, and a server whose models span every datatype in §2.3's list — nine of them do not occur in this server's models at all"},
	{ID: "INFO-2", UID: "ss-modbus-client-conf-v1.1::INFO-2", Depth: DepthPartial,
		Demonstrated: "the server serving the int16 not-implemented sentinel for every register and whether " +
			"the DUT reported it as a measurement; and — modsim's per-point sentinel verb " +
			"(sim/southbound/sentinel.go) landed — the Common Model's DA field separately seeded with its " +
			"own uint16 not-implemented sentinel and confirmed read back over the wire",
		Gap: "every OTHER datatype present in the server's models: this suite deliberately holds no model " +
			"definition directory (see sunspec.go's doc comment — ERR-3 would be testing the DUT's table " +
			"against itself if it had one), so only one datatype (uint16, via DA) is demonstrated this way",
		Capability: "a model definition directory this suite can safely consult for INJECTION addressing " +
			"without compromising ERR-3's independence, so every other present datatype can be seeded and " +
			"confirmed the same way the per-point verb now demonstrates for one"},
	{ID: "PROT-1", UID: "ss-modbus-client-conf-v1.1::PROT-1", Depth: DepthPartial,
		Demonstrated: "three readings of the document's undefined 'partial response' — a severed " +
			"transaction, an over-long response delay, and (modsim's protorelay verb, " +
			"sim/southbound/protorelay.go, landed) a structurally truncated response — each now HELD until " +
			"the DUT's own journal confirms a reaction (awaitJournalEvidence, not a fixed cycle count, " +
			"per a live-hardware finding — runs/warnmeas-mc-ssm-20260802T134537 — that a bare 2-cycle hold " +
			"routinely missed the DUT's ~10s poll), and the DUT's recovery held the same way afterward. " +
			"Attribution also now accepts conversations that overlap in time, not just sequential ones: " +
			"modsim's endpoint is dedicated and single-client regardless of how a reconnect's teardown/SYN " +
			"race falls",
		Gap: "the structurally truncated reading needs modsim STARTED with -protofault (it interposes a " +
			"second relay); without that launch flag the sim refuses the fault by name and this row falls " +
			"back to two readings",
		Capability: "modsim -protofault at launch; the fault verb itself needs no further sim work"},
	{ID: "PROT-2", UID: "ss-modbus-client-conf-v1.1::PROT-2", Depth: DepthPartial,
		Demonstrated: "that the DUT frames its peer's stream by MBAP length with no leftover bytes, and neither retries nor resets; a genuinely segmented ADU is asserted when the capture contains one",
		Gap:          "segmentation cannot be compelled — the sim writes each response once and every response is well under the path MTU",
		Capability:   "POST /fault {\"kind\":\"segment_response\",\"split_after\":N}, or a path MTU small enough to force it"},
	{ID: "ERR-1", UID: "ss-modbus-client-conf-v1.1::ERR-1", Depth: DepthObservationOnly,
		Demonstrated: "that the DUT probes only legal base addresses and never 40001, cited under SKIP",
		Gap:          "the noncompliant server itself — a SunSpec map at holding register 40001",
		Capability:   "the same settable map base CLI-4 needs, plus a DUT device entry pointing at that instance"},
	{ID: "ERR-2", UID: "ss-modbus-client-conf-v1.1::ERR-2", Depth: DepthPartial,
		Demonstrated: "the two exception classes §2.9.2 step 1 itself names — 0x04 SERVER DEVICE FAILURE " +
			"and 0x0B GATEWAY TARGET DEVICE FAILED TO RESPOND — each HELD until the DUT's own journal " +
			"confirms it reacted (awaitJournalEvidence, not a fixed cycle count) and observed on the wire, " +
			"with recovery held the same way through the DUT's reconnect-with-backoff. This is a rework " +
			"of an earlier version that armed FIVE classes on a fixed schedule: a live-hardware run " +
			"(runs/warnmeas-mc-ssm-20260802T134537) showed the DUT's own independent ~10s poll cadence — " +
			"it drops the session on a Modbus exception and reconnects 'on next poll' with backoff — meant " +
			"a fixed arm/clear pace routinely finished before the DUT ever polled, and the recovery " +
			"assertion FAILed outright when the window closed before the backoff completed. Reliability for " +
			"the two REQUIRED classes plus recovery now takes priority over breadth",
		Gap: "modsim's exception_target scoping (sim/southbound/exception_target.go) CAN target 0x01 " +
			"ILLEGAL FUNCTION, 0x02 ILLEGAL DATA ADDRESS and 0x03 ILLEGAL DATA VALUE at FC 0x03 — the " +
			"capability gap that used to block them is closed — but serializing three more held-and-" +
			"confirmed classes into the same test case as the two REQUIRED ones risks the exact timing " +
			"regression this rework fixes, for classes the procedure's own criteria do not require",
		Capability: "either a materially longer per-check budget than CheckTimeout=6m already grants this " +
			"row, or moving each additional class into its own dedicated test case so a slow DUT poll " +
			"cannot cascade delay across unrelated classes"},
	{ID: "ERR-3", UID: "ss-modbus-client-conf-v1.1::ERR-3", Depth: DepthPartial,
		Demonstrated: "the behaviour the criterion turns on — the DUT steps over a model it does not " +
			"consume using the length header and continues the chain walk — now demonstrated against a " +
			"GENUINELY unregistered ID (modsim's insert_model verb, sim/southbound/modelsplice.go, splices " +
			"one into the chain), plus the DUT's own admission journal read for the MUST that it not appear " +
			"in the client's discovered-model list",
		Gap: "lexa-modbus admits a device — and journals its model inventory — once, at first " +
			"identification; a tcp_drop reconnect resumes polling from the already-known block list without " +
			"re-scanning or re-journaling, so the journal-based assertion SKIPs unless a fresh admission " +
			"event happens to be journaled during this test case's window",
		Capability: "a DUT re-identify diagnostic this suite can trigger without a full device restart, " +
			"or the splice being in place before the device's very first admission"},
}

// Counts summarises the self-assessment.
func Counts() map[Depth]int {
	out := map[Depth]int{}
	for _, r := range Rows {
		out[r.Depth]++
	}
	return out
}

// GapMarkdown renders the self-assessment as a markdown section for the
// bundle's report.
func GapMarkdown() string {
	var sb strings.Builder
	sb.WriteString("## SS-MODBUS-CLIENT-CONF-v1.1 — reach of this bench\n\n")
	c := Counts()
	depths := []Depth{DepthFull, DepthPartial, DepthObservationOnly, DepthNotApplicable}
	var tally []string
	for _, d := range depths {
		tally = append(tally, fmt.Sprintf("%d %s", c[d], d))
	}
	fmt.Fprintf(&sb, "%d row(s): %s.\n\n", len(Rows), strings.Join(tally, ", "))
	sb.WriteString("| Row | Reach | Demonstrated (cited) | Not demonstrated | Capability that would close it |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	rows := append([]Row(nil), Rows...)
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, r := range rows {
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n",
			r.ID, r.Depth, cell(r.Demonstrated), cell(r.Gap), cell(r.Capability))
	}
	return sb.String()
}

// cell escapes a markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
