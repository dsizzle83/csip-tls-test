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
//
// It was rewritten for LAB29-011, and the shape of the rewrite is worth
// stating: almost every "Gap" that used to read "the sim cannot do X" now
// reads either "done" or "the DUT cannot be asked to do X from a read-only
// run". The bench stopped being the limiting factor. What remains is three
// kinds of thing, and they are not interchangeable:
//
//	a DUT OBSERVABILITY gap   the client does something the bench cannot see
//	                          (it reads model 1's body only at boot; it maps
//	                          Modbus exception codes to opaque transport
//	                          errors and journals no per-code event)
//	a DUT CONTROL gap         the client cannot be reconfigured from inside a
//	                          conformance run, because it reads its config once
//	                          at start and this harness's gateway client is
//	                          read-only by construction
//	a PROCEDURE gap           the row asks for something an autonomous gateway
//	                          has no analogue of (a five-value operator sweep,
//	                          an RTU broadcast)
var Rows = []Row{
	{ID: "CLI-1", UID: "ss-modbus-client-conf-v1.1::CLI-1", Depth: DepthPartial,
		Demonstrated: "discovery against a server at a named IPv4 address — identifier probe, model-chain " +
			"walk, MBAP framing — driven by a forced rediscovery at a named control-plane epoch and held " +
			"on the simulator's own transaction ledger rather than on a poll interval, so the window " +
			"contains the traffic the row cites by construction",
		Gap: "the SECOND server at a DIFFERENT IPv4 address. The bench half is ready (modsim -bind " +
			"presents the device at any address); the DUT half is not — it reads its southbound endpoint " +
			"from /etc/lexa/modbus.json once at process start, has no SIGHUP handler, no config watch " +
			"and no dev API, so changing it means an operator config write plus `systemctl restart " +
			"lexa-modbus`, and this harness's gateway client is read-only by construction. Also " +
			"unreachable: the Common Model's BODY, which the DUT reads only during boot admission",
		Capability: "an operator procedure, not a bench capability: prepare the second address's modsim " +
			"and the matching device entry before the run and record the two discoveries as two runs of " +
			"this row correlated in the bundle's DUT metadata. (The config-write API additionally " +
			"refuses once /etc/lexa/commissioned exists.)"},
	{ID: "CLI-2", UID: "ss-modbus-client-conf-v1.1::CLI-2", Depth: DepthFull,
		Demonstrated: "two servers on two distinct non-502 ports, full discovery on the plain one held " +
			"on the simulator's ledger, connection-level evidence on the secure one",
		Gap:        "the second server's model discovery is inside TLS and not decodable here",
		Capability: "none needed for the criterion; the second server's payload would need the DUT's client-side key log"},
	{ID: "CLI-3", UID: "ss-modbus-client-conf-v1.1::CLI-3", Depth: DepthPartial,
		Demonstrated: "every request carries one unit id in 1..247, echoed by every response — asserted " +
			"both from the capture and from the simulator's own ledger, which cannot miss a request that " +
			"fell outside the window. AND the served device is now RE-ADDRESSED at runtime (modsim's " +
			"unit_id gate): with the device answering unit 247, the DUT's requests to its configured id " +
			"come back 0x0B GATEWAY TARGET DEVICE FAILED TO RESPOND and the device never sees them, " +
			"which shows the DUT genuinely uses the unit-id field; the DUT then recovers when the gate " +
			"clears. Both are cited under SKIP as observations, because neither is the row's criterion",
		Gap: "the criterion itself — the CUT DISCOVERING a server whose unit id differs — needs the DUT " +
			"told the new id. devices[].unit_id is read once at process start and applied with a single " +
			"SetUnitID at connect; there is no runtime path to change it, and this run must not restart " +
			"the service",
		Capability: "an operator procedure: prepare the second unit id in the DUT's config before the " +
			"run and record the two discoveries as two correlated runs. The SIM capability this row used " +
			"to need is closed"},
	{ID: "CLI-4", UID: "ss-modbus-client-conf-v1.1::CLI-4", Depth: DepthPartial,
		Demonstrated: "discovery at all three canonical starting registers — 0, 40000 and 50000 — each " +
			"leg relocating the map, severing the connection at a named epoch, and grading THAT LEG'S " +
			"OWN ledger page. The previous version had to match a reconnect back to a base by hunting " +
			"for a probe at that address among several attributed conversations, which breaks the moment " +
			"one leg fails; fencing on the epoch cannot",
		Gap: "the 'contents of all the Common Model points' criterion. The DUT reads model 1's BODY " +
			"exactly once, during boot admission on a separate short-lived connection; its steady-state " +
			"poll and its post-reconnect rediscovery walk the chain's headers and then read only the " +
			"measurement model",
		Capability: "a DUT re-identify diagnostic a read-only client can trigger, or a capture that " +
			"begins before the DUT's own boot. This is a DUT observability gap, not a sim verb"},
	{ID: "CLI-5", UID: "ss-modbus-client-conf-v1.1::CLI-5", Depth: DepthNotApplicable,
		Demonstrated: "nothing; the row is the optional Modbus RTU baud-rate sweep",
		Gap:          "there is no RS-485 SunSpec server on the bench and no serial line to capture",
		Capability:   "an RS-485 SunSpec server on the DUT's /dev/lexa/rs485-1 and a line analyser — evidence that would not live in a pcap at all"},
	{ID: "READ-1", UID: "ss-modbus-client-conf-v1.1::READ-1", Depth: DepthObservationOnly,
		Demonstrated: "the DUT's actual read granularity, cited under SKIP, observed over one COMPLETE " +
			"poll cycle held on the simulator's poll barrier — so the pattern graded is a whole cycle's " +
			"rather than whatever a fixed sleep happened to catch",
		Gap:        "one FC 0x03 request per point — the DUT reads whole model blocks and exposes no way to request a single point",
		Capability: "a diagnostic point-read mode on the DUT's Modbus client. This is a device capability gap, not a bench gap: no sim work promotes it"},
	{ID: "READ-2", UID: "ss-modbus-client-conf-v1.1::READ-2", Depth: DepthFull,
		Demonstrated: "the 125-register ceiling on every read, the Common Model body in one request " +
			"where the window contains one, and a >125-register model read in maximal chunks — graded " +
			"over a forced rediscovery followed by one COMPLETE poll cycle, both held on the simulator. " +
			"The bundle records what a cycle IS (the barrier's own rule) beside the number",
		Gap:        "the client-side 'log every point as hex strings' criterion",
		Capability: "a diagnostic dump mode on the DUT; the bytes themselves are already in the bundle"},
	{ID: "WR-1", UID: "ss-modbus-client-conf-v1.1::WR-1", Depth: DepthNotApplicable,
		Demonstrated: "the judgement itself, with the procedure text quoted and the counter-argument " +
			"stated: §2.6.1's subject is 'all implemented adjustable points … using Modbus Function Code " +
			"0x06', and this client has no FC 0x06 write path at all — every register write it can emit " +
			"leaves as FC 0x10, hardcoded in the Modbus client it is built on, even for a single " +
			"register. The row's subject is the empty set",
		Gap: "§2.6.1 carries no explicit 'if the CUT supports FC 0x06' clause where its own step 3 does " +
			"carry one for RTU, so a lab could read it as unconditional and call this a product gap. The " +
			"counter-argument recorded in the assertion: §2.6.2 states FC 0x10 is a complete per-point " +
			"alternative, so WR-2 covers every adjustable point this client can write",
		Capability: "a PICS question for the certifying lab. NOT a bench capability, and deliberately " +
			"not closed by adding an FC 0x06 write path to the product to green a row"},
	{ID: "WR-2", UID: "ss-modbus-client-conf-v1.1::WR-2", Depth: DepthPartial,
		Demonstrated: "an FC 0x10 write by the DUT with quantity and byte count agreeing, the server's " +
			"acknowledgement, AND — the part every previous campaign missed — a divergence-and-reassert " +
			"round trip plus a read-back. The register diverged is LEARNED from the DUT's own write in " +
			"the simulator's ledger rather than guessed, which is why it now reaches the cell the " +
			"product owns (model 704) instead of the legacy model 123 mirror the sim re-derives on its " +
			"next animation tick — the reason both write rows SKIPped for want of a write in every " +
			"campaign to date",
		Gap: "the five-value and per-enumerated-value sweeps. The DUT has no operator console: the VALUE " +
			"it writes is a function of the northbound command it is enforcing. A write only happens at " +
			"all when -param modbus-client.dercontrol=on gives its reconciler a standing setpoint",
		Capability: "a driver that sweeps five northbound setpoints per reconciled axis and correlates " +
			"each with the resulting register write. That is now BUILDABLE on this bench — the ledger " +
			"already correlates a northbound command with the exact register the DUT writes — but it is " +
			"a campaign, not a single test case. The alternative is a diagnostic write verb on the DUT"},
	{ID: "INFO-1", UID: "ss-modbus-client-conf-v1.1::INFO-1", Depth: DepthPartial,
		Demonstrated: "model-block read coverage including the scale-factor registers, and that the " +
			"value the DUT reports is the value its raw reads decode to under the scale-factor " +
			"convention (with the server's animation frozen so both refer to one instant) — over a " +
			"forced rediscovery and one COMPLETE poll cycle, both held on the simulator",
		Gap: "the per-datatype rendering criteria (a)-(i), which exist only in the client's own log",
		Capability: "a point-browser diagnostic on the DUT. The 'a server whose models span every " +
			"datatype' half of this gap is CLOSED — see INFO-2"},
	{ID: "INFO-2", UID: "ss-modbus-client-conf-v1.1::INFO-2", Depth: DepthPartial,
		Demonstrated: "the whole-bank int16 sentinel, AND — the row's real criterion on the server side " +
			"— one point of EVERY SunSpec datatype seeded with its own not-implemented value and read " +
			"back by the DUT over the wire. Twenty-two datatypes, up from one. They are seeded INSIDE " +
			"the block the simulator observed the DUT reading every cycle, so the DUT is certain to read " +
			"them, and the address comes from the client's own traffic rather than from a model " +
			"definition directory this suite deliberately does not hold",
		Gap: "the client's RENDERING of an unimplemented point, which is not a wire fact. Also inherent: " +
			"acc16/acc32/acc64, ipaddr and string all have ZERO as their not-implemented value, which is " +
			"also an ordinary reading — that ambiguity is the Information Model's, not this bench's",
		Capability: "a point-availability signal or point browser on the DUT. The sim-side gap this row " +
			"carried — 'a model definition directory so every other datatype can be seeded' — is closed, " +
			"and closed WITHOUT one: the anchor the simulator learns from the DUT's own polling is the " +
			"block to seed"},
	{ID: "PROT-1", UID: "ss-modbus-client-conf-v1.1::PROT-1", Depth: DepthPartial,
		Demonstrated: "all three readings of §2.8.1's undefined 'partial response' — a response never " +
			"sent, a structurally truncated one, and one too late to be an answer — each armed as a " +
			"ONE-SHOT against the NEXT MATCHING REQUEST, so it lands inside a transaction this bundle " +
			"can name. That is the fix for this row's standing failure: the provocation used to be a " +
			"blanket that kept landing between requests. Each reading's recovery is held on the " +
			"simulator's ledger, so the DUT's reconnect-with-backoff has as long as it needs",
		Gap: "§2.8.1 steps 6-7's 'the CUT logs the Common Model read values as expected' — the DUT " +
			"re-reads model 1's body only at boot admission",
		Capability: "the same DUT re-identify diagnostic CLI-1..CLI-4 name. No sim work remains for this " +
			"row: -protofault is no longer needed for it either, because the truncated reading is now a " +
			"tap one-shot rather than a second relay's blanket"},
	{ID: "PROT-2", UID: "ss-modbus-client-conf-v1.1::PROT-2", Depth: DepthPartial,
		Demonstrated: "that the DUT frames its peer's stream by MBAP length with no leftover bytes, and " +
			"neither retries nor resets, over a rediscovery burst held on the simulator's ledger; and — " +
			"when modsim is started with -protofault — every response deliberately split across two " +
			"socket writes, with the DUT's transactions under it completing normally",
		Gap: "the deliberate segmentation needs modsim STARTED with -protofault (it interposes a second " +
			"relay). Without that flag the sim refuses the fault by name and this row falls back to " +
			"asserting framing over whatever the path happened to deliver",
		Capability: "add -protofault to the bench's modsim invocation. The fault verb itself needs no " +
			"further sim work"},
	{ID: "ERR-1", UID: "ss-modbus-client-conf-v1.1::ERR-1", Depth: DepthFull,
		Demonstrated: "the row, for the first time. The server's SunSpec map is re-homed to holding " +
			"register 40001 — §2.9.1's deliberately noncompliant off-by-one base — the DUT's connection " +
			"is severed so it re-probes, and the simulator's ledger shows it probing ONLY the legal " +
			"bases, finding no identifier at any of them, and never hunting at the noncompliant offset. " +
			"The map is then restored and the DUT's recovery is held on the ledger. The client-side " +
			"'accurately log the noncompliant server' criterion is read from the DUT's journal as a " +
			"Narrative, which is the most any client-log criterion can be",
		Gap:        "",
		Capability: ""},
	{ID: "ERR-2", UID: "ss-modbus-client-conf-v1.1::ERR-2", Depth: DepthPartial,
		Demonstrated: "ALL FIVE exception classes — 0x01, 0x02, 0x03, 0x04 and 0x0B — each armed at a " +
			"named epoch and held until the simulator's own ledger showed the DUT had met it, then " +
			"cleared; plus a recovery held the same way. The previous version drove two classes on a " +
			"time budget and reported the other three as a budget SKIP. The barrier used here is the " +
			"LEDGER's, not the poll barrier's, and that is load-bearing: the DUT drops its southbound " +
			"session on a Modbus exception and reconnects on the next poll, so under a persistent " +
			"exception it completes no poll cycle at all — a row waiting for one would time out while " +
			"its provocation landed perfectly on every session",
		Gap: "'the Client SHALL accurately log all exception codes'. The DUT maps Modbus exception codes " +
			"to opaque transport errors (the vendored client returns a string, and nothing in the " +
			"product branches on the code) and journals no per-code event, so its log can say a device " +
			"failed but not which exception it received. The assertion reports that distinction rather " +
			"than accepting an error line as though it named a code",
		Capability: "a DUT-side per-exception-code journal event. This is a product observability gap, " +
			"not a bench gap — the wire half is fully driven"},
	{ID: "ERR-3", UID: "ss-modbus-client-conf-v1.1::ERR-3", Depth: DepthPartial,
		Demonstrated: "the behaviour the criterion turns on — the DUT steps over a model it does not " +
			"consume using the length header and continues the chain walk — against a GENUINELY " +
			"unregistered ID spliced into the chain, with the rediscovery held on the simulator's ledger",
		Gap: "lexa-modbus admits a device — and journals its model inventory — once, at first " +
			"identification; a reconnect resumes polling from the already-known block list without " +
			"re-scanning or re-journaling, so the MUST that the unknown ID not appear in the discovered- " +
			"model list SKIPs unless a fresh admission event happens to be journaled during the window",
		Capability: "a DUT re-identify diagnostic this suite can trigger without a full service restart, " +
			"or the splice being in place before the device's very first admission. The same DUT-side " +
			"gap CLI-1..CLI-4 name for the Common Model body"},
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
