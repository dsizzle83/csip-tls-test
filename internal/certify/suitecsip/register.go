package suitecsip

// register.go binds every CSIP-CONF-v1.3 catalog uid to a check.
//
// EVERY uid — all seventy-nine — including the twenty-eight the catalog marks
// inapplicable, and they are inapplicable for two DIFFERENT reasons that must
// not be run together.
//
// SIX are bound to the notApplicable stub: they are blank in every §4 column
// and there is nothing to drive. Registering them anyway is a deliberate
// choice — a coverage report that simply lacked those rows would read as
// "nobody got to them", while a registered row reporting NOT APPLICABLE and
// quoting the catalog's own applicability_reason reads as a decision a reviewer
// can audit against the profile matrix, and disagree with, which is the point
// of writing it down.
//
// TWENTY-TWO are bound to REAL checks and run every campaign. They are the rows
// §4 requires of a DER Aggregator Client and not of a DER Client, and the owner
// decision of 2026-07-28 certifies this DUT as a DER Client in the GFEMS
// posture — so they are outside the CLAIM while staying inside the RUN. Their
// verdicts, including the negative ones, are informative evidence about a
// capability the product does not claim; no verdict of theirs gates
// conformance. See docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md.
//
// The Order values group the run so a live campaign produces a sensible
// sequence: transport first (if the TLS profile is wrong, nothing after it
// means anything), then the discovery core, then the control rows, then the
// scenario rows, then the aggregator-profile rows, then the fault-injecting row
// last, because it is the only one that deliberately makes the server misbehave
// and the only one whose failure mode could perturb what follows.

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitepki"
	"lexa-proto/sunspec"
)

// The curve rows' mode→model mapping provenance (IW15-008). Each says WHERE the
// correspondence comes from, because a southbound FAIL that names a register
// bank is only checkable if a reader can verify the bank was the right one.
//
// They are stated in terms of the STANDARDS' own carriage, not of any one
// gateway's source, so a different DUT graded by this suite is graded against
// the same mapping. Where this product's own reconciler agrees, it is cited as
// corroboration rather than as the authority.
const (
	mappingVoltVar = "IEEE 2030.5's opModVoltVar is the Q(V) function, whose SunSpec/IEEE-1547 carriage is " +
		"model 705 (DER Volt-Var) — the same correspondence this product's southbound reconciler uses " +
		"(lexa-gw cmd/modbus/reconcile_adv.go maps its volt-var axis onto sunspec.ModelDERVoltVar)"

	mappingVoltWatt = "IEEE 2030.5's opModVoltWatt is the P(V) function, whose SunSpec/IEEE-1547 carriage is " +
		"model 706 (DER Volt-Watt) — the same correspondence this product's southbound reconciler uses " +
		"(lexa-gw cmd/modbus/reconcile_adv.go maps its volt-watt axis onto sunspec.ModelDERVoltWatt)"

	// ── The LEGACY (12x) half of the same four mappings ─────────────────────
	//
	// A curve axis has a register home on BOTH SunSpec generations and they are
	// different models with different geometry, different commit semantics and
	// — for two of the four — a different DeptRef numbering. Naming them
	// separately is what lets one catalog row measure whichever DER is actually
	// on the bench and SAY which it measured, instead of carrying a single
	// model that is right on one bench and quietly wrong on the other.
	//
	// Every claim below is about the STANDARDS' own carriage, like the 7xx half:
	// the model numbers come from the vendored SunSpec model JSON
	// (lexa-proto docs/schema/sunspec-models, pinned 7abdf89) and the axis
	// semantics from each model's own point descriptions.

	mappingVoltVarLegacy = "IEEE 2030.5's opModVoltVar is the Q(V) function, whose LEGACY SunSpec carriage " +
		"is model 126 (Static Volt-VAR arrays): V<n> in %VRef against a signed VAr<n> in per cent of " +
		"whatever the bank's DeptRef names. It is the same function 705 carries on the 7xx generation and " +
		"a different register map — flat 54-register banks with the points inlined as parallel arrays, " +
		"selected by ActCrv rather than promoted by an adopt handshake, and a DeptRef enum that is " +
		"1-BASED where 705's is 0-based (126 declares {1 %WMax, 2 %VArMax, 3 %VArAval}). This referee " +
		"translates yRefType into that enum independently of the product, which is the whole point of " +
		"checking it"

	mappingVoltWattLegacy = "IEEE 2030.5's opModVoltWatt is the P(V) function, whose LEGACY SunSpec " +
		"carriage is model 132 (Volt-Watt): V<n> in %VRef against W<n> as a per cent of the bank's " +
		"DeptRef, which 132 declares as {1 %WMax, 2 %WAvail} — again 1-based. (The vendored JSON labels " +
		"132's W<n> units \"% VRef\", a known SunSpec erratum: the point is watts as a percentage of " +
		"DeptRef, per the model's own DeptRef description, and this referee decodes by DeptRef and not " +
		"by the units string)"

	mappingFreqWattLegacy = "IEEE 2030.5's opModFreqWatt is a BREAKPOINT curve (frequency -> watts), and " +
		"the LEGACY SunSpec set — unlike the 7xx one — HAS a model that stores exactly that: model 134 " +
		"(Curve-Based Frequency-Watt, \"Ref 3: 8.9.1.2, 8.9.4.2\"), whose banks hold Hz<n> as ABSOLUTE " +
		"frequency against W<n> as active power. This is the row's whole D2 acceptance criterion: on a 7xx " +
		"DER the axis has no home and this row is a decided FAIL saying why, and on a legacy DER it is a " +
		"measurement. One caution rides with it, and it is the IW15-002a pathology one model over: 134's " +
		"W<n> are % WRef, where WRef is a REGISTER in the same block (default WMax), while CSIP's " +
		"opModFreqWatt y is %setMaxW. The two are equal only when WRef == setMaxW, so this referee renders " +
		"the device's own WRef and its SnptW snapshot-mode flag on every reading rather than assuming them"

	mappingWattPFLegacy = "IEEE 2030.5's opModWattPF is a power-factor curve against active power, and its " +
		"ONE exact register home anywhere in SunSpec is legacy model 131 (Watt-PF): W<n> in %WMax against " +
		"PF<n> as a power factor in EEI cos() notation. 131 carries NO DeptRef — the spec fixes its x axis " +
		"at %WMax and a power factor is not a percentage OF anything — so this row asserts the points and " +
		"the selection state and deliberately asserts no y-axis reference register, which is a different " +
		"thing from asserting a reference and finding it absent"

	// BASIC-015 used to grade opModWattPF as an EXECUTION row against model 712,
	// on a mapping that said "there being no Watt-PF model in the 7xx set". That
	// mapping was the DEFECT, written down: 712 is DER Watt-VAr, a different
	// function whose y axis is a signed percentage of a VAR reference, and
	// opModWattPF's y axis is a signed power-factor displacement under the EEI
	// convention. Grading a PF curve against a var register bank certified a
	// substitution — and the product performed the same substitution, which is
	// why the row passed.
	//
	// The product ended it (lexa-gw curve P1, 2026-08-14): watt_var is now its
	// own axis and is the only thing written to 712, and opModWattPF is REFUSED
	// at receipt on a 7xx DER. So this is now the row's refusal reason.
	refusalWattPF = "opModWattPF's only exact register home is LEGACY SunSpec model 131 (Watt-PF). The 7xx " +
		"set has no watt-PF model at all: model 712 is DER Watt-Var, whose y axis means a signed " +
		"percentage of a var reference (its DeptRef names %VArMax or %VArAval) rather than a signed " +
		"power-factor displacement under the EEI convention, so writing a PF curve into it commands a " +
		"different function. sep 2.0.4 says the same thing from the other side: opModWattVar and " +
		"opModWattPF are separate DERControlBase elements with separate DERCurveType codes (10 and 2). " +
		"On a 7xx DER, therefore, the honest answer is cannot-comply at receipt — which is what this row " +
		"measures THERE, instead of grading a PF curve against a var bank and calling the substitution a " +
		"PASS. On a LEGACY 12x DER the same row is an EXECUTION row against model 131, because that DER " +
		"does have the axis; see mappingWattPFLegacy. The two halves are different KINDS of assertion, not " +
		"one assertion against two banks, and which applies is decided by the device the bench is running"

	// BASIC-012 is the row with no southbound home at all, and saying so is
	// the whole of its southbound evidence.
	noFreqWattRegister = "IEEE 2030.5's opModFreqWatt is a BREAKPOINT curve (frequency → watts), and the " +
		"SunSpec/IEEE-1547 7xx set has no model that stores frequency-watt breakpoints: frequency response " +
		"is expressed as model 711 (DER Frequency Droop), a PARAMETRIC control — deadbands DbOf/DbUf, gains " +
		"KOf/KUf, a response time — with no point table a published curve could be written into. This " +
		"product's own reconciler records the same conclusion for the same reason (lexa-gw " +
		"cmd/modbus/reconcile_adv.go, on releasing its freq-watt axis: \"No SunSpec model executes " +
		"freq-watt ... nothing to disable on release either\"), and its advAxisModel table has no model for " +
		"the axis at all. So this row can author its control northbound — that half is real evidence — and " +
		"NOTHING southbound can hold the curve's content. Closing it needs either a device profile that " +
		"stores frequency-watt breakpoints or a decision to re-scope the row; it cannot be closed by " +
		"asserting something weaker against 711, which is a different function. It IS closed on the other " +
		"generation: the LEGACY set carries model 134, which stores frequency-watt breakpoints, so this " +
		"row is a decided FAIL on a 7xx DER and a real measurement on a legacy one — see " +
		"mappingFreqWattLegacy"
)

// Suite is this suite's short name, used for -suite selection and printed in
// the report.
const Suite = "csip"

// uid builds a catalog uid for this document.
func uid(id string) string { return "csip-conf-v1.3::" + id }

// needs are the capability tags a row's check requires. Everything in this
// suite needs the bench and a capture; the rows that create their precondition
// through the simulator also need gridsim.
var (
	needCapture = []string{"bench", "capture"}
	needGridSim = []string{"bench", "capture", "gridsim"}
)

func init() { Register(certify.Default()) }

// Register binds this suite's checks into a registry. It is exported so a test
// can bind into a private registry rather than the process-wide one.
//
// Each Register call mints ONE run nonce (runNonce) and threads it through the
// event-precedence scenarios, so the BASIC-017..026 control mRIDs are unique
// per campaign — the test-isolation fix. A campaign is one process, so a nonce
// minted here at construction is stable for the whole run and different across
// runs; see registerEventScenarios and eventScenario.withNonce.
func Register(reg *certify.Registry) {
	nonce := runNonce()
	// ── Transport and security (order 0–19) ──────────────────────────────
	reg.Register(uid("COMM-002"), Suite, commBasicDiscovery,
		certify.WithRequires(needCapture...), certify.WithOrder(1))
	reg.Register(uid("COMM-003"), Suite, commBasicSecurity,
		certify.WithRequires(needCapture...), certify.WithOrder(2))
	reg.Register(uid("COMM-004"), Suite, commAdvancedSecurity,
		certify.WithRequires(needCapture...), certify.WithOrder(3))
	reg.Register(uid("COMM-004A"), Suite, commChainDepth(2, "SERCA -> device certificate"),
		certify.WithRequires(needCapture...), certify.WithOrder(4))
	reg.Register(uid("COMM-004B"), Suite, commChainDepth(3, "SERCA -> MICA -> device certificate"),
		certify.WithRequires(needCapture...), certify.WithOrder(5))
	reg.Register(uid("COMM-004C"), Suite, commChainDepth(4, "SERCA -> MCA -> MICA -> device certificate"),
		certify.WithRequires(needCapture...), certify.WithOrder(6))
	// D/E/F/G present a non-conformant chain through gridsim's runtime chain
	// lever and restore the bench afterwards; see commChainRejection and
	// chainswap.go. The second argument selects which fixture suitepki mints,
	// and the two must agree — a row whose PROSE says extendedKeyUsage while
	// its fixture carries a policy mapping would report a verdict about the
	// wrong defect. TestRejectionRowsPresentTheDefectTheyName pins the pairing.
	reg.Register(uid("COMM-004D"), Suite,
		commChainRejection("a MICA whose extendedKeyUsage extension is marked critical with an invalid value",
			suitepki.MICAEKUCritical),
		certify.WithRequires(needCapture...), certify.WithOrder(7))
	reg.Register(uid("COMM-004E"), Suite,
		commChainRejection("a MICA whose name extension is non-critical with an invalid value",
			suitepki.MICANameNonCritical),
		certify.WithRequires(needCapture...), certify.WithOrder(8))
	reg.Register(uid("COMM-004F"), Suite,
		commChainRejection("a MICA whose policy-mapping extension is non-critical with an invalid value",
			suitepki.MICAPolicyMapping),
		certify.WithRequires(needCapture...), certify.WithOrder(9))
	reg.Register(uid("COMM-004G"), Suite,
		commChainRejection("a self-signed device certificate with no chain to a trusted SERCA",
			suitepki.SelfSignedLeaf),
		certify.WithRequires(needCapture...), certify.WithOrder(10))

	// ── Discovery core (order 20–39) ─────────────────────────────────────
	reg.Register(uid("CORE-003"), Suite, corePolling,
		certify.WithRequires(needCapture...), certify.WithOrder(20))
	reg.Register(uid("CORE-005"), Suite, coreBasicTime,
		certify.WithRequires(needCapture...), certify.WithOrder(21))
	reg.Register(uid("BASIC-001"), Suite, basicIdentification,
		certify.WithRequires(needCapture...), certify.WithOrder(22))
	reg.Register(uid("CORE-009"), Suite, coreAdvancedEndDevice,
		certify.WithRequires(needCapture...), certify.WithOrder(23))
	reg.Register(uid("CORE-010"), Suite, coreFSA,
		certify.WithRequires(needCapture...), certify.WithOrder(24))
	reg.Register(uid("CORE-011"), Suite, coreAdvancedFSA,
		certify.WithRequires(needCapture...), certify.WithOrder(25))
	// Both group-management rows specify the CSIP Figure-3 topology fixture:
	// seven FunctionSetAssignments over seven topology DERPrograms and three
	// pre-registered EndDevices. gridsim builds one FSA and three programs, so
	// the scale criteria report what was actually served and SKIP — see
	// critFSAList / critProgramList.
	reg.Register(uid("BASIC-002"), Suite, basicGroupManagement(7, 7, 3),
		certify.WithRequires(needCapture...), certify.WithOrder(26))
	reg.Register(uid("BASIC-003"), Suite, basicGroupManagement(7, 7, 3),
		certify.WithRequires(needCapture...), certify.WithOrder(27))
	reg.Register(uid("CORE-014"), Suite, coreDERSettings,
		certify.WithRequires(needCapture...), certify.WithOrder(28))
	reg.Register(uid("BASIC-028"), Suite, basicInverterStatus,
		certify.WithRequires(needCapture...), certify.WithOrder(29))
	reg.Register(uid("BASIC-027"), Suite, basicAlarms,
		certify.WithRequires(needCapture...), certify.WithOrder(30))
	reg.Register(uid("BASIC-029"), Suite, basicMeterReading,
		certify.WithRequires(needCapture...), certify.WithOrder(31))

	// ── DER programs and controls (order 40–79) ──────────────────────────
	reg.Register(uid("CORE-012"), Suite, coreDERProgram,
		certify.WithRequires(needGridSim...), certify.WithOrder(40))
	reg.Register(uid("CORE-013"), Suite, coreAdvancedDERProgram,
		certify.WithRequires(needGridSim...), certify.WithOrder(41))
	registerInverterControls(reg)

	// ── Event precedence scenarios (order 80–99) ─────────────────────────
	registerEventScenarios(reg, nonce)

	// ── Response lifecycle (order 100–109) ───────────────────────────────
	reg.Register(uid("CORE-021"), Suite, coreRandomizedEvents,
		certify.WithRequires(needGridSim...), certify.WithOrder(100))
	// coreResponses/coreSuperseding take the SAME per-run nonce as the event
	// scenarios above, for the same reason (see withRunNonce's doc): CORE-022
	// and CORE-023 hardcode their control mRIDs just as BASIC-017..026 used
	// to, and hit the identical Response-tracker dedupe on a long-lived bench.
	reg.Register(uid("CORE-022"), Suite, coreResponses(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(101))
	reg.Register(uid("CORE-023"), Suite, coreSuperseding(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(102))

	// ── Aggregator profile (order 200–299) ───────────────────────────────
	// The SAME per-run nonce again: UTIL-004 and every AGG-0xx scenario
	// hardcode their control mRIDs exactly as BASIC-017..026 and CORE-022/023
	// used to, and their lifecycle criteria grade the Responses those mRIDs
	// earn. See registerAggregator's own doc for what re-publishing an
	// already-acknowledged mRID did to those criteria.
	registerAggregator(reg, nonce)

	// ── Error handling, last: it is the only row that deliberately makes
	//    the shared server misbehave. ──────────────────────────────────────
	reg.Register(uid("ERR-001"), Suite, errRedirect,
		certify.WithRequires(needGridSim...), certify.WithOrder(300))

	registerInapplicable(reg)
}

// registerAggregator binds the twenty-two rows the DER AGGREGATOR CLIENT
// profile requires and the DER Client profile does not (see aggregator.go).
//
// The DUT is certified against the DER CLIENT column (owner decision
// 2026-07-28, docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md), so none of
// these twenty-two is required of it and the catalog marks all twenty-two
// inapplicable. They stay bound to their real checks anyway. The criteria are
// evaluators, not placeholders, and the bench builds the fixtures they were
// written against; a check that runs is worth more than a check that was
// deleted, and a reader who wants to know how this gateway behaves under a
// four-EndDevice fan-out has nowhere else to look.
//
// They run AFTER every direct-client row and BEFORE ERR-001, for two reasons.
// The commissioning and subscription rows read the same resting tree the core
// rows read, so putting them later costs nothing; the AGG event rows publish
// DERControls on two programs at once and two of them (AGG-009, AGG-012) sleep
// inside their own setup waiting for an event to start, so a campaign that has
// to be cut short loses these rather than the profile's foundations.
//
// ── Why these rows take the run nonce too (F3/F4, 2026-08-14) ────────────────
//
// Every mRID below was a STATIC string, re-published verbatim by every campaign
// against the same long-lived gridsim — and gridsim's Response log is
// append-only and cross-campaign. Two things followed, and both were observed
// on hardware (csip-conf-v1.3::AGG-011 in runs/compliance-a78887f-20260813b).
//
// The DUT's own Response tracker dedupes on the bare mRID, so the second and
// every later run earned no fresh status 1 (Event Received) at all — the same
// suppression eventScenario.withNonce was minted for. And critEventLifecycle,
// which grades that status 1, then had to decide whether a missing Received was
// the DUT's behaviour or the harness's fixture; on a re-published mRID it can
// never be sure, so its FAIL was unreachable for exactly the DUT that had
// REGRESSED to never acknowledging events.
//
// A fresh mRID per run removes the question at the root rather than answering
// it: the event does not exist until this check publishes it, inside its own
// window, so an absent status 1 is a fact about the DUT again. The lifecycle
// criterion still checks its window's placement — that is what makes the FAIL
// honest — but on these rows the check now passes rather than excuses.
// TestAggregatorRowsPublishNoncedMRIDs (the scenario table, via aggRows) and
// TestUtilDERRetrievalSpecPublishesItsOwnNoncedMRID (the one row outside it)
// together pin that no mRID this function registers reaches a campaign
// un-nonced.
func registerAggregator(reg *certify.Registry, nonce string) {
	// Utility/aggregator commissioning: the resting-tree rows first, because
	// they arm nothing and a failure in them explains every row after.
	reg.Register(uid("UTIL-002"), Suite, utilCommissioning,
		certify.WithRequires(needCapture...), certify.WithOrder(200))
	reg.Register(uid("UTIL-003"), Suite, utilGroupRetrieval,
		certify.WithRequires(needCapture...), certify.WithOrder(201))
	reg.Register(uid("AGG-001"), Suite, aggSubscription,
		certify.WithRequires(needCapture...), certify.WithOrder(202))

	// Subscription and notification rows: nothing to arm, everything to read.
	reg.Register(uid("CORE-018"), Suite, coreBasicSubscription,
		certify.WithRequires(needCapture...), certify.WithOrder(210))
	reg.Register(uid("CORE-019"), Suite, coreAdvancedSubscription,
		certify.WithRequires(needCapture...), certify.WithOrder(211))
	reg.Register(uid("ERR-002"), Suite, errNotification,
		certify.WithRequires(needCapture...), certify.WithOrder(212))

	// Model maintenance. MAINT-004 is the only one with a lever, so it needs
	// gridsim; the other three read the tree and report what is missing.
	reg.Register(uid("MAINT-001"), Suite, maintOOBInverter,
		certify.WithRequires(needCapture...), certify.WithOrder(220))
	reg.Register(uid("MAINT-003"), Suite, maintGroup,
		certify.WithRequires(needCapture...), certify.WithOrder(221))
	reg.Register(uid("MAINT-004"), Suite, maintControls,
		certify.WithRequires(needGridSim...), certify.WithOrder(222))
	reg.Register(uid("MAINT-005"), Suite, maintPrograms,
		certify.WithRequires(needCapture...), certify.WithOrder(223))

	// UTIL-004 publishes a control, so it sits with the event rows.
	reg.Register(uid("UTIL-004"), Suite, utilDERRetrieval(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(230))

	for _, r := range aggRows(nonce) {
		req := needGridSim
		if len(r.sc.Controls) == 0 {
			req = needCapture
		}
		reg.Register(uid(r.id), Suite, aggEvent(r.sc),
			certify.WithRequires(req...), certify.WithOrder(r.order))
	}
}

// aggRow is one AGG-002..AGG-012 row: its catalog id, run order within the
// suite, and the scenario the check drives.
type aggRow struct {
	id    string
	order int
	sc    aggScenario
}

// aggRows returns the eleven aggregator event rows in document order with the
// per-run nonce applied to every scenario.
//
// It exists for the same reason eventScenarioRows does: the nonce is applied
// HERE, in one place every registered row goes through, so a row cannot be
// added later that quietly publishes a static mRID — and a test can assert
// that directly (TestAggregatorRowsPublishNoncedMRIDs) instead of trying to
// recover an mRID from a registered closure it cannot see inside.
//
// AGG-002 publishes nothing (it is the two-DefaultDERControl row), so the
// caller gives it the no-gridsim requirement set.
func aggRows(nonce string) []aggRow {
	scenarios := aggScenarios()
	ids := []string{
		"AGG-002", "AGG-003", "AGG-004", "AGG-005", "AGG-006",
		"AGG-007", "AGG-008", "AGG-009", "AGG-010", "AGG-011", "AGG-012",
	}
	rows := make([]aggRow, 0, len(ids))
	for i, id := range ids {
		sc, ok := scenarios[id]
		if !ok {
			panic("suitecsip: no aggregator scenario for " + id)
		}
		rows = append(rows, aggRow{id: id, order: 240 + i, sc: sc.withNonce(nonce)})
	}
	return rows
}

// inverterControlRow is one BASIC-004..015 control-mode row: its catalog id, run
// order within the suite, the mode it drives and the subject its criteria are
// phrased about.
type inverterControlRow struct {
	id      string
	order   int
	mode    controlMode
	subject string
}

// registerInverterControls binds BASIC-004..015, the twelve control-mode rows.
func registerInverterControls(reg *certify.Registry) {
	for _, r := range inverterControlRows() {
		reg.Register(uid(r.id), Suite, basicInverterControl(r.mode, r.subject),
			certify.WithRequires(requiresFor(r.mode)...), certify.WithOrder(r.order))
	}
}

// inverterControlRows is the twelve rows' one definition, factored out of the
// registration so a test can drive the SHIPPING row — its real mode, its real
// published curve, its real oracle — rather than a copy of its literals that
// can silently drift from it (IW15-008).
func inverterControlRows() []inverterControlRow {
	const noRideThrough = "IEEE 2030.5's ride-through modes (opModLVRTMustTrip / opModLVRTMayTrip / " +
		"opModLVRTMomentaryCessation and their HVRT / LFRT / HFRT counterparts) are curve-valued DERControl " +
		"modes that the bench's 2030.5 server cannot publish: gridsim's admin control API " +
		"(sim/gridsim/admin.go adminCtrlReq) exposes only the scalar modes, and its curve API " +
		"(sim/gridsim/curve.go) binds only Volt-VAr, Volt-Watt, Freq-Watt and Watt-PF. With no way to put " +
		"the mode on the wire there is nothing to observe, so nothing about this row has been tested. " +
		"Closing this needs a ride-through curve mode in gridsim"

	const noRampRate = "IEEE 2030.5 places the ramp rates setGradW and setSoftGradW ONLY in " +
		"DefaultDERControl — CSIP §5.2.4 is explicit that they cannot be scheduled — and gridsim's " +
		"POST /admin/default carries the same DERControlBase field set as its control API, which has no " +
		"gradient fields. The mode therefore cannot be placed on the wire from this bench"

	return []inverterControlRow{
		// IW15-008: an unreachable mode is a row that was NOT TESTED, and it now
		// says so in a decided FAIL (critModeUnauthorable) instead of the SKIP
		// that let it roll up as a passing row. Nothing about the bench changed
		// here; what changed is that the gap is visible in the verdict rather
		// than only in the prose nobody reads on a green row.
		{"BASIC-004", 50, unreachableMode("opModLVRTMustTrip", noRideThrough),
			"the low/high voltage ride-through settings"},
		{"BASIC-005", 51, unreachableMode("opModLFRTMustTrip", noRideThrough),
			"the low/high frequency ride-through settings"},
		// The curve rows carry the IW15-008 southbound curve oracle: the
		// breakpoints they publish must be found ADOPTED and ENABLED in the
		// DER's own curve model, point for point and in order. The mode→model
		// mapping is stated on each row because a FAIL that names a register
		// bank has to be checkable by whoever reads the bundle.
		{"BASIC-006", 52, curveMode("opModVoltVar", &curveBinding{
			Mode:   "volt_var",
			Points: []CurvePoint{{X: 92, Y: 60}, {X: 98, Y: 0}, {X: 102, Y: 0}, {X: 108, Y: -60}},
			// yRefType 3 = %statVarAvail, which translates to DeptRef 2 on 705
			// (0-based) and DeptRef 3 on 126 (1-based). The two codes differ and
			// the row states neither: the referee derives each from the standards
			// text for the model it resolved to (curveBinding.wantDeptRef).
			YRefType:      derUnitRefStatVarAvail,
			Model7xx:      sunspec.ModelDERVoltVar,
			Mapping7xx:    mappingVoltVar,
			ModelLegacy:   sunspec.ModelVoltVarLegacy,
			MappingLegacy: mappingVoltVarLegacy,
		}), "a Volt-VAr curve"},
		{"BASIC-007", 53, unreachableMode("setGradW", noRampRate), "the ramp-rate settings"},
		{"BASIC-008", 54, scalarMode("opModFixedPFInjectW", func(r *ControlRequest) {
			r.FixedPFInjectW = ptr(int64(95))
		}), "a fixed power factor while injecting"},
		{"BASIC-009", 55, scalarMode("opModConnect", func(r *ControlRequest) {
			r.Connect = ptr(false)
			r.Energize = ptr(false)
		}), "a connect/disconnect command"},
		// The commanded value is written ONCE, in scalarModeOracled, and the
		// oracle builder is handed to withOracle unapplied (IW14-003): the
		// published control and the oracle that judges it read the same number,
		// and the row can depart from it at run time when the DER already holds
		// it (see oracleBinding).
		{"BASIC-010", 56, withOracle(scalarModeOracled("opModMaxLimW", 6000,
			func(r *ControlRequest, hundredths int64) {
				r.MaxLimW = ptr(hundredths)
			}), oracleMaxLimW), "a maximum active power limit"},
		// yRefType 1 (%setMaxW), NOT the 3 (%statVarAvail) this row published
		// until 2026-08-14. Three independent anchors say 1 and nothing says 3:
		// sep 2.0.4's own opModVoltWatt documentation ("The y value specifies an
		// active power output in %setMaxW"), the catalog's own prescribed value
		// for this row (Figure 11 Volt-Watt Settings — DERCurve.yRefType:
		// Default 1; Test Values 1), and the physics — a volt-WATT curve's y
		// axis is active power, and %statVarAvail is a REACTIVE reference.
		//
		// It became load-bearing rather than merely wrong when the product
		// started translating yRefType into the curve bank's DeptRef and
		// REFUSING what it cannot translate (lexa-gw cmd/modbus's curveDeptRef):
		// %setMaxW is the only y reference sep 2.0.4 gives volt-watt, so 706
		// accepts only DeptRef=W_MAX_PCT and a curve naming %statVarAvail is now
		// answered cannot-comply. This row would have FAILED a correct DUT for a
		// defect in its own fixture.
		{"BASIC-011", 57, curveMode("opModVoltWatt", &curveBinding{
			Mode:          "volt_watt",
			Points:        []CurvePoint{{X: 106, Y: 100}, {X: 110, Y: 20}},
			YRefType:      derUnitRefSetMaxW,
			Model7xx:      sunspec.ModelDERVoltWatt,
			Mapping7xx:    mappingVoltWatt,
			ModelLegacy:   sunspec.ModelVoltWattLegacy,
			MappingLegacy: mappingVoltWattLegacy,
		}), "a Volt-Watt curve"},
		// yRefType 1 (%setMaxW) for the same reasons as BASIC-011: sep 2.0.4's
		// opModFreqWatt documentation ("The y value specifies a corresponding
		// active power output in %setMaxW") and the catalog's own prescribed
		// value (Figure 12 Frequency-Watt Settings — DERCurve.yRefType: Test
		// Values 1). Freq-watt's y axis is active power; the 3 this row carried
		// was a reactive reference on an active-power curve.
		//
		// It changes no verdict here — the row's southbound half is a decided
		// FAIL either way (noFreqWattRegister), and the axis is refused at
		// receipt besides — but the NORTHBOUND half of this row is real evidence
		// about what the DUT was offered, and evidence has to be conformant to
		// be evidence.
		//
		// THE X MULTIPLIER IS NOW -2, AND IT WAS A FIXTURE DEFECT BEFORE.
		// sep 2.0.4 gives opModFreqWatt's x as "a frequency in Hz", and this row
		// published xvalue=6000 with xMultiplier absent (0) — a DERCurve
		// declaring breakpoints at 6000 Hz and 6050 Hz. It changed no verdict
		// while the row's southbound half was a decided FAIL on every bench, but
		// the NORTHBOUND half is real evidence about what the DUT was offered,
		// and it stops being harmless the moment a legacy DER can actually
		// execute the curve: an oracle reading M134's Hz points would then be
		// comparing 60.00 Hz against a published 6000. 6000 x 10^-2 = 60.00 Hz
		// is what the row always meant.
		{"BASIC-012", 58, curveMode("opModFreqWatt", &curveBinding{
			Mode:     "freq_watt",
			Points:   []CurvePoint{{X: 6000, Y: 100}, {X: 6050, Y: 0}},
			XMult:    -2,
			YRefType: derUnitRefSetMaxW,
			// The 7xx arm names 711 as the NEAREST model and refuses to measure
			// against it: 711 is a parametric droop with no point table, so
			// there is nothing a published curve could be written into.
			Model7xx:          sunspec.ModelDERFreqDroop,
			NoRegisterHome7xx: noFreqWattRegister,
			// The legacy arm is a real home. This is D2's acceptance criterion.
			ModelLegacy:   sunspec.ModelFreqWattLegacy,
			MappingLegacy: mappingFreqWattLegacy,
		}), "a frequency-droop / frequency-watt curve"},
		// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §4.2):
		// BASIC-013's opModFixedW is SignedPerCent, hundredths of a percent —
		// FixedW=6000 means 60.00%, matching the catalog's own stated value
		// verbatim (testdata/catalog/catalog.json: "opModFixedW is scaled in
		// hundredths of a percent (5000 = 50%), so the test value 6000 = 60%
		// of max power"). The pre-fix FixedW=50 sent a value two orders of
		// magnitude off the catalog's own stated test value.
		//
		// IW15-004: this row publishes the procedure's OWN two values and
		// nothing else. CSIP CTP v1.3 BASIC-013 Figure 13 prescribes a 5000
		// (50.00%) DEFAULT and a 6000 (60.00%) test value, so the row drives
		// the DER into 50%, waits for that to reach the DER's own registers,
		// and then commands exactly 60% — and it carries NO ladder, because a
		// row whose procedure states its values may not substitute one. The
		// 2026-08-14 report sent 40% instead of 60% and reported the result as
		// BASIC-013 conformance evidence; the stale-register problem the ladder
		// existed for is now solved by the 50% reset, which is what the
		// procedure prescribes for it in the first place.
		{"BASIC-013", 59, withOracle(scalarModeOracledDefaultFirst("opModFixedW", 5000, 6000,
			func(r *ControlRequest, hundredths int64) {
				r.FixedW = ptr(hundredths)
			}), oracleFixedW), "a set-active-power command expressed as a percentage of maximum"},
		// BASIC-014 is opModTargetW (genuine nested ActivePower, watts — §1.1,
		// already correct) — NOT opModFixedW, which the pre-fix row rode
		// because ControlRequest/adminCtrlReq had no TargetW lever at all
		// (§4.2: "BASIC-014 cannot even in principle be sent correctly with
		// the harness's current request surface, independent of the units
		// bug"). TargetW=3000 matches the catalog's own stated value
		// ("opModTargetW | 2000 (value 2000, multiplier 0) | 3000 (0
		// multiplier)").
		//
		// It is deliberately NOT wired to oracleTargetW, and IW15-008 is what
		// finally settles what it IS wired to. opModTargetW is REFUSED by this
		// product (supported.go's ScalarSupportedAxes carries no ModeTargetW —
		// "enforcement TBD"), so an oracle asserting the DER HOLDS the
		// commanded value would FAIL every correctly-refusing DUT, exactly
		// backwards. IW13 flagged the opposite assertion as "a materially
		// different check the design doesn't specify" and left the row on
		// critDEREffectUnobservable's SKIP — which is how a refusal nobody had
		// ever verified rolled up as a PASS. That check is now specified and
		// built (curve.go's refusalBinding): the DUT must ANSWER the head end
		// cannot-comply, and NOT ONE REGISTER of the setpoint axis may move on
		// the DER while the refused control is live. A silent partial write, or
		// a Started for an axis nothing executed (the LXR-002 shape verbatim),
		// now FAILs here instead of passing unmeasured.
		{"BASIC-014", 60, scalarModeRefused("opModTargetW",
			"the 704 active-power SETPOINT axis (WSet / WSetPct, and the WSetMod enum that selects between "+
				"them)",
			"opModTargetW = 3000 W (value 3000, multiplier 0), the catalog's own stated test value",
			"opModTargetW is an axis this product does not execute end to end, so it is refused at receipt "+
				"rather than partially or silently complied with",
			[]string{"WSet", "WSetPct"},
			func(r *ControlRequest) { r.TargetW = ptr(int64(3000)) }),
			"a set-active-power command expressed in watts"},
		// BASIC-015 is now a REFUSAL row, and the flip is a product truth
		// change, not a harness re-scope. See refusalWattPF for the substance;
		// the shape is BASIC-014's, in two halves that must BOTH hold: the DUT
		// answered the head end cannot-comply (and never Started/Completed), and
		// not one register of model 712 moved while the refused control was
		// live. Either half alone lets the other's defect through.
		//
		// The curve it publishes is REAL and well-formed — same publisher, same
		// window, same resolvability check as an execution curve row — because a
		// malformed or unfetchable curve draws the same refusal from outside,
		// and the row must be able to tell the two apart.
		//
		// yRefType stays 3 (%statVarAvail) and is NOT load-bearing here, which
		// is worth stating because every other curve row's just became so. sep
		// 2.0.4 gives Watt-PF's y as a signed power-factor displacement under
		// the EEI convention and defines NO DERUnitRefType for a power factor —
		// none of the eight codes names one — while DERCurve declares yRefType
		// minOccurs=1, so SOME code must be sent and every choice is wrong in
		// the same way. It cannot be the cause of the refusal in any case: the
		// DUT refuses this axis at receipt, by element name, before any curve
		// content is read (lexa-gw scheduler's AdvancedSupportedAxes).
		//
		// WHAT FLIPS IT BACK. The legacy-curve staging Stage that lands the
		// model-131 (Watt-PF) writer — lexa-gw docs/design/
		// LEGACY_CURVES_RC0_2026-08-14.md §4.3, the same commit that adds
		// opModWattPF's internal/advaxis DerGen12x row and its fanOutClasses
		// row. Note that even then the admission is PER-DEVICE (§7.1): a 7xx DER
		// must go on refusing it, so this row does not simply revert — it
		// becomes an execution row against model 131 on a 12x DER and stays a
		// refusal row on a 7xx one, and the bench will need a 12x DER profile
		// before it can grade the execution half at all.
		//
		// IT IS NOW A PER-GENERATION ROW, and the flip on the legacy side is
		// the second half of the same product truth the refusal recorded. The
		// "WHAT FLIPS IT BACK" note above said this would become an execution
		// row against model 131 on a 12x DER while staying a refusal row on a
		// 7xx one, and that the bench would need a 12x DER profile before it
		// could grade the execution half. That profile now exists
		// (sim/southbound/curve12x.go), so the row carries both halves and the
		// DEVICE decides which runs.
		//
		// The 7xx half is UNCHANGED — same published curve, same yRefType, same
		// fingerprinted bank — because a 7xx DUT that refuses this axis is
		// correct and this row already proves it does so honestly. Changing it
		// to a decided FAIL (which the design's §6.4 table proposed) would have
		// replaced a measurement of the product's actual behaviour with an
		// assertion that nothing was measured, which is strictly less evidence.
		{"BASIC-015", 61, curveModePerGeneration("opModWattPF",
			// Kept short: it is read inside sentences like "nothing of X moved
			// in the DER's own registers". Why this bank is the right one to
			// watch — it is where the product used to write opModWattPF's
			// content, and so where a regression would land — is refusalWattPF's
			// job, and it is printed alongside this on every verdict.
			"the SunSpec model 712 (DER Watt-Var) curve bank",
			refusalWattPF,
			&curveBinding{
				Mode:     "watt_pf",
				Points:   []CurvePoint{{X: 0, Y: 100}, {X: 50, Y: 98}, {X: 100, Y: 95}},
				YRefType: derUnitRefStatVarAvail,
				Model7xx: sunspec.ModelDERWattVar,
			},
			// THE LEGACY ARM PUBLISHES yMultiplier = -2 where the 7xx refusal
			// arm publishes none, and the difference is not cosmetic. A power
			// factor is a number near 1; model 131 stores it at the device's own
			// PF_SF, which on any honest device is negative. The refusal arm's
			// y values are never compared against a register — the row's claim
			// there is that NOTHING moved — so its multiplier was free to stay
			// 0; the execution arm's are compared point for point, so the
			// published curve has to mean what the device holds. 95 x 10^-2 =
			// 0.95 is the power factor this row has always been describing.
			//
			// yRefType stays 3 and is STILL not load-bearing, for the reason the
			// 7xx note gives: sep 2.0.4 defines no DERUnitRefType for a power
			// factor, DERCurve declares yRefType minOccurs=1, so some code must
			// be sent and every choice is wrong in the same way. 131 carries no
			// DeptRef register at all, so the referee asserts none here rather
			// than inventing an expectation.
			&curveBinding{
				Mode:          "watt_pf",
				Points:        []CurvePoint{{X: 0, Y: 100}, {X: 50, Y: 98}, {X: 100, Y: 95}},
				YMult:         -2,
				YRefType:      derUnitRefStatVarAvail,
				ModelLegacy:   sunspec.ModelWattPFLegacy,
				MappingLegacy: mappingWattPFLegacy,
			}), "an advanced (curve-based) inverter control"},

		// TODO(curve plan #32): there is NO opModWattVar row here, and its
		// absence is a BENCH gap rather than a scope decision.
		//
		// opModWattVar is the axis model 712 actually implements, and as of
		// lexa-proto 8a65431 + lexa-gw's curve P1 wave the product decodes it,
		// screens it, arbitrates it inside the reactive group and writes it to
		// 712 with read-back verification. It is the strongest curve axis this
		// DUT has and nothing here exercises it.
		//
		// THE BLOCKER IS GRIDSIM, precisely: sim/gridsim/curve.go's
		// curveTypeForMode and setCurveLink know four modes (volt_var,
		// volt_watt, freq_watt, watt_pf) and there is no lever that emits an
		// <opModWattVar> DERCurveLink at all, so the control cannot be placed on
		// the wire. Adding one is curve plan #32's work: a "watt_var" mode
		// mapping to csipmodel.CurveTypeWattVar (10) and
		// ExtendedDERControlBase.OpModWattVar, both of which the pinned
		// lexa-proto now provides.
		//
		// It is recorded here rather than registered as an unreachableMode row
		// because the catalog has no uid for it — CSIP-CONF-v1.3's BASIC family
		// stops at BASIC-015 — and inventing a uid would put a row in the
		// bundle that no document asks for. When #32 lands, the axis belongs on
		// BASIC-015's sibling coverage or on an aggregate row, not here.
	}
}

func requiresFor(m controlMode) []string {
	if !m.publishable() {
		return needCapture
	}
	return needGridSim
}

// registerEventScenarios binds BASIC-016..026, the eleven precedence rows.
//
// The fixtures follow the rows' titles: a number of DERPrograms (each with a
// DefaultDERControl, which gridsim's tree already provides), and zero, one or
// two DERControls in a stated overlap relationship. gridsim's three programs are
// used as System (index 2, primacy 10), Site (index 1, primacy 5) and Service
// Point (index 0, primacy 1), which is the priority ordering these rows turn on.
func registerEventScenarios(reg *certify.Registry, nonce string) {
	for _, r := range eventScenarioRows(nonce) {
		req := needGridSim
		if len(r.sc.Controls) == 0 {
			req = needCapture
		}
		reg.Register(uid(r.id), Suite, basicEventScenario(r.sc),
			certify.WithRequires(req...), certify.WithOrder(r.order))
	}
}

// eventRow is one BASIC-016..026 precedence scenario: its catalog id, run order
// within the suite, and the fixture the check drives.
type eventRow struct {
	id    string
	order int
	sc    eventScenario
}

// eventScenarioRows returns the eleven precedence rows with the per-run nonce
// applied to every scenario (see eventScenario.withNonce). It is separated from
// registerEventScenarios so a test can assert both halves of the isolation fix
// directly: that two different nonces produce disjoint mRIDs across runs, and
// that within one nonce each ExpectWinner still names one of that scenario's own
// controls, so the within-run lifecycle correlation is preserved.
func eventScenarioRows(nonce string) []eventRow {
	const (
		servicePoint = 0
		system       = 2
	)
	rows := []eventRow{
		{"BASIC-016", 80, eventScenario{
			Summary: "2 DERPrograms, 2 DefaultDERControls, 0 DERControls: the DER must follow the " +
				"DefaultDERControl of the higher-priority (lower-primacy) program"}},
		{"BASIC-017", 81, eventScenario{
			Summary:      "1 DERProgram, 0 DefaultDERControls, 1 DERControl",
			ExpectWinner: "CERT-B017",
			Controls: []scenarioControl{
				{MRID: "CERT-B017", Program: servicePoint, StartOffset: 30, DurationS: 180, MaxLimW: 5000},
			}}},
		{"BASIC-018", 82, eventScenario{
			Summary:      "1 DERProgram, 1 DefaultDERControl, 1 DERControl: the control must win while active",
			ExpectWinner: "CERT-B018",
			Controls: []scenarioControl{
				{MRID: "CERT-B018", Program: servicePoint, StartOffset: 30, DurationS: 180, MaxLimW: 4500},
			}}},
		{"BASIC-019", 83, eventScenario{
			Summary:      "1 DERProgram, 1 DefaultDERControl, 2 non-overlapping similar DERControls",
			ExpectWinner: "CERT-B019A",
			Controls: []scenarioControl{
				{MRID: "CERT-B019A", Program: servicePoint, StartOffset: 30, DurationS: 60, MaxLimW: 4000},
				{MRID: "CERT-B019B", Program: servicePoint, StartOffset: 120, DurationS: 60, MaxLimW: 3000},
			}}},
		{"BASIC-020", 84, eventScenario{
			Summary:      "2 DERPrograms, 2 DefaultDERControls, 2 non-overlapping similar DERControls",
			ExpectWinner: "CERT-B020A",
			Controls: []scenarioControl{
				{MRID: "CERT-B020A", Program: servicePoint, StartOffset: 30, DurationS: 60, MaxLimW: 4000},
				{MRID: "CERT-B020B", Program: system, StartOffset: 120, DurationS: 60, MaxLimW: 3000},
			}}},
		{"BASIC-021", 85, eventScenario{
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls — the System " +
				"control follows the Service Point control",
			ExpectWinner: "CERT-B021SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B021SYS", Program: system, StartOffset: 30, DurationS: 180, MaxLimW: 3000,
					Superseded: true, CreationAge: -60},
				{MRID: "CERT-B021SP", Program: servicePoint, StartOffset: 30, DurationS: 180, MaxLimW: 2000},
			}}},
		{"BASIC-022", 86, eventScenario{
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls — the Service " +
				"Point control follows the System control",
			ExpectWinner: "CERT-B022SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B022SYS", Program: system, StartOffset: 30, DurationS: 180, MaxLimW: 3000,
					Superseded: true},
				{MRID: "CERT-B022SP", Program: servicePoint, StartOffset: 60, DurationS: 180, MaxLimW: 2000},
			}}},
		{"BASIC-023", 87, eventScenario{
			Summary:      "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls, staggered ends",
			ExpectWinner: "CERT-B023SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B023SYS", Program: system, StartOffset: 30, DurationS: 240, MaxLimW: 3000,
					Superseded: true, CreationAge: -60},
				{MRID: "CERT-B023SP", Program: servicePoint, StartOffset: 60, DurationS: 120, MaxLimW: 2000},
			}}},
		{"BASIC-024", 88, eventScenario{
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping INDEPENDENT DERControls — " +
				"independent modes may overlap without superseding (IEEE 2030.5 §10.2.3 rule t)",
			ExpectWinner: "CERT-B024SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B024SYS", Program: system, StartOffset: 30, DurationS: 180, MaxLimW: 3000},
				{MRID: "CERT-B024SP", Program: servicePoint, StartOffset: 30, DurationS: 180, MaxLimW: 2000},
			}}},
		{"BASIC-025", 89, eventScenario{
			Summary:      "2 DERPrograms, 2 DefaultDERControls, 2 overlapping independent DERControls, staggered starts",
			ExpectWinner: "CERT-B025SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B025SYS", Program: system, StartOffset: 30, DurationS: 180, MaxLimW: 3000},
				{MRID: "CERT-B025SP", Program: servicePoint, StartOffset: 60, DurationS: 180, MaxLimW: 2000},
			}}},
		{"BASIC-026", 90, eventScenario{
			Summary:      "2 DERPrograms, 2 DefaultDERControls, 2 overlapping independent DERControls, staggered ends",
			ExpectWinner: "CERT-B026SP",
			Controls: []scenarioControl{
				{MRID: "CERT-B026SYS", Program: system, StartOffset: 30, DurationS: 240, MaxLimW: 3000},
				{MRID: "CERT-B026SP", Program: servicePoint, StartOffset: 60, DurationS: 120, MaxLimW: 2000},
			}}},
	}
	for i := range rows {
		rows[i].sc = rows[i].sc.withNonce(nonce)
	}
	return rows
}

// runNonce mints the per-run token appended to the event-scenario mRIDs. A
// campaign is one process, so a nonce minted once at suite construction is
// stable for the whole run and — being random — differs across runs, which is
// all the isolation fix needs: the gateway's Response tracker never sees a
// re-run republish an mRID it has already carried to a terminal state. It
// mirrors what gridsim already does for curve-driven controls, whose mRIDs it
// stamps per run; here the harness owns the mRID, so the harness stamps it.
//
// Eight hex digits from crypto/rand are plenty to separate the handful of runs
// a bench ever performs against one long-running gateway; if the reader is
// somehow unavailable it falls back to the process start time in base-36, which
// is still distinct across the separate invocations a batch makes.
func runNonce() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// withRunNonce appends the per-run token to a bare mRID, or returns it
// unchanged when nonce is empty (an empty nonce is the identity — see
// runNonce's callers). It is the one-mRID building block eventScenario.withNonce
// uses per field; CORE-022 and CORE-023 (core.go's coreResponses and
// coreSuperseding) call it directly since each mints one or two bare mRIDs
// rather than a whole scenario struct.
//
// The reason CORE-022/023 need this at all is the same one BASIC-017..026's
// eventScenario.withNonce documents: lexa-gw's Response tracker dedupes
// Received(1) — and the rest of the lifecycle — on the bare mRID string,
// retained for the process's whole lifetime AND persisted to disk, so a
// long-lived bench that re-runs either catalog uid against the SAME hardcoded
// mRID never re-earns the Responses those uids' own assertions grade. Per-mRID
// duplicate suppression is a defensible 2030.5 posture — it is what a real ATL
// run's genuinely fresh events would sidestep too, not a defect a conformance
// harness should paper over — so presenting a fresh mRID each run is what
// re-running this suite honestly requires. The separate, still-open product
// question of whether a same-mRID event with a bumped version should re-earn
// responses is tracked independently of this harness fix.
func withRunNonce(mrid, nonce string) string {
	if nonce == "" {
		return mrid
	}
	return mrid + "-" + nonce
}

// inapplicableUIDs are the CSIP-CONF-v1.3 rows bound to the notApplicable STUB.
// They are listed explicitly rather than derived from the catalog at init time
// so that a future catalog revision that makes one of them applicable shows up
// as a coverage GAP — a loud, visible one — instead of being silently swallowed
// by a rule that reads applicability from the same file it is meant to be
// checked against.
//
// This is NOT the list of inapplicable rows. Twenty-eight rows are inapplicable
// and only these six are stubbed; the other twenty-two are the aggregator-only
// rows, which the DER Client claim of 2026-07-28 puts outside the certification
// while leaving their real checks registered and running (registerAggregator).
// Adding them here would delete twenty-two working evaluators to satisfy a
// bookkeeping symmetry, which is the trade this file refuses.
//
// None of the six is here because of the DUT's profile scope. All six are §4
// rows blank in ALL THREE columns — required of Server, DER Client and DER
// Aggregator Client alike, i.e. of nobody — and four of them are rows about a
// 2030.5 SERVER, which this DUT does not implement in any profile.
var inapplicableUIDs = []string{
	// 2030.5-SERVER rows: these test the utility server's own HTTP behaviour —
	// method handling (CORE-001), the non-TLS→TLS redirect of /dcap (CORE-002,
	// whose CLIENT half is ERR-001 and IS implemented), list pagination and
	// query-string handling (CORE-004), and the server's startup group
	// assignment (UTIL-001). All four are blank in all three §4 columns.
	"CORE-001", "CORE-002", "CORE-004", "UTIL-001",
	// ERRATA (seq 32) on MAINT-002: "Test not required as it is unlikely for
	// utilities to utilize the tested behavior. Make the test optional/remove
	// entirely from the spec." §4 leaves it blank in all three columns, so the
	// aggregator re-scope did NOT pull it in with its four MAINT siblings.
	// It stays registered so the decision is visible in the bundle.
	"MAINT-002",
	// xmDNS/DNS-SD discovery: the procedure's own Purpose says "This test is
	// optional for all device types", §4 leaves it blank in all three columns,
	// and this DUT is provisioned out of band — which COMM-002 certifies.
	"COMM-001",
}

func registerInapplicable(reg *certify.Registry) {
	for i, id := range inapplicableUIDs {
		reg.Register(uid(id), Suite, notApplicable, certify.WithOrder(900+i))
	}
}
