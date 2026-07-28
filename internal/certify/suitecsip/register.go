package suitecsip

// register.go binds every CSIP-CONF-v1.3 catalog uid to a check.
//
// EVERY uid — all seventy-nine — including the six the §4 profile matrix
// excludes for this DUT. Registering the inapplicable ones is a deliberate
// choice: a coverage report that simply lacked those rows would read as "nobody
// got to them", while a registered row reporting NOT APPLICABLE and quoting the
// catalog's own applicability_reason reads as a decision a reviewer can audit
// against the profile matrix — and disagree with, which is the point of writing
// it down.
//
// The Order values group the run so a live campaign produces a sensible
// sequence: transport first (if the TLS profile is wrong, nothing after it
// means anything), then the discovery core, then the control rows, then the
// scenario rows, then the aggregator-profile rows, then the fault-injecting row
// last, because it is the only one that deliberately makes the server misbehave
// and the only one whose failure mode could perturb what follows.

import "csip-tls-test/internal/certify"

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
func Register(reg *certify.Registry) {
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
	reg.Register(uid("COMM-004D"), Suite,
		commChainRejection("a MICA whose extendedKeyUsage extension is marked critical with an invalid value",
			"a chain with an invalid critical MICA extendedKeyUsage"),
		certify.WithRequires(needCapture...), certify.WithOrder(7))
	reg.Register(uid("COMM-004E"), Suite,
		commChainRejection("a MICA whose name extension is non-critical with an invalid value",
			"a chain with an invalid non-critical MICA name extension"),
		certify.WithRequires(needCapture...), certify.WithOrder(8))
	reg.Register(uid("COMM-004F"), Suite,
		commChainRejection("a MICA whose policy-mapping extension is non-critical with an invalid value",
			"a chain with an invalid non-critical MICA policy mapping"),
		certify.WithRequires(needCapture...), certify.WithOrder(9))
	reg.Register(uid("COMM-004G"), Suite,
		commChainRejection("a self-signed device certificate with no chain to a trusted SERCA",
			"a self-signed device certificate"),
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
	registerEventScenarios(reg)

	// ── Response lifecycle (order 100–109) ───────────────────────────────
	reg.Register(uid("CORE-021"), Suite, coreRandomizedEvents,
		certify.WithRequires(needGridSim...), certify.WithOrder(100))
	reg.Register(uid("CORE-022"), Suite, coreResponses,
		certify.WithRequires(needGridSim...), certify.WithOrder(101))
	reg.Register(uid("CORE-023"), Suite, coreSuperseding,
		certify.WithRequires(needGridSim...), certify.WithOrder(102))

	// ── Aggregator profile (order 200–299) ───────────────────────────────
	registerAggregator(reg)

	// ── Error handling, last: it is the only row that deliberately makes
	//    the shared server misbehave. ──────────────────────────────────────
	reg.Register(uid("ERR-001"), Suite, errRedirect,
		certify.WithRequires(needGridSim...), certify.WithOrder(300))

	registerInapplicable(reg)
}

// registerAggregator binds the twenty-two rows the DER AGGREGATOR CLIENT
// profile requires and the DER Client profile did not (owner decision
// 2026-07-28 — see aggregator.go).
//
// They run AFTER every direct-client row and BEFORE ERR-001, for two reasons.
// The commissioning and subscription rows read the same resting tree the core
// rows read, so putting them later costs nothing; the AGG event rows publish
// DERControls on two programs at once and two of them (AGG-009, AGG-012) sleep
// inside their own setup waiting for an event to start, so a campaign that has
// to be cut short loses these rather than the profile's foundations.
func registerAggregator(reg *certify.Registry) {
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
	reg.Register(uid("UTIL-004"), Suite, utilDERRetrieval,
		certify.WithRequires(needGridSim...), certify.WithOrder(230))

	// The aggregator event rows, in document order. AGG-002 publishes nothing
	// (it is the two-DefaultDERControl row), so it does not need gridsim.
	scenarios := aggScenarios()
	for i, id := range []string{
		"AGG-002", "AGG-003", "AGG-004", "AGG-005", "AGG-006",
		"AGG-007", "AGG-008", "AGG-009", "AGG-010", "AGG-011", "AGG-012",
	} {
		sc, ok := scenarios[id]
		if !ok {
			panic("suitecsip: no aggregator scenario for " + id)
		}
		req := needGridSim
		if len(sc.Controls) == 0 {
			req = needCapture
		}
		reg.Register(uid(id), Suite, aggEvent(sc),
			certify.WithRequires(req...), certify.WithOrder(240+i))
	}
}

// registerInverterControls binds BASIC-004..015, the twelve control-mode rows.
func registerInverterControls(reg *certify.Registry) {
	const noRideThrough = "IEEE 2030.5's ride-through modes (opModLVRTMustTrip / opModLVRTMayTrip / " +
		"opModLVRTMomentaryCessation and their HVRT / LFRT / HFRT counterparts) are curve-valued DERControl " +
		"modes that the bench's 2030.5 server cannot publish: gridsim's admin control API " +
		"(sim/gridsim/admin.go adminCtrlReq) exposes only the scalar modes, and its curve API " +
		"(sim/gridsim/curve.go) binds only Volt-VAr, Volt-Watt, Freq-Watt and Watt-PF. With no way to put " +
		"the mode on the wire there is nothing to observe, and reporting anything but a SKIP would be " +
		"certifying a test that was never run. Closing this needs a ride-through curve mode in gridsim"

	const noRampRate = "IEEE 2030.5 places the ramp rates setGradW and setSoftGradW ONLY in " +
		"DefaultDERControl — CSIP §5.2.4 is explicit that they cannot be scheduled — and gridsim's " +
		"POST /admin/default carries the same DERControlBase field set as its control API, which has no " +
		"gradient fields. The mode therefore cannot be placed on the wire from this bench"

	rows := []struct {
		id      string
		order   int
		mode    controlMode
		subject string
	}{
		{"BASIC-004", 50, unreachableMode("opModLVRTMustTrip", noRideThrough),
			"the low/high voltage ride-through settings"},
		{"BASIC-005", 51, unreachableMode("opModLFRTMustTrip", noRideThrough),
			"the low/high frequency ride-through settings"},
		{"BASIC-006", 52, curveMode("opModVoltVar", "volt_var",
			[]CurvePoint{{X: 92, Y: 60}, {X: 98, Y: 0}, {X: 102, Y: 0}, {X: 108, Y: -60}}, 3),
			"a Volt-VAr curve"},
		{"BASIC-007", 53, unreachableMode("setGradW", noRampRate), "the ramp-rate settings"},
		{"BASIC-008", 54, scalarMode("opModFixedPFInjectW", func(r *ControlRequest) {
			r.FixedPFInjectW = ptr(int64(95))
		}), "a fixed power factor while injecting"},
		{"BASIC-009", 55, scalarMode("opModConnect", func(r *ControlRequest) {
			r.Connect = ptr(false)
			r.Energize = ptr(false)
		}), "a connect/disconnect command"},
		{"BASIC-010", 56, scalarMode("opModMaxLimW", func(r *ControlRequest) {
			r.MaxLimW = ptr(int64(6000))
		}), "a maximum active power limit"},
		{"BASIC-011", 57, curveMode("opModVoltWatt", "volt_watt",
			[]CurvePoint{{X: 106, Y: 100}, {X: 110, Y: 20}}, 3), "a Volt-Watt curve"},
		{"BASIC-012", 58, curveMode("opModFreqWatt", "freq_watt",
			[]CurvePoint{{X: 6000, Y: 100}, {X: 6050, Y: 0}}, 3), "a frequency-droop / frequency-watt curve"},
		{"BASIC-013", 59, scalarMode("opModFixedW", func(r *ControlRequest) {
			r.FixedW = ptr(int64(50))
		}), "a set-active-power command expressed as a percentage of maximum"},
		{"BASIC-014", 60, scalarMode("opModFixedW", func(r *ControlRequest) {
			r.FixedW = ptr(int64(4000))
		}), "a set-active-power command expressed in watts"},
		{"BASIC-015", 61, curveMode("opModWattPF", "watt_pf",
			[]CurvePoint{{X: 0, Y: 100}, {X: 50, Y: 98}, {X: 100, Y: 95}}, 3),
			"an advanced (curve-based) inverter control"},
	}
	for _, r := range rows {
		reg.Register(uid(r.id), Suite, basicInverterControl(r.mode, r.subject),
			certify.WithRequires(requiresFor(r.mode)...), certify.WithOrder(r.order))
	}
}

func requiresFor(m controlMode) []string {
	if m.Publish == nil {
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
func registerEventScenarios(reg *certify.Registry) {
	const (
		servicePoint = 0
		system       = 2
	)
	rows := []struct {
		id    string
		order int
		sc    eventScenario
	}{
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
	for _, r := range rows {
		req := needGridSim
		if len(r.sc.Controls) == 0 {
			req = needCapture
		}
		reg.Register(uid(r.id), Suite, basicEventScenario(r.sc),
			certify.WithRequires(req...), certify.WithOrder(r.order))
	}
}

// inapplicableUIDs are the CSIP-CONF-v1.3 rows the §4 profile matrix excludes
// for THIS DUT, which since the owner decision of 2026-07-28 is a DER
// AGGREGATOR CLIENT (docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md).
// They are listed explicitly rather than derived from the catalog at init time
// so that a future catalog revision that makes one of them applicable shows up
// as a coverage GAP — a loud, visible one — instead of being silently swallowed
// by a rule that reads applicability from the same file it is meant to be
// checked against.
//
// The list used to hold twenty-eight rows. Twenty-two of them were excluded for
// exactly one reason — the DUT was scoped as a DIRECT DER client — and the
// re-scope made them real overnight, which is what the previous revision of
// this comment warned would happen. They are now implemented in aggregator.go,
// with the Annex A corrections applied where they change an observable rather
// than carried as a breadcrumb.
//
// SIX remain, and none of them is here because of the DUT's profile scope
// alone. Four are §4 rows blank in ALL THREE columns — required of Server, DER
// Client and DER Aggregator Client alike, i.e. of nobody — and two are rows
// about a 2030.5 SERVER, which this DUT does not implement in any profile.
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
