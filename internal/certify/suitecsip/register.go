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

	// The bench levers that do not exist, named once so a row can cite them the
	// way noRideThrough/noRampRate are cited.
	//
	// openLoopTms USED TO BE HERE and is not any more (curve plan #32): gridsim's
	// POST /admin/curve now carries it (sim/gridsim/curve.go adminCurveReq's
	// OpenLoopTms) and emits it on the served DERCurve, so BASIC-006 publishes
	// Figure 6's own test value and the row no longer holds itself for the
	// omission. The remaining members of the Figure-6 timing family are a
	// DIFFERENT KIND of gap and now say so.
	//
	// noVrefElementInSchema USED TO BE HERE TOO, and its deletion is IW15-027's
	// finding on this file. It read, verbatim, "sep 2.0.4 declares NO such
	// element on DERCurve ... this is therefore NOT a missing bench lever —
	// there is nothing to build", it held BASIC-006's two autonomous-Vref gaps,
	// and it was quoted into every bundle that row ever appeared in.
	//
	// It was a TRUE statement about docs/schema/sep-2.0.4.xsd — the
	// pre-publication ZigBee SEP 2.0 draft — and a FALSE statement about IEEE
	// Std 2030.5-2018, which declares autonomousVRefEnable (p.252),
	// autonomousVRefTimeConstant (p.253) and vRef (p.253) on DERCurve, and makes
	// the last of the three multiply every breakpoint of a volt-var curve
	// (p.250: "If VRef is present in DERCurve, then the x value of each pair is
	// additionally multiplied by VRef/10 000"). There WAS something to build,
	// the catalog had been asking for two of the three all along, and the row
	// was explaining away a bench gap with a citation into the wrong document.
	//
	// The lever exists now (sim/gridsim/curve.go's vrefFamily), BASIC-006
	// AUTHORS both elements Figure 6 prescribes, and the two gaps are gone
	// rather than re-worded. vRef itself, which no Figure prescribes, falls
	// under the rule immediately below.

	// The DERCurve elements no Figure prescribes. Named for completeness where a
	// row lists what it can and cannot author, and deliberately not authored: a
	// value nothing asks for is a value nothing tests.
	//
	// vRef JOINED THIS LIST when it stopped being imaginary. gridsim can serve
	// one, so this is no longer a missing lever at all — no row sends one
	// because no procedure asks for one, which is a different sentence with a
	// different remedy.
	noPrescribedCurveRampLever = "no Figure in this catalog prescribes it, so no row of this suite authors " +
		"a value for it and none claims to. DERCurve's rampDecTms/rampIncTms/rampPT1Tms and vRef are all " +
		"real IEEE 2030.5-2018 elements (p.253); gridsim can already SERVE a vRef (POST /admin/curve's " +
		"`vref`, opModVoltVar-only per p.252's SHALL NOT), and the ramp trio could be added the same way " +
		"openLoopTms was (curve plan #32) the moment a procedure asks for one"

	// The 711 register names the droop's five parameters land on, written once
	// so a row and a verdict cannot disagree about which registers were read.
	droopRegisterNames = "DbOf/DbUf dead bands, KOf/KUf gains and RspTms response time"

	// openLoopTms IS MEASURABLE ON 705 AND 706, and the constant that used to
	// sit here said the opposite. It asserted that the 7xx curve models "carry
	// an adopt handshake, a DeptRef and a point table and no open-loop response
	// register at all" — a statement of fact, quoted verbatim into every bundle
	// BASIC-006 appeared in, and false: model_705.json and model_706.json BOTH
	// declare Crv.RspTms (uint32 Secs, scaled by RspTms_SF, labelled "Open Loop
	// Response Time"), lexa-proto parses and encodes it, and the referee was
	// simply dropping it on the floor while its 711 sibling carried the
	// equivalent. Only 712 lacks the register.
	//
	// So the element is now COMPARED where a home exists, and these two
	// constants name the absence only where there really is one.
	noOpenLoopTmsRegister7xx = "this row's 7xx register home is a model that declares no open-loop " +
		"response register: of the 7xx curve models only 705 (Volt-Var) and 706 (Volt-Watt) carry " +
		"Crv.RspTms, and 712 (Watt-Var) carries none. (Model 711 does have RspTms — but that is " +
		"opModFreqDroop's OWN openLoopTms, a different element of a different mode, and reading a curve's " +
		"timing out of a frequency-droop control would be the substitution this suite exists to refuse.) " +
		"The element is SERVED northbound exactly as the procedure prescribes — that half is real evidence " +
		"about what the DUT was offered — and on this bank no southbound read can show what the DUT did " +
		"with it"

	// The autonomous volt-reference pair's absence, on BOTH generations, and it
	// is a different KIND of absence from openLoopTms's.
	//
	// openLoopTms has an exact SunSpec home on two of the curve models and none
	// on the rest — a coverage gap. This pair has none anywhere, and the thing
	// that looks like a home is a trap: model 705 declares VRefAuto, VRefAutoEna
	// and VRefAutoTms, which are the DER's OWN volt-var reference automation,
	// written from its settings. IEEE 2030.5's autonomousVRefEnable is an
	// attribute of a CURVE, scoped to that curve, and a gateway may legitimately
	// implement it without touching those registers at all. Grading one against
	// the other would certify a substitution, which is what this suite exists to
	// refuse.
	noAutonomousVRefRegister = "no SunSpec curve bank on either generation holds this element. The nearest " +
		"thing on a 7xx DER is model 705's VRefAutoEna / VRefAutoTms pair, and it is NOT the same " +
		"quantity: those are the DER's own volt-var reference automation, set from its settings and " +
		"scoped to the device, while IEEE 2030.5-2018's autonomousVRefEnable (p.252) is an attribute of " +
		"one DERCurve, scoped to that curve, which a gateway may implement without writing them. So the " +
		"element is SERVED northbound exactly as Figure 6 prescribes — that half is real evidence about " +
		"what the DUT was offered — and no southbound read on either generation can show what became of it"

	noOpenLoopTmsRegisterLegacy = "the legacy 12x banks carry no open-loop response register: 126 " +
		"declares Crv.RmpTms and 132/134 declare Crv.RmpPt1Tms, and BOTH are documented in their own " +
		"model definitions as \"the time of the PT1 ... to accomplish a change of 95%\" — a PT1 FILTER " +
		"time constant, which is IEEE Std 2030.5-2018's rampPT1Tms (p.253: \"the configuration parameter " +
		"for a low-pass filter, PT1 is a time ... in which the filter will settle to 95% of a step " +
		"change\"), a SEPARATE element of the same DERCurve from openLoopTms (p.253). Writing " +
		"an openLoopTms into it would command a different behaviour under a name that sounds alike, which " +
		"is the substitution this suite refuses. So on this generation the element is SERVED northbound " +
		"and nothing southbound can show what became of it"

	// The droop's own homes and absences.
	mappingFreqDroop7xx = "IEEE 2030.5's opModFreqDroop is a PARAMETRIC frequency-droop control — two dead " +
		"bands, two per-unit gains and an open-loop response time — and its exact register home is SunSpec " +
		"model 711 (DER Frequency Droop), whose Ctl block carries precisely those five quantities: " +
		"DbOf/DbUf (scaled by Db_SF), KOf/KUf (scaled by K_SF) and RspTms (scaled by RspTms_SF). The " +
		"correspondence is EXACT and needs no interpretation: IEEE Std 2030.5-2018's FreqDroopType (p.242) " +
		"states dBOF/dBUF in thousandths of hertz and kOF/kUF in thousandths unitless as 'per-unit " +
		"frequency change ... corresponding to one per-unit power output change', and model 711's own " +
		"documentation states the same quantity in the " +
		"same words, so the translation is five fixed decimal shifts and no nominal-frequency assumption " +
		"enters anywhere (see curveBinding.want711, which performs it independently from the standards' " +
		"text rather than from the product's table)"

	// Stated by REGISTER rather than by adjective, because the adjectives were
	// doing work they could not support: an earlier wording called 127
	// "snapshot-referenced ... with a single hysteresis dead band and a single
	// gain", which reads like a characterisation of 134 and cannot be checked
	// against anything. What follows can be: it names the points 127 declares.
	noFreqDroopRegisterLegacy = "the legacy 12x set has NO home for a frequency-droop control. Its nearest " +
		"model, 127 (Freq-Watt Param), declares WGra (a curtailment slope in % PM/Hz), HzStr/HzStop (the " +
		"frequency deviations at which a snapshot of instantaneous output is taken and released) and " +
		"HysEna — so of FreqDroopType's five mandatory elements, dBUF, kUF and openLoopTms have NO " +
		"register to land in at all (127 curtails on over-frequency only, and its RmpTms is a PT1 filter " +
		"time), and the two that look close are different quantities: HzStr is a snapshot TRIGGER rather " +
		"than a droop dead band, and WGra is % PM/Hz rather than the per-unit-per-per-unit k the standard " +
		"defines. Grading the droop against it would be the substitution this suite refuses; the honest " +
		"answer is that the element is SERVED northbound on this bench and that nothing on this " +
		"generation's device can show what became of it. This product reaches the same conclusion from its " +
		"own side: internal/advaxis has an ExecDroop row for DerGen7xx and deliberately none for DerGen12x"

	// THE curveType DIVERGENCE WAS THE BENCH'S, AND IT IS GONE (IW15-027).
	//
	// This block used to say that the catalog's printed curveType values "are
	// CSIP-CONF v1.3's own numbering and do not agree with sep 2.0.4's
	// DERCurveType": Figure 6 prints 11 for volt-var, Figure 11 prints 12 for
	// volt-watt, Figure 12 prints 0 for freq-watt, "where sep 2.0.4 declares 0,
	// 3 and 1. This bench emits the SCHEMA's codes." Every affected row carried a
	// gap saying so, and it went into the bundles.
	//
	// The catalog was right on all three. IEEE Std 2030.5-2018 p.254 declares
	// FIFTEEN DERCurveType values 0..14 — opModVoltVar 11, opModVoltWatt 12,
	// opModFreqWatt 0 — and states each of them a second time in the linking
	// element's own prose ("Specify DERCurveLink for curveType == 11" under
	// opModVoltVar, p.250). The 0/3/1 the bench emitted came from
	// docs/schema/sep-2.0.4.xsd, the pre-publication ZigBee draft, whose
	// enumeration stops at 10 in a different order. So the sentence "emitting
	// the catalog's value would make the evidence non-conformant" was exactly
	// backwards: emitting the DRAFT's value is what made it non-conformant, and
	// this bench served a volt-var curve labelled frequency-watt to every DUT
	// that walked the tree.
	//
	// Nothing has to be reconciled any more, so the three gaps are DELETED
	// rather than re-worded — a gap register that lists agreements is not a gap
	// register. The agreement is asserted instead, three ways, by
	// TestCurveRows_CurveTypeAgreesWithTheCatalogAndTheStandard, which is where
	// a claim of agreement belongs: a test can go red and a comment cannot.
	//
	// BASIC-015 is the one curve-carrying row whose values are NOT the
	// catalog's, and saying so is the point: CSIP CTP v1.3's BASIC-015 procedure
	// prescribes twenty-four fixed-power-factor DERControls and carries no curve
	// settings Figure at all. The Watt-PF curve this row publishes is therefore
	// this suite's OWN construction, chosen to exercise the opModWattPF axis
	// (which is what the row's refusal/execution halves are about), and the
	// bundle must not imply a provenance it does not have.
	basic015NoPrescribedCurve = "CSIP CTP v1.3 BASIC-015 prescribes NO curve settings figure — its " +
		"procedure is twenty-four fixed-power-factor DERControls — so the Watt-PF curve this row " +
		"publishes is this suite's own, chosen to exercise the opModWattPF axis the row is about. Its " +
		"values are NOT claimed to be catalog-prescribed"

	// curveTypeAgreement is what replaced curveTypeDivergence, and it is a
	// PROVENANCE line rather than a caveat: it appears in the row's Prescribed
	// text so a bundle reader can see that the number on the wire, the number
	// the procedure printed and the number the standard assigns are one number,
	// and can check it. It is asserted by
	// TestCurveRows_CurveTypeAgreesWithTheCatalogAndTheStandard.
	curveTypeAgreement = "DERCurve.curveType is the catalog's own printed value, which is also IEEE Std " +
		"2030.5-2018's code for the mode (p.254, cross-cited per element on p.250-251) and also what this " +
		"bench emits: opModFreqWatt 0, opModVoltVar 11, opModVoltWatt 12, opModWattPF 13, opModWattVar 14. " +
		"Until 2026-08-15 the bench emitted the pre-publication draft schema's codes (0, 3, 1 for the three " +
		"catalog-prescribed modes) and every affected row carried a note saying the CATALOG diverged; the " +
		"divergence was the bench's and the note is withdrawn (IW15-027)"

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
		"different function. IEEE Std 2030.5-2018 says the same thing from the other side: opModWattVar " +
		"and opModWattPF are separate DERControlBase elements (p.251) with separate DERCurveType codes, " +
		"14 and 13 (p.254). This sentence cited the pre-publication draft and its codes (10 and 2) until " +
		"IW15-030; the argument was always right and its authority was the wrong document, which on a " +
		"string that lands in certification bundles is a defect of its own. " +
		"On a 7xx DER, therefore, the honest answer is cannot-comply at receipt — which is what this row " +
		"measures THERE, instead of grading a PF curve against a var bank and calling the substitution a " +
		"PASS. On a LEGACY 12x DER the same row is an EXECUTION row against model 131, because that DER " +
		"does have the axis; see mappingWattPFLegacy. The two halves are different KINDS of assertion, not " +
		"one assertion against two banks, and which applies is decided by the device the bench is running"

	// BASIC-012's frequency-WATT BREAKPOINTS have no 7xx home, and that has not
	// changed. What changed is that they are no longer the whole of the row's
	// southbound evidence there — see the adjudication note below.
	noFreqWattRegister = "IEEE 2030.5's opModFreqWatt is a BREAKPOINT curve (frequency → watts), and the " +
		"SunSpec/IEEE-1547 7xx set has no model that stores frequency-watt breakpoints: frequency response " +
		"is expressed as model 711 (DER Frequency Droop), a PARAMETRIC control — deadbands DbOf/DbUf, gains " +
		"KOf/KUf, a response time — with no point table a published curve could be written into. This " +
		"product's own reconciler records the same conclusion for the same reason (lexa-gw " +
		"cmd/modbus/reconcile_adv.go, on releasing its freq-watt axis: \"No SunSpec model executes " +
		"freq-watt ... nothing to disable on release either\"), and its advAxisModel table has no model for " +
		"the axis at all. So the BREAKPOINTS are authored northbound — that half is real evidence about " +
		"what the DUT was offered — and nothing southbound on a 7xx DER can hold them. This is NOT closed " +
		"by asserting something weaker against 711, which is a different function; it stays open, and it " +
		"IS closed on the other generation, where model 134 stores frequency-watt breakpoints (see " +
		"mappingFreqWattLegacy)"
)

// Suite is this suite's short name, used for -suite selection and printed in
// the report.
const Suite = "csip"

// uid builds a catalog uid for this document.
func uid(id string) string { return "csip-conf-v1.3::" + id }

// extUID addresses the LOCAL EXTENSION family: rows this bench measures because
// the behaviour matters, for which NO PUBLISHED PROCEDURE EXISTS.
//
// It is a separate document key rather than an invented CSIP-CONF id, and that
// is the whole point. A row filed under csip-conf-v1.3 claims to be a procedure
// of a published specification; these are not, their Test Values are the
// harness's own, and the catalog marks them certifiable=false so no tally that
// bears on a certification claim can ever count one. See the family's own
// catalog record (LOCAL-EXT-v1) for the posture, stated where a reader of a
// bundle will meet it.
func extUID(id string) string { return "local-ext-v1::" + id }

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
	registerInverterControls(reg, nonce)
	registerLocalExtensions(reg, nonce)

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
//
// NINE of them go through inverterControlRows below. BASIC-004 and BASIC-005 —
// the two RIDE-THROUGH rows — go through registerRideThroughControls
// (ridethrough.go) instead, because their apparatus is a LIST of curves bound
// into ONE DERControl (Figure 4 prescribes four, Figure 5 two) and controlMode
// has no field that can carry a list. BASIC-007 — the RAMP-RATE row — is
// registered by registerRampRates (rampdefault.go) instead: its apparatus is a
// DefaultDERControl-only precondition with no scheduled event and no Response
// lifecycle at all, a shape inverterControlSpec's mRID/Response machinery does
// not fit (see rampdefault.go's own file doc). All three are registered from
// HERE, in the same call, so a reader looking for where the twelve rows are
// bound finds all twelve in one place.
func registerInverterControls(reg *certify.Registry, nonce string) {
	for _, r := range inverterControlRows() {
		reg.Register(uid(r.id), Suite, basicInverterControl(r.mode, r.subject, nonce),
			certify.WithRequires(requiresFor(r.mode)...), certify.WithOrder(r.order))
	}
	registerRideThroughControls(reg, nonce)
	registerRampRates(reg)
}

// inverterControlRows is the twelve rows' one definition, factored out of the
// registration so a test can drive the SHIPPING row — its real mode, its real
// published curve, its real oracle — rather than a copy of its literals that
// can silently drift from it (IW15-008).
func inverterControlRows() []inverterControlRow {
	// noRideThrough IS GONE, and its deletion is curve plan #32's deliverable on
	// this file. It read, verbatim: "IEEE 2030.5's ride-through modes
	// (opModLVRTMustTrip / opModLVRTMayTrip / opModLVRTMomentaryCessation and
	// their HVRT / LFRT / HFRT counterparts) are curve-valued DERControl modes
	// that the bench's 2030.5 server cannot publish: gridsim's admin control API
	// (sim/gridsim/admin.go adminCtrlReq) exposes only the scalar modes, and its
	// curve API (sim/gridsim/curve.go) binds only Volt-VAr, Volt-Watt, Freq-Watt
	// and Watt-PF. With no way to put the mode on the wire there is nothing to
	// observe, so nothing about this row has been tested. Closing this needs a
	// ride-through curve mode in gridsim."
	//
	// Every clause of that was TRUE when it was written, which is why the two
	// rows it held were decided FAILs rather than skips. What replaced it:
	//
	//   the LEVER — sim/gridsim/curve.go's curveTypeForMode and setCurveLink now
	//   carry all ten ride-through modes, and its `curves` array binds several
	//   of them into ONE DERControl, which is the shape both Figures prescribe;
	//
	//   the REFEREE — internal/invariant/curves.go decodes models 707/708/709/710
	//   with SUB-CURVE addressing, so a MomCess curve is graded against the
	//   MomCess sub-curve and not against whichever one was non-empty;
	//
	//   the FIXTURE — sim/southbound/trip1547.go raised its declared NPt to 8,
	//   because BASIC-004's own Figure 4 prescribes a SEVEN-point must-trip
	//   curve and the sim could not hold the procedure's own values at four.
	//
	// The two rows are registered by registerRideThroughControls (ridethrough.go)
	// and are NOT in the slice below: their apparatus is a list of curves, which
	// controlMode has no field for. See registerInverterControls.

	return []inverterControlRow{
		// BASIC-004 (order 50) and BASIC-005 (order 51) USED TO SIT HERE as
		// unreachableMode rows. They are real measured rows now and live in
		// ridethrough.go — see the note on noRideThrough above.
		//
		// IW15-008's rule still governs everything below: an unreachable mode is
		// a row that was NOT TESTED, and it says so in a decided FAIL
		// (critModeUnauthorable) instead of the SKIP that let it roll up as a
		// passing row.
		//
		// The curve rows carry the IW15-008 southbound curve oracle: the
		// breakpoints they publish must be found ADOPTED and ENABLED in the
		// DER's own curve model, point for point and in order. The mode→model
		// mapping is stated on each row because a FAIL that names a register
		// bank has to be checkable by whoever reads the bundle.
		//
		// THE PUBLISHED CURVE IS THE CATALOG'S, and until 2026-08-15 it was not.
		// This row published (92,60)(98,0)(102,0)(108,-60) with no multipliers —
		// which is not Figure 6's curve at any scale. It is the shape of
		// gridsim's own STATIC FIXTURE (sim/gridsim/extended.go's
		// staticVoltVarCurve0, x 92/98/102/108, y +/-30), inherited when the row
		// was first written and never reconciled to the procedure.
		//
		// The defect is PRE-EXISTING and predates the legacy-curve work; what
		// changed is that it became REACHABLE AS A PASS. While every curve row's
		// southbound half was a decided FAIL on every bench, publishing the
		// wrong curve altered no verdict. With a legacy execution arm the row
		// can go GREEN — on content the certification procedure never asked for,
		// straight into a conformance bundle. That is the IW15-004 class
		// BASIC-013 has carried a pinning test for since it was repaired, and
		// no curve row had one until now
		// (TestCurveRows_PublishTheCatalogPrescribedValues).
		{"BASIC-006", 52, curveMode("opModVoltVar", &curveBinding{
			Mode: "volt_var",
			// CSIP CTP v1.3 BASIC-006, Figure 6 Volt-VAr Settings, Test Values:
			// (9100,4000) (9570,0) (10400,0) (10600,-4000) at 10^-2 on both axes
			// — 91.00 %V -> +40.00 %, 95.70 %V -> 0, 104.00 %V -> 0,
			// 106.00 %V -> -40.00 %.
			Points: []CurvePoint{{X: 9100, Y: 4000}, {X: 9570, Y: 0}, {X: 10400, Y: 0}, {X: 10600, Y: -4000}},
			XMult:  -2,
			YMult:  -2,
			// yRefType is NOT prescribed by Figure 6 — the Figure lists
			// CurveData, openLoopTms, the autonomous-Vref pair, curveType and
			// the two multipliers and no y reference at all. 3 (%statVarAvail)
			// is this suite's own choice from opModVoltVar's admissible set
			// {%setMaxW, %setMaxVar, %statVarAvail}, and it is load-bearing:
			// it translates to DeptRef 2 on 705 (0-based) and DeptRef 3 on 126
			// (1-based). The row states neither code; the referee derives each
			// from the standards text for the model it resolved to.
			YRefType: derUnitRefStatVarAvail,
			// openLoopTms 5, Figure 6's own Test Value against its own default
			// of 10 — hundredths of a second, per DERCurve.openLoopTms
			// (IEEE Std 2030.5-2018 p.253).
			//
			// It USED TO BE A MATERIAL GAP, and holding this row at FAIL for it
			// was correct while it lasted: a run that left the element off sent
			// the DUT the procedure's DEFAULT timing while the report claimed
			// the test condition. Curve plan #32 built the lever
			// (sim/gridsim/curve.go's OpenLoopTms), so the row now AUTHORS it
			// and holds only if the serve itself fails. What it does NOT gain is
			// a southbound assertion: no SunSpec curve bank on either generation
			// has a register for it (noOpenLoopTmsRegister), so the element is
			// named on every verdict as served-and-not-device-mappable rather
			// than quietly dropped between the wire and the oracle.
			OpenLoopTms: ptr(uint16(5)),
			// The autonomous-Vref pair, Figure 6's own Test Values (false, 0) —
			// AUTHORED SINCE 2026-08-15, where they used to be two gaps saying
			// the elements did not exist.
			//
			// They do exist: IEEE Std 2030.5-2018 declares autonomousVRefEnable
			// on DERCurve at p.252 and autonomousVRefTimeConstant at p.253, both
			// [0..1] and both opModVoltVar-only. The claim that they did not was
			// read out of the pre-publication draft schema (see the withdrawn
			// noVrefElementInSchema above), and it meant this row was omitting
			// two elements its own procedure prints while explaining that there
			// was nothing to omit.
			//
			// BOTH ARE IMMATERIAL BY THE ROW'S OWN TEST — Figure 6 prints the
			// same value in the Default and Test Values columns, and 2018 p.252
			// makes false the value of an ABSENT autonomousVRefEnable — so
			// authoring them changes no DUT behaviour that the previous omission
			// changed either. That is exactly why it is worth doing: the row can
			// now publish its whole Figure at zero risk to what it measures, and
			// the bundle stops carrying a false sentence about the standard.
			AutonomousVRefEnable:       ptr(false),
			AutonomousVRefTimeConstant: ptr(uint32(0)),
			Prescribed: "CSIP CTP v1.3 BASIC-006, Figure 6 Volt-VAr Settings, Test Values column. " +
				curveTypeAgreement,
			Model7xx:      sunspec.ModelDERVoltVar,
			Mapping7xx:    mappingVoltVar,
			ModelLegacy:   sunspec.ModelVoltVarLegacy,
			MappingLegacy: mappingVoltVarLegacy,
			// NO GAPS. This row's Figure 6 has five non-breakpoint settings —
			// openLoopTms, the autonomous-Vref pair, curveType and the two
			// multipliers — and as of 2026-08-15 this bench places every one of
			// them on the wire. The three entries that used to be here were:
			//
			//   autonomousVrefEnable / autonomousVrefTimeContant, held by a
			//   citation into the draft schema claiming the elements do not
			//   exist. They do (2018 p.252-253) and the row AUTHORS them now.
			//
			//   curveType 11, held by a note saying the CATALOG's number was
			//   the divergent one. It was the bench's; 2018 p.254 says 11 and
			//   p.250 says it again in opModVoltVar's own prose.
			//
			// A row with nothing left to disclose discloses nothing, and
			// critCurvePublishedTheProcedureValues says so positively rather
			// than reciting three withdrawn caveats.
		}), "a Volt-VAr curve"},
		// BASIC-007 (order 53, ramp rates) USED TO SIT HERE as an
		// unreachableMode row (IW15-008's "noRampRate"). It is a real measured
		// row now and lives in rampdefault.go — see registerInverterControls's
		// own note on why its apparatus does not fit this slice's shape.
		//
		// BASIC-008 and BASIC-009 STOPPED SKIPPING on 2026-08-15. Both publish
		// a STRUCTURE — a nested power factor with its excitation flag, a pair
		// of booleans — which no single int64 describes, so neither fitted
		// oracleBinding's shape and both were left with
		// critDEREffectUnobservable's hard SKIP: the DER was never read, and a
		// Skip is severity 0 in a roll-up that only raises. They are the last
		// two rows of the twelve in that state, and directoracle.go is the
		// binding shape they needed.
		//
		// For BASIC-008 the omission was sharper than a missing shape. The
		// grader existed: fixedpf_oracle.go's gradeFixedPFDirection is a
		// complete, independently-derived, fully-tested oracle for exactly this
		// row's content — magnitude AND direction, with the 2018 p.258 negation
		// performed once and cited — written after a real product inversion.
		// It had no production caller. The instrument was built, proved, and
		// never pointed at the device.
		//
		// The commanded value is passed IN rather than restated: figure8FixedPF
		// is the same variable the ControlRequest publishes, so the published
		// control and the oracle that judges it read one statement (IW14-003's
		// rule, in the shape a structure allows).
		{"BASIC-008", 54, directMode("opModFixedPFInjectW", oracleFixedPFInject(figure8FixedPF),
			func(r *ControlRequest) {
				r.FixedPFInjectW = &figure8FixedPF
			}), "a fixed power factor while injecting"},
		// BASIC-009's two axes have register homes on OPPOSITE generations —
		// opModConnect only in legacy model 123's Conn point, opModEnergize
		// only in 7xx model 703's enter-service permission — so on either bench
		// exactly one of them is observable and the other is unobservable BY
		// CONSTRUCTION. The oracle measures the half this DER can hold and
		// names the half it cannot on every verdict, the same way BASIC-012
		// handles its curve and droop halves; see oracleConnect.
		//
		// The legacy half is measurable at all only because this referee now
		// transcribes model 123 itself (internal/invariant/legacyctl.go). That
		// transcription DISAGREES with the product's at every offset, which the
		// verdict discloses rather than resolves — see M123Divergence.
		{"BASIC-009", 55, directMode("opModConnect", oracleConnect(false, false),
			func(r *ControlRequest) {
				r.Connect = ptr(false)
				r.Energize = ptr(false)
			}), "a connect/disconnect command"},
		// The commanded value is written ONCE, in scalarModeOracled, and the
		// oracle builder is handed to withOracle unapplied (IW14-003): the
		// published control and the oracle that judges it read the same number,
		// and the row can depart from it at run time when the DER already holds
		// it (see oracleBinding).
		//
		// AND IT MUST STILL BE THERE (hold.go). This is the only row of the
		// twelve that arms the persistence half, because it is the only one
		// whose control is a standing CONSTRAINT rather than a value:
		// opModMaxLimW is "the maximum active power generation level at which
		// an EndDevice may operate", and a ceiling applied and then relaxed
		// while the control is still active has not been complied with. The
		// arrival oracle returns the instant the register matches, so on its
		// own it cannot tell a held ceiling from one the gateway's next
		// reconcile tick undid — which is a real failure mode of an
		// arbitration that re-derives its desired state every pass.
		//
		// BASIC-013's opModFixedW is deliberately NOT armed: a setpoint the
		// gateway may legitimately re-arbitrate against a newer input is not a
		// standing constraint, and asserting persistence there would fail
		// correct behaviour. Arming it is one call and is a decision about the
		// product's contract, not about this apparatus.
		{"BASIC-010", 56, withHold(withOracle(scalarModeOracled("opModMaxLimW", 6000,
			func(r *ControlRequest, hundredths int64) {
				r.MaxLimW = ptr(hundredths)
			}), oracleMaxLimW), holdMaxLim), "a maximum active power limit"},
		// yRefType 1 (%setMaxW), NOT the 3 (%statVarAvail) this row published
		// until 2026-08-14. Three independent anchors say 1 and nothing says 3:
		// IEEE Std 2030.5-2018's own opModVoltWatt documentation (p.250, "The y
		// value specifies an active power output in %setMaxW"), the catalog's own prescribed value
		// for this row (Figure 11 Volt-Watt Settings — DERCurve.yRefType:
		// Default 1; Test Values 1), and the physics — a volt-WATT curve's y
		// axis is active power, and %statVarAvail is a REACTIVE reference.
		//
		// It became load-bearing rather than merely wrong when the product
		// started translating yRefType into the curve bank's DeptRef and
		// REFUSING what it cannot translate (lexa-gw cmd/modbus's curveDeptRef):
		// %setMaxW is the only y reference 2018 gives volt-watt (p.250), so 706
		// accepts only DeptRef=W_MAX_PCT and a curve naming %statVarAvail is now
		// answered cannot-comply. This row would have FAILED a correct DUT for a
		// defect in its own fixture.
		{"BASIC-011", 57, curveMode("opModVoltWatt", &curveBinding{
			Mode: "volt_watt",
			// CSIP CTP v1.3 BASIC-011, Figure 11 Volt-Watt Settings, Test
			// Values: (10000,10000) (10500,10000) (10900,0) at 10^-2 on both
			// axes — 100.00 %V -> 100.00 %W, 105.00 %V -> 100.00 %W,
			// 109.00 %V -> 0. THREE points, where this row published two of its
			// own; see BASIC-006 for the provenance of the values that were here.
			Points:   []CurvePoint{{X: 10000, Y: 10000}, {X: 10500, Y: 10000}, {X: 10900, Y: 0}},
			XMult:    -2,
			YMult:    -2,
			YRefType: derUnitRefSetMaxW, // Figure 11 prescribes yRefType 1
			Prescribed: "CSIP CTP v1.3 BASIC-011, Figure 11 Volt-Watt Settings, Test Values column. " +
				curveTypeAgreement,
			Model7xx:      sunspec.ModelDERVoltWatt,
			Mapping7xx:    mappingVoltWatt,
			ModelLegacy:   sunspec.ModelVoltWattLegacy,
			MappingLegacy: mappingVoltWattLegacy,
			// NO GAPS: Figure 11's only non-breakpoint settings are curveType,
			// the two multipliers and yRefType, and this bench sends all four.
			// The curveType 12 entry that used to sit here said the CATALOG
			// diverged from the standard; 2018 p.254 assigns opModVoltWatt the
			// code 12 and p.250 repeats it in the element's own prose, so the
			// catalog and the standard agree and it was the bench (emitting the
			// draft schema's 3) that did not.
		}), "a Volt-Watt curve"},
		// yRefType 1 (%setMaxW) for the same reasons as BASIC-011: IEEE Std
		// 2030.5-2018's opModFreqWatt documentation (p.248, "The y value specifies
		// a corresponding active power output in %setMaxW") and the catalog's own prescribed
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
		// 2018 p.248 gives opModFreqWatt's x as "a frequency in Hz", and this row
		// published xvalue=6000 with xMultiplier absent (0) — a DERCurve
		// declaring breakpoints at 6000 Hz and 6050 Hz. It changed no verdict
		// while the row's southbound half was a decided FAIL on every bench, but
		// the NORTHBOUND half is real evidence about what the DUT was offered,
		// and it stops being harmless the moment a legacy DER can actually
		// execute the curve: an oracle reading M134's Hz points would then be
		// comparing 60.00 Hz against a published 6000. 6000 x 10^-2 = 60.00 Hz
		// is what the row always meant.
		{"BASIC-012", 58, curveMode("opModFreqWatt", &curveBinding{
			Mode: "freq_watt",
			// CSIP CTP v1.3 BASIC-012, Figure 12 Frequency-Watt Settings, Test
			// Values: (5900,100) (5950,80) (6050,80) (6200,0) with
			// xMultiplier -2 and yMultiplier 0 — 59.00 Hz -> 100 %, 59.50 Hz ->
			// 80 %, 60.50 Hz -> 80 %, 62.00 Hz -> 0. Four points; this row
			// published two of its own.
			Points:   []CurvePoint{{X: 5900, Y: 100}, {X: 5950, Y: 80}, {X: 6050, Y: 80}, {X: 6200, Y: 0}},
			XMult:    -2,
			YMult:    0,
			YRefType: derUnitRefSetMaxW, // Figure 12 prescribes yRefType 1
			Prescribed: "CSIP CTP v1.3 BASIC-012, Figure 12 Frequency-Watt Settings, Test Values column " +
				"(BOTH halves: the opModFreqWatt DERCurve and the immediate opModFreqDroop)",
			// FIGURE 12'S OTHER HALF, NOW AUTHORED (curve plan #32).
			//
			// Figure 12 prescribes a frequency-WATT curve AND an immediate
			// frequency-DROOP control, on one DERControl ("Function =
			// Frequency-Watt -> opModFreqWatt (Curve); Function =
			// Frequency-Droop -> opModFreqDroop (Immediate)"), and gridsim had
			// no lever for the second anywhere — so this row published half of
			// its own procedure and held itself at FAIL saying so. The lever
			// exists now (sim/gridsim/freqdroop.go), it authors the droop on the
			// SAME control that carries the curve link, and the five values are
			// the Figure's own Test Values column verbatim, in the wire's units.
			//
			// THE UNITS THE FIGURE PRINTS ARE INTERNALLY INCONSISTENT AND THIS
			// ROW SENDS THEM ANYWAY. dBOF/dBUF are printed Default 36 / Test
			// 60030, and the catalog's own note says so: 36 reads as a dead band
			// of hundredths of Hz while 60030/59970 read as absolute frequencies
			// in millihertz, and the document does not reconcile the two.
			// IEEE 2030.5-2018 p.242 fixes the unit — thousandths of Hz — so what goes on the
			// wire is 60.030 Hz and 59.970 Hz, which is what the Test Values
			// column says under the schema's own unit. A bench that "corrected"
			// the procedure's numbers would be certifying a control the
			// procedure never asked for; the transcription question belongs to
			// whoever owns the document, and the row's job is to send what it
			// prints and to say what it means.
			Droop: &droopBinding{
				Settings: FreqDroopSettings{
					DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600,
				},
				Model7xx:             sunspec.ModelDERFreqDroop,
				Mapping7xx:           mappingFreqDroop7xx,
				NoRegisterHomeLegacy: noFreqDroopRegisterLegacy,
			},
			// NO GAPS: the curveType 0 entry that used to sit here said the
			// CATALOG diverged from the standard and that this bench was right
			// to emit something else. Both halves were wrong. IEEE 2030.5-2018
			// p.254 assigns opModFreqWatt the code 0, p.248 repeats it under the
			// element ("Specify DERCurveLink for curveType == 0"), and Figure
			// 12's Test Values column prints 0 — so the gap's own "Prescribed:
			// 0" was the conformant value all along, while the bench emitted the
			// draft schema's 1, which under 2018 is opModHFRTMayTrip. The row
			// disclosed a real divergence and named the wrong party for it.
			//
			// THE 7xx ARM, RE-ADJUDICATED (curve plan #32).
			//
			// It still names 711 as the model and still refuses to grade the
			// BREAKPOINTS against it — 711 has no point table, and asserting
			// something weaker there is the substitution this suite exists to
			// refuse (noFreqWattRegister, unchanged). What changed is that the
			// breakpoints are no longer the only thing this row authors: with
			// the droop on the wire, 711 is the EXACT register home of the other
			// half of the same Figure, and the product has an execution path for
			// it (the D5 landing: scheduler fan-out ModeFreqDroop ->
			// authority/advFreqDroop -> cmd/modbus executeDroopLocked ->
			// derbase.WriteFreqDroop). So on a 7xx DER this row is now a REAL
			// MEASUREMENT of the droop, reported with the breakpoint half named
			// as served-and-not-asserted, instead of a decided FAIL that could
			// never move whatever the product did.
			//
			// It goes RED against a gateway whose advanced axes are SHUT, and
			// that is the point: the freq-droop axis is admitted only by
			// AdvancedSupportedAxes, gated behind advanced_axes_enabled, so
			// with that gate closed the DUT answers cannot-comply at receipt,
			// model 711 keeps its factory parameters, and this row says exactly
			// that.
			//
			// WHICH POSTURE THE IMAGE SHIPS IS NOT THIS FILE'S CLAIM TO MAKE.
			// `"adv":"off"` was the default when this was written; gw bd1e288
			// flips it open. Stage-7 discipline is what makes that a non-event
			// here: the row is honest about a product that does not execute the
			// axis and goes green the day the switches open, without a line of
			// this file changing — which is also why the sentence above no
			// longer asserts a default it would have to be edited to keep
			// true.
			Model7xx:          sunspec.ModelDERFreqDroop,
			NoRegisterHome7xx: noFreqWattRegister,
			// The legacy arm is a real home for the CURVE. This is D2's
			// acceptance criterion. The droop half has no legacy home at all
			// (noFreqDroopRegisterLegacy), so the two generations measure
			// opposite halves of the same row — and each says which.
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
		// is worth stating because every other curve row's just became so. IEEE
		// Std 2030.5-2018 (p.251) gives Watt-PF's y as a signed power-factor
		// displacement under
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
				Mode:       "watt_pf",
				Points:     []CurvePoint{{X: 0, Y: 100}, {X: 50, Y: 98}, {X: 100, Y: 95}},
				YRefType:   derUnitRefStatVarAvail,
				Model7xx:   sunspec.ModelDERWattVar,
				Prescribed: basic015NoPrescribedCurve,
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
			// 7xx note gives: IEEE Std 2030.5-2018 defines no DERUnitRefType for a
			// power factor (p.256), DERCurve declares yRefType minOccurs=1 (p.253), so some code must
			// be sent and every choice is wrong in the same way. 131 carries no
			// DeptRef register at all, so the referee asserts none here rather
			// than inventing an expectation.
			&curveBinding{
				Mode:          "watt_pf",
				Points:        []CurvePoint{{X: 0, Y: 100}, {X: 50, Y: 98}, {X: 100, Y: 95}},
				YMult:         -2,
				YRefType:      derUnitRefStatVarAvail,
				Prescribed:    basic015NoPrescribedCurve,
				ModelLegacy:   sunspec.ModelWattPFLegacy,
				MappingLegacy: mappingWattPFLegacy,
			}), "an advanced (curve-based) inverter control"},

		// There is NO opModWattVar row here, and as of 2026-08-15 its absence is
		// a SCOPE fact rather than a bench gap. The two halves of the note that
		// used to stand here have swapped over, and it is rewritten rather than
		// left as a TODO, because the blocker it named has been closed and a
		// stale TODO reads to whoever finds it as work nobody has started.
		//
		// opModWattVar is the axis model 712 actually implements, and as of
		// lexa-proto 8a65431 + lexa-gw's curve P1 wave the product decodes it,
		// screens it, arbitrates it inside the reactive group and writes it to
		// 712 with read-back verification. It is the strongest curve axis this
		// DUT has and nothing here exercises it.
		//
		// THE BLOCKER WAS GRIDSIM AND IS NOT ANY MORE. This note read "there is
		// no lever that emits an <opModWattVar> DERCurveLink at all, so the
		// control cannot be placed on the wire", and curve plan #32 built it:
		// sim/gridsim/curve.go's curveTypeForMode carries a "watt_var" mode
		// mapping to csipmodel.CurveTypeWattVar (14 under IEEE Std 2030.5-2018
		// p.254; this note said 10 until IW15-027, which was the draft schema's
		// code and is opModLVRTMustTrip under the standard) and setCurveLink
		// sets ExtendedDERControlBase.OpModWattVar. A row that wanted the axis
		// could publish it today with no bench change at all.
		//
		// What remains — and what was always the SECOND reason — is that the
		// CATALOG HAS NO UID FOR IT. CSIP-CONF-v1.3's BASIC family stops at
		// BASIC-015 and no procedure in this catalog prescribes an opModWattVar
		// curve, so registering one would put a row in a conformance bundle
		// that no document asks for and would have to invent its Test Values.
		// This suite's rule is BASIC-006's Figure work stated in one line: a
		// value nothing asks for is a value nothing tests. When a document does
		// ask, the axis belongs on BASIC-015's sibling coverage or on an
		// aggregate row, not here.
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
//
// ── OPEN: these eleven rows measure PRECEDENCE and not its OUTCOME ──────────
//
// Every one of them grades the DUT's Response lifecycle — which control it
// reported Started, which it reported Superseded — and none of them reads the
// DER. The winner's own commanded ceiling (scenarioControl.MaxLimW) is right
// there on the fixture, the southbound instrument to check it exists and is
// proven (oracleMaxLimW, basic.go), and the assertion that would close the
// family is one sentence: the DER's own resolved active-power ceiling must be
// the WINNER's value and must not be the loser's.
//
// It is NOT wired, deliberately, and the reason is a timing one rather than an
// apparatus one. The southbound read happens once, at PostWait, at an instant
// decided by when the DUT's poll cycle completed — while these scenarios are
// SCHEDULES: BASIC-019 and BASIC-020 stage two non-overlapping controls 90 s
// apart, BASIC-022 opens its Service Point control 30 s after its System one,
// BASIC-023 staggers the ends. Which control is legitimately in force at the
// read instant is therefore a function of the scenario's own timeline, and a
// row that asserted the winner's ceiling without modelling that timeline would
// FAIL a correct DUT whenever the read landed in the other control's window.
// A false FAIL in a conformance bundle is worse than an unmeasured half, which
// is the one trade this suite's rules make in that direction.
//
// WHAT CLOSING IT NEEDS, so the next person does not have to re-derive it:
// evaluate each scenario's schedule at the read instant (the controls carry
// StartOffset and DurationS already), assert the winner's ceiling only where
// exactly one control can be in force there, and report a DECIDED
// unavailability naming the ambiguity where more than one can. That is a
// self-limiting design — it grades what the timeline makes unambiguous and says
// so where it does not — and it is a wave of its own rather than a pre-flash
// edit to eleven catalog rows on a bench nobody can re-run tonight.
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
