package suitemodbusserver

// suite.go binds this package's checks to their catalog uids.
//
// Two things about the binding are deliberate.
//
// First, ORDER. The checks run read-only first, then the ones that write, then
// the ones that abuse the framing, then the long-running reversion procedures.
// A discovery failure should be reported by DEV-1 rather than by whichever
// check happened to run first; a framing procedure that leaves a session
// unusable should not sit in front of nine procedures that need one; and a
// reversion test that occupies a minute of wall clock should not delay the
// evidence for everything else.
//
// Second, WHAT IS NOT REGISTERED. Eight of this document's twenty-four rows are
// marked inapplicable by the catalog — TCP-1 and RTU-1..5, because the DUT has
// neither a plain Modbus/TCP interface nor a serial one, and CRV-2 and CRV-3,
// because both need a writable second curve the DUT does not serve. They are
// left unregistered on purpose: the framework's coverage report prints an
// unregistered inapplicable case together with the catalog's own reason,
// whereas registering one would file it under "implemented" and lose that
// reason. Every APPLICABLE row of both documents is registered, including the
// ones that can only report SKIP against this DUT, because a registered SKIP
// with a reason is an engineering judgement and an unregistered row is an
// oversight.
//
// CRV-1 left that list on 2026-07-28. It was excluded on the claim that the
// gateway's chain builder rejects models 705-712 northbound, which had stopped
// being true: they are chained device-conditionally, per unit, and CRV-1 tests
// the read-only posture the gateway does implement. See checks_crv.go.

import "csip-tls-test/internal/certify"

// SuiteName is the -suite selector for this package.
const SuiteName = "modbus-server"

func init() { Register(certify.Default()) }

// Register binds every check this suite implements into reg. Tests call it with
// a private registry so they neither see nor disturb the process-wide one.
func Register(reg *certify.Registry) {
	// Capability tags. Every check needs a DUT address ("bench") and, on the
	// live bench, a role certificate to open the mbaps session ("pki").
	// "capture" is deliberately NOT required: a check that cannot cite is still
	// worth running, because it still drives the DUT and still reports what it
	// observed — it just says, on every affected assertion, that the wire did
	// not corroborate it. Requiring the tag would turn a partially evidenced
	// run into no run at all.
	needs := certify.WithRequires("bench", "pki")

	// Read-only discovery and model examination.
	reg.Register("ss-modbus-conf-v1.4::DEV-1", SuiteName, checkDEV1, needs, certify.WithOrder(10))
	reg.Register("ss-modbus-conf-v1.4::DEV-2", SuiteName, checkDEV2, needs, certify.WithOrder(20))
	reg.Register("ss-modbus-conf-v1.4::MOD-1", SuiteName, checkMOD1, needs, certify.WithOrder(30))
	reg.Register("ss-modbus-conf-v1.4::MOD-2", SuiteName, checkMOD2, needs, certify.WithOrder(40))
	reg.Register("ss-modbus-conf-v1.4::MB-2", SuiteName, checkMB2, needs, certify.WithOrder(50))

	// The IEEE 1547 profile sweeps, which are read-only and depend on the same
	// discovery walk.
	reg.Register("ss-1547-test-v1.1::MOD-4", SuiteName, checkMOD4, needs, certify.WithOrder(60))
	reg.Register("ss-1547-test-v1.1::2.4", SuiteName, checkSF, needs, certify.WithOrder(70))

	// CRV-1 reads the same chain and belongs here rather than with its
	// section-mates: CRV-2 and CRV-3 need a writable curve, CRV-1 needs a
	// read-only one. See checks_crv.go.
	//
	// It DOES write, from the Stage-6 legacy coverage — one FC 6 per served
	// legacy model — and it still sits with the read-only checks rather than
	// with the write procedures, because the ordering rule above is about state
	// and stream health and neither is at stake. Every one of those writes
	// carries the value the register already holds, so an accepted one changes
	// nothing, and all of them target the legacy 12x models, which the write
	// procedures below never touch (they work on 704). Putting CRV-1 after them
	// would only delay the evidence.
	reg.Register("ss-modbus-conf-v1.4::CRV-1", SuiteName, checkCRV1, needs, certify.WithOrder(75))

	// Exception generation: EXC-3 first because it writes nothing.
	reg.Register("ss-modbus-conf-v1.4::EXC-3", SuiteName, checkEXC3, needs, certify.WithOrder(80))
	reg.Register("ss-modbus-conf-v1.4::EXC-2", SuiteName, checkEXC2, needs, certify.WithOrder(90))
	reg.Register("ss-modbus-conf-v1.4::EXC-1", SuiteName, checkEXC1, needs, certify.WithOrder(100))

	// The write procedures.
	reg.Register("ss-modbus-conf-v1.4::MB-1", SuiteName, checkMB1, needs, certify.WithOrder(110))
	reg.Register("ss-modbus-conf-v1.4::MOD-3", SuiteName, checkMOD3, needs, certify.WithOrder(120))

	// Framing manipulation. TCP-2 can legitimately leave its session unusable,
	// so it runs after everything that needs a healthy one.
	reg.Register("ss-modbus-conf-v1.4::TCP-3", SuiteName, checkTCP3, needs, certify.WithOrder(130))
	reg.Register("ss-modbus-conf-v1.4::TCP-2", SuiteName, checkTCP2, needs, certify.WithOrder(140))

	// The reversion procedures, last: each occupies tens of seconds of wall
	// clock waiting for a timer it armed.
	reg.Register("ss-modbus-conf-v1.4::REV-1", SuiteName, checkREV1, needs, certify.WithOrder(150))
	reg.Register("ss-modbus-conf-v1.4::REV-2", SuiteName, checkREV2, needs, certify.WithOrder(160))
	reg.Register("ss-modbus-conf-v1.4::REV-3", SuiteName, checkREV3, needs, certify.WithOrder(170))
}

// Inapplicable lists the catalog uids of this suite's documents that are NOT
// registered, with the reason. It exists so the reason is in the code as well
// as in the catalog: a reader of this package should not have to open the
// catalog to learn why six of the v1.4 rows have no implementation.
var Inapplicable = map[string]string{
	"ss-modbus-conf-v1.4::TCP-1": "asserts a Modbus/TCP interface on port 502. The DUT has none: its " +
		"northbound Modbus is mbaps-only on :802 (no plaintext fallback), so a PASS here would be a claim " +
		"about a port that is closed.",
	"ss-modbus-conf-v1.4::RTU-1": "the DUT has no northbound serial interface.",
	"ss-modbus-conf-v1.4::RTU-2": "the DUT has no northbound serial interface, so it has no baud rate.",
	"ss-modbus-conf-v1.4::RTU-3": "the DUT has no northbound serial interface; the TCP twin of this " +
		"procedure, TCP-2, IS implemented.",
	"ss-modbus-conf-v1.4::RTU-4": "the DUT has no northbound serial interface, and MBAP has no broadcast.",
	"ss-modbus-conf-v1.4::RTU-5": "the DUT has no northbound serial interface; Model 1's Device Address " +
		"point addresses a serial slave, and the gateway allocates its Modbus unit identifiers itself " +
		"rather than accepting one written by a client.",
	"ss-modbus-conf-v1.4::CRV-2": "requires a WRITABLE second curve, and the DUT serves the staging " +
		"curve wholly not-implemented: every Crv2./Ctl2. field reads the sentinel and every write to one " +
		"is refused before ACK, so the 1547 profile's item G3 is not met and there is no AdptCrvReq " +
		"executor for the adopt handshake to run against. The write path is design Stage 5 and is not " +
		"built. Note that curve models ARE reachable northbound — CRV-1 is registered and tests exactly " +
		"the read-only posture that kills this row.",
	"ss-modbus-conf-v1.4::CRV-3": "requires the same writable second curve as CRV-2: an out-of-range " +
		"adopt request cannot be issued to a device that refuses every write to the staging curve, so " +
		"there is no error for the procedure to observe being reported.",
}
