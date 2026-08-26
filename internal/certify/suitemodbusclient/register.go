package suitemodbusclient

// register.go binds this suite's checks to their catalog uids.
//
// Every applicable uid in SS-MODBUS-CLIENT-CONF-v1.1 is registered, including
// the ones this bench can only SKIP. That is deliberate: the framework's
// coverage report cannot tell the difference between "nobody got to this row"
// and "an engineer looked at this row and concluded it cannot be driven here",
// and those two things must not read the same in a conformance bundle. A
// registered check that returns a SKIP carrying its reason is a judgement a
// reviewer can weigh and disagree with; an unregistered uid is a hole.
//
// CLI-5 is the one exception, and it is an exception now for a reason that did
// not exist when this file was written: the catalog marks it inapplicable
// (facts-dut-capability.md §6.2 — no RS-485 SunSpec server exists on this
// bench), and bundle.VerdictNotApplicable now gives that fact its own
// verdict, with its own reason and source, on every row nothing implements —
// see certify's scope.go (CatalogScope) and CAMPAIGNS.md §5. A row in that
// shape is no longer "a hole distinguishable only by omission": it is a
// reasoned, citable N/A the runner produces on its own from the catalog's own
// applicability record, and a suite-authored SKIP repeating the same fact
// would be the "old idiom" this campaign's N/A verdict exists to retire —
// see checks_write.go's header for WR-1, which stays registered for the
// opposite reason: its exclusion is CANDIDATE-specific (a manifest fact), not
// catalog-wide, so the row must stay reachable for a candidate that claims
// otherwise.
//
// # Ordering
//
// Order matters on a bench where the DUT's behaviour is what is being measured.
// The passive rows run first, so the bundle's discovery and framing evidence
// comes from a device in its steady state. The fault-injecting rows run after,
// each restoring the sim and waiting for a clean poll before it returns, so no
// row's evidence is contaminated by the previous row's provocation. The write
// rows run last, because they are the only ones that can reach outside this
// suite's own surface.

import (
	"time"

	"csip-tls-test/internal/certify"
)

func init() { Register(certify.Default()) }

// Register binds this suite's checks to a registry. It is exported so a test
// can bind them to a private registry rather than the process-wide default.
func Register(reg *certify.Registry) {
	const (
		cli1 = "ss-modbus-client-conf-v1.1::CLI-1"
		cli2 = "ss-modbus-client-conf-v1.1::CLI-2"
		cli3 = "ss-modbus-client-conf-v1.1::CLI-3"
		cli4 = "ss-modbus-client-conf-v1.1::CLI-4"
		// CLI-5 is intentionally absent — see the file doc.
		rd1 = "ss-modbus-client-conf-v1.1::READ-1"
		rd2 = "ss-modbus-client-conf-v1.1::READ-2"
		wr1 = "ss-modbus-client-conf-v1.1::WR-1"
		wr2 = "ss-modbus-client-conf-v1.1::WR-2"
		in1 = "ss-modbus-client-conf-v1.1::INFO-1"
		in2 = "ss-modbus-client-conf-v1.1::INFO-2"
		pr1 = "ss-modbus-client-conf-v1.1::PROT-1"
		pr2 = "ss-modbus-client-conf-v1.1::PROT-2"
		er1 = "ss-modbus-client-conf-v1.1::ERR-1"
		er2 = "ss-modbus-client-conf-v1.1::ERR-2"
		er3 = "ss-modbus-client-conf-v1.1::ERR-3"
	)

	// Wire-observing rows. "bench" because the suite needs the bench's
	// southbound sims to exist at all; "capture" because every assertion these
	// rows make is a citation into the pcap.
	wire := []certify.Option{certify.WithRequires("bench", "capture")}

	// Pass 1 — the DUT observed as it is.
	//
	// Every one of these now waits on the SIMULATOR rather than on a clock:
	// they force a rediscovery at a named control-plane epoch and block on the
	// sim's transaction ledger (or, where the criterion is about a whole read
	// cycle, on its poll barrier) until the DUT has actually met them. See
	// deterministic.go.
	//
	// The timeouts below are budgets for a DUT that is slow, not margins for a
	// guess. deterministic.go's pollBudget bounds ONE wait at 90 s — generous
	// against a 10 s poll because a client's reconnect-with-backoff after a
	// Modbus exception can legitimately trail a fault clear by several cycles —
	// and a row that performs several waits is registered with room for them.
	// See Registration.Timeout's own doc for why this is a per-registration
	// override rather than a bump to the run's global -timeout.
	reg.Register(rd2, Suite, checkREAD2, append(wire, certify.WithOrder(10), certify.WithTimeout(6*time.Minute))...)
	reg.Register(rd1, Suite, checkREAD1, append(wire, certify.WithOrder(11), certify.WithTimeout(4*time.Minute))...)
	reg.Register(cli2, Suite, checkCLI2, append(wire, certify.WithOrder(20), certify.WithTimeout(5*time.Minute))...)
	reg.Register(cli1, Suite, checkCLI1, append(wire, certify.WithOrder(21), certify.WithTimeout(5*time.Minute))...)
	// CLI-3 performs a rediscovery, a re-addressing and a recovery: three
	// waits. CLI-4 performs FOUR — one per canonical base plus the default.
	reg.Register(cli3, Suite, checkCLI3, append(wire, certify.WithOrder(22), certify.WithTimeout(8*time.Minute))...)
	reg.Register(cli4, Suite, checkCLI4, append(wire, certify.WithOrder(23), certify.WithTimeout(10*time.Minute))...)
	reg.Register(pr2, Suite, checkPROT2, append(wire, certify.WithOrder(30), certify.WithTimeout(6*time.Minute))...)
	reg.Register(er3, Suite, checkERR3, append(wire, certify.WithOrder(31), certify.WithTimeout(5*time.Minute))...)

	// Pass 2 — the DUT provoked. Each of these arms a fault at a named epoch,
	// waits for the DUT to meet it, and restores the sim's as-built baseline
	// before returning.
	//
	// ERR-1 is here now rather than in pass 1: it moves the server's SunSpec
	// map to the deliberately noncompliant 40001 and is a provoking row like
	// any other. It used to be a pure observation because the bench could not
	// make a noncompliant server at all.
	reg.Register(er1, Suite, checkERR1, append(wire, certify.WithOrder(40), certify.WithTimeout(8*time.Minute))...)
	reg.Register(in1, Suite, checkINFO1, append(wire, certify.WithOrder(41), certify.WithTimeout(6*time.Minute))...)
	// ERR-2 drives FIVE exception classes plus a recovery, each held on the
	// ledger; PROT-1 drives three readings, each with its own recovery.
	reg.Register(er2, Suite, checkERR2, append(wire, certify.WithOrder(42), certify.WithTimeout(12*time.Minute))...)
	reg.Register(in2, Suite, checkINFO2, append(wire, certify.WithOrder(43), certify.WithTimeout(8*time.Minute))...)
	reg.Register(pr1, Suite, checkPROT1, append(wire, certify.WithOrder(44), certify.WithTimeout(12*time.Minute))...)

	// Pass 3 — the rows that may reach the northbound surface. WR-1 stays
	// registered although it is N/A for the CANDIDATE this campaign runs
	// against today (see checks_write.go's header): scope.go's
	// RequirementScope excludes it Plan()-time only when the manifest
	// contradicts its Requires, so a manifest that DOES claim FC 6 still
	// reaches this check and its wire citation.
	reg.Register(wr1, Suite, checkWR1, append(wire, certify.WithOrder(50))...)
	reg.Register(wr2, Suite, checkWR2, append(wire, certify.WithOrder(51), certify.WithTimeout(10*time.Minute))...)
}
