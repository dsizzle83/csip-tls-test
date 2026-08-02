package suitemodbusclient

// register.go binds this suite's checks to their catalog uids.
//
// Every applicable uid in SS-MODBUS-CLIENT-CONF-v1.1 is registered, including
// the ones this bench can only SKIP, and CLI-5 which the catalog marks
// inapplicable. That is deliberate: the framework's coverage report cannot tell
// the difference between "nobody got to this row" and "an engineer looked at
// this row and concluded it cannot be driven here", and those two things must
// not read the same in a conformance bundle. A registered check that returns a
// SKIP carrying its reason is a judgement a reviewer can weigh and disagree
// with; an unregistered uid is a hole.
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
		cli5 = "ss-modbus-client-conf-v1.1::CLI-5"
		rd1  = "ss-modbus-client-conf-v1.1::READ-1"
		rd2  = "ss-modbus-client-conf-v1.1::READ-2"
		wr1  = "ss-modbus-client-conf-v1.1::WR-1"
		wr2  = "ss-modbus-client-conf-v1.1::WR-2"
		in1  = "ss-modbus-client-conf-v1.1::INFO-1"
		in2  = "ss-modbus-client-conf-v1.1::INFO-2"
		pr1  = "ss-modbus-client-conf-v1.1::PROT-1"
		pr2  = "ss-modbus-client-conf-v1.1::PROT-2"
		er1  = "ss-modbus-client-conf-v1.1::ERR-1"
		er2  = "ss-modbus-client-conf-v1.1::ERR-2"
		er3  = "ss-modbus-client-conf-v1.1::ERR-3"
	)

	// Wire-observing rows. "bench" because the suite needs the bench's
	// southbound sims to exist at all; "capture" because every assertion these
	// rows make is a citation into the pcap.
	wire := []certify.Option{certify.WithRequires("bench", "capture")}

	// Pass 1 — the DUT observed as it is.
	//
	// CLI-4 and READ-2 carry an explicit WithTimeout: a live-hardware run
	// (runs/warnmeas-mc-ssm-20260802T134537) showed the DUT is an autonomous
	// gateway on its OWN ~10s poll cadence, and both checks now HOLD a
	// relocated base / a post-reconnect window until a fresh readback
	// confirms a complete poll cycle (awaitJournalEvidence, up to several
	// cycles per hold — CLI-4 holds THREE times, once per base) rather than
	// guessing a fixed cycle count. That can comfortably exceed
	// DefaultCheckTimeout (3 minutes) in the worst case; see Registration.
	// Timeout's own doc for why this is a per-registration override rather
	// than a bump to the run's global -timeout.
	reg.Register(rd2, Suite, checkREAD2, append(wire, certify.WithOrder(10), certify.WithTimeout(4*time.Minute))...)
	reg.Register(rd1, Suite, checkREAD1, append(wire, certify.WithOrder(11))...)
	reg.Register(cli2, Suite, checkCLI2, append(wire, certify.WithOrder(20))...)
	reg.Register(cli1, Suite, checkCLI1, append(wire, certify.WithOrder(21))...)
	reg.Register(cli3, Suite, checkCLI3, append(wire, certify.WithOrder(22))...)
	reg.Register(cli4, Suite, checkCLI4, append(wire, certify.WithOrder(23), certify.WithTimeout(7*time.Minute))...)
	reg.Register(pr2, Suite, checkPROT2, append(wire, certify.WithOrder(30))...)
	reg.Register(er3, Suite, checkERR3, append(wire, certify.WithOrder(31))...)
	reg.Register(er1, Suite, checkERR1, append(wire, certify.WithOrder(32))...)

	// Pass 2 — the DUT provoked. Each of these arms a fault on the server and
	// clears it before returning.
	//
	// ERR-2 and PROT-1 also carry an explicit WithTimeout, for the same
	// live-run reason: each fault phase now holds until the DUT's journal
	// confirms a reaction, and recovery is held the same way through the
	// DUT's reconnect-with-backoff, rather than a fixed guess that already
	// produced a FAIL (ERR-2) and several missed-window SKIPs (PROT-1) on
	// real hardware.
	reg.Register(in1, Suite, checkINFO1, append(wire, certify.WithOrder(40))...)
	reg.Register(er2, Suite, checkERR2, append(wire, certify.WithOrder(41), certify.WithTimeout(6*time.Minute))...)
	reg.Register(in2, Suite, checkINFO2, append(wire, certify.WithOrder(42))...)
	reg.Register(pr1, Suite, checkPROT1, append(wire, certify.WithOrder(43), certify.WithTimeout(6*time.Minute))...)

	// Pass 3 — the rows that may reach the northbound surface.
	reg.Register(wr1, Suite, checkWR1, append(wire, certify.WithOrder(50))...)
	reg.Register(wr2, Suite, checkWR2, append(wire, certify.WithOrder(51))...)

	// Inapplicable, registered so it is accounted for rather than missing.
	reg.Register(cli5, Suite, checkCLI5, certify.WithOrder(60))
}
