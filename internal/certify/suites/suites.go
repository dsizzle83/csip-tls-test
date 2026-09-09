// Package suites is the one place in the tree that knows which conformance
// suites exist.
//
// # Why a package whose body is six blank imports
//
// A suite registers its checks from an init function, so a suite that nobody
// imports contributes nothing — silently. That is the failure this package
// exists to prevent. If cmd/certify carried the blank imports itself, then a
// test, a future tool, or a second binary would each carry their own list, and
// the day someone adds a seventh suite the lists drift: the CLI runs seven
// suites and the acceptance test proves six, or the coverage report claims a
// document is unaddressed because the binary that printed it never linked the
// package implementing it.
//
// So the list lives here, once, and everything that needs "all the suites"
// imports this package. [Registry] then hands back the process-wide registry
// with the guarantee that every suite in the tree is in it.
//
// # The registry is process-wide, and that is deliberate
//
// certify.Register panics on a duplicate uid. Two suites claiming the same
// catalog test case is a coordination bug — whose check runs? whose evidence
// lands in the bundle? — and the only honest outcome is a loud failure before
// any evidence is produced, at process start, rather than a quiet arbitrary
// winner at run time. Linking all six suites into one binary is therefore also
// the check that they do not collide, and it runs every time the CLI starts.
//
// # What is NOT here
//
// No suite selection, no filtering, no ordering. Which of the linked suites a
// particular run executes is the operator's business (-suite / -doc / -uid) and
// the runner's; this package only guarantees they are all present to be chosen
// from.
package suites

import (
	"sort"

	"csip-tls-test/internal/certify"

	// The six suites. Each registers its checks into certify.Default() from an
	// init function; the blank import is what links it in.
	//
	//	report              SS-CSIP-RESULTS-v1.1 + SS-MODBUS-RESULTS-v1.2
	//	                    (the submission report itself — the only suite whose
	//	                    subject is US rather than the DUT)
	//	suitecsip           CSIP-CONF-v1.3        (the DUT as 2030.5 client)
	//	suitemodbusclient   SS-MODBUS-CLIENT-CONF-v1.1 (the DUT as Modbus client)
	//	suitemodbusserver   SS-MODBUS-CONF-v1.4 + SS-1547-TEST-v1.0
	//	                    (the DUT as SunSpec Modbus server)
	//	suitepki            SS-TEST-PKI           (certificates and identity)
	//	suitessm            SSM-CONF-v0.8         (Secure SunSpec Modbus/TLS)
	_ "csip-tls-test/internal/certify/report"
	_ "csip-tls-test/internal/certify/suitecsip"
	_ "csip-tls-test/internal/certify/suitemodbusclient"
	_ "csip-tls-test/internal/certify/suitemodbusserver"
	_ "csip-tls-test/internal/certify/suitepki"
	_ "csip-tls-test/internal/certify/suitessm"
)

// Registry returns the process-wide registry, with every suite in the tree
// linked into it.
func Registry() *certify.Registry { return certify.Default() }

// Names lists the linked suites' short names, sorted — the values -suite
// accepts.
func Names() []string { return certify.Default().Suites() }

// Docs maps each suite to the catalog documents it registered checks against,
// which is what -list prints so an operator can go from "I need to cover
// SSM-CONF-v0.8" to "that is -suite ssm" without reading the source.
func Docs(cat *certify.Catalog) map[string][]string {
	seen := map[string]map[string]bool{}
	for _, reg := range certify.Default().Registrations() {
		c, ok := cat.ByUID(reg.UID)
		if !ok {
			continue
		}
		if seen[reg.Suite] == nil {
			seen[reg.Suite] = map[string]bool{}
		}
		seen[reg.Suite][c.Doc] = true
	}
	out := make(map[string][]string, len(seen))
	for suite, docs := range seen {
		list := make([]string, 0, len(docs))
		for d := range docs {
			list = append(list, d)
		}
		sort.Strings(list)
		out[suite] = list
	}
	return out
}
