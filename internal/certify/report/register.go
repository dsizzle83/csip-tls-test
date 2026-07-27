package report

// register.go binds this suite's checks to the framework.
//
// Two entry points. The package's init registers into certify.Default(), which
// is what a suite binary gets by importing this package for its side effects.
// RegisterInto takes a caller-supplied registry, which is what the tests use so
// they can build and inspect a registry the global one never sees — the same
// separation certify.NewRegistry exists for.
//
// What is NOT registered is as deliberate as what is. Four catalog rows —
// RPT-005, RPT-006, RPT-APX-1, RPT-APX-2 — are marked inapplicable by the
// extraction, and registering a check that could only ever SKIP would move them
// out of the coverage report's "Not applicable to this product" section, where
// they appear with the extraction's own reason, into "Implemented", where a
// reader would have to open the bundle to find out the row was never exercised.
// See InapplicableCaseIDs.

import "csip-tls-test/internal/certify"

func init() { RegisterInto(certify.Default()) }

// RegisterInto binds every applicable SS-CSIP-RESULTS-v1.1 and
// SS-MODBUS-RESULTS-v1.2 case to a fresh suite.
func RegisterInto(reg *certify.Registry) *Suite {
	s := NewSuite()
	s.Register(reg)
	return s
}

// Register binds this suite's checks into reg.
func (s *Suite) Register(reg *certify.Registry) {
	s.registerCSIP(reg)
	s.registerModbus(reg)
}
