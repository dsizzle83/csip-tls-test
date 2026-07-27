package report

// cases.go lists the two documents' case IDs in document order.
//
// Two things need it. The readiness report sorts by it, so a reader sees the
// requirements in the order the specification states them rather than in the
// order Go's sort produces (which puts RPT-KV-10 before RPT-KV-2). And the
// suite's registration test walks it against the committed catalog, so a case
// the extraction adds — or renames — fails a test here rather than silently
// dropping out of coverage.

// CSIPCaseIDs are SS-CSIP-RESULTS-v1.1's 47 case IDs in document order. Note
// the gaps: there is no RPT-009, no RPT-042..049, no RPT-056..059. They are the
// extraction's numbering, not omissions.
var CSIPCaseIDs = []string{
	"RPT-001", "RPT-002", "RPT-003", "RPT-004", "RPT-005", "RPT-006", "RPT-007", "RPT-008",
	"RPT-010", "RPT-011", "RPT-012", "RPT-013", "RPT-014", "RPT-015", "RPT-016", "RPT-017",
	"RPT-018", "RPT-019", "RPT-020", "RPT-021", "RPT-022", "RPT-023", "RPT-024", "RPT-025",
	"RPT-026", "RPT-027", "RPT-028", "RPT-029", "RPT-030", "RPT-031", "RPT-032", "RPT-033",
	"RPT-034", "RPT-035", "RPT-036", "RPT-037", "RPT-038", "RPT-039", "RPT-040", "RPT-041",
	"RPT-050", "RPT-051", "RPT-052", "RPT-053", "RPT-054", "RPT-055", "RPT-060",
}

// ModbusCaseIDs are SS-MODBUS-RESULTS-v1.2's 54 case IDs in document order.
var ModbusCaseIDs = []string{
	"RPT-APX-1", "RPT-APX-2",
	"RPT-GEN-1", "RPT-GEN-2", "RPT-GEN-3",
	"RPT-KV-1", "RPT-KV-2", "RPT-KV-3", "RPT-KV-4", "RPT-KV-5", "RPT-KV-6", "RPT-KV-7",
	"RPT-KV-8", "RPT-KV-9", "RPT-KV-10", "RPT-KV-11", "RPT-KV-12", "RPT-KV-13", "RPT-KV-14",
	"RPT-KV-15", "RPT-KV-16", "RPT-KV-17", "RPT-KV-18", "RPT-KV-19", "RPT-KV-20", "RPT-KV-21",
	"RPT-KV-22", "RPT-KV-23", "RPT-KV-24", "RPT-KV-25", "RPT-KV-26", "RPT-KV-27", "RPT-KV-28",
	"RPT-KV-29", "RPT-KV-30",
	"RPT-LOG-1", "RPT-LOG-2", "RPT-LOG-3", "RPT-LOG-4", "RPT-LOG-5", "RPT-LOG-6", "RPT-LOG-7",
	"RPT-LOG-8", "RPT-LOG-9", "RPT-LOG-10", "RPT-LOG-11", "RPT-LOG-12", "RPT-LOG-13",
	"RPT-LOG-14", "RPT-LOG-15", "RPT-LOG-16",
	"RPT-TRR-1", "RPT-TRR-2", "RPT-TRR-3",
}

// InapplicableCaseIDs are the four rows the catalog marks inapplicable to this
// product, and which this suite therefore does NOT register.
//
// The choice is deliberate. Registering a check that could only ever SKIP would
// move these rows out of the coverage report's "Not applicable to this product"
// section — where they appear WITH the extraction's reason — and into
// "Implemented", where a reader would have to open the bundle to discover the
// row was never really exercised. Leaving them unregistered keeps the reason
// visible at the place a reviewer looks first.
//
// Their substance is not lost: the readiness report assesses RPT-APX-1 and
// RPT-APX-2 (the laboratory and offering enumerations) against any supplied
// configuration, because those enumerations are the only mechanical check that
// distinguishes a real submission from a bench rehearsal.
var InapplicableCaseIDs = map[string]string{
	"RPT-005": "the DUT is a CSIP client, not an aggregator client",
	"RPT-006": "the DUT is a CSIP client, not a 2030.5 server",
	"RPT-APX-1": "the authorized-laboratory enumeration is a fact about SunSpec's programme, " +
		"not something a bench run can execute; the readiness report validates a supplied value against it",
	"RPT-APX-2": "the certification-offering enumeration is likewise a programme fact; " +
		"the readiness report validates a supplied value against it",
}
