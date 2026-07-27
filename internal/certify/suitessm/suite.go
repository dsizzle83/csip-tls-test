package suitessm

// suite.go binds every applicable SSM-CONF-v0.8 test case to its check.
//
// # Why every applicable uid is registered, including the ones that can only SKIP
//
// The registry's real deliverable is coverage of the standard, and coverage
// distinguishes three things a reader needs kept apart:
//
//	implemented    — a check exists and ran
//	inapplicable   — the catalog says the procedure does not apply to this
//	                 product, with the extraction's reason
//	unimplemented  — nobody wrote it
//
// A procedure this bench cannot drive (PKI-001's ten-root install, PKI-002's
// certificate management, RBAC-010's role creation) is NOT unimplemented: a
// deliberate decision was made about it, the half that IS observable is
// asserted, and the half that is not carries a SKIP naming the exact obstacle.
// Leaving those unregistered would report them as oversights and would make the
// coverage line — "35 of 37 applicable" — say something false about why.
//
// Two uids are deliberately NOT registered, because the catalog marks them
// inapplicable and registering them would move them out of the coverage
// report's Inapplicable bucket and silently discard the extraction's reason:
//
//	ssm-conf-v0.8::PKI-005  Multi-PKI Server Certificate Selection [S] — the DUT
//	                        holds exactly one server identity (certmgr chain
//	                        nb-mbaps-server/leaf, trust domain nb-mbaps-clients),
//	                        so an SNI-driven two-PKI selection procedure has
//	                        nothing to select between.
//	ssm-conf-v0.8::RBAC-003 Optional IEC 62351-8 Role Support — the DUT's single
//	                        deferred requirement row; configs/rbac/rules.json
//	                        ships only the four mandatory SunSpec roles plus one
//	                        vendor role.
//
// # Capability tags
//
// Requirements are kept minimal on purpose. A check whose tags are unmet is
// skipped by the runner BEFORE it executes, which is right for "there is no
// DUT" and wrong for "there is no key log": a check with no key log still has
// wire-level criteria it can assert, and only its decrypted assertions should
// degrade. So "keylog" is never required — the checks handle its absence
// themselves, with a SKIP assertion naming it — and "gateway" is required only
// by the rows whose entire evidence is a read of the DUT's own configuration.

import "csip-tls-test/internal/certify"

func init() { Register(certify.Default()) }

// Register binds this suite's checks into a registry. The package-level init
// does it for certify.Default(); tests use their own registry so they neither
// see nor are seen by the global one.
//
// WithOrder groups the families in document order so a run's console output
// reads like the procedures document rather than like a map iteration. Ties
// break on uid, so the plan is fully deterministic either way.
func Register(reg *certify.Registry) {
	// §2.4 TLS Fundamentals.
	reg.Register("ssm-conf-v0.8::TLSF-001", suiteName, tlsf001, certify.WithRequires("bench", "pki"), certify.WithOrder(10))
	reg.Register("ssm-conf-v0.8::TLSF-002", suiteName, tlsf002, certify.WithRequires("bench", "pki"), certify.WithOrder(11))
	reg.Register("ssm-conf-v0.8::TLSF-003", suiteName, tlsf003, certify.WithRequires("bench", "pki"), certify.WithOrder(12))
	reg.Register("ssm-conf-v0.8::TLSF-004", suiteName, tlsf004, certify.WithRequires("bench", "pki"), certify.WithOrder(13))
	reg.Register("ssm-conf-v0.8::TLSF-005", suiteName, tlsf005, certify.WithRequires("bench", "pki"), certify.WithOrder(14))
	reg.Register("ssm-conf-v0.8::TLSF-006", suiteName, tlsf006, certify.WithRequires("bench", "pki"), certify.WithOrder(15))

	// §2.5 Cryptography.
	reg.Register("ssm-conf-v0.8::CRYP-001", suiteName, cryp001, certify.WithRequires("bench", "pki"), certify.WithOrder(20))
	reg.Register("ssm-conf-v0.8::CRYP-002", suiteName, cryp002, certify.WithRequires("bench", "pki"), certify.WithOrder(21))
	reg.Register("ssm-conf-v0.8::CRYP-003", suiteName, cryp003, certify.WithRequires("bench"), certify.WithOrder(22))
	reg.Register("ssm-conf-v0.8::CRYP-004", suiteName, cryp004, certify.WithRequires("bench"), certify.WithOrder(23))
	reg.Register("ssm-conf-v0.8::CRYP-005", suiteName, cryp005, certify.WithRequires("bench"), certify.WithOrder(24))
	reg.Register("ssm-conf-v0.8::CRYP-006", suiteName, cryp006, certify.WithRequires("bench"), certify.WithOrder(25))
	reg.Register("ssm-conf-v0.8::CRYP-007", suiteName, cryp007, certify.WithRequires("bench"), certify.WithOrder(26))

	// §2.6 Public Key Infrastructure. PKI-005 is inapplicable — see above.
	reg.Register("ssm-conf-v0.8::PKI-001", suiteName, pki001, certify.WithRequires("bench", "pki"), certify.WithOrder(30))
	reg.Register("ssm-conf-v0.8::PKI-002", suiteName, pki002, certify.WithRequires("bench"), certify.WithOrder(31))
	reg.Register("ssm-conf-v0.8::PKI-003", suiteName, pki003, certify.WithRequires("bench", "pki"), certify.WithOrder(32))
	reg.Register("ssm-conf-v0.8::PKI-004", suiteName, pki004, certify.WithRequires("bench", "pki"), certify.WithOrder(33))
	reg.Register("ssm-conf-v0.8::PKI-006", suiteName, pki006, certify.WithRequires("bench", "pki"), certify.WithOrder(34))
	reg.Register("ssm-conf-v0.8::PKI-007", suiteName, pki007, certify.WithRequires("bench", "pki"), certify.WithOrder(35))
	reg.Register("ssm-conf-v0.8::PKI-008", suiteName, pki008, certify.WithRequires("bench", "pki"), certify.WithOrder(36))
	// PKI-009's only evidence is a read of the DUT's southbound configuration,
	// so it needs gateway introspection and nothing else.
	reg.Register("ssm-conf-v0.8::PKI-009", suiteName, pki009, certify.WithRequires("gateway"), certify.WithOrder(37))

	// §2.7 Protocol.
	reg.Register("ssm-conf-v0.8::PROT-001", suiteName, prot001, certify.WithRequires("bench", "pki"), certify.WithOrder(40))
	reg.Register("ssm-conf-v0.8::PROT-002", suiteName, prot002, certify.WithRequires("bench"), certify.WithOrder(41))
	reg.Register("ssm-conf-v0.8::PROT-003", suiteName, prot003, certify.WithRequires("bench"), certify.WithOrder(42))
	reg.Register("ssm-conf-v0.8::PROT-004", suiteName, prot004, certify.WithRequires("bench"), certify.WithOrder(43))

	// §2.8 Role-Based Access Control. RBAC-003 is inapplicable — see above.
	reg.Register("ssm-conf-v0.8::RBAC-001", suiteName, rbac001, certify.WithRequires("bench", "pki"), certify.WithOrder(50))
	reg.Register("ssm-conf-v0.8::RBAC-002", suiteName, rbac002, certify.WithRequires("bench", "pki"), certify.WithOrder(51))
	// RBAC-004 has no wire traffic at all: its evidence is the DUT's own rules
	// database, read read-only.
	reg.Register("ssm-conf-v0.8::RBAC-004", suiteName, rbac004, certify.WithRequires("gateway"), certify.WithOrder(52))
	reg.Register("ssm-conf-v0.8::RBAC-005", suiteName, rbac005, certify.WithRequires("bench", "pki"), certify.WithOrder(53))
	reg.Register("ssm-conf-v0.8::RBAC-006", suiteName, rbac006, certify.WithRequires("bench", "pki"), certify.WithOrder(54))
	reg.Register("ssm-conf-v0.8::RBAC-007", suiteName, rbac007, certify.WithRequires("bench", "pki"), certify.WithOrder(55))
	reg.Register("ssm-conf-v0.8::RBAC-008", suiteName, rbac008, certify.WithRequires("bench", "pki"), certify.WithOrder(56))
	reg.Register("ssm-conf-v0.8::RBAC-009", suiteName, rbac009, certify.WithRequires("bench", "pki"), certify.WithOrder(57))
	reg.Register("ssm-conf-v0.8::RBAC-010", suiteName, rbac010, certify.WithRequires("gateway"), certify.WithOrder(58))
	reg.Register("ssm-conf-v0.8::RBAC-011", suiteName, rbac011, certify.WithRequires("bench"), certify.WithOrder(59))
	reg.Register("ssm-conf-v0.8::RBAC-012", suiteName, rbac012, certify.WithRequires("bench", "pki"), certify.WithOrder(60))

	// §2.9 Operational Security.
	reg.Register("ssm-conf-v0.8::OPS-001", suiteName, ops001, certify.WithRequires("bench"), certify.WithOrder(70))
}

// InapplicableUIDs are the SSM-CONF-v0.8 cases this suite deliberately does not
// register, with the reason. They are exported so a coverage audit can assert
// that the omissions are the intended ones rather than an accident.
var InapplicableUIDs = map[string]string{
	"ssm-conf-v0.8::PKI-005": "the DUT holds exactly one mbaps server identity, so a two-PKI " +
		"server-certificate selection procedure has nothing to select between",
	"ssm-conf-v0.8::RBAC-003": "the optional IEC 62351-8 roles are the DUT's single deferred " +
		"requirement row; its rules database ships only the mandatory SunSpec roles plus one vendor role",
}
