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

import (
	"strings"

	"csip-tls-test/internal/certify"
)

func init() { Register(certify.Default()) }

// Register binds this suite's checks into a registry. The package-level init
// does it for certify.Default(); tests use their own registry so they neither
// see nor are seen by the global one.
//
// WithOrder groups the families in document order so a run's console output
// reads like the procedures document rather than like a map iteration. Ties
// break on uid, so the plan is fully deterministic either way.
func Register(reg *certify.Registry) {
	// register binds one row and attaches the pcap file name(s) that row's
	// Reporting Requirements subsection prescribes.
	//
	// The names come from capturenames.go's transcription of the document and
	// are looked up by the bare test id, which the uid already carries — so no
	// call site repeats them and no row can be given a name from a different
	// section by a copy-paste. A row whose Reporting Requirements ask for
	// documents rather than a capture (RBAC-004, RBAC-005, OPS-001) gets an
	// empty list, which declares nothing.
	register := func(uid string, check certify.Check, opts ...certify.Option) {
		id := uid
		if _, after, ok := strings.Cut(uid, "::"); ok {
			id = after
		}
		opts = append(opts, certify.WithCaptureArtifacts(CaptureNames(id)...))
		// roleScoped wraps EVERY registration, so a check inherits the
		// per-assertion direction rule without having to know it exists: a
		// client-procedure assertion on a run whose candidate does not claim
		// the Secure SunSpec client direction becomes NOT APPLICABLE rather
		// than a SKIP that reads like unfinished work. See roles.go.
		reg.Register(uid, suiteName, roleScoped(uid, check), opts...)
	}

	// §2.4 TLS Fundamentals.
	register("ssm-conf-v0.8::TLSF-001", tlsf001, certify.WithRequires("bench", "pki"), certify.WithOrder(10))
	register("ssm-conf-v0.8::TLSF-002", tlsf002, certify.WithRequires("bench", "pki"), certify.WithOrder(11))
	register("ssm-conf-v0.8::TLSF-003", tlsf003, certify.WithRequires("bench", "pki"), certify.WithOrder(12))
	register("ssm-conf-v0.8::TLSF-004", tlsf004, certify.WithRequires("bench", "pki"), certify.WithOrder(13))
	register("ssm-conf-v0.8::TLSF-005", tlsf005, certify.WithRequires("bench", "pki"), certify.WithOrder(14))
	register("ssm-conf-v0.8::TLSF-006", tlsf006, certify.WithRequires("bench", "pki"), certify.WithOrder(15))

	// §2.5 Cryptography.
	register("ssm-conf-v0.8::CRYP-001", cryp001, certify.WithRequires("bench", "pki"), certify.WithOrder(20))
	register("ssm-conf-v0.8::CRYP-002", cryp002, certify.WithRequires("bench", "pki"), certify.WithOrder(21))
	register("ssm-conf-v0.8::CRYP-003", cryp003, certify.WithRequires("bench"), certify.WithOrder(22))
	register("ssm-conf-v0.8::CRYP-004", cryp004, certify.WithRequires("bench"), certify.WithOrder(23))
	register("ssm-conf-v0.8::CRYP-005", cryp005, certify.WithRequires("bench"), certify.WithOrder(24))
	register("ssm-conf-v0.8::CRYP-006", cryp006, certify.WithRequires("bench"), certify.WithOrder(25))
	register("ssm-conf-v0.8::CRYP-007", cryp007, certify.WithRequires("bench"), certify.WithOrder(26))

	// §2.6 Public Key Infrastructure. PKI-005 is inapplicable — see above.
	register("ssm-conf-v0.8::PKI-001", pki001, certify.WithRequires("bench", "pki"), certify.WithOrder(30))
	register("ssm-conf-v0.8::PKI-002", pki002, certify.WithRequires("bench"), certify.WithOrder(31))
	register("ssm-conf-v0.8::PKI-003", pki003, certify.WithRequires("bench", "pki"), certify.WithOrder(32))
	register("ssm-conf-v0.8::PKI-004", pki004, certify.WithRequires("bench", "pki"), certify.WithOrder(33))
	register("ssm-conf-v0.8::PKI-006", pki006, certify.WithRequires("bench", "pki"), certify.WithOrder(34))
	register("ssm-conf-v0.8::PKI-007", pki007, certify.WithRequires("bench", "pki"), certify.WithOrder(35))
	register("ssm-conf-v0.8::PKI-008", pki008, certify.WithRequires("bench", "pki"), certify.WithOrder(36))
	// PKI-009's only evidence is a read of the DUT's southbound configuration,
	// so it needs gateway introspection and nothing else.
	register("ssm-conf-v0.8::PKI-009", pki009, certify.WithRequires("gateway"), certify.WithOrder(37))

	// §2.7 Protocol.
	register("ssm-conf-v0.8::PROT-001", prot001, certify.WithRequires("bench", "pki"), certify.WithOrder(40))
	register("ssm-conf-v0.8::PROT-002", prot002, certify.WithRequires("bench"), certify.WithOrder(41))
	register("ssm-conf-v0.8::PROT-003", prot003, certify.WithRequires("bench"), certify.WithOrder(42))
	register("ssm-conf-v0.8::PROT-004", prot004, certify.WithRequires("bench"), certify.WithOrder(43))

	// §2.8 Role-Based Access Control. RBAC-003 is inapplicable — see above.
	register("ssm-conf-v0.8::RBAC-001", rbac001, certify.WithRequires("bench", "pki"), certify.WithOrder(50))
	register("ssm-conf-v0.8::RBAC-002", rbac002, certify.WithRequires("bench", "pki"), certify.WithOrder(51))
	// RBAC-004 has no wire traffic at all: its evidence is the DUT's own rules
	// database, read read-only.
	register("ssm-conf-v0.8::RBAC-004", rbac004, certify.WithRequires("gateway"), certify.WithOrder(52))
	register("ssm-conf-v0.8::RBAC-005", rbac005, certify.WithRequires("bench", "pki"), certify.WithOrder(53))
	register("ssm-conf-v0.8::RBAC-006", rbac006, certify.WithRequires("bench", "pki"), certify.WithOrder(54))
	register("ssm-conf-v0.8::RBAC-007", rbac007, certify.WithRequires("bench", "pki"), certify.WithOrder(55))
	register("ssm-conf-v0.8::RBAC-008", rbac008, certify.WithRequires("bench", "pki"), certify.WithOrder(56))
	register("ssm-conf-v0.8::RBAC-009", rbac009, certify.WithRequires("bench", "pki"), certify.WithOrder(57))
	register("ssm-conf-v0.8::RBAC-010", rbac010, certify.WithRequires("gateway"), certify.WithOrder(58))
	register("ssm-conf-v0.8::RBAC-011", rbac011, certify.WithRequires("bench"), certify.WithOrder(59))
	register("ssm-conf-v0.8::RBAC-012", rbac012, certify.WithRequires("bench", "pki"), certify.WithOrder(60))

	// §2.9 Operational Security.
	register("ssm-conf-v0.8::OPS-001", ops001, certify.WithRequires("bench"), certify.WithOrder(70))
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
