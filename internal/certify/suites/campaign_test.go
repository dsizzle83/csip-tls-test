package suites_test

// campaign_test.go holds the three TABLES the campaign machinery rests on
// against the two things they describe: the LINKED suites and the REAL catalog.
//
// This is the only package that can do it. certify cannot import suites (suites
// imports certify), so certify's own tests have to mirror the suite map in a
// fixture; here the real registrations and the real 283-row catalog are both in
// scope, and every drift between them and the tables shows up as a failure with
// a name.

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suites"
)

func catalog(t *testing.T) *certify.Catalog {
	t.Helper()
	cat, err := certify.Load(filepath.Join("..", "..", "..", certify.CatalogFile))
	if err != nil {
		t.Fatalf("load the catalog: %v", err)
	}
	return cat
}

// ── the campaign table against the linked suites ──────────────────────────

func TestCampaignSuitesAllExistInTheLinkedRegistry(t *testing.T) {
	have := map[string]bool{}
	for _, s := range suites.Names() {
		have[s] = true
	}
	for _, spec := range certify.Campaigns() {
		for _, s := range spec.Suites {
			if !have[s] {
				t.Errorf("campaign %q expands to suite %q, which nothing registers (have: %s). The "+
					"campaign would silently select fewer rows than it claims",
					spec.Name, s, strings.Join(suites.Names(), ", "))
			}
		}
	}
}

// Every suite must belong to exactly one campaign, or be deliberately outside
// them all. A suite in NO campaign is a protocol lane nobody can run a gating
// run for; a suite in TWO is a row whose verdict belongs to two claims.
func TestEverySuiteIsInAtMostOneCampaign(t *testing.T) {
	// results-report is the one suite deliberately outside the campaigns: its
	// subject is THIS TOOL's submission output, not the DUT, so it has no DUT
	// precondition and no protocol lane of its own.
	const outsideCampaigns = "results-report"

	owner := map[string]certify.Campaign{}
	for _, spec := range certify.Campaigns() {
		for _, s := range spec.Suites {
			if prev, dup := owner[s]; dup {
				t.Errorf("suite %q is in both the %s and %s campaigns", s, prev, spec.Name)
			}
			owner[s] = spec.Name
		}
	}
	for _, s := range suites.Names() {
		if s == outsideCampaigns {
			if _, in := owner[s]; in {
				t.Errorf("suite %q was expected to sit outside the campaigns and is in %q", s, owner[s])
			}
			continue
		}
		if _, in := owner[s]; !in {
			t.Errorf("suite %q is in no campaign, so no gating run can ever cover it. Add it to a "+
				"campaign or state here why it belongs outside them", s)
		}
	}
}

// ── the authority table against the catalog ───────────────────────────────

// Every uid in the classification must be a row that exists. A stale entry
// classifies nothing and silently narrows the precondition.
func TestAuthorityTableUIDsExistInTheCatalog(t *testing.T) {
	cat := catalog(t)
	for _, uid := range certify.ClassifiedAuthorityUIDs() {
		if _, ok := cat.ByUID(uid); !ok {
			t.Errorf("the authority classification names %q, which the catalog does not contain", uid)
		}
	}
}

func TestAuthorityTableEntriesCarryAReason(t *testing.T) {
	for _, uid := range certify.ClassifiedAuthorityUIDs() {
		a, because, ok := certify.AuthorityPreconditionFor(uid)
		if !ok {
			t.Fatalf("%s is listed but does not resolve", uid)
		}
		if a != certify.AuthorityCSIP && a != certify.AuthorityMBAPS {
			t.Errorf("%s requires posture %q; only csip and mbaps are lanes a row can need", uid, a)
		}
		if len(strings.TrimSpace(because)) < 40 {
			t.Errorf("%s carries no usable reason (%q). The reason IS the refusal message", uid, because)
		}
	}
}

// THE RESIDUE TEST. Every row a campaign will EXECUTE is either classified, or
// listed below as deliberately unclassified with a justification. A new catalog
// row therefore cannot join a campaign without somebody deciding, in writing,
// which control lane it needs — which is the property the old RBAC-prefix guard
// could not have.
func TestAuthorityClassificationResidueIsAcknowledged(t *testing.T) {
	// Rows a campaign runs that need NO control-authority posture: they read,
	// discover, or exercise the transport, and measure the same thing under
	// every posture. Grouped by why.
	unclassified := map[string]string{
		// CSIP: discovery, security and read-only resource walks.
		"csip-conf-v1.3::COMM-002":  "out-of-band discovery: no control path involved",
		"csip-conf-v1.3::COMM-003":  "TLS/identity: transport, not control",
		"csip-conf-v1.3::COMM-004":  "certificate chain validation: transport, not control",
		"csip-conf-v1.3::COMM-004A": "certificate chain depth 2: transport, not control",
		"csip-conf-v1.3::COMM-004B": "certificate chain depth 3: transport, not control",
		"csip-conf-v1.3::COMM-004C": "certificate chain depth 4: transport, not control",
		"csip-conf-v1.3::COMM-004D": "certificate rejection: transport, not control",
		"csip-conf-v1.3::COMM-004E": "certificate rejection: transport, not control",
		"csip-conf-v1.3::COMM-004F": "certificate rejection: transport, not control",
		"csip-conf-v1.3::COMM-004G": "certificate rejection: transport, not control",
		"csip-conf-v1.3::CORE-003":  "polling cadence: a read loop",
		"csip-conf-v1.3::CORE-005":  "time synchronisation: a read",
		"csip-conf-v1.3::CORE-009":  "EndDevice resource walk: a read",
		"csip-conf-v1.3::CORE-010":  "FunctionSetAssignments walk: a read",
		"csip-conf-v1.3::CORE-011":  "FunctionSetAssignments walk: a read",
		"csip-conf-v1.3::CORE-014":  "DERSettings walk: a read",
		"csip-conf-v1.3::BASIC-001": "DER identification: a read",
		"csip-conf-v1.3::BASIC-002": "group management: a read of the topology resources",
		"csip-conf-v1.3::BASIC-003": "group management: a read of the topology resources",
		"csip-conf-v1.3::BASIC-027": "alarms: the DUT REPORTS, it is not commanded",
		"csip-conf-v1.3::BASIC-028": "inverter status: the DUT REPORTS",
		"csip-conf-v1.3::BASIC-029": "meter reading: the DUT REPORTS",
		"csip-conf-v1.3::ERR-001":   "error handling on a malformed server response: no control applied",

		// Secure SunSpec Modbus: transport, crypto and identity.
		"ssm-conf-v0.8::CRYP-001": "TLS cipher suites: transport",
		"ssm-conf-v0.8::CRYP-002": "TLS cipher suites: transport",
		"ssm-conf-v0.8::CRYP-003": "TLS cipher suites: transport",
		"ssm-conf-v0.8::CRYP-004": "TLS curves: transport",
		"ssm-conf-v0.8::CRYP-005": "TLS hashes: transport",
		"ssm-conf-v0.8::CRYP-006": "IANA registry compliance: transport",
		"ssm-conf-v0.8::CRYP-007": "cipher selection: transport",
		"ssm-conf-v0.8::OPS-001":  "export compliance: a property of the build",
		"ssm-conf-v0.8::PKI-001":  "root store: identity, not control",
		"ssm-conf-v0.8::PKI-002":  "certificate management: identity, not control",
		"ssm-conf-v0.8::PKI-003":  "public network security: identity, not control",
		"ssm-conf-v0.8::PKI-004":  "chain delivery: identity, not control",
		"ssm-conf-v0.8::PKI-006":  "session resumption: transport",
		"ssm-conf-v0.8::PKI-007":  "RFC 5280 compliance: identity, not control",
		"ssm-conf-v0.8::PKI-008":  "X.509v3 identity: identity, not control",
		"ssm-conf-v0.8::PKI-009":  "self-signed certificate support: identity, not control",
		"ssm-conf-v0.8::PROT-001": "MBAP integrity: framing",
		"ssm-conf-v0.8::PROT-002": "fragment length negotiation: framing",
		"ssm-conf-v0.8::PROT-003": "TLS compression: transport",
		"ssm-conf-v0.8::PROT-004": "renegotiation indication: transport",
		"ssm-conf-v0.8::TLSF-001": "TLS 1.2 basic operation: transport",
		"ssm-conf-v0.8::TLSF-002": "TLS 1.3 basic operation: transport",
		"ssm-conf-v0.8::TLSF-003": "bad certificate detection: transport",
		"ssm-conf-v0.8::TLSF-004": "fatal alert on missing certificate: transport",
		"ssm-conf-v0.8::TLSF-005": "fatal alert persistence: transport",
		"ssm-conf-v0.8::TLSF-006": "CertificateRequest verification: transport",

		// SunSpec Modbus server: discovery and reads.
		"ss-modbus-conf-v1.4::DEV-1": "general discovery: a read",
		"ss-modbus-conf-v1.4::DEV-2": "model 1 support: a read",
		"ss-modbus-conf-v1.4::MOD-1": "model implementation: a read",
		"ss-modbus-conf-v1.4::MOD-2": "model read",
		"ss-modbus-conf-v1.4::MB-2":  "single register read",
		"ss-modbus-conf-v1.4::EXC-3": "illegal function code: a malformed REQUEST, not a control write",
		"ss-modbus-conf-v1.4::TCP-2": "partial request: framing",
		"ss-modbus-conf-v1.4::TCP-3": "multiple TCP packets: framing",
		"ss-1547-test-v1.1::MOD-4":   "mandatory points: a read",
		"ss-1547-test-v1.1::2.4":     "scale factor: a read",

		// SS-TEST-PKI: the whole document is about certificates and the trust
		// hierarchy behind them. Identity is established during the handshake,
		// before any control lane exists to be in.
		"ss-test-pki::PKI-1":  "TLS is mandatory for CSIP connections: transport, not control",
		"ss-test-pki::PKI-3":  "client/server certificate package types: identity, not control",
		"ss-test-pki::PKI-8":  "test-environment certificate chain topology: identity, not control",
		"ss-test-pki::PKI-11": "the DUT's certificate chain: identity, not control",
		"ss-test-pki::PKI-19": "CA hierarchy: identity, not control",
		"ss-test-pki::PKI-20": "error certificates: identity, not control",

		// SunSpec Modbus CLIENT campaign: the DUT is the one polling, and its
		// southbound behaviour is the same under every northbound posture.
		// Its write rows (WR-1/WR-2) are driven by whichever control path the
		// candidate declares, which is why that campaign pins no posture at all
		// (certify.CampaignModbusClient, AuthorityAny) rather than classifying
		// its rows one by one.
		"ss-modbus-client-conf-v1.1::CLI-1":  "southbound discovery",
		"ss-modbus-client-conf-v1.1::CLI-2":  "southbound discovery",
		"ss-modbus-client-conf-v1.1::CLI-3":  "southbound discovery",
		"ss-modbus-client-conf-v1.1::CLI-4":  "southbound discovery",
		"ss-modbus-client-conf-v1.1::ERR-1":  "southbound error handling",
		"ss-modbus-client-conf-v1.1::ERR-2":  "southbound exception handling",
		"ss-modbus-client-conf-v1.1::ERR-3":  "southbound unknown model handling",
		"ss-modbus-client-conf-v1.1::INFO-1": "southbound type interpretation",
		"ss-modbus-client-conf-v1.1::INFO-2": "southbound unimplemented-point interpretation",
		"ss-modbus-client-conf-v1.1::PROT-1": "southbound partial response",
		"ss-modbus-client-conf-v1.1::PROT-2": "southbound TCP segmentation",
		"ss-modbus-client-conf-v1.1::READ-1": "southbound single point read",
		"ss-modbus-client-conf-v1.1::READ-2": "southbound multiple point read",
		"ss-modbus-client-conf-v1.1::WR-1":   "southbound write, driven by the campaign's declared posture",
		"ss-modbus-client-conf-v1.1::WR-2":   "southbound write, driven by the campaign's declared posture",
	}
	for uid, why := range unclassified {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is acknowledged unclassified with no justification", uid)
		}
	}

	classified := map[string]bool{}
	for _, uid := range certify.ClassifiedAuthorityUIDs() {
		classified[uid] = true
	}

	cat := catalog(t)
	reg := suites.Registry()
	var residue []string
	for _, spec := range certify.Campaigns() {
		f := certify.Filter{ApplicableOnly: true, Match: func(c *certify.Case) bool {
			r, ok := reg.Lookup(c.UID)
			if !ok {
				return false
			}
			for _, s := range spec.Suites {
				if strings.EqualFold(s, r.Suite) {
					return true
				}
			}
			return false
		}}
		for _, c := range cat.Select(f) {
			if classified[c.UID] {
				continue
			}
			if _, ok := unclassified[c.UID]; ok {
				continue
			}
			residue = append(residue, c.UID)
		}
	}
	sort.Strings(residue)
	if len(residue) > 0 {
		t.Errorf("%d campaign row(s) have no control-authority classification and are not acknowledged "+
			"as needing none:\n  %s\n\nEach one must be either added to authorityFamilies in "+
			"internal/certify/authority.go (with the reason it needs that lane) or listed in this "+
			"test's `unclassified` map (with the reason it needs none). A row that is neither is a row "+
			"a campaign may measure under a posture nobody chose.",
			len(residue), strings.Join(residue, "\n  "))
	}

	// The other direction: an acknowledgement for a row no campaign runs is
	// stale, and a stale list is one nobody trusts.
	inCampaign := map[string]bool{}
	for _, spec := range certify.Campaigns() {
		for _, c := range cat.All() {
			r, ok := reg.Lookup(c.UID)
			if !ok || !c.Applicable {
				continue
			}
			for _, s := range spec.Suites {
				if strings.EqualFold(s, r.Suite) {
					inCampaign[c.UID] = true
				}
			}
		}
	}
	for uid := range unclassified {
		if !inCampaign[uid] {
			t.Errorf("%s is acknowledged unclassified but no campaign runs it; drop the entry", uid)
		}
	}
}

// The classification must also be REACHABLE: a classified row that no campaign
// runs guards nothing.
func TestClassifiedRowsAreRunBySomeCampaign(t *testing.T) {
	cat, reg := catalog(t), suites.Registry()
	for _, uid := range certify.ClassifiedAuthorityUIDs() {
		c, ok := cat.ByUID(uid)
		if !ok {
			continue // reported by TestAuthorityTableUIDsExistInTheCatalog
		}
		r, registered := reg.Lookup(uid)
		if !registered {
			t.Logf("note: %s is classified but no suite implements it yet — the classification is "+
				"harmless and will start guarding the row the day one does", uid)
			continue
		}
		if !c.Applicable {
			t.Logf("note: %s is classified but the catalog marks it inapplicable, so no campaign "+
				"selects it", uid)
			continue
		}
		var found bool
		for _, spec := range certify.Campaigns() {
			for _, s := range spec.Suites {
				if strings.EqualFold(s, r.Suite) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s is classified as needing an authority posture but sits in suite %q, which no "+
				"campaign runs", uid, r.Suite)
		}
	}
}

// TestSuiteDocumentMapMatchesTheLinkedSuites is the mirror check for
// internal/certify/campaign_test.go's `docSuites`.
//
// That file needs to know which suite owns each catalog document in order to
// test a campaign's SELECTION, and it cannot import this package (the import
// runs the other way). So it carries a literal copy, and this test holds the
// same literal against the real registrations. If a document ever moves between
// suites, this fails — and the fix is two edits, in the two places this comment
// names, rather than a silent divergence in which certify's tests pass against a
// suite map the binary does not have.
func TestSuiteDocumentMapMatchesTheLinkedSuites(t *testing.T) {
	want := map[string]string{
		"CSIP-CONF-v1.3":             "csip",
		"LOCAL-EXT-v1":               "csip",
		"SSM-CONF-v0.8":              "ssm",
		"SS-MODBUS-CONF-v1.4":        "modbus-server",
		"SS-1547-TEST-v1.1":          "modbus-server",
		"SS-MODBUS-CLIENT-CONF-v1.1": "modbus-client",
		"SS-TEST-PKI":                "pki",
		"SS-CSIP-RESULTS-v1.1":       "results-report",
		"SS-MODBUS-RESULTS-v1.2":     "results-report",
	}
	got := map[string][]string{} // doc -> suites that register rows in it
	for suite, docs := range suites.Docs(catalog(t)) {
		for _, d := range docs {
			got[d] = append(got[d], suite)
		}
	}
	for doc, suitesFor := range got {
		sort.Strings(suitesFor)
		if len(suitesFor) != 1 {
			t.Errorf("document %q is registered by %v; internal/certify/campaign_test.go's docSuites "+
				"maps each document to exactly ONE suite and cannot represent this", doc, suitesFor)
			continue
		}
		if w, ok := want[doc]; !ok {
			t.Errorf("document %q is registered by suite %q and is in neither map; add it here AND in "+
				"internal/certify/campaign_test.go's docSuites", doc, suitesFor[0])
		} else if w != suitesFor[0] {
			t.Errorf("document %q is registered by suite %q, both maps say %q; update this test AND "+
				"internal/certify/campaign_test.go's docSuites", doc, suitesFor[0], w)
		}
	}
	// A catalog document nothing registers is fine (nothing implements it yet);
	// a map entry for a document the CATALOG does not have is stale.
	cat := catalog(t)
	for doc := range want {
		if _, ok := cat.Doc(doc); !ok {
			t.Errorf("the suite map names document %q, which the catalog does not contain", doc)
		}
	}
}
