package suitessm

// roles_test.go is the drift guard for roles.go and the roll-up proof for what
// it changes.
//
// Two different failures are being prevented, and they need different tests.
//
// DRIFT: somebody adds a [C]-half assertion to a check and does not add it to
// the table. Nothing breaks; the assertion simply keeps the row's declared
// default, is asserted against a direction the candidate does not claim, and
// re-introduces exactly the SKIP this whole mechanism removed. The guard reads
// the suite's OWN SOURCE for the document's "[C]:" marker and requires the table
// to account for every occurrence.
//
// ROLL-UP: the split has to change the verdict a case reports, in one direction
// only. A server-only candidate's CRYP-001 must roll up to PASS on its six
// server assertions; a candidate that DOES claim the client direction must keep
// its client assertion and, when that assertion fails, must still FAIL.

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/evidence/bundle"
)

// clientMarker is how SSM-CONF-v0.8 tags a Client Procedure step, and how this
// suite tags the assertion that implements one. The trailing colon is load
// bearing: prose such as "the [C] half was not observed" is a note about the
// bench, not a criterion, and must not be swept into the table.
const clientMarker = "[C]:"

// serverOnly is the candidate manifest configs/candidate.json declares, reduced
// to the parts scope decisions are made from.
const serverOnly = `{
  "profile": "one-to-one-7xx-tcp",
  "topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]},
  "csip": {"role": "der-client", "end_devices": 1, "der_resources": 1},
  "secure_sunspec": {"roles": ["server"], "transport": "tls-tcp", "port": 802},
  "modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"},
  "authority_profiles": ["csip", "mbaps"],
  "models": [1, 701, 702, 703, 704]
}`

// bothRoles is the same candidate claiming BOTH directions, which is what a
// device certifying as an mbaps client as well as a server would publish.
var bothRoles = strings.Replace(serverOnly, `"roles": ["server"]`, `"roles": ["server", "client"]`, 1)

func mustManifest(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse([]byte(doc), "candidate.json")
	if err != nil {
		t.Fatalf("parse the test manifest: %v", err)
	}
	return m
}

// candidate is a stand-in for the run context's two scope methods, with the
// SAME nil-manifest rule certify.RunCtx.RoleClaimed applies: no declaration
// excludes nothing.
type candidate struct{ m *manifest.Manifest }

func (c candidate) Manifest() *manifest.Manifest { return c.m }

func (c candidate) RoleClaimed(role string) bool {
	if c.m == nil {
		return true
	}
	return c.m.SecureSunSpec.HasRole(role)
}

// theSameRuleAsTheRunner is the check that keeps the stand-in above honest: the
// runner's own RunCtx must answer RoleClaimed identically for a nil manifest,
// or every test in this file is measuring something the runner does not do.
func TestTheStandInFollowsTheRunnersOwnNilRule(t *testing.T) {
	var rc *certify.RunCtx
	if !rc.RoleClaimed("client") {
		t.Fatal("certify.RunCtx.RoleClaimed on a nil context/manifest answered false; a run with no " +
			"-manifest must assert everything")
	}
	if !(candidate{}).RoleClaimed("client") {
		t.Fatal("the stand-in disagrees with the runner on the nil-manifest rule")
	}
}

// ── the drift guard ─────────────────────────────────────────────────────────

func TestEverySSMAssertionCarriesARole(t *testing.T) {
	cat := loadCatalog(t)
	reg := registry(t)

	registered := map[string]bool{}
	for _, r := range reg.Registrations() {
		registered[caseID(r.UID)] = true
	}

	// 1. Every registered case has an entry, and every entry is well formed.
	for _, r := range reg.Registrations() {
		id := caseID(r.UID)
		e, ok := assertionRoles[id]
		if !ok {
			t.Errorf("%s is registered but roles.go declares no assertion directions for it: every "+
				"assertion of every row must carry a direction, and an absent entry means a whole row's "+
				"worth are unlabelled", r.UID)
			continue
		}
		if !e.Case.Valid() {
			t.Errorf("%s declares Table-1 role %q, which is not server/client/both", id, e.Case)
		}
		if !e.Default.Valid() {
			t.Errorf("%s declares default direction %q, which is not server/client/both", id, e.Default)
		}
		// A Table 1 "Server" row has no Client Procedure subsection at all, so
		// an assertion claiming to implement one is a transcription error.
		// A Table 1 "Server" row has no Client Procedure subsection at all, so
		// an assertion claiming to implement one is a transcription error.
		if e.Case == DirServer {
			if e.Default == DirClient {
				t.Errorf("%s is a Table-1 SERVER row but defaults its assertions to the client "+
					"direction", id)
			}
			for _, r := range e.Rules {
				if r.Dir == DirClient {
					t.Errorf("%s is a Table-1 SERVER row but declares client-direction rule %q; the "+
						"document gives that row no Client Procedure to implement", id, r.Prefix)
				}
			}
		}
		if e.Case == DirClient && e.Default != DirClient {
			t.Errorf("%s is a Table-1 CLIENT row but defaults its assertions to %q", id, e.Default)
		}
		seen := map[string]bool{}
		for _, r := range e.Rules {
			if r.Prefix == "" {
				t.Errorf("%s declares a rule with an empty prefix, which would swallow every assertion "+
					"in the row", id)
			}
			if !r.Dir.Valid() {
				t.Errorf("%s declares rule %q with direction %q", id, r.Prefix, r.Dir)
			}
			if seen[r.Prefix] {
				t.Errorf("%s declares the prefix %q twice; only the first can ever match", id, r.Prefix)
			}
			seen[r.Prefix] = true
		}
	}

	// 2. No entry names a case nobody registers.
	for id := range assertionRoles {
		if !registered[id] {
			t.Errorf("roles.go declares directions for %s, which this suite does not register — a stale "+
				"entry is a rule nobody applies", id)
		}
	}

	// 3. The Table-1 role and the catalog's dut_role scalar must be coherent.
	for _, r := range reg.Registrations() {
		c, ok := cat.ByUID(r.UID)
		if !ok {
			t.Errorf("%s is registered but absent from the catalog", r.UID)
			continue
		}
		id := caseID(r.UID)
		e := assertionRoles[id]
		switch c.DUTRole {
		case certify.RoleMBAPSClient:
			if e.Case == DirClient {
				continue
			}
			if _, acknowledged := clientOnlyByCatalog[id]; !acknowledged {
				t.Errorf("the catalog puts %s on dut_role %q but Table 1 marks it %q, and no reason for "+
					"the disagreement is recorded in clientOnlyByCatalog", id, c.DUTRole, e.Case)
			}
		case certify.RoleMBAPSServer:
			if e.Case == DirClient {
				t.Errorf("Table 1 marks %s a CLIENT row but the catalog puts it on dut_role %q", id, c.DUTRole)
			}
			if e.Default == DirClient {
				t.Errorf("%s is an mbaps-server row in the catalog — the bench drives its server surface — "+
					"but every one of its assertions defaults to the client direction", id)
			}
		default:
			t.Errorf("%s has catalog dut_role %q, which this suite's role split does not model", id, c.DUTRole)
		}
	}
	for id := range clientOnlyByCatalog {
		c, ok := cat.ByUID("ssm-conf-v0.8::" + id)
		if !ok {
			t.Errorf("clientOnlyByCatalog names %s, which is not in the catalog", id)
			continue
		}
		if c.DUTRole != certify.RoleMBAPSClient {
			t.Errorf("clientOnlyByCatalog explains %s as a catalog client row, but its dut_role is %q",
				id, c.DUTRole)
		}
	}

	// 4. The half that actually catches drift, read from the suite's own
	//    source: every [C]-marked claim is accounted for by a client-direction
	//    rule of the case that mints it, and every rule matches a claim that
	//    exists. A new client-direction assertion cannot be added without an
	//    entry, and an entry cannot outlive the claim it names.
	byCase := suiteClaims(t)
	if len(byCase) == 0 {
		t.Fatal("no claim literals were found in the suite's source; the scan is broken, and a broken " +
			"scan silently passes")
	}
	marked := 0
	for id, lits := range byCase {
		e, ok := assertionRoles[id]
		if !ok {
			t.Errorf("the suite mints claims for %s, which roles.go does not cover", id)
			continue
		}
		for _, lit := range lits {
			if !strings.Contains(lit.text, clientMarker) {
				continue
			}
			marked++
			if got := directionOf(id, lit.text); got != DirClient {
				t.Errorf("%s (%s) mints a claim marked %q that roles.go classifies as %s, so it would be "+
					"asserted against a direction the candidate may not claim:\n    %q",
					id, lit.fn, clientMarker, got, lit.text)
			}
		}
		for _, r := range e.Rules {
			hit := false
			for _, lit := range lits {
				if strings.HasPrefix(lit.text, r.Prefix) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("%s declares rule %q, which matches no claim in the suite's source — a stale "+
					"rule silently stops classifying anything", id, r.Prefix)
			}
		}
	}
	// Every row that has an unmatched rule is caught above; this catches the
	// reverse shape, a case whose rules exist but whose claims never reach the
	// scan because the fn-to-case mapping went stale.
	for id, e := range assertionRoles {
		if len(e.Rules) > 0 && len(byCase[id]) == 0 {
			t.Errorf("roles.go declares %d rule(s) for %s but the source scan found no claim literal for "+
				"it at all; caseFuncs is out of date", len(e.Rules), id)
		}
	}
	if marked != countClientRules() {
		t.Errorf("the suite mints %d claim(s) carrying %q but roles.go declares %d client-direction "+
			"rule(s); the two must move together", marked, clientMarker, countClientRules())
	}

	// 5. The summary, printed so a reviewer can read the split without reading
	//    the table.
	t.Log(roleTableSummary())
}

// countClientRules is how many client-direction rules the table declares.
func countClientRules() int {
	n := 0
	for _, e := range assertionRoles {
		for _, r := range e.Rules {
			if r.Dir == DirClient {
				n++
			}
		}
	}
	return n
}

// claimLit is one string literal found in the suite's source, with the function
// that holds it.
type claimLit struct{ fn, text string }

// caseFuncs maps the SHARED helpers that mint a claim on behalf of exactly one
// case onto that case. Every other case function is recognised by its name
// (cryp001 → CRYP-001), which is the suite's own convention.
var caseFuncs = map[string]string{
	// gatewayChainAssertion mints PKI-004's [C] half; it is a function rather
	// than an inline closure because it asserts on the gateway's own
	// Certificate message rather than on its hello.
	"gatewayChainAssertion": "PKI-004",
	// citeRBAC011 is RBAC-011's whole citation phase.
	"citeRBAC011": "RBAC-011",
}

var caseFuncPattern = regexp.MustCompile(`^(tlsf|cryp|pki|prot|rbac|ops)(\d{3})$`)

// caseOfFunc returns the case id a suite function mints claims for, or "".
func caseOfFunc(name string) string {
	if id, ok := caseFuncs[name]; ok {
		return id
	}
	m := caseFuncPattern.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1]) + "-" + m[2]
}

// suiteClaims parses the suite's own non-test sources and returns every string
// literal inside a case's functions, keyed by case id.
//
// Parsing rather than grepping, so a marker inside a COMMENT — of which this
// package has several, explaining the mechanism — is not mistaken for a claim.
// roles.go is excluded: its literals are the table itself.
func suiteClaims(t *testing.T) map[string][]claimLit {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go") && fi.Name() != "roles.go"
	}, 0)
	if err != nil {
		t.Fatalf("parse the suite's own sources: %v", err)
	}
	out := map[string][]claimLit{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				id := caseOfFunc(fd.Name.Name)
				if id == "" {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					bl, ok := n.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						return true
					}
					s, uerr := strconv.Unquote(bl.Value)
					if uerr != nil || s == "" {
						return true
					}
					out[id] = append(out[id], claimLit{fn: fd.Name.Name, text: s})
					return true
				})
			}
		}
	}
	for id := range out {
		sort.Slice(out[id], func(i, j int) bool { return out[id][i].text < out[id][j].text })
	}
	return out
}

// roleTableSummary renders the counts per direction per case.
func roleTableSummary() string {
	var sb strings.Builder
	sb.WriteString("SSM assertion-direction table (Table-1 role / default / explicit rules):\n")
	for _, id := range AssertionRoleIDs() {
		e := assertionRoles[id]
		n := map[Direction]int{}
		for _, r := range e.Rules {
			n[r.Dir]++
		}
		sb.WriteString("  " + id + strings.Repeat(" ", 10-len(id)) +
			" table1=" + string(e.Case) +
			" default=" + string(e.Default) +
			" client=" + strconv.Itoa(n[DirClient]) +
			" both=" + strconv.Itoa(n[DirBoth]) +
			" server=" + strconv.Itoa(n[DirServer]) + "\n")
	}
	return sb.String()
}

func TestDirectionOfPrefersTheExplicitEntryOverTheDefault(t *testing.T) {
	cases := []struct {
		id, claim string
		want      Direction
	}{
		{"CRYP-001", "SunSpecTCP-17 [C]: the gateway's own southbound ClientHello offers all three", DirClient},
		{"CRYP-001", "SunSpecTCP-17: offered ONLY 0xC02B, the EUT-S accepted it", DirServer},
		{"CRYP-006", "SunSpecTCP-15/16 [C]: every cipher suite the gateway offers", DirClient},
		{"CRYP-006", "SunSpecTCP-15/16: every cipher suite in the vendor's PICS is IANA-registered", DirBoth},
		{"CRYP-006", "SunSpecTCP-15/16: the cipher suite the EUT-S selected", DirServer},
		{"OPS-001", "SunSpecTCP-58: the vendor's Cryptographic Export Declaration lists every", DirBoth},
		{"RBAC-011", "SunSpecTCP-27/28: the EUT-C's client certificate carries a role", DirClient},
		{"NOPE-999", "anything at all", DirServer},
	}
	for _, tc := range cases {
		if got := directionOf(tc.id, tc.claim); got != tc.want {
			t.Errorf("directionOf(%s, %.48q) = %s, want %s", tc.id, tc.claim, got, tc.want)
		}
	}
}

// ── the roll-up ─────────────────────────────────────────────────────────────

// cryp001Shape is CRYP-001's assertion set as run f4c16eb-mbaps-battery
// recorded it: six server-direction assertions that PASS, and the [C] half.
// clientVerdict is what the client assertion reached.
func cryp001Shape(clientVerdict certify.Verdict, observed string) []certify.Assertion {
	as := make([]certify.Assertion, 0, 7)
	for _, suite := range []string{"0xC02B", "0xCCA9", "0xC0AE"} {
		as = append(as,
			certify.Assertion{
				Claim:        "SunSpecTCP-17: offered ONLY " + suite + ", the EUT-S accepted it and answered with a ServerHello selecting it",
				Method:       "single-suite TLS 1.2 ClientHello",
				Verdict:      certify.Pass,
				Observed:     "ServerHello.cipher_suite = " + suite,
				FramesSHA256: "deadbeef",
			},
			certify.Assertion{
				Claim:        "SunSpecTCP-19: with only " + suite + " offered, the EUT-S proceeded through its whole server flight rather than aborting",
				Method:       "ordered handshake message types",
				Verdict:      certify.Pass,
				Observed:     "EUT-S cleartext flight complete",
				FramesSHA256: "deadbeef",
			})
	}
	return append(as, certify.Assertion{
		Claim:    "SunSpecTCP-17 [C]: the gateway's own southbound ClientHello offers all three mandatory TLS 1.2 suites",
		Method:   "cipher_suites list of the gateway's ClientHello to the bench device sim",
		Verdict:  clientVerdict,
		Observed: observed,
	})
}

// scopedCRYP001 runs cryp001's shape through the real direction decision.
func scopedCRYP001(t *testing.T, m *manifest.Manifest, clientVerdict certify.Verdict, observed string) []certify.Assertion {
	t.Helper()
	res := scopeResult(candidate{m}, "CRYP-001",
		certify.Result{Assertions: cryp001Shape(clientVerdict, observed)})
	return res.Assertions
}

func rollUp(as []certify.Assertion) bundle.Verdict {
	return bundle.TestCaseResult{ID: "CRYP-001", Assertions: as}.RollUp()
}

func counts(as []certify.Assertion) map[bundle.Verdict]int {
	out := map[bundle.Verdict]int{}
	for _, a := range as {
		out[a.Verdict]++
	}
	return out
}

// TestCRYP001RollsUpToPassOnItsServerHalfWhenTheClientDirectionIsUnclaimed is
// the case the whole file exists for: six passing server assertions and a [C]
// half that measured nothing, against the candidate manifest the product ships.
func TestCRYP001RollsUpToPassOnItsServerHalfWhenTheClientDirectionIsUnclaimed(t *testing.T) {
	m := mustManifest(t, serverOnly)
	as := scopedCRYP001(t, m, certify.Skip, "no ClientHello from the gateway appears in the frames attributed to this test case")

	if got := rollUp(as); got != bundle.Pass {
		t.Errorf("CRYP-001 rolled up to %s, want PASS: every remaining assertion is a passing "+
			"server-direction one", got)
	}
	c := counts(as)
	if c[bundle.Skip] != 0 {
		t.Errorf("%d SKIP assertion(s) survived; an unclaimed direction is not an evidence gap and must "+
			"not read as one", c[bundle.Skip])
	}
	if c[bundle.VerdictNotApplicable] != 1 {
		t.Errorf("%d N/A assertion(s), want exactly the one [C] half", c[bundle.VerdictNotApplicable])
	}
	if c[bundle.Pass] != 6 {
		t.Errorf("%d PASS assertion(s), want the six server-direction ones", c[bundle.Pass])
	}

	na := as[len(as)-1]
	if na.Verdict != bundle.VerdictNotApplicable {
		t.Fatalf("the [C] assertion is %s, want %s", na.Verdict, bundle.VerdictNotApplicable)
	}
	if !strings.Contains(na.Claim, clientMarker) {
		t.Error("the claim did not survive; a reader cannot see which criterion was excluded")
	}
	for _, want := range []string{"CLIENT", "one-to-one-7xx-tcp", "secure_sunspec.roles", "server"} {
		if !strings.Contains(na.Observed, want) {
			t.Errorf("the reason does not name %q:\n%s", want, na.Observed)
		}
	}
	if !strings.Contains(na.Note, string(bundle.NASourceManifest)) {
		t.Errorf("the note does not name the source %q:\n%s", bundle.NASourceManifest, na.Note)
	}
	if na.FramesSHA256 != "" || na.BytesSHA256 != "" {
		t.Error("an out-of-scope assertion carries a citation digest, which would say it was measured")
	}
}

// TestAClaimedClientDirectionIsStillAsserted is the other half of the same
// decision, and the one that fails if roleScoped stops consulting
// RunCtx.RoleClaimed: a candidate that DOES claim the client direction must
// keep its [C] assertion exactly as the check produced it.
func TestAClaimedClientDirectionIsStillAsserted(t *testing.T) {
	for name, m := range map[string]*manifest.Manifest{
		"both roles claimed": mustManifest(t, bothRoles),
		"no manifest at all": nil,
	} {
		t.Run(name, func(t *testing.T) {
			as := scopedCRYP001(t, m, certify.Skip, "no ClientHello from the gateway was observed")
			last := as[len(as)-1]
			if last.Verdict != bundle.Skip {
				t.Fatalf("the [C] assertion is %s, want the SKIP the check produced: this candidate "+
					"claims the client direction, so the criterion is in scope and its absence of "+
					"evidence is a real evidence gap", last.Verdict)
			}
			if counts(as)[bundle.VerdictNotApplicable] != 0 {
				t.Error("an assertion was taken out of scope for a candidate that claims the direction")
			}
		})
	}
}

// TestAClientDirectionFailureStillFailsAClaimingCandidate is the sharper
// mutation detector. A check whose [C] half FAILS is a non-conformant mbaps
// client, and a candidate claiming that direction must FAIL on it.
func TestAClientDirectionFailureStillFailsAClaimingCandidate(t *testing.T) {
	as := scopedCRYP001(t, mustManifest(t, bothRoles), certify.Fail,
		"gateway ClientHello cipher_suites = [0xC02B] — missing 0xCCA9, 0xC0AE")
	if got := rollUp(as); got != bundle.Fail {
		t.Fatalf("CRYP-001 rolled up to %s, want FAIL: the candidate claims the client direction and its "+
			"ClientHello omits two mandatory suites", got)
	}
}

// TestAnObservedClientFailureIsRecordedNotDiscarded holds the honesty rule: a
// candidate that does not claim the direction is not judged on it, and the
// observation the bench nevertheless made is still in the bundle.
func TestAnObservedClientFailureIsRecordedNotDiscarded(t *testing.T) {
	const observed = "gateway ClientHello cipher_suites = [0xC02B] — missing 0xCCA9, 0xC0AE"
	as := scopedCRYP001(t, mustManifest(t, serverOnly), certify.Fail, observed)
	if got := rollUp(as); got != bundle.Pass {
		t.Errorf("CRYP-001 rolled up to %s, want PASS: the [C] criterion is a requirement on an EUT-C and "+
			"this candidate does not claim to be one", got)
	}
	na := as[len(as)-1]
	if !strings.Contains(na.Note, observed) {
		t.Errorf("the observation the bench made was discarded rather than recorded:\n%s", na.Note)
	}
	if !strings.Contains(na.Note, string(bundle.Fail)) {
		t.Errorf("the note does not say which verdict the excluded observation had reached:\n%s", na.Note)
	}
}

// TestEveryOtherCasesClientHalfIsTakenOutOfScopeToo walks the whole table, so
// the roll-up property is proven for every row that has a [C] half rather than
// for CRYP-001 alone.
func TestEveryOtherCasesClientHalfIsTakenOutOfScopeToo(t *testing.T) {
	m := mustManifest(t, serverOnly)
	n := 0
	for _, id := range AssertionRoleIDs() {
		e := assertionRoles[id]
		if e.Case == DirClient {
			continue // the whole row is out of scope at case level; see scope.go
		}
		for _, r := range e.Rules {
			if r.Dir != DirClient {
				continue
			}
			n++
			res := scopeResult(candidate{m}, id, certify.Result{Assertions: []certify.Assertion{
				{Claim: r.Prefix + " the gateway's own southbound ClientHello", Verdict: certify.Skip},
				{Claim: "a server-direction criterion", Verdict: certify.Pass, FramesSHA256: "beef"},
			}})
			if res.Assertions[0].Verdict != bundle.VerdictNotApplicable {
				t.Errorf("%s: %q is %s, want N/A", id, r.Prefix, res.Assertions[0].Verdict)
			}
			if res.Assertions[1].Verdict != bundle.Pass {
				t.Errorf("%s: the server-direction assertion was touched (%s)", id, res.Assertions[1].Verdict)
			}
			if got := rollUp(res.Assertions); got != bundle.Pass {
				t.Errorf("%s rolled up to %s, want PASS", id, got)
			}
		}
	}
	if n == 0 {
		t.Fatal("no case declares a client-direction assertion; the table is empty and this test proves nothing")
	}
	t.Logf("%d client-direction assertion(s) across %d case(s) are taken out of scope by a server-only manifest",
		n, len(assertionRoles))
}

// TestTheCitationPhaseIsScopedToo proves the wrapper reaches the assertions
// minted AFTER the capture is read back, which is where every [C] half in this
// suite actually lives.
func TestTheCitationPhaseIsScopedToo(t *testing.T) {
	res := scopeResult(candidate{mustManifest(t, serverOnly)}, "CRYP-001", certify.Result{
		Cite: func(context.Context, *certify.Evidence) ([]certify.Assertion, error) {
			return cryp001Shape(certify.Skip, "nothing observed"), nil
		},
	})
	if res.Cite == nil {
		t.Fatal("the wrapper dropped the citation callback")
	}
	as, err := res.Cite(context.Background(), nil)
	if err != nil {
		t.Fatalf("cite: %v", err)
	}
	if as[len(as)-1].Verdict != bundle.VerdictNotApplicable {
		t.Errorf("the cited [C] assertion is %s, want N/A — a wrapper that only scoped the live phase "+
			"would leave every real [C] half untouched", as[len(as)-1].Verdict)
	}
}

// ── end to end, through the real runner ─────────────────────────────────────

// TestTheRunnerAppliesTheSplitToARegisteredCheck is the only test here that
// proves the WIRING: that Register wraps every check, that a -manifest reaches
// the wrapper through the run context, and that the bundle the runner writes
// carries the not-applicable record rather than a SKIP.
//
// CRYP-007 is the case because the suite already stands a loopback peer up for
// it (it has no NULL-encryption cipher, so its refusal is real) and because it
// carries a [C] half — the same shape as the other ten.
func TestTheRunnerAppliesTheSplitToARegisteredCheck(t *testing.T) {
	const uid = "ssm-conf-v0.8::CRYP-007"

	withManifest := runCaseWithManifest(t, uid, serverOnly)
	withoutManifest := runCaseWithManifest(t, uid, "")

	find := func(res certify.CaseResult) certify.Assertion {
		t.Helper()
		for _, a := range res.Assertions {
			if strings.Contains(a.Claim, clientMarker) {
				return a
			}
		}
		t.Fatalf("CRYP-007 produced no [C] assertion at all: %s", renderAssertions(res))
		return certify.Assertion{}
	}

	na := find(withManifest)
	if na.Verdict != bundle.VerdictNotApplicable {
		t.Errorf("with a server-only manifest the [C] half is %s, want N/A:%s",
			na.Verdict, renderAssertions(withManifest))
	}
	if !strings.Contains(na.Note, string(bundle.NASourceManifest)) {
		t.Errorf("the bundle's record does not name the manifest as the source:\n%s", na.Note)
	}
	if !strings.Contains(na.Observed, "one-to-one-7xx-tcp") {
		t.Errorf("the reason does not name the candidate profile:\n%s", na.Observed)
	}
	if withManifest.Verdict != certify.Pass {
		t.Errorf("CRYP-007 is %s with a server-only manifest, want PASS: its server assertions all "+
			"hold and its only other criterion is out of scope:%s",
			withManifest.Verdict, renderAssertions(withManifest))
	}

	skipped := find(withoutManifest)
	if skipped.Verdict != certify.Skip {
		t.Errorf("with NO manifest the [C] half is %s, want the SKIP it has always been: a run without a "+
			"declaration must behave exactly as it did before scope decisions existed:%s",
			skipped.Verdict, renderAssertions(withoutManifest))
	}
}

// runCaseWithManifest is runCase with a candidate manifest written to a
// temporary file, or none when doc is empty.
func runCaseWithManifest(t *testing.T, uid, doc string) certify.CaseResult {
	t.Helper()
	addr, pkiDir := loopbackPeer(t, peerOpts{})

	tp := &tap{}
	prev := connTap
	connTap = tp.wrap
	t.Cleanup(func() { connTap = prev })

	console := &bytes.Buffer{}
	opts := certify.DefaultOptions()
	opts.UIDs = []string{uid}
	opts.OutDir = filepath.Join(t.TempDir(), "bundle")
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.PKIDir = pkiDir
	opts.CheckTimeout = 30 * time.Second
	opts.Targets = certify.Targets{Gateway: addr, GatewayHost: "127.0.0.1"}
	opts.Capturer = &tapCapture{path: filepath.Join(t.TempDir(), "run.pcap"), tap: tp}
	opts.Params = map[string]string{"ssm.client_wait": "10ms"}
	if doc != "" {
		path := filepath.Join(t.TempDir(), "candidate.json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		opts.ManifestPath = path
	}

	run, err := certify.New(registry(t), loadCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	for _, c := range rep.Cases {
		if c.Case.UID == uid {
			return c
		}
	}
	t.Fatalf("%s did not appear in the run report\n%s", uid, console.String())
	return certify.CaseResult{}
}
