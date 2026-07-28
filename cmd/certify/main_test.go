package main

// main_test.go covers the CLI's own decisions — the ones no suite and no
// framework test can reach, because they happen before a check ever runs.
//
// The bar here is the same as everywhere else in this tool: prove the negative.
// It is easy to test that `-list` prints a table. What matters is that a
// mistyped document name is REFUSED rather than silently producing a clean
// report of zero test cases, that two modes on one command line are refused
// rather than one of them quietly winning, and that a key log this binary
// cannot produce is refused rather than accepted and ignored. Each of those is
// a way the tool could hand back a confident, wrong answer.
//
// Nothing here touches a network, a bench, or a device.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// exec runs the CLI in-process and returns its exit code and streams.
func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// repoRoot walks up to the directory holding the committed catalog, so the
// tests find it regardless of where `go test` was invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(certify.CatalogFile))); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no %s in any parent of %s", certify.CatalogFile, dir)
		}
		dir = parent
	}
}

func catalogFlag(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), filepath.FromSlash(certify.CatalogFile))
}

func TestListReportsTheWholeCatalogAndItsGaps(t *testing.T) {
	code, out, errOut := exec(t, "-list", "-catalog", catalogFlag(t))
	if code != exitOK {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	// Every source document must appear: a coverage report that quietly omits a
	// document is the second dishonesty mode this tool exists to prevent.
	for _, doc := range []string{
		"CSIP-CONF-v1.3", "SS-1547-TEST-v1.1", "SS-CSIP-RESULTS-v1.1",
		"SS-MODBUS-CLIENT-CONF-v1.1", "SS-MODBUS-CONF-v1.4", "SS-MODBUS-RESULTS-v1.2",
		"SS-TEST-PKI", "SSM-CONF-v0.8",
	} {
		if !strings.Contains(out, doc) {
			t.Errorf("-list does not mention %s", doc)
		}
	}
	// And every suite, so an operator can map a document to a -suite value.
	for _, suite := range []string{"csip", "modbus-client", "modbus-server", "pki", "results-report", "ssm"} {
		if !strings.Contains(out, suite) {
			t.Errorf("-list does not mention suite %s", suite)
		}
	}
	if !strings.Contains(out, "sha256") {
		t.Error("-list does not print the catalog digest, so a reader cannot tell which specification this is")
	}
}

// TestListIsAGate pins that -list's exit code carries the coverage verdict. A
// coverage regression must be able to fail a pipeline; a mode that always
// exits 0 is decoration.
func TestListIsAGate(t *testing.T) {
	code, _, _ := exec(t, "-list", "-catalog", catalogFlag(t))
	if code != exitOK {
		t.Fatalf("the tree's coverage is complete, so -list must exit %d; got %d", exitOK, code)
	}
	cov := listCoverage(t)
	if !cov.Complete() {
		t.Fatal("coverage is not complete but -list exited 0")
	}
}

func listCoverage(t *testing.T) certify.Coverage {
	t.Helper()
	code, out, errOut := exec(t, "-list", "-json", "-catalog", catalogFlag(t))
	if code != exitOK {
		t.Fatalf("exit %d\nstderr: %s", code, errOut)
	}
	var cov certify.Coverage
	if err := json.Unmarshal([]byte(out), &cov); err != nil {
		t.Fatalf("-list -json is not valid JSON: %v", err)
	}
	return cov
}

// TestListJSONHasNoOrphansOrGaps is the assembly check that only exists once
// every suite is linked into one binary: a registration for a uid the catalog
// does not contain means a suite and the specification have diverged.
func TestListJSONHasNoOrphansOrGaps(t *testing.T) {
	cov := listCoverage(t)
	if len(cov.Orphans) > 0 {
		t.Errorf("registered uids that are not in the catalog: %v", cov.Orphans)
	}
	total, applicable, implemented, missing := cov.Totals()
	if missing != 0 {
		t.Errorf("%d applicable test case(s) have no implementation", missing)
	}
	if total == 0 || applicable == 0 || implemented == 0 {
		t.Errorf("implausible coverage totals: total=%d applicable=%d implemented=%d", total, applicable, implemented)
	}
}

// TestSelectorTypoIsRefused is the important negative. `-doc SSM-CONF-v0.9`
// selects nothing, and a tool that ran zero test cases and printed a clean
// summary would be reporting a pass for a document it never opened.
func TestSelectorTypoIsRefused(t *testing.T) {
	for _, args := range [][]string{
		{"-list", "-doc", "SSM-CONF-v0.9"},
		{"-dry-run", "-doc", "NOT-A-DOCUMENT"},
		{"-dry-run", "-uid", "NOT-A-TEST-CASE"},
	} {
		args = append(args, "-catalog", catalogFlag(t))
		code, _, errOut := exec(t, args...)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want %d (a typo must not silently select nothing)", args, code, exitUsage)
		}
		if !strings.Contains(errOut, "certify:") {
			t.Errorf("%v: stderr does not explain the refusal: %q", args, errOut)
		}
	}
}

func TestModesAreMutuallyExclusive(t *testing.T) {
	code, _, errOut := exec(t, "-list", "-verify", "somewhere")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "pick one") {
		t.Errorf("stderr does not name the conflict: %q", errOut)
	}
}

func TestPositionalArgumentIsRefused(t *testing.T) {
	code, _, errOut := exec(t, "runs/whatever")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "unexpected argument") {
		t.Errorf("stderr does not explain: %q", errOut)
	}
}

// TestTargetAliasWinsAndDerivesTheHost pins two behaviours an operator relies
// on: -target is the spelling every other tool in this bench uses, and the
// DUT's bare host is derived from it. A stale GatewayHost makes suitessm
// compare frame directions against a device that is not under test.
func TestTargetAliasWinsAndDerivesTheHost(t *testing.T) {
	c := &cli{opts: certify.DefaultOptions()}
	c.opts.Targets.Gateway = "69.0.0.2:802"
	c.target = "127.0.0.1:9502"
	if err := c.resolve(); err != nil {
		t.Fatal(err)
	}
	if c.opts.Targets.Gateway != "127.0.0.1:9502" {
		t.Errorf("Gateway = %q, want the -target value", c.opts.Targets.Gateway)
	}
	if c.opts.Targets.GatewayHost != "127.0.0.1" {
		t.Errorf("GatewayHost = %q, want it derived from -target", c.opts.Targets.GatewayHost)
	}
	if c.opts.DUT.Address != "127.0.0.1:9502" {
		t.Errorf("the bundle would record DUT address %q", c.opts.DUT.Address)
	}
}

// TestRunOutputDirectoryIsTimestamped keeps two campaigns from writing into
// each other's bundle when the operator does not pass -out.
func TestRunOutputDirectoryIsTimestamped(t *testing.T) {
	c := &cli{opts: certify.DefaultOptions()}
	c.opts.OutDir = ""
	if err := c.resolve(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.opts.OutDir, "runs"+string(filepath.Separator)) {
		t.Errorf("default -out = %q, want runs/<timestamp>", c.opts.OutDir)
	}

	// The non-run modes must NOT invent an output directory: -verify writes
	// nothing, and a stray runs/<ts>/ appearing because somebody verified a
	// bundle would be litter with a misleading name.
	c2 := &cli{opts: certify.DefaultOptions(), verify: "somewhere"}
	c2.opts.OutDir = ""
	if err := c2.resolve(); err != nil {
		t.Fatal(err)
	}
	if c2.opts.OutDir != "" {
		t.Errorf("-verify set an output directory %q", c2.opts.OutDir)
	}
}

func TestVerifyOnSomethingThatIsNotABundle(t *testing.T) {
	code, _, errOut := exec(t, "-verify", t.TempDir())
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "not a readable evidence bundle") {
		t.Errorf("stderr does not explain: %q", errOut)
	}
}

func TestReportOnSomethingThatIsNotABundle(t *testing.T) {
	code, _, errOut := exec(t, "-report", t.TempDir())
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "not a readable evidence bundle") {
		t.Errorf("stderr does not explain: %q", errOut)
	}
}

// TestCapabilitiesExplainsEveryTagAnyCheckRequires closes the dead end an
// operator hits when a run reports "SKIP: missing capability: gateway" and the
// tool never says which flag supplies it.
func TestCapabilitiesExplainsEveryTagAnyCheckRequires(t *testing.T) {
	code, out, errOut := exec(t, "-capabilities", "-catalog", catalogFlag(t))
	if code != exitOK {
		t.Fatalf("exit %d\nstderr: %s", code, errOut)
	}
	for _, reg := range certifyRegistrations() {
		for _, tag := range reg.Requires {
			if !strings.Contains(out, tag) {
				t.Errorf("capability %q gates %s but is not listed", tag, reg.UID)
			}
		}
	}
	if !strings.Contains(out, "-target") || !strings.Contains(out, "-pki") {
		t.Error("the listing does not say which flag supplies a tag")
	}
}

// TestKeylogIsEitherHonouredOrRefusedLoudly is written to hold in BOTH build
// configurations, which is the point.
//
// In the ordinary build there is no key export, and accepting -keylog would
// produce a run that believes its capture is decryptable when it is not —
// discovered days later by whoever tries to verify it. In the keylog build it
// must actually work. Neither build may silently do nothing.
func TestKeylogIsEitherHonouredOrRefusedLoudly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.keylog")
	err := openKeylog(path)
	if err == nil {
		defer closeKeylog()
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("openKeylog reported success but wrote no key log at %s: %v", path, statErr)
		}
		return
	}
	msg := err.Error()
	for _, want := range []string{"-keylog", "keylog"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q: %s", want, msg)
		}
	}
	if !strings.Contains(msg, "decrypt") {
		t.Errorf("the refusal does not say what is lost: %s", msg)
	}
}

// certifyRegistrations is a small indirection so the test above reads by
// intent rather than by package path.
func certifyRegistrations() []certify.Registration {
	return certify.Default().Registrations()
}

// TestSubmissionIsNeverWrittenInsideTheBundle pins the fix for a bug this mode
// shipped with in its first form.
//
// A bundle verifies partly by checking that every file present in the directory
// is listed in its manifest — that is what stops somebody slipping an extra
// artefact in beside the evidence. Writing the submission to
// `<bundle>/submission` therefore made the SOURCE BUNDLE stop verifying the
// moment a report was generated, and the failure surfaced one step later, on the
// next -verify, looking exactly like tampering.
func TestSubmissionIsNeverWrittenInsideTheBundle(t *testing.T) {
	got, err := submissionDir("runs/2026-07-26", "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("runs", "2026-07-26-submission")
	if got != want {
		t.Errorf("default submission dir = %q, want %q (a sibling, not a child)", got, want)
	}
	// A trailing separator must not produce a differently-shaped answer.
	if got, err := submissionDir("runs/2026-07-26/", ""); err != nil || got != want {
		t.Errorf("submissionDir with a trailing separator = %q, %v; want %q", got, err, want)
	}

	for _, inside := range []string{
		"runs/2026-07-26/submission",
		"runs/2026-07-26",
		"runs/2026-07-26/a/b/c",
	} {
		if _, err := submissionDir("runs/2026-07-26", inside); err == nil {
			t.Errorf("-report-out %q was accepted; it would break the bundle it was built from", inside)
		}
	}
	// Anything genuinely outside is fine, including a sibling that merely
	// shares a prefix with the bundle's name.
	for _, outside := range []string{"runs/2026-07-26-submission", "/tmp/sub", "runs/other"} {
		if _, err := submissionDir("runs/2026-07-26", outside); err != nil {
			t.Errorf("-report-out %q was refused: %v", outside, err)
		}
	}
}

// TestInvocationIsRecordedForTheBundle: the bundle's account of how a run was
// made starts here, with the argv this process was handed. The binary's own
// name is part of it because bin/certify and bin/certify-keylog behave
// differently — one can export TLS secrets — and a bundle that named neither
// would leave a reader guessing why its capture does or does not decrypt.
func TestInvocationIsRecordedForTheBundle(t *testing.T) {
	got := invocation([]string{"-doc", "SSM-CONF-v0.8", "-gateway-ssh", "cc93"})
	if len(got) != 5 {
		t.Fatalf("invocation = %v, want the binary name plus the four arguments", got)
	}
	if got[0] == "" || strings.ContainsRune(got[0], '/') {
		t.Errorf("invocation[0] = %q, want the binary's base name", got[0])
	}
	if strings.Join(got[1:], " ") != "-doc SSM-CONF-v0.8 -gateway-ssh cc93" {
		t.Errorf("invocation dropped or reordered arguments: %v", got)
	}
}
