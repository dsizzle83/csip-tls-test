package certify

// clients.go is the control plane a check drives the bench with: the gridsim
// admin API, the sims' simapi sidecars, and READ-ONLY introspection of the
// gateway.
//
// These are deliberately thin. They speak the three sim APIs the bench already
// exposes (GET /state, POST /inject, POST /control on simapi; /admin/* on
// gridsim) and hand back raw JSON or a caller-supplied destination, because the
// payload schemas belong to the sims, not to this framework — modelling them
// here would create a second definition to drift out of sync with the first.
//
// # Why the gateway client refuses to do most things
//
// The bench has several agents working in parallel and one gateway. A check
// that restarts a service or edits config to make its own test pass does not
// just break the other agents' runs; it invalidates the evidence of every test
// case that ran before it, because the DUT that produced those frames is no
// longer the DUT the bundle claims. Gateway therefore executes only commands
// whose first word is on a read-only allowlist, and refuses everything else
// with an error naming the constraint. It is a guard rail, not a security
// boundary — an agent determined to route around it can — but it makes the
// mutation deliberate rather than accidental, which is what a guard rail is for.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// httpTimeout bounds every control-plane request. A hung admin API must not
// hang the run: a check that cannot reach its sim should FAIL promptly with
// that fact, which is evidence, rather than stall until the operator gives up.
const httpTimeout = 15 * time.Second

// HTTPClient is the small slice of *http.Client this package needs, so a test
// can substitute a transport without a live listener.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// restClient is the shared JSON-over-HTTP plumbing.
type restClient struct {
	base string
	http HTTPClient
}

func newREST(base string, hc HTTPClient) restClient {
	if hc == nil {
		hc = &http.Client{Timeout: httpTimeout}
	}
	return restClient{base: strings.TrimRight(base, "/"), http: hc}
}

// do issues a request and returns the body. Non-2xx is an error carrying the
// status and a bounded slice of the body — a 500 whose text nobody printed is a
// debugging session nobody needed to have.
func (c restClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	if c.base == "" {
		return nil, fmt.Errorf("certify: no base URL configured for %s %s", method, path)
	}
	var rdr io.Reader
	if body != nil {
		enc, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("certify: encode %s %s body: %w", method, path, err)
		}
		rdr = bytes.NewReader(enc)
	}
	url := c.base + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, fmt.Errorf("certify: %s %s: %w", method, url, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certify: %s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, fmt.Errorf("certify: %s %s: HTTP %d: %s", method, url, resp.StatusCode, snippet(data))
	}
	if readErr != nil {
		return nil, fmt.Errorf("certify: %s %s: read body: %w", method, url, readErr)
	}
	return data, nil
}

func (c restClient) json(ctx context.Context, method, path string, body, out any) error {
	data, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("certify: %s %s: decode response: %w (body: %s)", method, path, err, snippet(data))
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// AdminClient drives the gridsim 2030.5 server simulator's admin API — the
// bench's lever for making the DUT's CSIP client see a particular server
// behaviour (a DERControl, a redirect, a malformed resource, a clock warp).
//
// Every method takes a caller-supplied destination for the response rather than
// a typed struct: gridsim owns those schemas.
type AdminClient struct {
	restClient
	// BaseURL is the admin API root, e.g. "http://69.0.0.20:11114".
	BaseURL string
}

// NewAdminClient returns a gridsim admin client. An empty base URL yields a
// client whose every call fails with a clear message, so a check that needs
// gridsim and did not get it produces a FAIL that says why.
func NewAdminClient(baseURL string, hc HTTPClient) *AdminClient {
	return &AdminClient{restClient: newREST(baseURL, hc), BaseURL: baseURL}
}

// Available reports whether an admin URL was configured at all.
func (a *AdminClient) Available() bool { return a != nil && a.BaseURL != "" }

// Get issues GET /admin/<path> and decodes into out.
func (a *AdminClient) Get(ctx context.Context, path string, out any) error {
	return a.json(ctx, http.MethodGet, "/admin/"+strings.TrimLeft(path, "/"), nil, out)
}

// Post issues POST /admin/<path> with a JSON body and decodes into out.
func (a *AdminClient) Post(ctx context.Context, path string, body, out any) error {
	return a.json(ctx, http.MethodPost, "/admin/"+strings.TrimLeft(path, "/"), body, out)
}

// Status reads /admin/status.
func (a *AdminClient) Status(ctx context.Context, out any) error { return a.Get(ctx, "status", out) }

// Logs reads /admin/logs.json?since=<cursor>: the simulator's request log as a
// cursor-based slice.
//
// Use this, not the /admin/logs SSE stream, for anything that computes "what
// happened since I last looked". The log is a bounded ring, so a delta taken
// from the stream's replay length collapses to empty once it wraps — which
// reports a busy device as an idle one.
func (a *AdminClient) Logs(ctx context.Context, cursor uint64, out any) error {
	return a.Get(ctx, fmt.Sprintf("logs.json?since=%d", cursor), out)
}

// Control posts a DERControl to /admin/control.
func (a *AdminClient) Control(ctx context.Context, body, out any) error {
	return a.Post(ctx, "control", body, out)
}

// Clock warps the simulator's 2030.5 clock via /admin/clock, which is how a
// test case reaches a scheduled event without waiting for it.
func (a *AdminClient) Clock(ctx context.Context, body, out any) error {
	return a.Post(ctx, "clock", body, out)
}

// Responses reads /admin/responses: the DERControlResponse POSTs the DUT made.
// It is the server-side half of the evidence for every scheduling test case,
// and it is a NON-wire source — an assertion resting on it is a Narrative, not
// a citation.
func (a *AdminClient) Responses(ctx context.Context, out any) error {
	return a.Get(ctx, "responses", out)
}

// DERPuts reads /admin/derputs: the DERCapability/DERSettings/DERStatus PUTs
// the DUT made.
func (a *AdminClient) DERPuts(ctx context.Context, out any) error {
	return a.Get(ctx, "derputs", out)
}

// LogEvents reads /admin/logevents.
func (a *AdminClient) LogEvents(ctx context.Context, out any) error {
	return a.Get(ctx, "logevents", out)
}

// Chain reads GET /admin/chain: which certificate chain the bench's 2030.5
// server is presenting to NEW connections, and which one it started with.
//
// A gridsim predating the lever answers 404; one whose binary has no TLS data
// plane wired to it answers 501. Both arrive here as an error, and a check MUST
// establish that this call succeeded before running a rejection sub-test:
// driving COMM-004 D/E/F/G against a bench that never installed the fixture
// would credit the DUT with a rejection it was never asked to make.
func (a *AdminClient) Chain(ctx context.Context, out any) error {
	return a.Get(ctx, "chain", out)
}

// SwapChain posts a chain to /admin/chain. body carries label, cert_pem and
// key_pem; gridsim owns that schema, so it is not modelled here.
//
// Every caller MUST pair this with a DEFERRED RestoreChain. A bench left
// presenting a fixture chain fails every conformance case that runs after it,
// including other agents' — which is a far worse outcome than the single failed
// case an un-restored bench was ever going to save.
func (a *AdminClient) SwapChain(ctx context.Context, body, out any) error {
	return a.Post(ctx, "chain", body, out)
}

// RestoreChain posts {"restore":true} to /admin/chain, reinstalling the chain
// the bench's 2030.5 server started with.
//
// It deliberately takes no argument beyond the context: it is the call a
// cleanup path makes, and a cleanup path must not depend on state the check
// that failed was supposed to have kept.
func (a *AdminClient) RestoreChain(ctx context.Context, out any) error {
	return a.Post(ctx, "chain", map[string]any{"restore": true}, out)
}

// Raw is the escape hatch for admin endpoints this client does not name.
func (a *AdminClient) Raw(ctx context.Context, method, path string, body any) ([]byte, error) {
	return a.do(ctx, method, path, body)
}

// SimClient drives one device simulator's simapi sidecar.
type SimClient struct {
	restClient
	// Name is the sim's short name ("modsim", "mbapsdev"), used in errors and
	// in the report so a reader knows which device was driven.
	Name string
	// BaseURL is the simapi root, e.g. "http://69.0.0.20:6020".
	BaseURL string
}

// NewSimClient returns a simapi client.
func NewSimClient(name, baseURL string, hc HTTPClient) *SimClient {
	return &SimClient{restClient: newREST(baseURL, hc), Name: name, BaseURL: baseURL}
}

// Available reports whether a simapi URL was configured.
func (s *SimClient) Available() bool { return s != nil && s.BaseURL != "" }

// State reads GET /state — the sim's world model.
func (s *SimClient) State(ctx context.Context, out any) error {
	return s.json(ctx, http.MethodGet, "/state", nil, out)
}

// Inject posts POST /inject — set an environmental or measurement value.
func (s *SimClient) Inject(ctx context.Context, body, out any) error {
	return s.json(ctx, http.MethodPost, "/inject", body, out)
}

// Control posts POST /control — drive the device's operating state.
func (s *SimClient) Control(ctx context.Context, body, out any) error {
	return s.json(ctx, http.MethodPost, "/control", body, out)
}

// Registers reads GET /registers — the raw SunSpec register image, which is
// what a Modbus test case compares its wire read against.
func (s *SimClient) Registers(ctx context.Context, out any) error {
	return s.json(ctx, http.MethodGet, "/registers", nil, out)
}

// Fault posts POST /fault — inject a device fault condition.
func (s *SimClient) Fault(ctx context.Context, body, out any) error {
	return s.json(ctx, http.MethodPost, "/fault", body, out)
}

// Raw is the escape hatch.
func (s *SimClient) Raw(ctx context.Context, method, path string, body any) ([]byte, error) {
	return s.do(ctx, method, path, body)
}

// readOnlyCommands is the allowlist of gateway commands a check may run. Every
// one of them observes; none of them changes anything. `systemctl` is admitted
// only for its reporting subcommands, checked separately.
//
// `wget` (IW27-004) is here so metricscrape.NewSSHSource can fetch the DUT's
// own loopback-bound /metrics endpoint by asking the DUT to fetch it itself —
// only ever invoked as `wget -qO- <url>`, a plain GET, never with
// `--post-data`/`--method` or any other verb-changing flag.
var readOnlyCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "ls": true, "stat": true,
	"grep": true, "journalctl": true, "uname": true, "hostname": true,
	"date": true, "uptime": true, "df": true, "ss": true, "ip": true,
	"openssl": true, "sha256sum": true, "md5sum": true, "readlink": true,
	"find": true, "wc": true, "id": true, "env": true, "true": true,
	"systemctl": true, "fw_printenv": true, "bootcount": true, "wget": true,
}

// systemctlReadOnly is the set of systemctl subcommands that only report.
var systemctlReadOnly = map[string]bool{
	"show": true, "status": true, "is-active": true, "is-enabled": true,
	"is-failed": true, "list-units": true, "list-unit-files": true, "cat": true,
}

// wgetMutatingFlagPrefixes are wget flags that turn a fetch into a write to
// the DUT (a differently-verbed request, a body upload) — checked as
// prefixes because wget accepts both "--post-data=x" and "--post-data x"
// forms. This exists because readOnlyCommands' doc comment asserts wget is
// "only ever invoked as `wget -qO- <url>`... never with --post-data" as an
// invariant of its one caller (metricscrape.NewSSHSource) — true today, but
// not enforced by the allowlist itself the way systemctl's subcommand is. A
// second caller added later without reading that comment would silently
// inherit an unrestricted wget.
var wgetMutatingFlagPrefixes = []string{
	"--post-data", "--post-file", "--method", "--body-data", "--body-file",
}

// wgetStdoutTokens are the exact argument spellings this repo's one caller
// (metricscrape.NewSSHSource, "wget -qO- <url>") and its reasonable variants
// use to send the fetched body to stdout instead of wget's own default of
// writing a same-named file to the DUT's filesystem. Matched exactly, not by
// prefix/suffix, so an unanticipated combined short-flag spelling is treated
// as unsafe rather than guessed at.
var wgetStdoutTokens = map[string]bool{
	"-O-": true, "-qO-": true, "-nvO-": true, "--output-document=-": true,
}

// wgetReadOnly reports whether a wget invocation is the plain-GET-to-stdout
// shape this allowlist exists to permit, rejecting anything else even though
// the command's head token is allowed.
func wgetReadOnly(args []string) error {
	sawStdoutOutput := false
	for _, a := range args {
		for _, bad := range wgetMutatingFlagPrefixes {
			if strings.HasPrefix(a, bad) {
				return fmt.Errorf("%w: wget %q is a verb-changing flag; only a plain GET is permitted",
					ErrNotReadOnly, a)
			}
		}
		if wgetStdoutTokens[a] {
			sawStdoutOutput = true
			continue
		}
		if strings.HasPrefix(a, "-O") || strings.HasPrefix(a, "--output-document") {
			return fmt.Errorf("%w: wget %q writes to a file instead of stdout; only -O- (or -qO-) is permitted",
				ErrNotReadOnly, a)
		}
	}
	if !sawStdoutOutput {
		return fmt.Errorf("%w: wget invocation does not fetch to stdout (-O-/-qO-/--output-document=-); refusing an ambiguous form that would default to writing a file on the DUT",
			ErrNotReadOnly)
	}
	return nil
}

// ErrNotReadOnly is returned when a check tries to run a mutating command on
// the gateway.
var ErrNotReadOnly = errors.New("certify: the gateway client is read-only")

// Gateway is read-only introspection of the device under test over SSH.
//
// It exists because some catalog cases' evidence is a fact about the DUT's
// configuration (which certificates are installed, which build is running) that
// no amount of packet capture will show. Those facts become Narrative
// assertions with "gateway introspection" as the source — never citations.
type Gateway struct {
	// SSH is the ssh destination or alias ("cc93", "root@69.0.0.2"). Empty
	// disables introspection, and every call then fails with that fact.
	SSH string
	// Timeout bounds one command.
	Timeout time.Duration
	// Runner executes the command; nil means real ssh. A test substitutes it.
	Runner func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Available reports whether gateway introspection was configured.
func (g *Gateway) Available() bool { return g != nil && g.SSH != "" }

// CheckReadOnly reports whether a command is on the read-only allowlist,
// returning a descriptive error when it is not. It is exported so a suite can
// test its own intent before building a command line.
func CheckReadOnly(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: empty command", ErrNotReadOnly)
	}
	head := args[0]
	if !readOnlyCommands[head] {
		return fmt.Errorf("%w: %q is not on the read-only allowlist (%s). The bench is shared and a "+
			"conformance run must not change the DUT it is measuring",
			ErrNotReadOnly, head, strings.Join(sortedKeys(readOnlyCommands), " "))
	}
	if head == "systemctl" {
		sub := ""
		for _, a := range args[1:] {
			if !strings.HasPrefix(a, "-") {
				sub = a
				break
			}
		}
		if !systemctlReadOnly[sub] {
			return fmt.Errorf("%w: systemctl %q changes service state; only %s are permitted",
				ErrNotReadOnly, sub, strings.Join(sortedKeys(systemctlReadOnly), "/"))
		}
	}
	if head == "wget" {
		if err := wgetReadOnly(args[1:]); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Run executes a read-only command on the gateway and returns its stdout.
func (g *Gateway) Run(ctx context.Context, args ...string) ([]byte, error) {
	if !g.Available() {
		return nil, errors.New("certify: no gateway ssh destination configured (-gateway-ssh)")
	}
	if err := CheckReadOnly(args); err != nil {
		return nil, err
	}
	to := g.Timeout
	if to <= 0 {
		to = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	run := g.Runner
	if run == nil {
		run = func(ctx context.Context, name string, a ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, a...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
			}
			return out, nil
		}
	}
	sshArgs := append([]string{"-o", "BatchMode=yes", g.SSH}, args...)
	out, err := run(ctx, "ssh", sshArgs...)
	if err != nil {
		return out, fmt.Errorf("certify: gateway %s: %v: %w", g.SSH, args, err)
	}
	return out, nil
}

// ReadFile reads a file from the gateway.
func (g *Gateway) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return g.Run(ctx, "cat", path)
}

// Journal reads the last n lines of a unit's journal.
func (g *Gateway) Journal(ctx context.Context, unit string, lines int) ([]byte, error) {
	if lines <= 0 {
		lines = 200
	}
	return g.Run(ctx, "journalctl", "-u", unit, "-n", fmt.Sprint(lines), "--no-pager", "-o", "short-iso")
}

// UnitActive reports whether a systemd unit is active.
func (g *Gateway) UnitActive(ctx context.Context, unit string) (bool, error) {
	out, err := g.Run(ctx, "systemctl", "is-active", unit)
	state := strings.TrimSpace(string(out))
	if err != nil && state == "" {
		return false, err
	}
	return state == "active", nil
}

// Build returns a best-effort firmware/build identifier for the bundle's DUT
// record. A failure is not fatal: an unrecorded build is a gap in the bundle's
// metadata, not a reason to abandon a conformance run.
func (g *Gateway) Build(ctx context.Context) (string, error) {
	for _, p := range []string{"/etc/lexa-release", "/etc/os-release"} {
		if out, err := g.ReadFile(ctx, p); err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	out, err := g.Run(ctx, "uname", "-a")
	return strings.TrimSpace(string(out)), err
}
