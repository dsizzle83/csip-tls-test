package certify

// authority.go knows which catalog rows have a DUT ARBITRATION POSTURE as their
// precondition, and how to read the live posture off the device.
//
// # What an authority precondition is
//
// The product arbitrates control of its DER between mutually exclusive lanes —
// the CSIP control path, the northbound Secure SunSpec Modbus write path, and a
// local commissioning path — and exactly one of them owns lexa/desired/* at a
// time (lexa-gw internal/authority/manager.go). The lane that does NOT own it is
// not merely idle: the arbitration layer DELIBERATELY REFUSES its writes, and on
// the Secure SunSpec side it does so through an RBAC overlay that denies model
// 704-712 control writes to every role including SuperAdministratorSunSpec
// (configs/rbac/overlays.d/10-csip-mode.json, the "D1 lock-screen").
//
// So a conformance row whose subject is a CONTROL PATH has a precondition no
// published document mentions: the lane it exercises must be the one in
// authority. Run it under the other posture and it measures a refusal that is
// correct product behaviour, and reports it as the row's own verdict. That is
// not a hypothetical — it is RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES
// (lexa-gw/docs/known_issues.json), a whole cluster of RBAC findings that were
// findings about the lock-screen.
//
// # Why this is a table and not a derivation
//
// It was tried the other way first. The catalog's `preconditions` are the
// published documents' own words, and those documents know nothing about this
// product's arbitration — SSM-CONF-v0.8's RBAC-002 preconditions say "EUT-S
// configured as a Secure SunSpec Modbus server", nothing more. Nothing in the
// catalog distinguishes a control row from a read row in a machine-readable way
// either: `observables` and `expected` are prose, and classifying rows by
// grepping prose for "DERControl" is a rule that fails silently the first time
// someone rewords a row.
//
// So the classification is a TABLE, written down once, each entry carrying the
// reason it is there — and it is guarded by three tests rather than by care:
// every uid in it must exist in the catalog, every entry must carry a reason,
// and every row in a campaign-owned suite must be either classified or listed in
// the test's acknowledged-unclassified set with a justification. A new catalog
// row therefore cannot join a campaign without somebody deciding, in writing,
// which lane it needs.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// AuthorityProfile is a DUT control-arbitration posture. The values are the
// product's own (lexa-gw internal/authority/manager.go and the
// configs/schema/mode.schema.json enum), not this harness's invention.
type AuthorityProfile string

// The postures.
const (
	// AuthorityAny is the ABSENCE of a pinned requirement, not a posture. A
	// campaign carrying it requires only that whatever is live be a posture the
	// candidate manifest declares.
	AuthorityAny AuthorityProfile = ""
	// AuthorityMBAPS — the northbound Modbus write path owns lexa/desired/*.
	// The product default.
	AuthorityMBAPS AuthorityProfile = "mbaps"
	// AuthorityCSIP — the 2030.5 northbound walker's resolved active control
	// owns lexa/desired/*.
	AuthorityCSIP AuthorityProfile = "csip"
	// AuthorityLocal — dev-API commissioning intents own lexa/desired/*.
	AuthorityLocal AuthorityProfile = "local"
)

// ValidAuthority reports whether a is a posture the product defines. A value
// outside the three is not an unfamiliar posture to tolerate: it is a reading
// this harness cannot interpret, and a precondition it cannot interpret is one
// it has not checked.
func ValidAuthority(a AuthorityProfile) bool {
	switch a {
	case AuthorityMBAPS, AuthorityCSIP, AuthorityLocal:
		return true
	}
	return false
}

// KnownAuthorities lists the postures, for an error message.
func KnownAuthorities() []string {
	return []string{string(AuthorityMBAPS), string(AuthorityCSIP), string(AuthorityLocal)}
}

// authorityFamily is a group of rows sharing one precondition and one reason.
type authorityFamily struct {
	Authority AuthorityProfile
	// Because is the reason the whole family needs this posture, in the words a
	// refusal message will use. Every family must carry one — see
	// TestAuthorityFamiliesCarryReasons.
	Because string
	UIDs    []string
}

// authorityFamilies is the classification. Rows are listed in full rather than
// by prefix so that `grep BASIC-011 internal/certify` finds this decision.
var authorityFamilies = []authorityFamily{
	{
		Authority: AuthorityCSIP,
		Because: "the row publishes a DERControl and grades what the DER actually did, so the CSIP " +
			"control path must own lexa/desired/*. Under any other posture the arbitration layer declines " +
			"to apply the control and the row measures that refusal",
		UIDs: []string{
			"csip-conf-v1.3::BASIC-004", // Low/High Voltage Ride-Through curves
			"csip-conf-v1.3::BASIC-005", // Low/High Frequency Ride-Through curves
			"csip-conf-v1.3::BASIC-006", // Volt/Var
			"csip-conf-v1.3::BASIC-007", // Ramp Rates
			"csip-conf-v1.3::BASIC-008", // Fixed Power Factor
			"csip-conf-v1.3::BASIC-009", // Connect/Disconnect
			"csip-conf-v1.3::BASIC-010", // Limit Max Active Power
			"csip-conf-v1.3::BASIC-011", // Volt-Watt
			"csip-conf-v1.3::BASIC-012", // Frequency Droop / Frequency-Watt
			"csip-conf-v1.3::BASIC-013", // Set Active Power Mode (%)
			"csip-conf-v1.3::BASIC-014", // Set Active Power Mode (W)
			"csip-conf-v1.3::BASIC-015", // Advanced Inverter Control
		},
	},
	{
		Authority: AuthorityCSIP,
		Because: "the row publishes SEVERAL overlapping DERControls and grades which one the DUT applied, " +
			"so the CSIP control path must own lexa/desired/*. Under any other posture none of them is " +
			"applied and the precedence question the row asks never arises",
		UIDs: []string{
			"csip-conf-v1.3::BASIC-016",
			"csip-conf-v1.3::BASIC-017",
			"csip-conf-v1.3::BASIC-018",
			"csip-conf-v1.3::BASIC-019",
			"csip-conf-v1.3::BASIC-020",
			"csip-conf-v1.3::BASIC-021",
			"csip-conf-v1.3::BASIC-022",
			"csip-conf-v1.3::BASIC-023",
			"csip-conf-v1.3::BASIC-024",
			"csip-conf-v1.3::BASIC-025",
			"csip-conf-v1.3::BASIC-026",
		},
	},
	{
		Authority: AuthorityCSIP,
		Because: "the row's subject is the DER program/control lifecycle itself — adoption, randomisation, " +
			"the Response the DUT owes for a control it applied, and which control supersedes which — and " +
			"every one of those observables exists only while the CSIP control path owns lexa/desired/*",
		UIDs: []string{
			"csip-conf-v1.3::CORE-012", // Basic DER Program/Control
			"csip-conf-v1.3::CORE-013", // Advanced DER Program/Control
			"csip-conf-v1.3::CORE-021", // Randomized Events
			"csip-conf-v1.3::CORE-022", // Responses
			"csip-conf-v1.3::CORE-023", // Superseding Events
			"local-ext-v1::EXT-002",    // reserved currentStatus is not a cancel (REV0907-B1)
			"local-ext-v1::EXT-003",    // Cancelled with Randomization (currentStatus 3)
		},
	},
	{
		Authority: AuthorityCSIP,
		Because: "the row publishes an opModWattVar curve and grades its adoption in the DER's own model " +
			"712 registers, which is a CSIP control path observable",
		UIDs: []string{"local-ext-v1::EXT-001"},
	},
	{
		Authority: AuthorityMBAPS,
		Because: "the row's subject is the northbound Modbus role-to-rights decision on a CONTROL write, " +
			"so the mbaps write path must own lexa/desired/*. Under \"csip\" the D1 lock-screen overlay " +
			"(configs/rbac/overlays.d/10-csip-mode.json) denies every model 704-712 control write for " +
			"EVERY role — SuperAdministratorSunSpec included — by design, and the row then measures the " +
			"lock-screen instead of its own subject. That is RBAC-002-MODEL704-REG40298-WRITE-DENIED-" +
			"ALL-ROLES (lexa-gw/docs/known_issues.json)",
		UIDs: []string{
			"ssm-conf-v0.8::RBAC-001",
			"ssm-conf-v0.8::RBAC-002",
			"ssm-conf-v0.8::RBAC-003",
			"ssm-conf-v0.8::RBAC-004",
			"ssm-conf-v0.8::RBAC-005",
			"ssm-conf-v0.8::RBAC-006",
			"ssm-conf-v0.8::RBAC-007",
			"ssm-conf-v0.8::RBAC-008",
			"ssm-conf-v0.8::RBAC-009",
			"ssm-conf-v0.8::RBAC-010",
			"ssm-conf-v0.8::RBAC-011",
			"ssm-conf-v0.8::RBAC-012",
		},
	},
	{
		Authority: AuthorityMBAPS,
		Because: "the row WRITES a register and grades what the write did, so the mbaps write path must " +
			"own lexa/desired/*. Under \"csip\" the lock-screen overlay refuses the write, and a row whose " +
			"pass criterion is a refusal then passes for entirely the wrong reason — which is worse than " +
			"failing, because nothing about the bundle looks wrong",
		UIDs: []string{
			"ss-modbus-conf-v1.4::MB-1",  // single/multiple register write
			"ss-modbus-conf-v1.4::MOD-3", // point write
			"ss-modbus-conf-v1.4::EXC-1", // invalid value: a write that must be refused
			"ss-modbus-conf-v1.4::EXC-2", // writing a read-only register: likewise
			"ss-modbus-conf-v1.4::CRV-1", // curve support: writes a curve
			"ss-modbus-conf-v1.4::REV-1", // reversion timeout: writes, then waits for reversion
			"ss-modbus-conf-v1.4::REV-2", // reversion time update: writes
			"ss-modbus-conf-v1.4::REV-3", // reversion cancel: writes
		},
	},
}

// authorityByUID is the flattened lookup, built once with a duplicate check.
var authorityByUID = func() map[string]authorityFamily {
	m := make(map[string]authorityFamily)
	for _, f := range authorityFamilies {
		for _, uid := range f.UIDs {
			if prev, dup := m[uid]; dup {
				// Two families claiming one row means two different answers to
				// "which lane does this need", and picking either at random is
				// how a precondition check comes to enforce the wrong one.
				panic(fmt.Sprintf("certify: %s is classified twice in authorityFamilies (%s and %s)",
					uid, prev.Authority, f.Authority))
			}
			m[uid] = f
		}
	}
	return m
}()

// AuthorityPreconditionFor reports the posture a catalog row needs, and why.
// The bool is false for a row with no authority precondition at all — a
// discovery, read or transport row, which measures the same thing under every
// posture.
func AuthorityPreconditionFor(uid string) (AuthorityProfile, string, bool) {
	f, ok := authorityByUID[uid]
	if !ok {
		return AuthorityAny, "", false
	}
	return f.Authority, f.Because, true
}

// ClassifiedAuthorityUIDs lists every classified row, sorted. Exported for the
// tests that hold this table against the catalog.
func ClassifiedAuthorityUIDs() []string {
	out := make([]string, 0, len(authorityByUID))
	for uid := range authorityByUID {
		out = append(out, uid)
	}
	sort.Strings(out)
	return out
}

// authorityDemand is what a plan needs: which postures, and which rows want
// them.
type authorityDemand struct {
	// Rows maps a required posture to the uids that require it, sorted.
	Rows map[AuthorityProfile][]string
}

// Postures lists the required postures, sorted, so a message is deterministic.
func (d authorityDemand) Postures() []AuthorityProfile {
	out := make([]AuthorityProfile, 0, len(d.Rows))
	for a := range d.Rows {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// planAuthorityDemand reports the postures the rows this run will ACTUALLY
// EXECUTE require.
//
// A case that will skip anyway — unimplemented, missing a capability, filtered
// out — costs nothing to measure under the wrong posture, so it does not arm the
// check. That is the same rule the original RBAC-only version applied, kept
// deliberately: arming on rows that never run would make the check something
// operators learn to bypass.
func planAuthorityDemand(plan []Planned) authorityDemand {
	d := authorityDemand{Rows: map[AuthorityProfile][]string{}}
	for _, p := range plan {
		if !p.Implemented || p.Skip != "" || p.Case == nil {
			continue
		}
		if a, _, ok := AuthorityPreconditionFor(p.Case.UID); ok {
			d.Rows[a] = append(d.Rows[a], p.Case.UID)
		}
	}
	for a := range d.Rows {
		sort.Strings(d.Rows[a])
	}
	return d
}

// Where the live posture is read from. All three are read-only and all three go
// through Gateway's allowlist.
const (
	// DefaultDevAPI is the DUT's dev API base URL. lexa-gw's configs/api.json
	// binds it to the LOOPBACK 127.0.0.1:9100 and serves HTTPS with a
	// per-device self-signed leaf, so it is reachable only from ON the device —
	// which is exactly what the gateway runner gives us.
	DefaultDevAPI = "https://127.0.0.1:9100"
	// devAPITokenPath is where lexa-gw's shipped api.json points api_token_file.
	// GET /mode is bearer-protected whenever that file is present and non-empty.
	devAPITokenPath = "/etc/lexa/api.token"
	// gatewayModePath is the ADMIN-OWNED boot posture. lexa-mode only reads it.
	gatewayModePath = "/etc/lexa/mode.json"
	// gatewayModeOverlayPath is the INTENT-OWNED runtime half, written by
	// lexa-mode when an authority intent is applied. When it declares an
	// authority, IT is the configured posture and mode.json is merely the
	// factory default underneath it — reading only mode.json would make every
	// legitimately-flipped device look like a disagreement.
	gatewayModeOverlayPath = "/var/lib/lexa/mode-overlay.json"
)

// AuthorityReading is what the DUT said about its own posture, from both
// channels.
type AuthorityReading struct {
	// Live is the posture the running system is IN, read from the dev API's
	// projection of the retained lexa/mode document.
	Live AuthorityProfile
	// LiveFrom names the channel, for the evidence line.
	LiveFrom string
	// Configured is the posture the device is configured to hold, from the
	// overlay if it declares one and otherwise from mode.json.
	Configured AuthorityProfile
	// ConfiguredFrom is which of the two files Configured came from.
	ConfiguredFrom string
	// CSIPEnabled and FailsafeEngaged ride along because both change what a
	// control row can possibly observe, and a refusal that mentions them saves
	// an operator a bench session.
	CSIPEnabled     bool
	FailsafeEngaged bool
	// Authenticated records whether the dev API request carried a bearer token.
	Authenticated bool
}

// String renders the reading for a console line.
func (r AuthorityReading) String() string {
	s := fmt.Sprintf("live=%q (%s) configured=%q (%s)", r.Live, r.LiveFrom, r.Configured, r.ConfiguredFrom)
	if !r.CSIPEnabled {
		s += " csip_enabled=false"
	}
	if r.FailsafeEngaged {
		s += " FAILSAFE ENGAGED"
	}
	return s
}

// devAPIMode is the subset of GET /mode this check reads. The dev API's response
// is flat and every key is always present (lexa-gw cmd/api/mode.go modeResp), so
// a missing control_authority is a real anomaly rather than an older device.
type devAPIMode struct {
	ControlAuthority string `json:"control_authority"`
	CSIPEnabled      bool   `json:"csip_enabled"`
	FailsafeEngaged  bool   `json:"failsafe_engaged"`
}

// gatewayModeFile is the subset of /etc/lexa/mode.json this check reads.
type gatewayModeFile struct {
	Authority string `json:"authority"`
}

// gatewayModeOverlay is the subset of /var/lib/lexa/mode-overlay.json this check
// reads. Authority is a POINTER in the product's own struct because absent and
// empty are different there, and it is one here for the same reason.
type gatewayModeOverlay struct {
	Authority *string `json:"authority"`
}

// ReadAuthority reads the DUT's live and configured postures through the gateway
// runner.
//
// # Why the live half goes through the dev API rather than the config file
//
// /etc/lexa/mode.json is what the device was CONFIGURED with. The posture it is
// IN can differ — an applied authority intent writes /var/lib/lexa/mode-overlay
// .json, and live arbitration moves it again — so a check that read only the
// config file would confirm a posture nobody is in. That was the original
// version of this check, and its own comment said POST /intent {"type":
// "authority"} could not flip authority at all. That has not been true since
// lexa-gw cmd/mode/main.go subscribed lexa/intent/authority and
// internal/authority/intentin.go grew a real fail-closed transition: the lever
// works, the live posture is published RETAINED on lexa/mode, and the dev API
// projects it at GET /mode. So the live half is read there, and the configured
// half is kept as a CROSS-CHECK rather than as the answer.
func ReadAuthority(ctx context.Context, gw *Gateway, devAPIBase string) (AuthorityReading, error) {
	var out AuthorityReading
	if !gw.Available() {
		return out, fmt.Errorf("certify: no gateway introspection configured, so the DUT's live control " +
			"authority cannot be read (pass -gateway-ssh for a remote DUT, or -gateway-exec for one on " +
			"this host)")
	}
	if devAPIBase == "" {
		devAPIBase = DefaultDevAPI
	}
	url := strings.TrimRight(devAPIBase, "/") + "/mode"

	// The bearer token, when the device has one. lexa-gw's requireBearer is
	// staged-open — an unconfigured token leaves the route open — so a token we
	// cannot read is a reason to try without one, not a reason to give up. What
	// is recorded either way is which of the two happened.
	args := []string{"wget", "-qO-", "--no-check-certificate"}
	if tok, err := gw.Run(ctx, "cat", devAPITokenPath); err == nil {
		if t := strings.TrimSpace(string(tok)); t != "" {
			args = append(args, "--header", "Authorization: Bearer "+t)
			out.Authenticated = true
		}
	}
	args = append(args, url)

	body, err := gw.Run(ctx, args...)
	if err != nil {
		return out, fmt.Errorf("certify: could not read the DUT's live control authority from %s over %s: "+
			"%w. wget's exit status does not separate a transport failure from a non-200, so this is "+
			"either lexa-api not listening, a bearer token this run could not read (%s), or the API "+
			"answering 503 because no retained lexa/mode document has arrived yet — all three of which "+
			"mean the posture is unknown",
			url, gw.Describe(), err, devAPITokenPath)
	}
	var m devAPIMode
	if err := json.Unmarshal(body, &m); err != nil {
		return out, fmt.Errorf("certify: %s did not answer with the dev API's mode document: %w (got %q)",
			url, err, trunc(strings.TrimSpace(string(body)), 200))
	}
	out.Live = AuthorityProfile(strings.TrimSpace(m.ControlAuthority))
	out.LiveFrom = url
	out.CSIPEnabled = m.CSIPEnabled
	out.FailsafeEngaged = m.FailsafeEngaged

	// The cross-check. The overlay wins when it declares one: see
	// gatewayModeOverlayPath.
	if raw, err := gw.Run(ctx, "cat", gatewayModeOverlayPath); err == nil {
		var ov gatewayModeOverlay
		if err := json.Unmarshal(raw, &ov); err == nil && ov.Authority != nil {
			out.Configured = AuthorityProfile(strings.TrimSpace(*ov.Authority))
			out.ConfiguredFrom = gatewayModeOverlayPath
		}
	}
	if out.Configured == "" {
		raw, err := gw.Run(ctx, "cat", gatewayModePath)
		if err != nil {
			return out, fmt.Errorf("certify: the DUT's live control authority is %q, but %s could not be "+
				"read over %s to cross-check it: %w. A live posture with nothing to check it against is a "+
				"posture this run cannot evidence",
				out.Live, gatewayModePath, gw.Describe(), err)
		}
		var f gatewayModeFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return out, fmt.Errorf("certify: %s on the DUT did not decode as JSON: %w", gatewayModePath, err)
		}
		out.Configured = AuthorityProfile(strings.TrimSpace(f.Authority))
		out.ConfiguredFrom = gatewayModePath
	}
	return out, nil
}

// CheckAuthority grades a reading against the posture a run requires.
//
// want may be AuthorityAny, in which case no single posture is demanded and the
// live one only has to be one the candidate CLAIMS — claimed is the caller's
// predicate, so this function stays independent of the manifest package.
func CheckAuthority(r AuthorityReading, want AuthorityProfile, because string, claimed func(AuthorityProfile) bool) error {
	switch {
	case r.Live == "":
		return fmt.Errorf("certify: preflight: the DUT's dev API answered but declared NO control " +
			"authority. A posture this run cannot name is one it cannot hold a precondition against")
	case !ValidAuthority(r.Live):
		return fmt.Errorf("certify: preflight: the DUT reports control authority %q, which is not one of "+
			"%s. This harness will not proceed against a posture it cannot interpret",
			r.Live, strings.Join(KnownAuthorities(), " / "))
	case r.Configured == "":
		return fmt.Errorf("certify: preflight: the DUT's live control authority is %q but %s declares "+
			"none, so the live reading has nothing to be cross-checked against. Fix the DUT's %s (its "+
			"\"authority\" key) rather than running against an unconfirmed posture",
			r.Live, r.ConfiguredFrom, r.ConfiguredFrom)
	case r.Live != r.Configured:
		return fmt.Errorf("certify: preflight: the DUT's LIVE control authority is %q but its CONFIGURED "+
			"posture is %q (%s). The two disagreeing means arbitration has moved the device away from "+
			"what it is set to hold — mid-flight, or left there by an earlier run — and a campaign "+
			"measured across that boundary is a campaign whose rows saw two different devices. Park the "+
			"device: set the authority you want in %s (or apply an authority intent), confirm no control "+
			"is active in the other lane, then re-run",
			r.Live, r.Configured, r.ConfiguredFrom, r.ConfiguredFrom)
	}
	if want == AuthorityAny {
		if claimed != nil && !claimed(r.Live) {
			return fmt.Errorf("certify: preflight: the DUT's live control authority is %q, which the "+
				"candidate manifest does not list in authority_profiles. A run measured under a posture "+
				"the candidate does not claim is evidence about a device nobody is certifying", r.Live)
		}
		return nil
	}
	if r.Live != want {
		msg := fmt.Sprintf("certify: preflight: this run requires the DUT's live control authority to be "+
			"%q, and it is %q", want, r.Live)
		if because != "" {
			msg += ".\n  " + because
		}
		msg += fmt.Sprintf(".\n  Flip it on the DUT and re-run: apply an authority intent (lexa-gw "+
			"subscribes lexa/intent/authority and performs a real fail-closed transition), or set "+
			"\"authority\" in %s and restart lexa-mode. Then confirm no control is active in the other "+
			"lane. This check will not be waved through: a row measured under the wrong posture produces "+
			"a verdict about the arbitration layer, published as a verdict about the row",
			gatewayModePath)
		if want == AuthorityCSIP && !r.CSIPEnabled {
			msg += ".\n  Note: the DUT also reports csip_enabled=false, and lexa-mode refuses a " +
				"transition to \"csip\" while it is — so enabling CSIP is the first of two steps here"
		}
		if r.FailsafeEngaged {
			msg += ".\n  Note: the DUT reports FAILSAFE ENGAGED, which changes what its control path " +
				"will apply at all — clear the fail-safe before treating any control row as measured"
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
