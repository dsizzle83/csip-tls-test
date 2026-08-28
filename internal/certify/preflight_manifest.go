package certify

// preflight_manifest.go holds the candidate's DECLARATION against the device's
// own report of itself.
//
// # Why a declaration needs checking at all
//
// The manifest is what every scope decision in a campaign rests on: rows leave
// the run because the candidate says it is not that kind of device. A manifest
// that does not describe the device on the bench therefore does not merely
// mislabel one row — it silently re-scopes the whole campaign, and the bundle
// records the result as though the product had claimed it. So the facts the
// declaration makes that the DUT can be ASKED about are asked about, once, before
// the capture starts.
//
// # What it can and cannot see
//
// The dev API reports the ADMITTED southbound inventory: how many DERs the
// running gateway actually has, their role, their transport, the northbound unit
// each is exposed at. That covers topology.configured_der, topology.role,
// topology.northbound_units and modbus_client.{transport,device_count} — five of
// the manifest's claims, from the device, with no new product surface required.
//
// It cannot see the CONFIGURED count as distinct from the admitted one: lexa-gw
// has no endpoint reporting "how many DERs am I set up for" (the single-DER rule
// is enforced at config load in cmd/modbus/config.go and never published). A
// device configured for one DER that has admitted none is therefore
// indistinguishable here from one configured for none — so a count of ZERO is
// reported as an UNPROVEN claim rather than as a contradiction, and a count that
// disagrees non-trivially is a contradiction. When the product grows that fact,
// this file gains one more comparison and nothing else changes.
//
// # Contradiction is fatal, silence is not
//
// A fact the DUT reports that CONTRADICTS the manifest ends the run: the scope
// decisions the campaign is about to make are made from a document that has just
// been shown to be wrong about this device. A fact the DUT cannot report is
// stated as unproven and the run continues, because refusing to run against
// every question the product cannot yet answer would make this check something
// operators turn off.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify/manifest"
)

// devAPIStatus is the subset of the dev API's GET /status this check reads.
type devAPIStatus struct {
	Southbound struct {
		DeviceCount int `json:"device_count"`
	} `json:"southbound"`
}

// devAPIInventory is the subset of GET /southbound/inventory this check reads.
// The DUT's record carries more; only the fields a manifest claim is about are
// modelled, so a product-side addition does not break this reader.
type devAPIInventory struct {
	Devices []inventoryDevice `json:"devices"`
	Stale   bool              `json:"stale"`
}

// inventoryDevice is one admitted southbound device, as the DUT reports it.
type inventoryDevice struct {
	Device    string   `json:"device"`
	Transport string   `json:"transport"`
	UnitID    int      `json:"unit_id"`
	NBUnit    int      `json:"nb_unit"`
	Role      string   `json:"role"`
	Models    []uint16 `json:"models"`
}

// preflightManifest checks the candidate manifest's observable topology claims
// against the DUT. It is a no-op when no manifest was given.
func (r *Runner) preflightManifest(ctx context.Context, reporter *Reporter) error {
	m := r.manifest
	if m == nil {
		return nil
	}
	reporter.Line("candidate: %s (sha256 %s)", m.Summary(), short(m.SHA256(), 16))

	gw := r.gateway()
	if !gw.Available() {
		reporter.Line("candidate: no gateway introspection is configured, so none of the manifest's " +
			"topology claims were checked against the device. Every scope decision in this run rests on " +
			"the declaration alone")
		return nil
	}

	inv, err := r.readInventory(ctx, gw)
	if err != nil {
		// UNPROVEN, not contradicted. An endpoint that did not answer says
		// nothing about the manifest, and manufacturing a failure from it would
		// teach operators to bypass this check.
		reporter.Line("candidate: the DUT's southbound inventory could not be read (%v), so the "+
			"manifest's topology claims are UNPROVEN in this run", err)
		return nil
	}

	var problems []string
	admitted := len(inv.Devices)
	switch {
	case inv.Stale || admitted == 0:
		reporter.Line("candidate: the DUT reports NO admitted southbound device (stale=%v). The manifest "+
			"declares %d — that is not a contradiction (the dev API publishes the ADMITTED inventory, not "+
			"the configured one, so a device that has not finished admitting looks the same as one that "+
			"is not configured), but nothing in this run proves the declared topology",
			inv.Stale, m.ConfiguredDER)
	case admitted != m.ConfiguredDER:
		problems = append(problems, fmt.Sprintf(
			"topology.configured_der declares %d DER(s); the DUT has admitted %d (%s)",
			m.ConfiguredDER, admitted, strings.Join(inventoryNames(inv), ", ")))
	default:
		d := inv.Devices[0]
		if m.Role != "" && !strings.EqualFold(d.Role, m.Role) {
			problems = append(problems, fmt.Sprintf(
				"topology.role declares %q; the DUT's one admitted device %q reports role %q",
				m.Role, d.Device, d.Role))
		}
		if m.ModbusClient.Transport != "" && !strings.EqualFold(d.Transport, m.ModbusClient.Transport) {
			problems = append(problems, fmt.Sprintf(
				"modbus_client.transport declares %q; the DUT polls %q over %q",
				m.ModbusClient.Transport, d.Device, d.Transport))
		}
		if len(m.NorthboundUnits) == 1 && d.NBUnit != 0 && m.NorthboundUnits[0] != d.NBUnit {
			problems = append(problems, fmt.Sprintf(
				"topology.northbound_units declares [%d]; the DUT exposes %q at northbound unit %d",
				m.NorthboundUnits[0], d.Device, d.NBUnit))
		}
		if missing := modelsMissing(m, d.Models); len(missing) > 0 {
			// A model the DEVICE serves that the manifest does not declare is an
			// under-declaration, and it is treated the SAME WAY preflightFixture
			// treats the fixture serving a model the manifest omits: FATAL on the
			// gating path, a WARN on an exploratory one. The two checks read
			// different witnesses (this one the DUT's admitted inventory, that
			// one the DER simulator's served chain) but reach the same judgement
			// on a served-but-undeclared model, so a gating campaign cannot
			// generate cert evidence against a device its own manifest does not
			// fully describe. (The admitted-inventory caveat that made this a
			// bare WARN before — the dev API publishes only what has finished
			// admitting — is why it stays a WARN off the gating path.)
			if r.gatingCampaign() {
				problems = append(problems, fmt.Sprintf(
					"the DUT's device %q serves model(s) %v that the manifest's `models` list does NOT "+
						"declare (under-declaration)", d.Device, missing))
			} else {
				reporter.Line("candidate: the DUT's device %q serves model(s) %v that the manifest's "+
					"`models` list does not declare. This is an EXPLORATORY run (no -campaign), so it is a "+
					"WARNING, not a refusal; a gating campaign would stop here", d.Device, missing)
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("certify: preflight: the candidate manifest %s does not describe the device on "+
			"this bench:\n  - %s\nEvery scope decision in this run is made from that manifest, so a run "+
			"against a device it does not describe would record this tool's misreading as the product's "+
			"claim. Correct the manifest, or point the run at the device it describes",
			m.Path(), strings.Join(problems, "\n  - "))
	}
	if admitted > 0 && !inv.Stale {
		reporter.Line("candidate: the DUT's admitted topology matches the manifest — %d device(s), %s",
			admitted, strings.Join(inventoryNames(inv), ", "))
	}
	return nil
}

// readInventory fetches the DUT's admitted southbound inventory through the
// gateway runner, falling back to /status's cheap rollup.
//
// The fallback exists because the two are computed from ONE source in lexa-gw
// (cmd/api/handlers.go reads len(snap.inventory.Records) for the rollup), so
// they cannot disagree — the rollup is strictly less detail, never a different
// answer. Trying the detailed endpoint first and degrading to the count is
// therefore free of the usual risk of two sources.
func (r *Runner) readInventory(ctx context.Context, gw *Gateway) (devAPIInventory, error) {
	var inv devAPIInventory
	body, err := r.devAPIGet(ctx, gw, "/southbound/inventory")
	if err == nil {
		if jerr := json.Unmarshal(body, &inv); jerr == nil {
			return inv, nil
		}
		err = fmt.Errorf("the inventory endpoint answered with something this reader does not recognise")
	}
	body, serr := r.devAPIGet(ctx, gw, "/status")
	if serr != nil {
		return inv, fmt.Errorf("%v; and /status did not answer either: %v", err, serr)
	}
	var st devAPIStatus
	if jerr := json.Unmarshal(body, &st); jerr != nil {
		return inv, fmt.Errorf("%v; and /status did not decode: %v", err, jerr)
	}
	// Synthesise the count only. The per-device fields are genuinely unknown
	// here and are left zero rather than invented, and every comparison above
	// that would use one is guarded.
	inv.Devices = make([]inventoryDevice, st.Southbound.DeviceCount)
	return inv, nil
}

// devAPIGet fetches one dev API path from ON the device, the same way the
// authority reading does: the endpoint is loopback-bound, so the DUT is asked to
// fetch it for us.
func (r *Runner) devAPIGet(ctx context.Context, gw *Gateway, path string) ([]byte, error) {
	base := r.opts.DevAPI
	if base == "" {
		base = DefaultDevAPI
	}
	args := []string{"wget", "-qO-", "--no-check-certificate"}
	if tok, err := gw.Run(ctx, "cat", devAPITokenPath); err == nil {
		if t := strings.TrimSpace(string(tok)); t != "" {
			args = append(args, "--header", "Authorization: Bearer "+t)
		}
	}
	args = append(args, strings.TrimRight(base, "/")+path)
	return gw.Run(ctx, args...)
}

func inventoryNames(inv devAPIInventory) []string {
	out := make([]string, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		name := d.Device
		if name == "" {
			name = "(unnamed)"
		}
		if d.Role != "" {
			name += " [" + d.Role + "]"
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

// modelsMissing lists the models the device serves that the manifest omits.
func modelsMissing(m *manifest.Manifest, served []uint16) []int {
	var out []int
	for _, id := range served {
		if !m.HasModel(int(id)) {
			out = append(out, int(id))
		}
	}
	return out
}
