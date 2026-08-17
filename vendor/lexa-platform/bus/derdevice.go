package bus

// DERDeviceReport is the PER-DEVICE counterpart of DERSiteReport (product
// decision D3.1/D3.3, docs/PRODUCT_DECISIONS.md): where DERSiteReport is the
// single PCC-level aggregate the (never-ported) lexa-hub GFEMS aggregator
// summed across the fleet, DERDeviceReport carries the SAME capability /
// settings / status / availability payload for ONE admitted DER, keyed by
// Device. It is published RETAINED at QoS 1 on DERDeviceReportTopic(device)
// ("lexa/der/{device}/report") — state, not an edge: latest wins, and a
// restarting consumer re-seeds every device's report from the broker.
//
// D3 makes the gateway itself the producer (there is no in-repo hub): a
// gateway-owned producer builds one of these per admitted DER from the raw
// per-device measurement plane (lexa/measurements/{device}) plus the
// southbound inventory (lexa/southbound/inventory — per-device
// ratings/role/identity). lexa-northbound's derreport manager
// (internal/northbound/derreport) is the consumer: it converts each report
// into csipmodel DERCapabilityFull / DERSettingsFull / DERStatusFull /
// DERAvailability and PUTs them to that DER's DERList entry hrefs. This type
// therefore carries EVERYTHING that consumer reads off DERSiteReport today,
// but per device rather than summed.
//
// This is ADDITIVE (AD-006 additive-only discipline): DERSiteReport and its
// topic are untouched; DERDeviceReport reuses DERSiteStatus /
// DERSiteAvailability verbatim (the "Site" in those names is historical — the
// blocks are the generic live-status / availability shapes, identical field-
// for-field to what a per-device report needs, and reusing them keeps the
// consumer's build path — derreport.buildStatus/buildAvailability — a single
// code path for both the aggregate and per-device sources).
//
// D2/D3 semantics carried here, per device rather than summed:
//   - Ratings (rtg_*) are the device's physical nameplate values. rtg_max_w
//     is the admitted device's SunSpec nameplate (InventoryRecord.NameplateW);
//     0 means the producer has no source for a rating (e.g. rtg_max_wh for a
//     non-battery, or a device that answered identify without a nameplate).
//   - VA/Var ratings appear ONLY when device data exists (G27: omission over
//     fabrication) — *float64, nil-absent.
//   - Settings (set_*) are min(rtg, local policy) — ≤ ratings BY CONSTRUCTION.
//     With no site optimiser in the MVP (D2), the producer sets set_max_w to
//     the rating.
//   - ModesSupported is a TRUTH MASK of csipmodel.Mode* bits the gateway
//     actually enforces end-to-end for THIS device — never advertise what a
//     CannotComply would immediately contradict.
type DERDeviceReport struct {
	Envelope

	// Device is the stable per-device name this report is keyed by — the same
	// name used on lexa/measurements/{device} and in the southbound inventory
	// (InventoryRecord.Device). It matches the {device} segment of the topic
	// (DeviceFromDERDeviceReportTopic).
	Device string `json:"device"`

	// Src is the WP3 provenance writer-identity ("src") for this retained doc
	// — the publishing service's short bus-user name, so a boot-time state
	// auditor can attribute the retained report to its single writer without
	// knowing the family schema. omitempty keeps the wire shape byte-identical
	// to a legacy/unstamped publisher (Src ""); the gateway producer stamps it
	// from the topic census. This mirrors the gateway's internal/topics
	// Provenance "src" convention; it is declared as a plain field here (not an
	// embedded type) because that convention lives in the gateway module, which
	// this shared module cannot import.
	Src string `json:"src,omitempty"`

	// DERType is the 2030.5 DERCapability `type` code for this device
	// (DERType* constants in dersite.go).
	DERType uint8 `json:"der_type"`

	// ModesSupported is the csipmodel.Mode* truth mask (see type doc).
	ModesSupported uint32 `json:"modes_supported"`

	// Ratings — always-present physical nameplate values (0 when the producer
	// has no source for a rating).
	RtgMaxW              float64 `json:"rtg_max_w"`
	RtgMaxChargeRateW    float64 `json:"rtg_max_charge_rate_w"`
	RtgMaxDischargeRateW float64 `json:"rtg_max_discharge_rate_w"`
	RtgMaxWh             float64 `json:"rtg_max_wh"`
	// VA/Var ratings — nil unless real device data exists (G27; see type doc).
	RtgMaxVA  *float64 `json:"rtg_max_va,omitempty"`
	RtgMaxVar *float64 `json:"rtg_max_var,omitempty"`

	// Settings — operational caps, ≤ the matching rating by construction.
	SetMaxW              float64  `json:"set_max_w"`
	SetMaxChargeRateW    float64  `json:"set_max_charge_rate_w"`
	SetMaxDischargeRateW float64  `json:"set_max_discharge_rate_w"`
	SetMaxWh             float64  `json:"set_max_wh"`
	SetMaxVA             *float64 `json:"set_max_va,omitempty"`
	SetMaxVar            *float64 `json:"set_max_var,omitempty"`

	// SettingsRef is the PROVENANCE of the active-power settings above
	// (IW15-002): which register point set_max_w came from, when it was read,
	// and — the load-bearing member — whether the producer could resolve one at
	// all. nil on a legacy/unstamped publisher, which every consumer must treat
	// as "no provenance stated", never as "resolved".
	//
	// It exists because set_max_w is no longer a copy of rtg_max_w. Once the
	// mutable 702 SETTING can differ from the RATING, the number advertised
	// northbound as setMaxW, the number the authority converts a percent
	// against, and the number the register layer divides by must be shown to be
	// the same number — this field is what lets a traceability bundle bind
	// advertised → used → written without re-deriving any of them.
	//
	// Additive at DERDeviceReportV: an absent key decodes nil.
	SettingsRef *DERSettingsRef `json:"settings_ref,omitempty"`

	// Status is the device's live status block (Table 13 / G30 source). Reuses
	// DERSiteStatus (see type doc).
	Status DERSiteStatus `json:"status"`

	// Avail is the availability block (statWAvail etc.) — nil when nothing is
	// derivable (no fresh generation or storage data; G27). Reuses
	// DERSiteAvailability (see type doc).
	Avail *DERSiteAvailability `json:"avail,omitempty"`

	// ContentHash is a stable hash of the CAPABILITY/SETTINGS-scoped content
	// only — der_type, modes_supported, and every rtg_*/set_* field — and
	// deliberately EXCLUDES the live Status/Avail blocks and Ts. It is the
	// G29 on-change trigger for the northbound DERCapability/DERSettings PUTs:
	// status/SoC jitter re-publishes the retained doc but must never re-PUT
	// nameplate data the server already has. Computed producer-side so every
	// subscriber agrees on one value.
	ContentHash string `json:"content_hash"`

	// Ts is the publish wall-clock time (gateway-local Unix seconds).
	Ts int64 `json:"ts"`
}

// DERSettingsRef is the provenance of DERDeviceReport's active-power settings
// (IW15-002). One struct rather than a Point/AsOf pair per field: setMaxW is
// the reference the other two fall back to, so its provenance is the one a
// reader has to have, and three copies of the same two strings would be noise.
type DERSettingsRef struct {
	// MaxWPoint is the register point set_max_w was resolved from — "WMax"
	// (the device's mutable 702 setting), "WMaxRtg" (the immutable rating,
	// which is what an ABSENT setting defaults to per IEEE 2030.5-2018
	// DERSettings), or "M121.WMax" on a legacy 12x device.
	MaxWPoint string `json:"max_w_point,omitempty"`
	// MaxWFrom says WHICH KIND of point that was — "setting", "rating-default"
	// — in the resolver's own words, so an operator reading the retained doc
	// does not have to know the SunSpec naming convention to see that a
	// derated device is being advertised at its derate.
	MaxWFrom string `json:"max_w_from,omitempty"`
	// AsOf is the Unix-second time of the register read the settings came
	// from. 0 means the producer had no dated snapshot (a record predating the
	// settings feed), which is not the same as "read at the epoch".
	AsOf int64 `json:"as_of,omitempty"`
	// Pending, when non-empty, is the reason the producer could NOT resolve a
	// reference: an unknown nameplate, or a settings snapshot too old to
	// stand behind. The settings fields are then NOT a statement about the
	// device and MUST NOT be published northbound — DERSettings.setMaxW is
	// minOccurs=1 in sep.xsd, so the honest posture is to withhold the whole
	// resource rather than PUT a guessed number a server would then scale its
	// percentages against.
	Pending string `json:"pending,omitempty"`
}

// Finite is DERDeviceReport's GAP-09 defense-in-depth check — the same shape
// as DERSiteReport.Finite: always-present ratings/settings via finiteVal,
// optional fields via finite's nil-skip wrapper, plus the nested status/
// availability blocks.
func (r DERDeviceReport) Finite() error {
	if err := finiteVal("rtg_max_w", r.RtgMaxW); err != nil {
		return err
	}
	if err := finiteVal("rtg_max_charge_rate_w", r.RtgMaxChargeRateW); err != nil {
		return err
	}
	if err := finiteVal("rtg_max_discharge_rate_w", r.RtgMaxDischargeRateW); err != nil {
		return err
	}
	if err := finiteVal("rtg_max_wh", r.RtgMaxWh); err != nil {
		return err
	}
	if err := finite("rtg_max_va", r.RtgMaxVA); err != nil {
		return err
	}
	if err := finite("rtg_max_var", r.RtgMaxVar); err != nil {
		return err
	}
	if err := finiteVal("set_max_w", r.SetMaxW); err != nil {
		return err
	}
	if err := finiteVal("set_max_charge_rate_w", r.SetMaxChargeRateW); err != nil {
		return err
	}
	if err := finiteVal("set_max_discharge_rate_w", r.SetMaxDischargeRateW); err != nil {
		return err
	}
	if err := finiteVal("set_max_wh", r.SetMaxWh); err != nil {
		return err
	}
	if err := finite("set_max_va", r.SetMaxVA); err != nil {
		return err
	}
	if err := finite("set_max_var", r.SetMaxVar); err != nil {
		return err
	}
	if err := finite("status.soc_pct", r.Status.SocPct); err != nil {
		return err
	}
	if r.Avail != nil {
		if err := finite("avail.estimated_w_avail", r.Avail.EstimatedWAvailW); err != nil {
			return err
		}
	}
	return nil
}
