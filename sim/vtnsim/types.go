// vtnsim is a MINIMAL OpenADR 3.1 VTN (Virtual Top Node) stub — a fake
// server standing in for a real utility/aggregator VEN endpoint so the
// Mayhem suite (cmd/dashboard) can exercise lexa-openadr (the VEN, in
// lexa-hub) against a scriptable OpenADR event without a real VTN.
//
// Scope: exactly the handful of 3.1 REST resources lexa-hub's
// internal/openadr.Client actually calls (see that package's client.go —
// this stub was written by reading it, not the full 3.1 spec):
//
//	GET  /auth/server        — token endpoint discovery (DiscoverTokenURL)
//	POST /auth/token         — OAuth2 client-credentials grant (TokenSource.fetch)
//	GET  /vens?venName=X     — idempotent ven-object lookup (Client.EnsureVen)
//	POST /vens               — ven-object registration
//	GET  /programs           — paged program list (Client.Programs)
//	GET  /events?programID=X — paged event list for one program (Client.Events)
//	POST /reports            — telemetry report POST (Client.PostReport)
//
// Everything else a real 3.1 VTN might expose (webhooks/subscriptions,
// resource objects, full CRUD on events) is out of scope: the VEN this repo
// talks to never calls it.
//
// Test control is an "/admin/*" surface — same convention as gridsim's
// /admin/* and every southbound sim's simapi (GET /state, POST /inject):
// a Mayhem scenario or a human operator arms/clears VTN-side state (an
// event appearing, an auth requirement flipping on) the same way it arms a
// device fault. /admin/* is never part of the 3.1 resource namespace, so it
// can never collide with a real VTN path.
//
// Auth is OFF by default (requireAuth=false): a public-tariff VTN needing no
// client credentials at all is the common, and simplest, 3.1-conformant
// case — internal/openadr.Client already supports it (Tokens == nil when
// cfg.ClientID == ""). POST /admin/auth turns it on for a scenario that
// specifically wants to exercise the OAuth2 path.
package main

// PayloadDescriptor is the shared event/program payload descriptor shape
// (3.1 §8.1.2/§8.1.4, the CP-profile slice: payloadType/units/currency).
type PayloadDescriptor struct {
	ObjectType  string `json:"objectType,omitempty"`
	PayloadType string `json:"payloadType"`
	Units       string `json:"units,omitempty"`
	Currency    string `json:"currency,omitempty"`
}

// IntervalPeriod is the 3.1 {start, duration, randomizeStart} triple.
// start is RFC3339; duration/randomizeStart are ISO 8601 durations
// ("PT1H", "P9999Y" ≈ infinity per the VEN's own duration.go convention).
type IntervalPeriod struct {
	Start          string `json:"start"`
	Duration       string `json:"duration,omitempty"`
	RandomizeStart string `json:"randomizeStart,omitempty"`
}

// ValuesMap is the 3.1 {type, values[]} pair. Values is untyped JSON so a
// caller can post numbers, strings, or booleans exactly as the spec allows;
// this stub never interprets them — it only stores and replays what the VEN
// will itself decode (mirrors lexa-hub's own ValuesMap.FirstNumber
// tolerance, one layer up).
type ValuesMap struct {
	Type   string `json:"type"`
	Values []any  `json:"values"`
}

// Interval is one event interval: an optional period override plus payloads.
type Interval struct {
	ID             int             `json:"id"`
	IntervalPeriod *IntervalPeriod `json:"intervalPeriod,omitempty"`
	Payloads       []ValuesMap     `json:"payloads"`
}

// Program is the slice of the 3.1 program object the VEN reads.
type Program struct {
	ID                 string              `json:"id"`
	ProgramName        string              `json:"programName,omitempty"`
	PayloadDescriptors []PayloadDescriptor `json:"payloadDescriptors,omitempty"`
	IntervalPeriod     *IntervalPeriod     `json:"intervalPeriod,omitempty"`
}

// Event is the slice of the 3.1 event object the VEN reads.
type Event struct {
	ID                   string              `json:"id"`
	ProgramID            string              `json:"programID"`
	EventName            string              `json:"eventName,omitempty"`
	Priority             *int                `json:"priority,omitempty"`
	PayloadDescriptors   []PayloadDescriptor `json:"payloadDescriptors,omitempty"`
	IntervalPeriod       *IntervalPeriod     `json:"intervalPeriod,omitempty"`
	Intervals            []Interval          `json:"intervals"`
	ModificationDateTime string              `json:"modificationDateTime,omitempty"`
}

// Ven is the 3.1 ven-object (venName unique per VTN).
type Ven struct {
	ID      string `json:"id,omitempty"`
	VenName string `json:"venName"`
}

// Report is the 3.1 report object POSTed to /reports. Resources is left as
// raw JSON — this stub only records that a report arrived (and lets a test
// inspect its shape via GET /admin/state), it never validates report
// content against a reading type.
type Report struct {
	ObjectType         string              `json:"objectType,omitempty"`
	ProgramID          string              `json:"programID"`
	EventID            string              `json:"eventID"`
	ClientName         string              `json:"clientName"`
	PayloadDescriptors []PayloadDescriptor `json:"payloadDescriptors,omitempty"`
	Resources          []any               `json:"resources,omitempty"`
	// ReceivedAtUnix is stamped by the sim on arrival (not part of the wire
	// shape POSTed in, but echoed back in GET /admin/state for visibility).
	ReceivedAtUnix int64 `json:"received_at_unix,omitempty"`
}

// Event payloadTypes the CP-profile vocabulary uses (mirrors
// lexa-hub/internal/openadr.types.go's constants — this stub keeps its own
// copy rather than importing lexa-hub, per the two-repo boundary: sims talk
// to lexa-hub only over the wire, never via a shared Go package).
const (
	PayloadPrice               = "PRICE"
	PayloadExportPrice         = "EXPORT_PRICE"
	PayloadImportCapacityLimit = "IMPORT_CAPACITY_LIMIT"
	PayloadExportCapacityLimit = "EXPORT_CAPACITY_LIMIT"
)
