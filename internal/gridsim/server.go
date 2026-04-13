// Package gridsim implements a minimal IEEE 2030.5 server that serves
// the CSIP conformance test resource tree. It's designed to be used
// both as a test server in Go integration tests and as a standalone
// simulator you can run on your desktop.
//
// The resource tree matches the CSIP Conformance Test Procedures v1.3
// setup for CORE-010 (Function Set Assignments) and CORE-012 (Basic
// DER Program/Control).
//
// Phase 2 features:
//   - LFDI-gated /edev: returns only the connecting device's EndDevice
//     when the X-Peer-LFDI request header is present.
//   - 403 Forbidden for /edev/0 and /edev/1 (dummy aggregator devices).
//   - 3 DERPrograms (primacy 1/5/10) with rich DERControlLists.
//   - MirrorUsagePoint POST flow: POST /mup → 201+Location,
//     POST /mup/{n} → 204, GET /mup/{n} → the registered MUP.
package gridsim

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/csip/model"
)

// ContentType is the IEEE 2030.5 mandated content type (GEN.003).
const ContentType = "application/sep+xml"

// Server holds the resource tree and serves it over HTTP.
type Server struct {
	mu         sync.RWMutex
	resources  map[string]interface{} // path → resource struct
	mux        *http.ServeMux
	ClientLFDI string // The LFDI of the client we expect to connect
	clientSFDI uint64 // derived from ClientLFDI; updated by SetClientCertDER

	// MirrorUsagePoint store (Phase 2 POST /mup flow)
	mupNextID int32 // atomic counter for new MUP IDs

	// Response log (CORE-022: client POSTs Response on event transitions)
	responseMu sync.Mutex
	responses  []model.Response
}

// NewServer creates a grid sim with a complete CSIP conformance resource tree.
// clientLFDI is the hex-encoded LFDI of the client device (from their cert).
func NewServer(clientLFDI string) *Server {
	s := &Server{
		resources:  make(map[string]interface{}),
		mux:        http.NewServeMux(),
		ClientLFDI: clientLFDI,
	}
	s.buildResourceTree()
	s.mux.HandleFunc("/", s.handleRequest)
	return s
}

// Handler returns the http.Handler for use with your TLS server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// SetClientCertDER derives the LFDI and SFDI from the peer certificate's DER
// bytes and rebuilds the /edev resource. Call this once per connection after
// the mTLS handshake completes. Safe to call from any goroutine.
func (s *Server) SetClientCertDER(der []byte) {
	lfdi, sfdi := identity.FromCertificateDER(der)
	s.mu.Lock()
	s.ClientLFDI = lfdi.String()
	s.clientSFDI = uint64(sfdi)
	s.rebuildEndDeviceList()
	s.mu.Unlock()
	log.Printf("[gridsim] client identity from cert: LFDI=%s SFDI=%d", lfdi, sfdi)
}

// rebuildEndDeviceList reconstructs the /edev resource with the current
// ClientLFDI and clientSFDI. Caller must hold s.mu for writing.
func (s *Server) rebuildEndDeviceList() {
	boolTrue := true
	now := time.Now().Unix()

	s.resources["/edev"] = &model.EndDeviceList{
		Resource: model.Resource{Href: "/edev"},
		All:      3,
		Results:  3,
		PollRate: 300,
		EndDevice: []model.EndDevice{
			{
				Resource:    model.Resource{Href: "/edev/0"},
				LFDI:        "0000000000000000000000000000000000000001",
				SFDI:        100000001,
				ChangedTime: now - 1000,
			},
			{
				Resource:    model.Resource{Href: "/edev/1"},
				LFDI:        "0000000000000000000000000000000000000002",
				SFDI:        100000002,
				ChangedTime: now - 500,
			},
			{
				Resource:         model.Resource{Href: "/edev/2"},
				LFDI:             s.ClientLFDI,
				SFDI:             s.clientSFDI,
				ChangedTime:      now,
				Enabled:          &boolTrue,
				RegistrationLink: &model.Link{Href: "/edev/2/reg"},
				DERListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/der"},
					All:  1,
				},
				FunctionSetAssignmentsListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa"},
					All:  1,
				},
			},
		},
	}
}

// handleRequest dispatches GET and POST requests.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	peerLFDI := r.Header.Get("X-Peer-LFDI")
	log.Printf("[gridsim] %s %s (peer=%s)", r.Method, path, peerLFDI)

	switch r.Method {
	case http.MethodGet:
		s.handleGET(w, path, peerLFDI)
	case http.MethodPost:
		s.handlePOST(w, r, path, peerLFDI)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGET(w http.ResponseWriter, path, peerLFDI string) {
	// LFDI-gated: /edev/0 and /edev/1 are dummy aggregator devices.
	// A connecting client may only see its own EndDevice sub-resources.
	if peerLFDI != "" {
		if path == "/edev/0" || strings.HasPrefix(path, "/edev/0/") ||
			path == "/edev/1" || strings.HasPrefix(path, "/edev/1/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Return a filtered EndDeviceList showing only the connecting device.
		if path == "/edev" {
			s.serveFilteredEndDeviceList(w, peerLFDI)
			return
		}
	}

	s.mu.RLock()
	resource, ok := s.resources[path]
	s.mu.RUnlock()

	if !ok {
		log.Printf("[gridsim] 404: no resource at %s", path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.serveXML(w, resource)
}

// serveFilteredEndDeviceList builds an EndDeviceList containing only the
// EndDevice whose LFDI matches peerLFDI. Case-insensitive comparison.
func (s *Server) serveFilteredEndDeviceList(w http.ResponseWriter, peerLFDI string) {
	s.mu.RLock()
	edl, ok := s.resources["/edev"].(*model.EndDeviceList)
	s.mu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var filtered []model.EndDevice
	for _, ed := range edl.EndDevice {
		if strings.EqualFold(ed.LFDI, peerLFDI) {
			filtered = append(filtered, ed)
		}
	}
	n := uint32(len(filtered))
	s.serveXML(w, &model.EndDeviceList{
		Resource:  model.Resource{Href: "/edev"},
		All:       n,
		Results:   n,
		PollRate:  edl.PollRate,
		EndDevice: filtered,
	})
}

func (s *Server) handlePOST(w http.ResponseWriter, r *http.Request, path, peerLFDI string) {
	switch {
	case path == "/mup":
		s.handleMUPCreate(w, r, peerLFDI)
	case strings.HasPrefix(path, "/mup/"):
		s.handleMUPReadings(w, r, path)
	case strings.HasPrefix(path, "/rsps/") && strings.HasSuffix(path, "/r"):
		s.handleResponsePost(w, r, path)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleMUPCreate handles POST /mup to register a new MirrorUsagePoint.
// Returns 201 Created with a Location header pointing to the new resource.
func (s *Server) handleMUPCreate(w http.ResponseWriter, r *http.Request, peerLFDI string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var mup model.MirrorUsagePoint
	if err := xml.Unmarshal(body, &mup); err != nil {
		log.Printf("[gridsim] POST /mup: unmarshal error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	id := atomic.AddInt32(&s.mupNextID, 1) - 1
	location := fmt.Sprintf("/mup/%d", id)
	mup.Href = location
	if peerLFDI != "" {
		mup.DeviceLFDI = peerLFDI
	}
	if mup.PostRate == 0 {
		mup.PostRate = 900 // default: 15 min
	}

	s.mu.Lock()
	s.resources[location] = &mup
	// Update the MUP list count and entries.
	if ml, ok := s.resources["/mup"].(*model.MirrorUsagePointList); ok {
		ml.All++
		ml.Results++
		ml.MirrorUsagePoint = append(ml.MirrorUsagePoint, mup)
	}
	s.mu.Unlock()

	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
	log.Printf("[gridsim] POST /mup → created %s (postRate=%d)", location, mup.PostRate)
}

// handleMUPReadings handles POST /mup/{n} to accept periodic meter readings.
// Returns 204 No Content on success.
func (s *Server) handleMUPReadings(w http.ResponseWriter, r *http.Request, path string) {
	_, _ = io.ReadAll(r.Body) // drain body; readings are not persisted in the sim

	s.mu.RLock()
	_, ok := s.resources[path]
	s.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	log.Printf("[gridsim] POST %s → readings accepted (204)", path)
}

// serveXML marshals resource to IEEE 2030.5 XML and writes it to w.
func (s *Server) serveXML(w http.ResponseWriter, resource interface{}) {
	data, err := xml.MarshalIndent(resource, "", "  ")
	if err != nil {
		log.Printf("[gridsim] marshal error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	xmlDecl := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	body := append(xmlDecl, data...)
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// buildResourceTree creates the full CSIP conformance test resource tree.
// This matches CORE-010 setup: 3 EndDevices, the client's device is last,
// with a full FSA → 3 DERPrograms → DERControl chain.
func (s *Server) buildResourceTree() {
	boolTrue := true
	now := time.Now().Unix()

	// ── DeviceCapability (/dcap) ──────────────────────────────
	s.resources["/dcap"] = &model.DeviceCapability{
		Resource: model.Resource{Href: "/dcap"},
		PollRate: 300,
		TimeLink: &model.Link{Href: "/tm"},
		EndDeviceListLink: &model.ListLink{
			Link: model.Link{Href: "/edev"},
			All:  3,
		},
		MirrorUsagePointListLink: &model.ListLink{
			Link: model.Link{Href: "/mup"},
			All:  0,
		},
		ResponseSetListLink: &model.ListLink{
			Link: model.Link{Href: "/rsps"},
			All:  1,
		},
		SelfDeviceLink: &model.Link{Href: "/sdev"},
	}

	// ── ResponseSetList (/rsps) ───────────────────────────────
	// One ResponseSet per program (CORE-022 / GEN.044). Clients POST
	// Response resources to /rsps/0/r to acknowledge event transitions.
	s.resources["/rsps"] = &model.ResponseSetList{
		Resource: model.Resource{Href: "/rsps"},
		All:      1,
		Results:  1,
		ResponseSet: []model.ResponseSet{
			{
				Resource: model.Resource{Href: "/rsps/0"},
				MRID:     "RSP-SP-001",
				ResponseList: &model.ListLink{
					Link: model.Link{Href: "/rsps/0/r"},
					All:  0,
				},
			},
		},
	}
	s.resources["/rsps/0"] = &model.ResponseSet{
		Resource: model.Resource{Href: "/rsps/0"},
		MRID:     "RSP-SP-001",
		ResponseList: &model.ListLink{
			Link: model.Link{Href: "/rsps/0/r"},
			All:  0,
		},
	}

	// ── Time (/tm) ────────────────────────────────────────────
	s.resources["/tm"] = &model.Time{
		Resource:    model.Resource{Href: "/tm"},
		CurrentTime: now,
		DstEndTime:  now - 86400,
		DstOffset:   3600,
		TzOffset:    -18000,
		Quality:     7,
		PollRate:    900,
	}

	// ── EndDeviceList (/edev) ─────────────────────────────────
	s.resources["/edev"] = &model.EndDeviceList{
		Resource: model.Resource{Href: "/edev"},
		All:      3,
		Results:  3,
		PollRate: 300,
		EndDevice: []model.EndDevice{
			{
				Resource:    model.Resource{Href: "/edev/0"},
				LFDI:        "0000000000000000000000000000000000000001",
				SFDI:        100000001,
				ChangedTime: now - 1000,
			},
			{
				Resource:    model.Resource{Href: "/edev/1"},
				LFDI:        "0000000000000000000000000000000000000002",
				SFDI:        100000002,
				ChangedTime: now - 500,
			},
			{
				Resource:         model.Resource{Href: "/edev/2"},
				LFDI:             s.ClientLFDI,
				SFDI:             123456789,
				ChangedTime:      now,
				Enabled:          &boolTrue,
				RegistrationLink: &model.Link{Href: "/edev/2/reg"},
				DERListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/der"},
					All:  1,
				},
				FunctionSetAssignmentsListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa"},
					All:  1,
				},
			},
		},
	}

	// ── Registration (/edev/2/reg) ────────────────────────────
	s.resources["/edev/2/reg"] = &model.Registration{
		Resource:           model.Resource{Href: "/edev/2/reg"},
		DateTimeRegistered: now - 86400,
		PIN:                111115,
	}

	// ── DERList (/edev/2/der) ─────────────────────────────────
	s.resources["/edev/2/der"] = &model.DERList{
		Resource: model.Resource{Href: "/edev/2/der"},
		All:      1,
		Results:  1,
		DER: []model.DER{
			{
				Resource:          model.Resource{Href: "/edev/2/der/0"},
				DERCapabilityLink: &model.Link{Href: "/edev/2/der/0/dercap"},
				DERSettingsLink:   &model.Link{Href: "/edev/2/der/0/derset"},
				DERStatusLink:     &model.Link{Href: "/edev/2/der/0/derstat"},
			},
		},
	}

	// ── DERCapability (/edev/2/der/0/dercap) ──────────────────
	s.resources["/edev/2/der/0/dercap"] = &model.DERCapability{
		Resource: model.Resource{Href: "/edev/2/der/0/dercap"},
		Type:     80, // PV (photovoltaic)
		RtgMaxW:  model.ActivePower{Multiplier: 0, Value: 10000},
	}

	// ── DERSettings (/edev/2/der/0/derset) ───────────────────
	s.resources["/edev/2/der/0/derset"] = &model.DERSettings{
		Resource:    model.Resource{Href: "/edev/2/der/0/derset"},
		SetMaxW:     &model.ActivePower{Multiplier: 0, Value: 10000},
		UpdatedTime: now,
	}

	// ── DERStatus (/edev/2/der/0/derstat) ────────────────────
	genConnected := uint8(1)
	opMode := uint8(1)
	s.resources["/edev/2/der/0/derstat"] = &model.DERStatus{
		Resource:             model.Resource{Href: "/edev/2/der/0/derstat"},
		GenConnectStatus:     &genConnected,
		OperationalModeStatus: &opMode,
		ReadingTime:          now,
	}

	// ── FunctionSetAssignmentsList (/edev/2/fsa) ──────────────
	s.resources["/edev/2/fsa"] = &model.FunctionSetAssignmentsList{
		Resource: model.Resource{Href: "/edev/2/fsa"},
		All:      1,
		Results:  1,
		PollRate: 300,
		FunctionSetAssignments: []model.FunctionSetAssignments{
			{
				Resource:    model.Resource{Href: "/edev/2/fsa/0"},
				MRID:        "FSA-SP-001",
				Description: "Service Point FSA",
				DERProgramListLink: &model.ListLink{
					Link: model.Link{Href: "/edev/2/fsa/0/derp"},
					All:  3,
				},
				TimeLink: &model.Link{Href: "/tm"},
			},
		},
	}

	// ── DERProgramList (/edev/2/fsa/0/derp) ───────────────────
	// 3 programs with different primacy levels (lower = higher priority).
	s.resources["/edev/2/fsa/0/derp"] = &model.DERProgramList{
		Resource: model.Resource{Href: "/edev/2/fsa/0/derp"},
		All:      3,
		Results:  3,
		PollRate: 60,
		DERProgram: []model.DERProgram{
			{
				// Service Point program — highest priority.
				Resource:              model.Resource{Href: "/derp/0"},
				MRID:                  "DERP-SP-001",
				Description:           "Service Point DER Program",
				Primacy:               1,
				DefaultDERControlLink: &model.Link{Href: "/derp/0/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/derc"},
					All:  4,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/actderc"},
					All:  1,
				},
			},
			{
				// Site-level program — middle priority.
				Resource:              model.Resource{Href: "/derp/1"},
				MRID:                  "DERP-SITE-001",
				Description:           "Site-Level DER Program",
				Primacy:               5,
				DefaultDERControlLink: &model.Link{Href: "/derp/1/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/1/derc"},
					All:  2,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/1/actderc"},
					All:  0,
				},
			},
			{
				// System-level program — lowest priority (utility-wide baseline).
				Resource:              model.Resource{Href: "/derp/2"},
				MRID:                  "DERP-SYS-001",
				Description:           "System-Level DER Program",
				Primacy:               10,
				DefaultDERControlLink: &model.Link{Href: "/derp/2/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/2/derc"},
					All:  1,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/2/actderc"},
					All:  0,
				},
			},
		},
	}

	s.buildProgram0(now)
	s.buildProgram1(now)
	s.buildProgram2(now)

	// ── MirrorUsagePointList (/mup) ───────────────────────────
	s.resources["/mup"] = &model.MirrorUsagePointList{
		Resource: model.Resource{Href: "/mup"},
		All:      0,
		Results:  0,
	}
}

// buildProgram0 builds the Service Point program (primacy=1) with a rich
// set of DERControls that exercise overlapping/superseded, cancelled,
// randomized, and actively-executing scenarios.
func (s *Server) buildProgram0(now int64) {
	boolTrue := true
	ptrue := true

	// ── DefaultDERControl (/derp/0/dderc) ─────────────────────
	s.resources["/derp/0/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/0/dderc"},
		MRID:        "DDERC-SP-001",
		Description: "Default: export limit 5kW, connect and energize",
		DERControlBase: model.DERControlBase{
			OpModExpLimW:  &model.ActivePower{Multiplier: 0, Value: 5000},
			OpModConnect:  &boolTrue,
			OpModEnergize: &boolTrue,
		},
	}

	// ── DERControlList (/derp/0/derc) ─────────────────────────
	// Four controls demonstrating the full range of event states:
	//   SP-001 — scheduled, potentiallySuperseded by SP-002 (same interval, newer)
	//   SP-002 — scheduled, supersedes SP-001 (same start, longer duration, newer creationTime)
	//   SP-003 — cancelled (currentStatus=6); client must drop it
	//   SP-004 — scheduled future, randomizeStart=30s for device staggering
	eventStart := now + 180 // 3 minutes from now

	s.resources["/derp/0/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/derc"},
		All:      4,
		Results:  4,
		PollRate: 60,
		DERControl: []model.DERControl{
			{
				// SP-001: superseded by SP-002.
				Resource:     model.Resource{Href: "/derp/0/derc/0"},
				MRID:         "DERC-SP-001",
				Description:  "Limit export to 3kW (potentially superseded)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now,
					PotentiallySuperseded: true,
				},
				Interval: model.DateTimeInterval{
					Duration: 120,
					Start:    eventStart,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 3000},
				},
			},
			{
				// SP-002: supersedes SP-001 (same start, later creationTime).
				Resource:     model.Resource{Href: "/derp/0/derc/1"},
				MRID:         "DERC-SP-002",
				Description:  "Limit export to 2.5kW (supersedes SP-001)",
				CreationTime: now + 1,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now + 1,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 300, // longer — will outlast SP-001's window
					Start:    eventStart,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 2500},
				},
			},
			{
				// SP-003: cancelled — client must skip it.
				Resource:     model.Resource{Href: "/derp/0/derc/2"},
				MRID:         "DERC-SP-003",
				Description:  "Cancelled control (client must ignore)",
				CreationTime: now - 600,
				EventStatus: &model.EventStatus{
					CurrentStatus:         6, // Cancelled
					DateTime:              now - 60,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 120,
					Start:    now - 600,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 4000},
				},
			},
			{
				// SP-004: future control with randomizeStart for device staggering.
				Resource:     model.Resource{Href: "/derp/0/derc/3"},
				MRID:         "DERC-SP-004",
				Description:  "Randomized export limit 3.5kW",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 180,
					Start:    now + 600,
				},
				RandomizeStart: int32Ptr(30),
				DERControlBase: model.DERControlBase{
					OpModExpLimW:  &model.ActivePower{Multiplier: 0, Value: 3500},
					OpModConnect:  &ptrue,
				},
			},
		},
	}

	// ── ActiveDERControlList (/derp/0/actderc) ────────────────
	// One control currently executing (started 60s ago, 600s total).
	s.resources["/derp/0/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/actderc"},
		All:      1,
		Results:  1,
		PollRate: 60,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/0/actderc/0"},
				MRID:         "DERC-SP-000",
				Description:  "Currently active: export limit 2kW",
				CreationTime: now - 300,
				EventStatus: &model.EventStatus{
					CurrentStatus:         1, // Active
					DateTime:              now - 60,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 600,
					Start:    now - 60,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 2000},
				},
			},
		},
	}
}

// buildProgram1 builds the Site-Level program (primacy=5).
func (s *Server) buildProgram1(now int64) {
	boolTrue := true

	s.resources["/derp/1/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/1/dderc"},
		MRID:        "DDERC-SITE-001",
		Description: "Site default: export limit 7kW",
		DERControlBase: model.DERControlBase{
			OpModExpLimW:  &model.ActivePower{Multiplier: 0, Value: 7000},
			OpModConnect:  &boolTrue,
			OpModEnergize: &boolTrue,
		},
	}

	// Two non-overlapping scheduled controls.
	s.resources["/derp/1/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/1/derc"},
		All:      2,
		Results:  2,
		PollRate: 120,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/1/derc/0"},
				MRID:         "DERC-SITE-001",
				Description:  "Site: limit to 6kW (morning peak)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 3600,
					Start:    now + 3600,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 6000},
				},
			},
			{
				Resource:     model.Resource{Href: "/derp/1/derc/1"},
				MRID:         "DERC-SITE-002",
				Description:  "Site: limit to 5kW (afternoon peak)",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 7200,
					Start:    now + 7200,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 5000},
				},
			},
		},
	}

	s.resources["/derp/1/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/1/actderc"},
		All:      0,
		Results:  0,
	}
}

// buildProgram2 builds the System-Level program (primacy=10, lowest priority).
func (s *Server) buildProgram2(now int64) {
	boolTrue := true

	s.resources["/derp/2/dderc"] = &model.DefaultDERControl{
		Resource:    model.Resource{Href: "/derp/2/dderc"},
		MRID:        "DDERC-SYS-001",
		Description: "System default: export limit 9kW (utility-wide baseline)",
		DERControlBase: model.DERControlBase{
			OpModExpLimW:  &model.ActivePower{Multiplier: 0, Value: 9000},
			OpModConnect:  &boolTrue,
			OpModEnergize: &boolTrue,
		},
	}

	s.resources["/derp/2/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/2/derc"},
		All:      1,
		Results:  1,
		PollRate: 300,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/2/derc/0"},
				MRID:         "DERC-SYS-001",
				Description:  "System: utility-wide curtailment 8kW",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0,
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 14400,
					Start:    now + 1800,
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 8000},
				},
			},
		},
	}

	s.resources["/derp/2/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/2/actderc"},
		All:      0,
		Results:  0,
	}
}

// handleResponsePost handles POST /rsps/{n}/r — client acknowledging an event.
// Per GEN.044 / CORE-022: client POSTs a Response resource with status
// 1=Received, 2=Started, or 3=Completed. Returns 201 Created.
func (s *Server) handleResponsePost(w http.ResponseWriter, r *http.Request, path string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var resp model.Response
	if err := xml.Unmarshal(body, &resp); err != nil {
		log.Printf("[gridsim] POST %s: unmarshal Response error: %v", path, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.responseMu.Lock()
	s.responses = append(s.responses, resp)
	s.responseMu.Unlock()
	log.Printf("[gridsim] POST %s → Response accepted: subject=%s status=%d",
		path, resp.Subject, resp.Status)
	w.WriteHeader(http.StatusCreated)
}

// ReceivedResponses returns a copy of all Response resources POSTed by
// clients. Useful for verifying CORE-022 / GEN.044 compliance in tests.
func (s *Server) ReceivedResponses() []model.Response {
	s.responseMu.Lock()
	defer s.responseMu.Unlock()
	out := make([]model.Response, len(s.responses))
	copy(out, s.responses)
	return out
}

// AddResource lets you inject or override resources in the tree,
// useful for testing different scenarios.
func (s *Server) AddResource(path string, resource interface{}) {
	s.resources[path] = resource
}

func int32Ptr(v int32) *int32 { return &v }
