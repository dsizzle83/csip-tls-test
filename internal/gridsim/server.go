// Package gridsim implements a minimal IEEE 2030.5 server that serves
// the CSIP conformance test resource tree. It's designed to be used
// both as a test server in Go integration tests and as a standalone
// simulator you can run on your desktop.
//
// The resource tree matches the CSIP Conformance Test Procedures v1.3
// setup for CORE-010 (Function Set Assignments) and CORE-012 (Basic
// DER Program/Control).
//
// This is NOT a production server. It serves static XML. But the XML
// it serves is conformant to the 2030.5 schema, uses the correct
// namespace, and follows the link structure that the conformance test
// expects. This is what your client code will talk to during development.
package gridsim

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"time"

	"csip-tls-test/internal/csip/model"
)

// ContentType is the IEEE 2030.5 mandated content type (GEN.003).
const ContentType = "application/sep+xml"

// Server holds the resource tree and serves it over HTTP.
type Server struct {
	resources  map[string]interface{} // path → resource struct
	mux        *http.ServeMux
	ClientLFDI string // The LFDI of the client we expect to connect
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

// handleRequest serves any registered resource as XML with the correct content type.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	log.Printf("[gridsim] %s %s", r.Method, path)

	if r.Method != http.MethodGet {
		// For Milestone 3 we only need GET. POST/PUT come in later milestones.
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	resource, ok := s.resources[path]
	if !ok {
		log.Printf("[gridsim] 404: no resource at %s", path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	data, err := xml.MarshalIndent(resource, "", "  ")
	if err != nil {
		log.Printf("[gridsim] marshal error for %s: %v", path, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Prepend XML declaration (required: GEN.052 XML version 1.0, GEN.053 UTF-8)
	xmlDecl := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	body := append(xmlDecl, data...)

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// buildResourceTree creates the full CSIP conformance test resource tree.
// This matches CORE-010 setup: 3 EndDevices, the client's device is last,
// with a full FSA → DERProgram → DERControl chain.
func (s *Server) buildResourceTree() {
	boolTrue := true
	now := time.Now().Unix()

	// ── DeviceCapability (/dcap) ──────────────────────────────
	// Section 3.2.3: Path to DeviceCapability = /dcap
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
		SelfDeviceLink: &model.Link{Href: "/sdev"},
	}

	// ── Time (/tm) ────────────────────────────────────────────
	// CORE-005: quality=7 (intentionally uncoordinated)
	s.resources["/tm"] = &model.Time{
		Resource:    model.Resource{Href: "/tm"},
		CurrentTime: now,
		DstEndTime:  now - 86400,
		DstOffset:   3600,
		TzOffset:    -18000, // EST (Boston)
		Quality:     7,
		PollRate:    900,
	}

	// ── EndDeviceList (/edev) ─────────────────────────────────
	// CORE-010 setup: 3 EndDevices, client's is last (most recent changedTime)
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
				// Client's EndDevice
				Resource:         model.Resource{Href: "/edev/2"},
				LFDI:             s.ClientLFDI,
				SFDI:             123456789, // TODO: compute from LFDI
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
	// Section 3.2.3 & 3.2.5: PIN = 111115
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
		Type:     80,                                             // PV
		RtgMaxW:  model.ActivePower{Multiplier: 0, Value: 10000}, // 10kW
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
					All:  1,
				},
				TimeLink: &model.Link{Href: "/tm"},
			},
		},
	}

	// ── DERProgramList (/edev/2/fsa/0/derp) ───────────────────
	s.resources["/edev/2/fsa/0/derp"] = &model.DERProgramList{
		Resource: model.Resource{Href: "/edev/2/fsa/0/derp"},
		All:      1,
		Results:  1,
		PollRate: 60,
		DERProgram: []model.DERProgram{
			{
				Resource:              model.Resource{Href: "/derp/0"},
				MRID:                  "DERP-SP-001",
				Description:           "Service Point DER Program",
				Primacy:               1,
				DefaultDERControlLink: &model.Link{Href: "/derp/0/dderc"},
				DERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/derc"},
					All:  1,
				},
				ActiveDERControlListLink: &model.ListLink{
					Link: model.Link{Href: "/derp/0/actderc"},
					All:  0,
				},
			},
		},
	}

	// ── DefaultDERControl (/derp/0/dderc) ─────────────────────
	// CORE-012: active when no DERControl event is running
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
	// CORE-012 setup: one control starting in 3 minutes, duration 2 minutes
	eventStart := now + 180 // 3 minutes from now
	s.resources["/derp/0/derc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/derc"},
		All:      1,
		Results:  1,
		PollRate: 60,
		DERControl: []model.DERControl{
			{
				Resource:     model.Resource{Href: "/derp/0/derc/0"},
				MRID:         "DERC-SP-001",
				Description:  "Limit export to 3kW",
				CreationTime: now,
				EventStatus: &model.EventStatus{
					CurrentStatus:         0, // Scheduled
					DateTime:              now,
					PotentiallySuperseded: false,
				},
				Interval: model.DateTimeInterval{
					Duration: 120,        // 2 minutes
					Start:    eventStart, // 3 minutes from now
				},
				DERControlBase: model.DERControlBase{
					OpModExpLimW: &model.ActivePower{Multiplier: 0, Value: 3000},
				},
			},
		},
	}

	// ── ActiveDERControlList (/derp/0/actderc) ────────────────
	// Empty for now — no active events yet
	s.resources["/derp/0/actderc"] = &model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/actderc"},
		All:      0,
		Results:  0,
	}

	// ── MirrorUsagePointList (/mup) ───────────────────────────
	// Empty — telemetry setup is Milestone 5
	s.resources["/mup"] = &model.MirrorUsagePointList{
		Resource: model.Resource{Href: "/mup"},
		All:      0,
		Results:  0,
	}
}

// AddResource lets you inject or override resources in the tree,
// useful for testing different scenarios.
func (s *Server) AddResource(path string, resource interface{}) {
	s.resources[path] = resource
}
