package gridsim

// malform.go — deliberately non-conformant CSIP resource injection for QA.
//
// When a malform kind is armed (POST /admin/malform), serveXML emits a
// purpose-broken variant of the matching resource, modelling a misbehaving or
// buggy 2030.5 server. The hub MUST contain the error: never panic, never
// replace a safe control with garbage or with "none". Some malformations (an
// empty list, an absurd ActivePower) are expressible as a modified struct; the
// genuinely structural ones (a missing href, a duplicate mRID) are not, so they
// are produced as transformed bytes — which is faithful, since the whole point
// is bytes the parser must survive.
//
// See docs/QA_FAULT_INJECTION.md (Phase 6, malformed resources).

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"csip-tls-test/internal/csip/model"
)

// Supported malform kinds.
const (
	MalformEmptyProgramList = "empty_program_list" // DERProgramList served with no programs
	MalformHugeActivePower  = "huge_activepower"   // a control limit set to an absurd watt value (overflow bait)
	MalformBadDuration      = "bad_duration"       // a control interval with a ~136-year duration
	MalformDupMRID          = "dup_mrid"           // a DERControlList with the same control (mRID) twice
	MalformMissingHref      = "missing_href"       // a DERProgramList with its href stripped — unresolvable
)

var malformKinds = map[string]bool{
	MalformEmptyProgramList: true,
	MalformHugeActivePower:  true,
	MalformBadDuration:      true,
	MalformDupMRID:          true,
	MalformMissingHref:      true,
}

// SetMalform arms (kind != "") or clears (kind == "") the malform mode.
func (s *Server) SetMalform(kind string) error {
	if kind != "" && !malformKinds[kind] {
		return fmt.Errorf("unknown malform kind %q", kind)
	}
	s.mu.Lock()
	s.malformKind = kind
	s.mu.Unlock()
	return nil
}

// handleAdminMalform is POST /admin/malform {"kind":"...","clear":bool}.
func (s *Server) handleAdminMalform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Kind  string `json:"kind"`
		Clear bool   `json:"clear"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	kind := req.Kind
	if req.Clear {
		kind = ""
	}
	if err := s.SetMalform(kind); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// malformedXML returns deliberately non-conformant XML for the given resource
// under the armed malform kind, or (nil,false) to serve the resource normally.
// A kind only applies to the resource type it targets; everything else passes
// through, so the rest of the discovery tree stays well-formed.
func (s *Server) malformedXML(resource interface{}) ([]byte, bool) {
	s.mu.RLock()
	kind := s.malformKind
	s.mu.RUnlock()
	if kind == "" {
		return nil, false
	}

	switch kind {
	case MalformEmptyProgramList:
		if pl, ok := resource.(*model.DERProgramList); ok {
			c := *pl
			c.DERProgram = nil
			c.All, c.Results = 0, 0
			return marshalOrNil(&c)
		}

	case MalformMissingHref:
		if pl, ok := resource.(*model.DERProgramList); ok {
			if b, ok := marshalOrNil(pl); ok {
				return stripFirstHref(b), true
			}
		}

	case MalformHugeActivePower:
		if cp, ok := copyControlListIfNonEmpty(resource); ok {
			huge := model.ActivePower{Multiplier: 9, Value: 32767} // 32767e9 W
			cp.DERControl[0].DERControlBase.OpModExpLimW = &huge
			return marshalOrNil(cp)
		}

	case MalformBadDuration:
		if cp, ok := copyControlListIfNonEmpty(resource); ok {
			cp.DERControl[0].Interval.Duration = 4294967295 // ~136 years
			return marshalOrNil(cp)
		}

	case MalformDupMRID:
		if list, ok := resource.(*model.DERControlList); ok && len(list.DERControl) > 0 {
			if b, ok := marshalOrNil(list); ok {
				return duplicateFirstDERControl(b), true
			}
		}
	}
	return nil, false
}

// copyControlListIfNonEmpty deep-copies a non-empty DERControlList (via an XML
// round-trip, so no nested pointer aliases the stored resource) for in-place
// malformation. Returns (nil,false) for any other resource.
func copyControlListIfNonEmpty(resource interface{}) (*model.DERControlList, bool) {
	list, ok := resource.(*model.DERControlList)
	if !ok || len(list.DERControl) == 0 {
		return nil, false
	}
	b, err := xml.Marshal(list)
	if err != nil {
		return nil, false
	}
	var cp model.DERControlList
	if err := xml.Unmarshal(b, &cp); err != nil || len(cp.DERControl) == 0 {
		return nil, false
	}
	return &cp, true
}

func marshalOrNil(v interface{}) ([]byte, bool) {
	b, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, false
	}
	return b, true
}

// stripFirstHref removes the first ` href="..."` attribute from b (the root
// element's), making the resource unresolvable.
func stripFirstHref(b []byte) []byte {
	s := string(b)
	const pre = ` href="`
	i := strings.Index(s, pre)
	if i < 0 {
		return b
	}
	j := strings.Index(s[i+len(pre):], `"`)
	if j < 0 {
		return b
	}
	end := i + len(pre) + j + 1
	return []byte(s[:i] + s[end:])
}

// duplicateFirstDERControl inserts a byte-for-byte copy of the first
// <DERControl>…</DERControl> block right after it, yielding two controls with
// the same mRID (and an all/results count that no longer matches).
func duplicateFirstDERControl(b []byte) []byte {
	s := string(b)
	open := strings.Index(s, "<DERControl ")
	if open < 0 {
		open = strings.Index(s, "<DERControl>")
	}
	if open < 0 {
		return b
	}
	rel := strings.Index(s[open:], "</DERControl>")
	if rel < 0 {
		return b
	}
	end := open + rel + len("</DERControl>")
	block := s[open:end]
	return []byte(s[:end] + "\n" + block + s[end:])
}
