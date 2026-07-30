package gridsim

// rehome.go — the CORE-009/CORE-014 DER re-home lever (QA test-server action,
// triggered per case; nothing here is EUT behaviour).
//
// # Why this exists
//
// CSIP IG §6.3.5.2 has the client PUT its DERCapability and DERSettings "at
// device start-up and on any changes", and DERStatus at pollRate. A capture
// window opened hours after the DUT booted therefore sees DERStatus PUTs on
// the DUT's ordinary cadence and nothing else — the DUT already sent its
// capability/settings exactly once, at connection, and correctly has no
// reason to send them again until something changes. CORE-009 and CORE-014
// exist to observe those PUTs, and a window that opens long after boot cannot
// see an event that already happened.
//
// lexa-gw's northbound reporter (internal/northbound/derreport/derreport.go,
// Manager.updateDERsLocked, called from OnWalk on every discovery walk) resets
// a DER's capability/settings dedupe latch whenever that DER's CAPABILITY or
// SETTINGS href changes between one walk and the next, and forces a re-PUT to
// the new href even though the content is unchanged. RehomeDER manufactures
// that trigger deterministically: it moves the DUT's DERCapability and
// DERSettings to a fresh, version-suffixed href, so the DUT's NEXT discovery
// walk finds them somewhere new and reports them again — inside whatever
// window a check is watching, rather than at a start-up this run's capture
// missed.
//
// # Why a test-server action is sound territory here
//
// gridsim's own resource tree is server-defined (IEEE 2030.5 §4.6): nothing
// about WHERE a resource lives is a DUT property, so moving it is not "testing
// a hypothesis about the DUT" in the way probing the DUT itself would be. It
// is the same species of lever the CTP scripts on the SERVER side elsewhere —
// ERR-002 arms a server power-reset as a setup step — and the RRS constrains
// only the EUT, not the test server that serves it.
//
// # What it does NOT do
//
// It never touches the DUT: no SSH, no config push, nothing sent over the
// 2030.5 wire that the DUT did not ask for by following a link it fetched.
// The OLD hrefs are removed outright rather than redirected or aliased, so a
// GET of either now 404s exactly as a real DERMS reindex would leave no trace
// at the vacated address — the DUT's only way to learn the new location is
// the ordinary discovery walk IEEE 2030.5 §4.6 already requires of it.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	model "lexa-proto/csipmodel"
)

// RehomeDER moves DER `der` of EndDevice `edev`'s DERCapability and
// DERSettings resources to a fresh, version-suffixed href beneath the same
// DER path, and updates the DERList entry a DUT's NEXT discovery walk reads so
// it advertises the NEW hrefs. The OLD hrefs are deleted from the tree
// entirely: a GET of either now 404s.
//
// It returns the two new hrefs so a caller can log them and a citation can
// name the exact path the PUT is now expected against. An error names why the
// DER at (edev, der) does not exist in the tree this server currently serves
// — a caller's argument mistake, never a DUT fact.
//
// Deterministic and logged: each call advances the process-wide derHomeGen
// counter by exactly one, so the generation in the returned hrefs is
// reproducible from the call count alone, and the move is written to the
// standard log the bench already tees to every conformance run's evidence.
func (s *Server) RehomeDER(edev, der int) (capHref, setHref string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	derListPath := fmt.Sprintf("/edev/%d/der", edev)
	dl, ok := s.resources[derListPath].(*model.DERList)
	if !ok {
		return "", "", fmt.Errorf("gridsim: no DERList at %s to re-home", derListPath)
	}
	if der < 0 || der >= len(dl.DER) {
		return "", "", fmt.Errorf("gridsim: DERList at %s serves %d DER(s); no DER[%d] to re-home",
			derListPath, len(dl.DER), der)
	}
	d := &dl.DER[der]

	s.derHomeGen++
	gen := s.derHomeGen
	base := fmt.Sprintf("%s/%d/g%d", derListPath, der, gen)
	capHref, setHref = base+"/dercap", base+"/derset"

	var oldCapHref, oldSetHref string
	if d.DERCapabilityLink != nil {
		oldCapHref = d.DERCapabilityLink.Href
	}
	if d.DERSettingsLink != nil {
		oldSetHref = d.DERSettingsLink.Href
	}

	// Carry the payload itself to its new home — a client that reads <href> out
	// of the DERCapability/DERSettings body (rather than only the DER's link)
	// must see the same new path there too. A DER whose capability or settings
	// resource was never built (should not happen against this bench's fixed
	// tree, but a caller could re-home twice before the first PUT lands) simply
	// has no payload to carry; the link still moves.
	if cap, ok := s.resources[oldCapHref].(*model.DERCapability); ok {
		cap.Href = capHref
		s.resources[capHref] = cap
	}
	if set, ok := s.resources[oldSetHref].(*model.DERSettings); ok {
		set.Href = setHref
		s.resources[setHref] = set
	}
	// The OLD hrefs are gone outright: a re-laid-out server does not leave a
	// stale copy answering at the address it just vacated, and does not
	// redirect from it either — the only way to learn the new location is the
	// DERList the DUT is expected to re-walk.
	delete(s.resources, oldCapHref)
	delete(s.resources, oldSetHref)

	d.DERCapabilityLink = &model.Link{Href: capHref}
	d.DERSettingsLink = &model.Link{Href: setHref}

	log.Printf("[gridsim] DER %s re-homed (gen %d): DERCapability %s -> %s, DERSettings %s -> %s "+
		"(CSIP IG §6.3.5.2 re-announce trigger; old hrefs now 404)",
		d.Href, gen, oldCapHref, capHref, oldSetHref, setHref)
	return capHref, setHref, nil
}

// adminRehomeResp is POST /admin/rehome's answer: the fresh hrefs, so a
// caller can log/cite them without re-deriving gridsim's naming scheme.
type adminRehomeResp struct {
	DERCapabilityHref string `json:"der_capability_href"`
	DERSettingsHref   string `json:"der_settings_href"`
}

// handleAdminRehome is POST /admin/rehome: re-home the DUT's own DER
// (/edev/2/der/0 — aggregatorEdevIndex, DER 0), the only DER this bench's
// default tree serves and the one every CORE-009/CORE-014 check acts on. It
// takes no body: a direct CSIP client run has exactly one DER to address, and
// giving this lever parameters RehomeDER's own tests do not exercise would
// invite a caller to pick values nothing here has coverage for.
func (s *Server) handleAdminRehome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	capHref, setHref, err := s.RehomeDER(aggregatorEdevIndex, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminRehomeResp{
		DERCapabilityHref: capHref,
		DERSettingsHref:   setHref,
	})
}
