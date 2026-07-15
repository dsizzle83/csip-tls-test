package gridsim

// derput.go — the server half of the DER* self-report pipeline (WP-4,
// CORE-009 PUT half / CORE-014). lexa-northbound PUTs its aggregate
// DERCapability/DERSettings/DERStatus/DERAvailability to the hrefs this server
// advertised under the EndDevice's DER tree; gridsim validates the body
// (well-formed + 2030.5 namespace), stores the last one per resource, and
// exposes them for test/bench assertion via GET /admin/derputs (mirroring how
// received Responses are surfaced via GET /admin/alerts).
//
// This is additive and always-on: it only ever fires for a PUT (GET/POST
// behaviour is unchanged), and a PUT to a non-DER path still returns 405.

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"strings"
)

// csipNamespace is the mandatory IEEE 2030.5 XML namespace every root element
// must carry (the same invariant serveXML upholds on the way out).
const csipNamespace = "urn:ieee:std:2030.5:ns"

// derPutSuffixes maps the last path segment of a DER report target to the
// root element the PUT body must carry. These are exactly the hrefs gridsim
// advertises in its DER resource (see buildResourceTree), so matching on the
// server's own suffix scheme is sufficient and unambiguous.
var derPutSuffixes = map[string]string{
	"dercap":   "DERCapability",
	"derset":   "DERSettings",
	"derstat":  "DERStatus",
	"deravail": "DERAvailability",
}

// DERPut is one received DER* report PUT, recorded for inspection.
type DERPut struct {
	Path       string `json:"path"`        // resource path written
	Resource   string `json:"resource"`    // root element observed (e.g. "DERStatus")
	Body       string `json:"body"`        // raw request body (verbatim)
	ReceivedAt int64  `json:"received_at"` // gridsim server time (Unix seconds)
}

// derPutTarget returns the expected root element for a DER report PUT path,
// or ("", false) if path is not a DER report target. It matches the last
// segment against derPutSuffixes and requires the path to sit under an
// EndDevice DER tree (…/der/…), so a stray "/dercap" cannot match.
func derPutTarget(path string) (string, bool) {
	slash := strings.LastIndexByte(path, '/')
	if slash < 0 {
		return "", false
	}
	root, ok := derPutSuffixes[path[slash+1:]]
	if !ok {
		return "", false
	}
	if !strings.Contains(path, "/der/") {
		return "", false
	}
	return root, true
}

// handlePUT accepts a DER* self-report PUT. A recognised, well-formed,
// correctly-namespaced body is stored and answered 204 No Content; a malformed
// or mis-namespaced body is 400; a PUT to any other path is 405.
func (s *Server) handlePUT(w http.ResponseWriter, r *http.Request, path string) {
	wantRoot, ok := derPutTarget(path)
	if !ok {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gotRoot, valid := validateCSIPXML(body)
	if !valid {
		log.Printf("[gridsim] PUT %s: rejected (not well-formed 2030.5 XML)", path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if gotRoot != wantRoot {
		log.Printf("[gridsim] PUT %s: rejected (root <%s>, want <%s>)", path, gotRoot, wantRoot)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.derPutMu.Lock()
	if s.derPuts == nil {
		s.derPuts = make(map[string]DERPut)
	}
	s.derPuts[path] = DERPut{
		Path:       path,
		Resource:   gotRoot,
		Body:       string(body),
		ReceivedAt: s.Now(),
	}
	s.derPutMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
	log.Printf("[gridsim] PUT %s → %s report stored (204)", path, gotRoot)
}

// validateCSIPXML reports whether body is well-formed XML whose root element
// carries the IEEE 2030.5 namespace, returning the root local name. A body
// that is not parseable, empty, or missing the namespace is invalid — the
// "garbage → 400" and "xmlns required" checks the WP-4 brief asks for. It is
// type-agnostic (short vs Full DER* structs share a root name), so it validates
// the framing without pinning the exact struct shape.
func validateCSIPXML(body []byte) (root string, ok bool) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	var rootName *xml.Name
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false // not well-formed
		}
		if se, isStart := tok.(xml.StartElement); isStart && rootName == nil {
			n := se.Name
			rootName = &n
		}
	}
	if rootName == nil {
		return "", false // no element at all
	}
	if rootName.Space != csipNamespace {
		return rootName.Local, false // missing/wrong xmlns
	}
	return rootName.Local, true
}

// ReceivedDERPuts returns a copy of the last DER* report PUT received per
// resource path. Useful for verifying WP-4 DER reporting in tests.
func (s *Server) ReceivedDERPuts() map[string]DERPut {
	s.derPutMu.Lock()
	defer s.derPutMu.Unlock()
	out := make(map[string]DERPut, len(s.derPuts))
	for k, v := range s.derPuts {
		out[k] = v
	}
	return out
}

// handleAdminDERPuts serves GET /admin/derputs — the received DER* report
// bodies, keyed by resource path.
func (s *Server) handleAdminDERPuts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	puts := s.ReceivedDERPuts()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"der_puts":    puts,
		"server_time": s.Now(),
	})
}
