package gridsim

// redirect.go — ERR-001 redirect injection (QA fault mode, default OFF).
//
// When armed (POST /admin/redirect), the first N GETs of a configured path
// (default /dcap) answer 301 or 302 with a Location header instead of the
// resource, so the hub's redirect-following path (redirect_max, D3/ERR-001)
// can be exercised on the wire. After N redirects the path serves normally
// again — so a Location that points back at the same path drives "N redirects
// then success", and arming N > redirect_max drives the "redirect limit
// exceeded" error path.
//
// Default behaviour is unchanged: with remaining == 0 the intercept is a cheap
// no-op and every GET serves as before.

import (
	"encoding/json"
	"log"
	"net/http"
)

// redirectState is the armed redirect-injection configuration. Zero value
// (remaining == 0) means disarmed.
type redirectState struct {
	path      string // GET path that triggers a redirect (e.g. "/dcap")
	location  string // Location header value; empty ⇒ same as path (self-redirect)
	code      int    // 301 or 302
	remaining int    // GETs left to redirect; 0 ⇒ disarmed
}

// redirectIntercept answers a GET with a 301/302 while the redirect mode is
// armed and this path matches. Returns true if it wrote a redirect response
// (the caller must then stop). A path-only Location (or an empty one, meaning
// "same path") keeps the client on the same host/scheme, which the hub's
// fail-closed follower accepts; an operator can also arm an absolute or
// cross-host Location to exercise the refusal paths.
func (s *Server) redirectIntercept(w http.ResponseWriter, path string) bool {
	s.redirectMu.Lock()
	st := s.redirect
	armed := st.remaining > 0 && path == st.path
	if armed {
		s.redirect.remaining--
	}
	s.redirectMu.Unlock()

	if !armed {
		return false
	}
	loc := st.location
	if loc == "" {
		loc = st.path
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(st.code)
	log.Printf("[gridsim] redirect: GET %s → %d Location:%s (%d left)", path, st.code, loc, st.remaining-1)
	return true
}

// SetRedirect arms (count > 0) or disarms (count <= 0) redirect injection.
// path defaults to /dcap; code defaults to 302 and must be 301 or 302.
func (s *Server) SetRedirect(path, location string, code, count int) error {
	if count <= 0 {
		s.redirectMu.Lock()
		s.redirect = redirectState{}
		s.redirectMu.Unlock()
		return nil
	}
	if path == "" {
		path = "/dcap"
	}
	if code == 0 {
		code = http.StatusFound // 302
	}
	if code != http.StatusMovedPermanently && code != http.StatusFound {
		return errBadRedirectCode
	}
	s.redirectMu.Lock()
	s.redirect = redirectState{path: path, location: location, code: code, remaining: count}
	s.redirectMu.Unlock()
	return nil
}

var errBadRedirectCode = &redirectError{"redirect code must be 301 or 302"}

type redirectError struct{ msg string }

func (e *redirectError) Error() string { return e.msg }

// adminRedirectReq is the body for POST /admin/redirect.
type adminRedirectReq struct {
	Path     string `json:"path"`     // default /dcap
	Location string `json:"location"` // default: same as path (self-redirect)
	Code     int    `json:"code"`     // 301 or 302; default 302
	Count    int    `json:"count"`    // number of GETs to redirect; 0/absent + clear disarms
	Clear    bool   `json:"clear"`
}

// handleAdminRedirect is POST /admin/redirect. Arm with
// {"path":"/dcap","code":302,"count":1}; disarm with {"clear":true}.
func (s *Server) handleAdminRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req adminRedirectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	count := req.Count
	if req.Clear {
		count = 0
	}
	if err := s.SetRedirect(req.Path, req.Location, req.Code, count); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
