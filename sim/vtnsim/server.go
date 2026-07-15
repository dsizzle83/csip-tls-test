package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// defaultPageLimit mirrors internal/openadr/client.go's own defaultPageLimit
// (50) — not load-bearing here (this stub honors whatever "limit" a client
// asks for), just a sane default when a request omits it entirely.
const defaultPageLimit = 50

// Server is the in-memory VTN stub. All state is guarded by mu; every
// exported behavior is reachable only through the HTTP handlers so a test
// can drive it exactly the way a real client (or the Mayhem driver's admin
// calls) would.
type Server struct {
	mu           sync.Mutex
	programs     map[string]Program
	events       map[string]Event
	vens         map[string]Ven
	reports      []Report
	nextVenID    int
	requireAuth  bool
	tokenValue   string
	clientID     string
	clientSecret string

	baseURL string // advertised in GET /auth/server's token_url
	now     func() time.Time
}

// New builds a Server with empty state and auth OFF (the common
// public-tariff-VTN case — see the package doc). baseURL is used to render
// an absolute token_url from GET /auth/server; pass the address this
// Server's Handler() will actually be served on (e.g.
// "http://69.0.0.20:6030").
func New(baseURL string) *Server {
	return &Server{
		programs:   make(map[string]Program),
		events:     make(map[string]Event),
		vens:       make(map[string]Ven),
		tokenValue: "vtnsim-static-token",
		baseURL:    baseURL,
		now:        time.Now,
	}
}

// Handler returns the complete mux (3.1 resources + /admin/*), CORS-wrapped
// like every other sim's simapi so a browser-based dashboard can reach it
// directly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs", s.handlePrograms)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/vens", s.handleVens)
	mux.HandleFunc("/reports", s.handleReports)
	mux.HandleFunc("/auth/server", s.handleAuthServer)
	mux.HandleFunc("/auth/token", s.handleAuthToken)

	mux.HandleFunc("/admin/programs", s.handleAdminPrograms)
	mux.HandleFunc("/admin/events", s.handleAdminEvents)
	mux.HandleFunc("/admin/state", s.handleAdminState)
	mux.HandleFunc("/admin/reset", s.handleAdminReset)
	mux.HandleFunc("/admin/auth", s.handleAdminAuth)
	return cors(mux)
}

// ── 3.1 resource endpoints ───────────────────────────────────────────────────

func (s *Server) handlePrograms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !s.authOK(r) {
		unauthorized(w)
		return
	}
	s.mu.Lock()
	all := make([]Program, 0, len(s.programs))
	for _, p := range s.programs {
		all = append(all, p)
	}
	s.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	writeJSON(w, http.StatusOK, paginate(all, r))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !s.authOK(r) {
		unauthorized(w)
		return
	}
	programID := r.URL.Query().Get("programID")
	s.mu.Lock()
	var all []Event
	for _, e := range s.events {
		if programID == "" || e.ProgramID == programID {
			all = append(all, e)
		}
	}
	s.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	writeJSON(w, http.StatusOK, paginate(all, r))
}

func (s *Server) handleVens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.authOK(r) {
			unauthorized(w)
			return
		}
		name := r.URL.Query().Get("venName")
		s.mu.Lock()
		var out []Ven
		for _, v := range s.vens {
			if name == "" || v.VenName == name {
				out = append(out, v)
			}
		}
		s.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		writeJSON(w, http.StatusOK, paginate(out, r))
	case http.MethodPost:
		if !s.authOK(r) {
			unauthorized(w)
			return
		}
		var v Ven
		if err := decodeJSON(r, &v); err != nil {
			badRequest(w, err)
			return
		}
		if v.VenName == "" {
			badRequest(w, fmt.Errorf("venName is required"))
			return
		}
		s.mu.Lock()
		s.nextVenID++
		v.ID = fmt.Sprintf("ven-%d", s.nextVenID)
		s.vens[v.ID] = v
		s.mu.Unlock()
		writeJSON(w, http.StatusCreated, v)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.authOK(r) {
		unauthorized(w)
		return
	}
	var rep Report
	if err := decodeJSON(r, &rep); err != nil {
		badRequest(w, err)
		return
	}
	rep.ReceivedAtUnix = s.now().Unix()
	if rep.ObjectType == "" {
		rep.ObjectType = "REPORT"
	}
	s.mu.Lock()
	s.reports = append(s.reports, rep)
	s.mu.Unlock()
	log.Printf("vtnsim: received report programID=%s eventID=%s clientName=%s", rep.ProgramID, rep.EventID, rep.ClientName)
	writeJSON(w, http.StatusCreated, rep)
}

// ── OAuth2 client-credentials (optional — see requireAuth) ──────────────────

func (s *Server) handleAuthServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token_url": s.baseURL + "/auth/token"})
}

func (s *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		badRequest(w, err)
		return
	}
	if r.FormValue("grant_type") != "client_credentials" {
		badRequest(w, fmt.Errorf("unsupported grant_type %q (want client_credentials)", r.FormValue("grant_type")))
		return
	}
	s.mu.Lock()
	wantID, wantSecret, tok := s.clientID, s.clientSecret, s.tokenValue
	s.mu.Unlock()
	if wantID != "" && (r.FormValue("client_id") != wantID || r.FormValue("client_secret") != wantSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// authOK gates every resource endpoint (never /auth/* itself) when
// requireAuth is on — a plain Authorization: Bearer <tokenValue> check, no
// expiry modeling (this stub isn't testing token *lifecycle*, just that an
// auth-required VTN 401s an unauthenticated/blank-token VEN and 2xxs a
// correctly-authenticated one).
func (s *Server) authOK(r *http.Request) bool {
	s.mu.Lock()
	need, tok := s.requireAuth, s.tokenValue
	s.mu.Unlock()
	if !need {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+tok
}

// ── /admin/* test-control surface ────────────────────────────────────────────

// handleAdminPrograms: POST upserts a program (body: Program JSON, "id"
// required); DELETE removes one (body: {"id":"..."}).
func (s *Server) handleAdminPrograms(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var p Program
		if err := decodeJSON(r, &p); err != nil {
			badRequest(w, err)
			return
		}
		if p.ID == "" {
			badRequest(w, fmt.Errorf("id is required"))
			return
		}
		s.mu.Lock()
		s.programs[p.ID] = p
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		var body struct {
			ID string `json:"id"`
		}
		_ = decodeJSON(r, &body)
		s.mu.Lock()
		delete(s.programs, body.ID)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

// handleAdminEvents: POST upserts an event (body: Event JSON, "id" and
// "programID" required — a dangling programID is tolerated, exactly like a
// real VTN's own program/event resources are independently addressable);
// DELETE removes one (body: {"id":"..."}).
func (s *Server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var e Event
		if err := decodeJSON(r, &e); err != nil {
			badRequest(w, err)
			return
		}
		if e.ID == "" {
			badRequest(w, fmt.Errorf("id is required"))
			return
		}
		if e.ProgramID == "" {
			badRequest(w, fmt.Errorf("programID is required"))
			return
		}
		s.mu.Lock()
		s.events[e.ID] = e
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		var body struct {
			ID string `json:"id"`
		}
		_ = decodeJSON(r, &body)
		s.mu.Lock()
		delete(s.events, body.ID)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

// adminState is GET /admin/state's response shape — a full debug dump, the
// vtnsim analogue of every southbound sim's GET /state.
type adminState struct {
	Programs    map[string]Program `json:"programs"`
	Events      map[string]Event   `json:"events"`
	Vens        map[string]Ven     `json:"vens"`
	Reports     []Report           `json:"reports"`
	RequireAuth bool               `json:"require_auth"`
}

func (s *Server) handleAdminState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, adminState{
		Programs:    s.programs,
		Events:      s.events,
		Vens:        s.vens,
		Reports:     s.reports,
		RequireAuth: s.requireAuth,
	})
}

// handleAdminReset clears all programs/events/vens/reports (bench
// convenience between scenarios — resetForScenario-style isolation) but
// leaves the auth posture untouched (auth is a deliberate scenario setup
// choice, not per-scenario device state).
func (s *Server) handleAdminReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	s.programs = make(map[string]Program)
	s.events = make(map[string]Event)
	s.vens = make(map[string]Ven)
	s.reports = nil
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminAuth toggles the OAuth2 gate: body {"enable":true,
// "client_id":"...", "client_secret":"..."} turns auth ON (client_id/secret
// only update when non-empty, so {"enable":false} alone just disables
// without clobbering a previously-set identity).
func (s *Server) handleAdminAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		Enable       bool   `json:"enable"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, err)
		return
	}
	s.mu.Lock()
	s.requireAuth = body.Enable
	if body.ClientID != "" {
		s.clientID = body.ClientID
	}
	if body.ClientSecret != "" {
		s.clientSecret = body.ClientSecret
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// paginate slices all per the request's skip/limit query params — the exact
// contract internal/openadr/client.go's getPaged relies on: at most `limit`
// items per page, so the client's "len(items) < limit ⇒ last page" loop
// terminates correctly.
func paginate[T any](all []T, r *http.Request) []T {
	skip, limit := pageParams(r)
	if skip >= len(all) {
		return []T{}
	}
	end := skip + limit
	if end > len(all) {
		end = len(all)
	}
	return all[skip:end]
}

func pageParams(r *http.Request) (skip, limit int) {
	q := r.URL.Query()
	skip, _ = strconv.Atoi(q.Get("skip"))
	limit, _ = strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if skip < 0 {
		skip = 0
	}
	return skip, limit
}

func decodeJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("empty request body")
	}
	return json.Unmarshal(body, dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
func badRequest(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusBadRequest) }
func unauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// cors mirrors sim/simapi's permissive CORS wrapper so a browser-based
// dashboard (or this repo's own admin tooling) can reach vtnsim directly.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
