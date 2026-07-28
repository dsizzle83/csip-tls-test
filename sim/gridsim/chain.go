package gridsim

// chain.go is the admin plane's certificate-chain lever: GET /admin/chain
// reports which chain the CSIP data plane is presenting, POST /admin/chain
// installs a different one for NEW connections, and POST {"restore":true} puts
// the original back.
//
// It exists for COMM-004 D/E/F/G, the four rows that ask whether the DUT
// REJECTS a non-conformant server chain. A test that asks that question must
// present such a chain, and until this endpoint existed the only way to do so
// was to restart the 2030.5 server — which invalidates the evidence of every
// test case already run against the running instance.
//
// # Why the chain arrives as PEM text and not as a path
//
// The harness mints its fixtures in memory, in its own process, on a machine
// that need not share a filesystem with the simulator. Accepting paths would
// have made the lever work on one bench and silently fail on another; worse, a
// path is a lever for reading any file the simulator can reach. The PEM travels
// in the request body and this file writes it into a private temporary
// directory that only ever holds swap material.
//
// # Why gridsim does not import sim/tlsserver
//
// gridsim is pure Go and its tests run without cgo or a wolfSSL sysroot;
// tlsserver is the cgo wolfSSL binding. Importing it here would have dragged
// the whole TLS toolchain into every gridsim unit test. The embedding binary
// (sim/server) adapts its tlsserver.Server to the small ChainSwapper interface
// below instead, which is three methods wide and easy to fake in a test.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ChainState describes the certificate chain the CSIP data plane presents.
type ChainState struct {
	// Label names the installed chain; "startup" is the one the process began
	// with.
	Label string `json:"label"`
	// LeafSHA256 is the hex SHA-256 of the leaf certificate's DER — the field a
	// conformance check compares against the leaf it saw in the capture, and
	// therefore the one that settles "was my fixture the chain on the wire?".
	LeafSHA256 string `json:"leaf_sha256"`
	// ChainLen is how many certificates the server sends.
	ChainLen int `json:"chain_len"`
	// Subjects and Issuers are the chain's DNs, leaf first. The last Issuer is
	// the trust anchor the chain expects the peer to hold, which is how a check
	// can tell whether a fixture is anchored where the bench's normal chain is.
	Subjects []string `json:"subjects,omitempty"`
	Issuers  []string `json:"issuers,omitempty"`
	// Original reports whether this is the chain the process started with.
	Original bool `json:"original"`
	// InstalledUnix is when this chain became the one served.
	InstalledUnix int64 `json:"installed_unix"`
	// Swaps counts applied swaps since start-up.
	Swaps int `json:"swaps"`
	// Warnings records anything about the material that could not be checked,
	// e.g. a deliberately malformed leaf a strict parser refuses.
	Warnings []string `json:"warnings,omitempty"`
}

// ChainSwapper is the slice of the data-plane TLS server this lever needs.
// sim/server adapts tlsserver.Server to it; a test fakes it in ten lines.
type ChainSwapper interface {
	// ActiveChain reports what NEW connections are being offered.
	ActiveChain() ChainState
	// OriginalChain reports what the process started with, installed or not.
	OriginalChain() ChainState
	// SwapChain installs a chain (leaf first, then intermediates, no anchor)
	// and its key for NEW connections, leaving open connections alone.
	SwapChain(label, certPEMPath, keyPEMPath string) (ChainState, error)
	// RestoreChain reinstalls the start-up chain.
	RestoreChain() (ChainState, error)
}

// chainLever is the server-side state of the endpoint.
type chainLever struct {
	mu      sync.Mutex
	swapper ChainSwapper
	// dir holds the material of the CURRENTLY installed swap. It is removed
	// when a later swap or a restore supersedes it, so the simulator never
	// accumulates private keys it is no longer serving.
	dir string
}

// SetChainSwapper wires the data-plane TLS server's chain lever into the admin
// API. A gridsim with no swapper answers /admin/chain 501, which is precisely
// what a conformance check probes for before deciding to run or to SKIP.
func (s *Server) SetChainSwapper(sw ChainSwapper) {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	s.chain.swapper = sw
}

// adminChainReq is the body of POST /admin/chain.
type adminChainReq struct {
	// Label names the chain in the report. Required for an install.
	Label string `json:"label"`
	// CertPEM is the chain to present: the leaf FIRST, then any intermediates,
	// excluding the trust anchor (RFC 5246 §7.4.2 — a peer that ships its own
	// anchor is asking to be trusted on its own say-so).
	CertPEM string `json:"cert_pem"`
	// KeyPEM is the leaf's private key.
	KeyPEM string `json:"key_pem"`
	// Restore, when true, reinstalls the start-up chain and ignores everything
	// above. This is the call a check makes from its cleanup path, and it must
	// keep working even if the check's own state is confused, so it takes no
	// other argument.
	Restore bool `json:"restore"`
}

// handleAdminChain serves GET and POST /admin/chain.
func (s *Server) handleAdminChain(w http.ResponseWriter, r *http.Request) {
	s.chain.mu.Lock()
	sw := s.chain.swapper
	s.chain.mu.Unlock()
	if sw == nil {
		// 501, not 404: the route EXISTS and this build understands it — the
		// embedding binary simply serves no TLS data plane (a unit-test
		// gridsim, or a future headless mode). A probing check can tell the two
		// apart, which is the difference between "your bench is old" and "this
		// process has no data plane".
		writeChainErr(w, http.StatusNotImplemented,
			"this gridsim has no TLS data plane wired to the chain lever, so there is no chain to report "+
				"or to swap (sim/server calls SetChainSwapper; a bare gridsim does not)")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{
			"active":      sw.ActiveChain(),
			"original":    sw.OriginalChain(),
			"server_time": s.Now(),
		})
	case http.MethodPost:
		var req adminChainReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeChainErr(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
			return
		}
		st, err := s.applyChainReq(sw, req)
		if err != nil {
			writeChainErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{
			"active":      st,
			"original":    sw.OriginalChain(),
			"server_time": s.Now(),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// applyChainReq performs a restore or an install.
func (s *Server) applyChainReq(sw ChainSwapper, req adminChainReq) (ChainState, error) {
	if req.Restore {
		st, err := sw.RestoreChain()
		if err != nil {
			return ChainState{}, fmt.Errorf("restore the start-up chain: %w", err)
		}
		s.clearChainDir()
		log.Printf("[gridsim] certificate chain RESTORED to %q (leaf %s)", st.Label, short(st.LeafSHA256))
		return st, nil
	}
	if strings.TrimSpace(req.Label) == "" {
		return ChainState{}, fmt.Errorf("a chain install needs a label naming the chain; an unlabelled " +
			"chain cannot be reported in a conformance bundle")
	}
	if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
		return ChainState{}, fmt.Errorf("a chain install needs both cert_pem (leaf first, then " +
			"intermediates, excluding the trust anchor) and key_pem")
	}

	dir, err := os.MkdirTemp("", "gridsim-chain-")
	if err != nil {
		return ChainState{}, fmt.Errorf("create a directory for the swap material: %w", err)
	}
	certPath := filepath.Join(dir, "chain.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte(req.CertPEM), 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return ChainState{}, fmt.Errorf("write the swap chain: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(req.KeyPEM), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return ChainState{}, fmt.Errorf("write the swap key: %w", err)
	}

	st, err := sw.SwapChain(req.Label, certPath, keyPath)
	if err != nil {
		// The install failed, so the server is still serving what it was
		// serving. Take the unused material away with it.
		_ = os.RemoveAll(dir)
		return ChainState{}, fmt.Errorf("install chain %q: %w", req.Label, err)
	}
	// Only now retire the PREVIOUS swap's material: the TLS server loaded the
	// new files during SwapChain, and removing the old directory any earlier
	// would have deleted the files the running credential came from.
	s.chain.mu.Lock()
	prev := s.chain.dir
	s.chain.dir = dir
	s.chain.mu.Unlock()
	if prev != "" {
		_ = os.RemoveAll(prev)
	}
	log.Printf("[gridsim] certificate chain SWAPPED to %q (%d cert(s), leaf %s) — NEW connections only; "+
		"open connections keep the chain they handshook with",
		st.Label, st.ChainLen, short(st.LeafSHA256))
	return st, nil
}

// clearChainDir removes the material of the swap that is no longer installed.
func (s *Server) clearChainDir() {
	s.chain.mu.Lock()
	dir := s.chain.dir
	s.chain.dir = ""
	s.chain.mu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func writeChainErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// short abbreviates a fingerprint for a log line.
func short(sha string) string {
	if len(sha) > 16 {
		return sha[:16] + "…"
	}
	return sha
}
