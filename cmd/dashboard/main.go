// cmd/dashboard serves a single-page DERMS dashboard that proxies API
// calls to the hub, gridsim, and device simulator APIs.
//
// Usage:
//
//	dashboard -addr :8080 -hub https://hub:9100 -gridsim http://hub:11112 \
//	          -solar http://solar:6020 -battery http://bat:6021 -meter http://meter:6022
package main

import (
	"embed"
	"flag"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Dashboard V2 SPA (Vite + React + TS, cmd/dashboard/ui). ui/dist is
// committed (see Makefile `ui` target + docs/dashboard-v2/CONTRACTS.md §6)
// so the pure-go CI build needs no node/npm. Served at "/" with an
// index.html fallback for client-side routing; the legacy page moves to
// /legacy until V2 reaches parity.
//
//go:embed all:ui/dist
var uiDistFS embed.FS

// uiDist strips the "ui/dist" prefix baked in by go:embed so paths line up
// with the SPA's own root-relative asset URLs (e.g. "/assets/index-*.js").
var uiDist = mustSubFS(uiDistFS, "ui/dist")

func mustSubFS(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		log.Fatalf("dashboard: embed ui/dist: %v", err)
	}
	return sub
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	hub := flag.String("hub", "https://localhost:9100", "hub metrics/status address (lexa-api serves HTTPS on :9100, self-signed — WS-B)")
	gridsim := flag.String("gridsim", "http://localhost:11112", "gridsim admin address")
	solar := flag.String("solar", "http://localhost:6020", "solar simapi address")
	battery := flag.String("battery", "http://localhost:6021", "battery simapi address")
	meter := flag.String("meter", "http://localhost:6022", "meter simapi address")
	ev := flag.String("ev", "http://localhost:6024", "EV charger simapi address")
	mqttproxy := flag.String("mqttproxy", "http://69.0.0.2:11882", "MQTT fault-proxy control API (mayhem chaos)")
	scenarioDir := flag.String("scenario-dir", "qa/scenarios", "TASK-076: directory of *.json Mayhem scenario specs, re-read on every run (empty = specs disabled)")
	hubTokenFile := flag.String("hub-token-file", "", "path to lexa-api's bearer token (TASK-014, AD-008); empty = no auth presented, today's behavior")
	whatifScenarioDir := flag.String("whatif-scenario-dir", "data/scenarios", "dashboard V2: scenario datasets for the what-if engine")
	whatifTariffDir := flag.String("whatif-tariff-dir", "data/tariffs", "dashboard V2: sourced tariff files for the what-if engine")
	flag.Parse()

	// TASK-014: present lexa-api's bearer token, scoped to the "hub" backend
	// only (setHubAuth in hubauth.go). A missing/empty file is not fatal —
	// the dashboard must keep serving against a not-yet-token-enabled hub
	// during the staged rollout (AD-008).
	if tok, err := loadHubToken(*hubTokenFile); err != nil {
		log.Printf("dashboard: -hub-token-file %s: %v — continuing without hub auth", *hubTokenFile, err)
	} else {
		hubToken = tok
		if hubToken != "" {
			log.Printf("dashboard: presenting bearer token to hub backend (%s)", *hub)
		}
	}

	mux := http.NewServeMux()

	// Legacy monolith page (dashboard.html), kept at /legacy until V2 reaches
	// parity (CONTRACTS.md §6). Exact-path match: ServeMux prefers this over
	// the "/" catch-all below for the literal "/legacy" request.
	mux.HandleFunc("/legacy", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/legacy" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})

	// Dashboard V2 SPA: real files under ui/dist (JS/CSS/brand assets) serve
	// directly; any other non-/api, non-/legacy path falls back to
	// index.html so react-router's BrowserRouter can resolve client-side
	// routes like /ops or /proof on a hard refresh.
	mux.Handle("/", spaHandler(uiDist))

	// Reserved namespaces must never fall back to the SPA's index.html: an
	// unknown /api/* route is a 404 (pre-V2 behavior), and /legacy has no
	// subpaths. Longest-prefix mux routing lets the specific /api/... mounts
	// above win; these catch what they miss.
	mux.Handle("/api/", http.NotFoundHandler())
	mux.Handle("/legacy/", http.NotFoundHandler())

	mux.Handle("/api/hub/", stripHubAuthProxy("/api/hub", *hub))
	mux.Handle("/api/gridsim/", stripProxy("/api/gridsim", *gridsim))
	mux.Handle("/api/solar/", stripProxy("/api/solar", *solar))
	mux.Handle("/api/battery/", stripProxy("/api/battery", *battery))
	mux.Handle("/api/meter/", stripProxy("/api/meter", *meter))
	mux.Handle("/api/ev/", stripProxy("/api/ev", *ev))

	// Single merged SSE stream of every backend's /logs (see logmux.go).
	mux.Handle("/api/logs/all", newLogMux(map[string]string{
		"hub":     *hub + "/logs",
		"grid":    *gridsim + "/admin/logs",
		"solar":   *solar + "/logs",
		"battery": *battery + "/logs",
		"meter":   *meter + "/logs",
		"ev":      *ev + "/logs",
	}))

	// Bench replay driver: server-side so an overnight hardware-in-the-loop
	// run survives the browser tab closing (see replay.go).
	replay := newReplayDriver(map[string]string{
		"hub":     *hub,
		"gridsim": *gridsim,
		"solar":   *solar,
		"battery": *battery,
		"meter":   *meter,
		"ev":      *ev,
	})
	mux.HandleFunc("/api/replay/start", replay.handleStart)
	mux.HandleFunc("/api/replay/status", replay.handleStatus)
	mux.HandleFunc("/api/replay/abort", replay.handleAbort)

	// Mayhem QA driver: adversarial fault-injection suite over the whole bench,
	// server-side so a run survives the tab closing (see mayhem.go).
	mayhem := newMayhemDriver(map[string]string{
		"hub":       *hub,
		"gridsim":   *gridsim,
		"solar":     *solar,
		"battery":   *battery,
		"meter":     *meter,
		"ev":        *ev,
		"mqttproxy": *mqttproxy,
	})
	// TASK-076: specs load fresh on every run (scenarios() reads the dir at
	// request time, not here) — see scenariospec.go and qa/scenarios/README.md.
	mayhem.scenarioDir = *scenarioDir
	// Dashboard V2 what-if engine: offline cost simulation over the real
	// scenario datasets + sourced tariffs (see whatif_api.go, CONTRACTS.md §3).
	registerWhatif(mux, *whatifScenarioDir, *whatifTariffDir)

	mux.HandleFunc("/api/qa/start", mayhem.handleStart)
	mux.HandleFunc("/api/qa/status", mayhem.handleStatus)
	mux.HandleFunc("/api/qa/scenarios", mayhem.handleScenarios)
	mux.HandleFunc("/api/qa/abort", mayhem.handleAbort)
	// Saved run reports (writeReport in mayhem.go writes to logs/qa/): list +
	// fetch by name, read-only (see qa_reports.go, CONTRACTS.md §4).
	mux.HandleFunc("/api/qa/reports", handleQAReports)
	mux.HandleFunc("/api/qa/reports/{name}", handleQAReportFetch)

	log.Printf("dashboard: serving at http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// spaHandler serves the embedded Dashboard V2 build (ui/dist): a request for
// a path that exists as a real file (e.g. /assets/index-xxx.js, /brand/
// logo.png) is served as that file; everything else — "/" itself, and any
// client-side route the SPA owns (/studio, /ops, /proof, /logs, /bench) —
// falls back to index.html. Reserved namespaces (/api/*, /legacy/*) are kept
// out of the fallback by mux registrations in main(), not here — spaHandler
// stays a namespace-agnostic SPA server.
func spaHandler(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)

		rel := strings.TrimPrefix(clean, "/")
		if rel == "" || rel == "." {
			rel = "index.html"
		}

		if info, err := fs.Stat(dist, rel); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		// A missing build asset is a real 404 (stale HTML referencing an old
		// hashed bundle must fail loudly), never an index.html fallback that
		// a <script> tag would try to parse as JS.
		if strings.HasPrefix(rel, "assets/") || strings.HasPrefix(rel, "brand/") {
			http.NotFound(w, r)
			return
		}

		f, err := dist.Open("index.html")
		if err != nil {
			http.Error(w, "dashboard: embedded ui/dist/index.html missing — run `make ui`", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("dashboard: spa fallback write: %v", err)
		}
	})
}

func stripProxy(prefix, target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatalf("invalid target URL %q: %v", target, err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.FlushInterval = -1 // immediate flush; required for SSE pass-through
	return http.StripPrefix(prefix, rp)
}

// stripHubAuthProxy is stripProxy for the "hub" mount specifically: its
// Director additionally sets the bearer-token header (TASK-014). This is
// the only proxy mount that ever gets the token — simapi/gridsim targets
// use plain stripProxy and must never see it (AD-008).
func stripHubAuthProxy(prefix, target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatalf("invalid target URL %q: %v", target, err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.FlushInterval = -1 // immediate flush; required for SSE pass-through
	// WS-B: lexa-api serves HTTPS on :9100 with a self-signed leaf; skip
	// verification for the hub mount (see hubtls.go). Harmless if the target
	// is still plain http (TLS config is ignored for http:// requests).
	rp.Transport = benchHubTransport()
	baseDirector := rp.Director
	rp.Director = func(req *http.Request) {
		baseDirector(req)
		setHubAuth(req, "hub")
	}
	return http.StripPrefix(prefix, rp)
}
