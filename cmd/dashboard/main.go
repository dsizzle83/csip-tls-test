// cmd/dashboard serves a single-page DERMS dashboard that proxies API
// calls to the hub, gridsim, and device simulator APIs.
//
// Usage:
//
//	dashboard -addr :8080 -hub http://hub:9100 -gridsim http://hub:11112 \
//	          -solar http://solar:6020 -battery http://bat:6021 -meter http://meter:6022
package main

import (
	_ "embed"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

//go:embed dashboard.html
var dashboardHTML []byte

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	hub := flag.String("hub", "http://localhost:9100", "hub metrics/status address")
	gridsim := flag.String("gridsim", "http://localhost:11112", "gridsim admin address")
	solar := flag.String("solar", "http://localhost:6020", "solar simapi address")
	battery := flag.String("battery", "http://localhost:6021", "battery simapi address")
	meter := flag.String("meter", "http://localhost:6022", "meter simapi address")
	ev := flag.String("ev", "http://localhost:6024", "EV charger simapi address")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})

	mux.Handle("/api/hub/", stripProxy("/api/hub", *hub))
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
		"hub":     *hub,
		"gridsim": *gridsim,
		"solar":   *solar,
		"battery": *battery,
		"meter":   *meter,
		"ev":      *ev,
	})
	mux.HandleFunc("/api/qa/start", mayhem.handleStart)
	mux.HandleFunc("/api/qa/status", mayhem.handleStatus)
	mux.HandleFunc("/api/qa/scenarios", mayhem.handleScenarios)
	mux.HandleFunc("/api/qa/abort", mayhem.handleAbort)

	log.Printf("dashboard: serving at http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
