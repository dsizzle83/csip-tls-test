package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":6030", "listen address")
	baseURL := flag.String("base-url", "", `base URL this server is reachable at, e.g. "http://69.0.0.20:6030" (advertised in GET /auth/server's token_url); defaults to "http://127.0.0.1<addr>"`)
	flag.Parse()

	base := *baseURL
	if base == "" {
		base = "http://127.0.0.1" + *addr
	}

	srv := New(base)
	log.Printf("vtnsim: OpenADR 3.1 VTN stub listening on %s (base_url=%s) — GET /programs GET /events POST /reports GET/POST /vens GET /auth/server POST /auth/token, admin: /admin/programs /admin/events /admin/state /admin/reset /admin/auth", *addr, base)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
