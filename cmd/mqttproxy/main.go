package main

import (
	"flag"
	"log"
	"net"
	"net/http"
)

func main() {
	listen := flag.String("listen", ":1882", "TCP listen address for service connections")
	upstream := flag.String("upstream", "127.0.0.1:1883", "real mosquitto broker host:port")
	control := flag.String("control", ":11882", "HTTP control API address (bind on the hub LAN IP)")
	flag.Parse()

	proxy := NewProxy(*upstream)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("mqttproxy: listen %s: %v", *listen, err)
	}
	log.Printf("mqttproxy: forwarding %s → %s (pass mode); control on %s", *listen, *upstream, *control)

	go func() {
		ctl := controlAPI(proxy, *upstream)
		if err := http.ListenAndServe(*control, ctl.routes()); err != nil {
			log.Fatalf("mqttproxy: control server: %v", err)
		}
	}()

	if err := proxy.Serve(ln); err != nil {
		log.Fatalf("mqttproxy: serve: %v", err)
	}
}

// controlAPI is a tiny constructor so main reads cleanly.
func controlAPI(p *Proxy, broker string) control {
	return control{proxy: p, broker: broker}
}
