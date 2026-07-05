package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	listen := flag.String("listen", ":1882", "TCP listen address for service connections")
	upstream := flag.String("upstream", "127.0.0.1:1883", "real mosquitto broker host:port")
	control := flag.String("control", ":11882", "HTTP control API address (bind on the hub LAN IP)")
	user := flag.String("user", "", "broker username for /inject's direct publish (TASK-013/W7); empty = anonymous CONNECT")
	passFile := flag.String("passfile", "", "path to a file holding the broker password for -user; required if -user is set")
	flag.Parse()

	pass, err := loadPassword(*user, *passFile)
	if err != nil {
		log.Fatalf("mqttproxy: %v", err)
	}
	if *user != "" {
		log.Printf("mqttproxy: /inject will authenticate as broker user %s", *user)
	} else {
		log.Printf("mqttproxy: /inject will connect anonymously (no -user set) — breaks once the broker's ACL requires credentials")
	}

	proxy := NewProxy(*upstream)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("mqttproxy: listen %s: %v", *listen, err)
	}
	log.Printf("mqttproxy: forwarding %s → %s (pass mode); control on %s", *listen, *upstream, *control)

	go func() {
		ctl := controlAPI(proxy, *upstream, *user, pass)
		if err := http.ListenAndServe(*control, ctl.routes()); err != nil {
			log.Fatalf("mqttproxy: control server: %v", err)
		}
	}()

	if err := proxy.Serve(ln); err != nil {
		log.Fatalf("mqttproxy: serve: %v", err)
	}
}

// controlAPI is a tiny constructor so main reads cleanly.
func controlAPI(p *Proxy, broker, mqttUser, mqttPass string) control {
	return control{proxy: p, broker: broker, mqttUser: mqttUser, mqttPass: mqttPass}
}

// loadPassword reads the broker password for user from passFile, trimming
// the trailing newline the openssl-rand-generated pass-files carry. An empty
// user returns ("", nil) regardless of passFile — anonymous mode, today's
// default. A non-empty user with an empty/missing/unreadable passFile is a
// startup-time configuration error: fail loud rather than send a username
// with an empty password (the broker will reject it, which is far harder to
// diagnose than a clear error at boot).
func loadPassword(user, passFile string) (string, error) {
	if user == "" {
		return "", nil
	}
	if passFile == "" {
		return "", fmt.Errorf("-user %s set with no -passfile", user)
	}
	data, err := os.ReadFile(passFile)
	if err != nil {
		return "", fmt.Errorf("read -passfile %s: %w", passFile, err)
	}
	pass := strings.TrimSpace(string(data))
	if pass == "" {
		return "", fmt.Errorf("-passfile %s is empty", passFile)
	}
	return pass, nil
}
