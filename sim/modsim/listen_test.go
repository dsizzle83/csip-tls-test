package main

import "testing"

// TestListenAddr pins -bind's contract: empty preserves the historical
// wildcard bind (0.0.0.0), and any non-empty value passes through verbatim
// so a WAN/LAN split bench can pin the listener to one segment.
func TestListenAddr(t *testing.T) {
	for _, tc := range []struct {
		bind string
		port int
		want string
	}{
		{"", 5020, "0.0.0.0:5020"},
		{"192.168.0.188", 5020, "192.168.0.188:5020"},
		{"69.0.0.20", 8021, "69.0.0.20:8021"},
		{"0.0.0.0", 5020, "0.0.0.0:5020"}, // explicit wildcard passes through unchanged too
	} {
		if got := listenAddr(tc.bind, tc.port); got != tc.want {
			t.Errorf("listenAddr(%q, %d) = %q, want %q", tc.bind, tc.port, got, tc.want)
		}
	}
}
