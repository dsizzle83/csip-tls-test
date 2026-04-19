# gridsim package — context for Step A

## Current state

`NewServer(clientLFDI string)` takes the LFDI as a constructor argument and
bakes it into the EndDevice at `/edev/2` at startup. `server/main.go`
pre-computes the LFDI by reading `certs/client-cert.pem` from disk — this
gives the correct value but requires knowing the cert before any connection
arrives.

## Step A goal

Replace the static LFDI with one derived from the peer cert presented during
the mTLS handshake. This is how a real DERMS works: it sees the LFDI for the
first time when the device connects.

## Recommended approach

Add a method to `Server` that lets the caller update the LFDI (and rebuild
the EndDevice entry) after the handshake:

```go
// SetClientLFDI updates the LFDI used in the EndDevice record.
// Call this once per connection after deriving the LFDI from the peer cert.
func (s *Server) SetClientLFDI(lfdi string) {
    s.ClientLFDI = lfdi
    // rebuild just the /edev list (or /edev/2) so future GETs reflect it
    s.rebuildEndDeviceList()
}
```

`rebuildEndDeviceList` re-runs the `/edev` and `/edev/2` block of
`buildResourceTree` with the new LFDI. The rest of the tree (/tm, /mup, /derp,
etc.) is LFDI-independent and doesn't need to change.

**Concurrency note:** The gridsim currently has no locking. If `SetClientLFDI`
is called from the connection handler goroutine while an HTTP request is being
served, there's a data race on `s.resources`. Add a `sync.RWMutex` to `Server`
and hold the write lock in `SetClientLFDI`, read lock in `handleRequest`.

## SFDI is also wrong

`server/main.go` currently hard-codes `SFDI: 123456789`. After Step A, compute
SFDI from LFDI using `identity.FromCertificateDER` (which returns both). The
`identity` package is pure Go with no cgo — safe to import from gridsim.
