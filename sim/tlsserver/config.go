package tlsserver

// DefaultCipherList is the IEEE 2030.5 / CSIP §5.2.1.1 mandated cipher
// suite. Production code should always use this constant rather than
// typing the literal string.
const DefaultCipherList = "ECDHE-ECDSA-AES128-CCM-8"

// Config holds everything needed to construct a Server.
type Config struct {
	CACertPath     string // CA used to verify client certs
	ServerCertPath string // server leaf cert (single certificate)
	ServerKeyPath  string // server private key
	CipherList     string // empty → DefaultCipherList

	// ServerCertChainPath, when non-empty, is a PEM file holding the full
	// certificate chain (leaf first, then intermediate CA(s), excluding the
	// trust anchor). It takes precedence over ServerCertPath and is loaded
	// via wolfSSL_CTX_use_certificate_chain_file so the server presents the
	// intermediates a depth-3/4 chain verification needs (COMM-004 A/B/C).
	// Empty ⇒ the single-leaf ServerCertPath path, unchanged.
	//
	// This is the chain the process STARTS with, and the one RestoreChain
	// returns to. The rejection sub-tests (COMM-004 D/E/F/G) install their own
	// chain at RUNTIME instead — see chain.go — because a chain chosen here
	// could only be changed by restarting the process, and a restart
	// mid-campaign invalidates the evidence of every test case already run
	// against the running instance.
	ServerCertChainPath string

	// NoSessionTickets makes every handshake a FULL handshake: no RFC 5077
	// session ticket is issued and the server-side session cache is off, so no
	// client can resume and no ClientHello can arrive with a ticket in it.
	//
	// WHY a bench server needs the option. A resumed session carries no
	// certificates — that is the point of resumption — so a conformance window
	// that happens to catch a resumed connection has no certificate evidence to
	// cite, and every criterion about the certificate exchange must decline to
	// decide. The CSIP suite copes (it reads the full handshake from another
	// conversation of the same window when there is one, and says so), but
	// "when there is one" is luck, and a run whose evidence depends on luck is a
	// run that will one day produce a bundle with a hole in it.
	//
	// Off by default. Resumption is a MAY that a real 2030.5 client is entitled
	// to use, and a bench that never issued a ticket would stop exercising the
	// DUT's resumption path — so this is a switch for evidence-gathering runs,
	// not a new default.
	NoSessionTickets bool
}
