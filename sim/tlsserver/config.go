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
	// intermediates a depth-3/4 chain verification needs (COMM-004
	// 004B/C/D/E/F). Empty ⇒ the single-leaf ServerCertPath path, unchanged.
	ServerCertChainPath string
}
