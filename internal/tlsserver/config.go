package tlsserver

// DefaultCipherList is the IEEE 2030.5 / CSIP §5.2.1.1 mandated cipher
// suite. Note the wolfSSL spelling uses dashes throughout, which is
// different from the OpenSSL spelling. Production code should always
// use this constant rather than typing the literal string.
const DefaultCipherList = "ECDHE-ECDSA-AES128-CCM-8"

// Config holds everything needed to construct a Server.
type Config struct {
	// CACertPath is the PEM-encoded CA cert used to verify client certs
	// during the mTLS handshake.
	CACertPath string

	// ServerCertPath is the PEM-encoded server leaf cert.
	ServerCertPath string

	// ServerKeyPath is the PEM-encoded server private key. Must match
	// the public key in ServerCertPath.
	ServerKeyPath string

	// CipherList is the wolfSSL cipher list. Empty means DefaultCipherList.
	// Override only for negative testing — production code should leave
	// this empty to enforce CSIP compliance.
	CipherList string
}
