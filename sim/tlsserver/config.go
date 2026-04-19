package tlsserver

// DefaultCipherList is the IEEE 2030.5 / CSIP §5.2.1.1 mandated cipher
// suite. Production code should always use this constant rather than
// typing the literal string.
const DefaultCipherList = "ECDHE-ECDSA-AES128-CCM-8"

// Config holds everything needed to construct a Server.
type Config struct {
	CACertPath     string // CA used to verify client certs
	ServerCertPath string // server leaf cert
	ServerKeyPath  string // server private key
	CipherList     string // empty → DefaultCipherList
}
