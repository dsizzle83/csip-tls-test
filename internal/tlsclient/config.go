package tlsclient

// DefaultCipherList is the IEEE 2030.5 / CSIP §5.2.1.1 mandated cipher
// suite. Production code should always use this constant.
const DefaultCipherList = "ECDHE-ECDSA-AES128-CCM-8"

// Config holds everything needed to construct a Client.
type Config struct {
	// ServerAddr is the host:port to connect to.
	ServerAddr string

	// CACertPath is the PEM-encoded CA cert used to verify the server's
	// certificate during the mTLS handshake.
	CACertPath string

	// ClientCertPath is the PEM-encoded client (DER device) cert
	// presented to the server during mTLS.
	ClientCertPath string

	// ClientKeyPath is the PEM-encoded private key matching ClientCertPath.
	ClientKeyPath string

	// CipherList is the wolfSSL cipher list. Empty means DefaultCipherList.
	// Override only for negative testing — production code should leave
	// this empty to enforce CSIP compliance.
	CipherList string
}
