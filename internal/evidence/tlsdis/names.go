package tlsdis

import "fmt"

// This file is the IANA registry transcription the evidence engine reports
// through. Two rules govern it, and both exist because of what a conformance
// report is for:
//
//  1. An unknown codepoint is PRINTED, never dropped. A suite the bench has
//     never heard of appearing in a gateway's ClientHello is a finding, and a
//     table that silently omitted it would turn that finding into an absence.
//     Every lookup falls back to UNKNOWN(0x____).
//
//  2. The names are the IANA registry names verbatim, not vendor spellings.
//     SunSpecTCP-15 ("cipher suites MUST be IANA-listed") is asserted by
//     looking a suite up here, and an OpenSSL-style "ECDHE-ECDSA-AES128-CCM8"
//     would not be checkable against the registry it cites.

// CipherSuiteName returns the IANA name of a cipher suite.
//
// 0xC0AE (TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) is the suite CSIP §5.2.1.1
// mandates and this bench pins, so it is the one entry here whose exact
// spelling is load-bearing for a conformance verdict.
func CipherSuiteName(id uint16) string {
	if n, ok := cipherSuites[id]; ok {
		return n
	}
	if IsGREASE(id) {
		return fmt.Sprintf("GREASE(0x%04X)", id)
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", id)
}

// KnownCipherSuite reports whether the suite is in the IANA registry as
// transcribed here — the predicate behind "MUST be IANA-listed".
func KnownCipherSuite(id uint16) bool {
	_, ok := cipherSuites[id]
	return ok
}

// CipherSuiteNames maps a list of codepoints to names, preserving order — the
// order itself is a conformance requirement (SunSpecTCP-19).
func CipherSuiteNames(ids []uint16) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = CipherSuiteName(id)
	}
	return out
}

// IsGREASE reports whether a codepoint is one of RFC 8701's reserved
// "grease" values, which clients inject to keep middleboxes honest. They are
// not real suites/groups/versions and must never be reported as unknown-and-
// therefore-suspicious.
func IsGREASE(v uint16) bool {
	return v&0x0F0F == 0x0A0A && byte(v>>8) == byte(v)
}

// VersionName renders a ProtocolVersion.
func VersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	case 0xFEFF:
		return "DTLS 1.0"
	case 0xFEFD:
		return "DTLS 1.2"
	case 0xFEFC:
		return "DTLS 1.3"
	}
	if IsGREASE(v) {
		return fmt.Sprintf("GREASE(0x%04X)", v)
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", v)
}

// Protocol version codepoints used across the package.
const (
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// NamedGroupName renders a supported_groups / key_share group.
func NamedGroupName(g uint16) string {
	if n, ok := namedGroups[g]; ok {
		return n
	}
	if IsGREASE(g) {
		return fmt.Sprintf("GREASE(0x%04X)", g)
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", g)
}

// SignatureSchemeName renders a signature_algorithms entry.
func SignatureSchemeName(s uint16) string {
	if n, ok := signatureSchemes[s]; ok {
		return n
	}
	if IsGREASE(s) {
		return fmt.Sprintf("GREASE(0x%04X)", s)
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", s)
}

// ExtensionName renders an extension type.
func ExtensionName(t uint16) string {
	if n, ok := extensionNames[t]; ok {
		return n
	}
	if IsGREASE(t) {
		return fmt.Sprintf("GREASE(0x%04X)", t)
	}
	return fmt.Sprintf("UNKNOWN(0x%04X)", t)
}

// AlertLevelName renders an alert level. A fatal alert is required evidence for
// several negative test cases (SunSpecTCP-13/48), so the distinction between
// warning and fatal is reported, never flattened.
func AlertLevelName(l uint8) string {
	switch l {
	case 1:
		return "warning"
	case 2:
		return "fatal"
	}
	return fmt.Sprintf("UNKNOWN(%d)", l)
}

// AlertDescriptionName renders an alert description.
func AlertDescriptionName(d uint8) string {
	if n, ok := alertDescriptions[d]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", d)
}

// HandshakeTypeName renders a handshake message type.
func HandshakeTypeName(t HandshakeType) string {
	if n, ok := handshakeTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
}

// ContentTypeName renders a record content type.
func ContentTypeName(t ContentType) string {
	switch t {
	case ContentChangeCipherSpec:
		return "change_cipher_spec"
	case ContentAlert:
		return "alert"
	case ContentHandshake:
		return "handshake"
	case ContentApplicationData:
		return "application_data"
	case ContentHeartbeat:
		return "heartbeat"
	}
	return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
}

// CompressionMethodName renders a compression method. SunSpecTCP-61 requires
// the ClientHello to offer NULL and nothing else, so "null" is a verdict.
func CompressionMethodName(m uint8) string {
	switch m {
	case 0:
		return "null"
	case 1:
		return "DEFLATE"
	case 64:
		return "LZS"
	}
	return fmt.Sprintf("UNKNOWN(%d)", m)
}

// ECPointFormatName renders an ec_point_formats entry (SunSpecTCP-44).
func ECPointFormatName(f uint8) string {
	switch f {
	case 0:
		return "uncompressed"
	case 1:
		return "ansiX962_compressed_prime"
	case 2:
		return "ansiX962_compressed_char2"
	}
	return fmt.Sprintf("UNKNOWN(%d)", f)
}

// PSKKeyExchangeModeName renders a psk_key_exchange_modes entry.
func PSKKeyExchangeModeName(m uint8) string {
	switch m {
	case 0:
		return "psk_ke"
	case 1:
		return "psk_dhe_ke"
	}
	return fmt.Sprintf("UNKNOWN(%d)", m)
}

// MaxFragmentLengthBytes converts the max_fragment_length codepoint (RFC 6066)
// to the byte count it selects. SunSpecTCP-60 requires 512 to be negotiable,
// which is codepoint 1.
func MaxFragmentLengthBytes(code uint8) (int, bool) {
	if code >= 1 && code <= 4 {
		return 1 << (8 + code), true
	}
	return 0, false
}

var handshakeTypeNames = map[HandshakeType]string{
	HandshakeHelloRequest:        "hello_request",
	HandshakeClientHello:         "client_hello",
	HandshakeServerHello:         "server_hello",
	HandshakeNewSessionTicket:    "new_session_ticket",
	HandshakeEndOfEarlyData:      "end_of_early_data",
	HandshakeEncryptedExtensions: "encrypted_extensions",
	HandshakeCertificate:         "certificate",
	HandshakeServerKeyExchange:   "server_key_exchange",
	HandshakeCertificateRequest:  "certificate_request",
	HandshakeServerHelloDone:     "server_hello_done",
	HandshakeCertificateVerify:   "certificate_verify",
	HandshakeClientKeyExchange:   "client_key_exchange",
	HandshakeFinished:            "finished",
	HandshakeKeyUpdate:           "key_update",
	HandshakeMessageHash:         "message_hash",
}

var extensionNames = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	25:    "cached_info",
	27:    "compress_certificate",
	28:    "record_size_limit",
	35:    "session_ticket",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	17513: "application_settings",
	65037: "encrypted_client_hello",
	65281: "renegotiation_info",
}

// Extension type codepoints referenced by the parsers.
const (
	ExtServerName          uint16 = 0
	ExtMaxFragmentLength   uint16 = 1
	ExtStatusRequest       uint16 = 5
	ExtSupportedGroups     uint16 = 10
	ExtECPointFormats      uint16 = 11
	ExtSignatureAlgorithms uint16 = 13
	ExtALPN                uint16 = 16
	ExtRecordSizeLimit     uint16 = 28
	ExtSessionTicket       uint16 = 35
	ExtPreSharedKey        uint16 = 41
	ExtSupportedVersions   uint16 = 43
	ExtCookie              uint16 = 44
	ExtPSKKeyExchangeModes uint16 = 45
	ExtKeyShare            uint16 = 51
	ExtRenegotiationInfo   uint16 = 65281
)

var alertDescriptions = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	21:  "decryption_failed_RESERVED",
	22:  "record_overflow",
	30:  "decompression_failure_RESERVED",
	40:  "handshake_failure",
	41:  "no_certificate_RESERVED",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	60:  "export_restriction_RESERVED",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	100: "no_renegotiation_RESERVED",
	109: "missing_extension",
	110: "unsupported_extension",
	111: "certificate_unobtainable_RESERVED",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	114: "bad_certificate_hash_value_RESERVED",
	115: "unknown_psk_identity",
	116: "certificate_required",
	120: "no_application_protocol",
}

var namedGroups = map[uint16]string{
	1:     "sect163k1",
	2:     "sect163r1",
	3:     "sect163r2",
	4:     "sect193r1",
	5:     "sect193r2",
	6:     "sect233k1",
	7:     "sect233r1",
	8:     "sect239k1",
	9:     "sect283k1",
	10:    "sect283r1",
	11:    "sect409k1",
	12:    "sect409r1",
	13:    "sect571k1",
	14:    "sect571r1",
	15:    "secp160k1",
	16:    "secp160r1",
	17:    "secp160r2",
	18:    "secp192k1",
	19:    "secp192r1",
	20:    "secp224k1",
	21:    "secp224r1",
	22:    "secp256k1",
	23:    "secp256r1",
	24:    "secp384r1",
	25:    "secp521r1",
	26:    "brainpoolP256r1",
	27:    "brainpoolP384r1",
	28:    "brainpoolP512r1",
	29:    "x25519",
	30:    "x448",
	31:    "brainpoolP256r1tls13",
	32:    "brainpoolP384r1tls13",
	33:    "brainpoolP512r1tls13",
	256:   "ffdhe2048",
	257:   "ffdhe3072",
	258:   "ffdhe4096",
	259:   "ffdhe6144",
	260:   "ffdhe8192",
	512:   "MLKEM512",
	513:   "MLKEM768",
	514:   "MLKEM1024",
	4587:  "SecP256r1MLKEM768",
	4588:  "X25519MLKEM768",
	4589:  "SecP384r1MLKEM1024",
	25497: "X25519Kyber768Draft00",
}

var signatureSchemes = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0202: "dsa_sha1",
	0x0203: "ecdsa_sha1",
	0x0301: "rsa_pkcs1_sha224",
	0x0303: "ecdsa_sha224",
	0x0401: "rsa_pkcs1_sha256",
	0x0402: "dsa_sha256",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0420: "rsa_pkcs1_sha256_legacy",
	0x0501: "rsa_pkcs1_sha384",
	0x0502: "dsa_sha384",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0520: "rsa_pkcs1_sha384_legacy",
	0x0601: "rsa_pkcs1_sha512",
	0x0602: "dsa_sha512",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0620: "rsa_pkcs1_sha512_legacy",
	0x0708: "sm2sig_sm3",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
	0x0809: "rsa_pss_pss_sha256",
	0x080A: "rsa_pss_pss_sha384",
	0x080B: "rsa_pss_pss_sha512",
}

// cipherSuites covers everything plausibly on a CSIP / Secure SunSpec Modbus
// wire: all five TLS 1.3 suites, the whole ECDHE/ECDH family, the RSA and DHE
// families, every PSK variant, the CCM block (RFC 6655 and RFC 7251 — which is
// where the mandatory 0xC0AE lives), the ChaCha20-Poly1305 block, and the
// legacy suites a non-conformant device might still offer, because "the DUT
// offered TLS_RSA_WITH_RC4_128_MD5" is a finding that has to be nameable.
var cipherSuites = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
	0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
	0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
	0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
	0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
	0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0x00A0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
	0x00A1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
	0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
	0x00A4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
	0x00A5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
	0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
	0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
	0x00AA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
	0x00AB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	0x00AC: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
	0x00AD: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
	0x00AE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
	0x00AF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
	0x00B0: "TLS_PSK_WITH_NULL_SHA256",
	0x00B1: "TLS_PSK_WITH_NULL_SHA384",
	0x00B2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
	0x00B3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	0x00B4: "TLS_DHE_PSK_WITH_NULL_SHA256",
	0x00B5: "TLS_DHE_PSK_WITH_NULL_SHA384",
	0x00B6: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
	0x00B7: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
	0x00B8: "TLS_RSA_PSK_WITH_NULL_SHA256",
	0x00B9: "TLS_RSA_PSK_WITH_NULL_SHA384",
	0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",

	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",

	0x5600: "TLS_FALLBACK_SCSV",

	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
	0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
	0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
	0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
	0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
	0xC033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
	0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
	0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
	0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	0xC038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
	0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384",

	// RFC 6655 — AES-CCM with RSA/DHE/PSK key exchange.
	0xC09C: "TLS_RSA_WITH_AES_128_CCM",
	0xC09D: "TLS_RSA_WITH_AES_256_CCM",
	0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
	0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
	0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
	0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8",
	0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
	0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
	0xC0A4: "TLS_PSK_WITH_AES_128_CCM",
	0xC0A5: "TLS_PSK_WITH_AES_256_CCM",
	0xC0A6: "TLS_DHE_PSK_WITH_AES_128_CCM",
	0xC0A7: "TLS_DHE_PSK_WITH_AES_256_CCM",
	0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8",
	0xC0A9: "TLS_PSK_WITH_AES_256_CCM_8",
	0xC0AA: "TLS_PSK_DHE_WITH_AES_128_CCM_8",
	0xC0AB: "TLS_PSK_DHE_WITH_AES_256_CCM_8",

	// RFC 7251 — AES-CCM with ECDHE_ECDSA. 0xC0AE is the CSIP-mandatory suite.
	0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
	0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
	0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
	0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",

	// RFC 7905 — ChaCha20-Poly1305.
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAB: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAD: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	0xCCAE: "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",

	// RFC 8442 — ECDHE_PSK with AEAD.
	0xD001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
	0xD002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	0xD003: "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
	0xD005: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
}
