package gwmayhem

// linkfix.go imports internal/wolfssl directly so this package's test binary
// emits the wolfSSL cgo link flags in the same order as the mbtls/mbapsdev
// packages (which link the wolfSSL DH object cleanly). Without a direct import,
// -lm lands before -lwolfssl and the DH object's pow/log go unresolved once the
// net cgo resolver drags dh.o into the static link.
import _ "csip-tls-test/internal/wolfssl"
