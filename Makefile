.PHONY: all build test test-fast test-integration test-update-golden gen-test-certs clean

TESTDATA := internal/tlsserver/testdata
CERTS    := $(TESTDATA)/certs
CA_CERT  := $(CERTS)/ca-cert.pem

all: build

# Build the server binary into ./bin/server
build:
	@mkdir -p bin
	go build -o bin/server ./server

# Fast unit tests — pure-Go logic only (route, golden file, edge cases).
# Still pulls cgo for compilation because the package as a whole has
# cgo files, but no TLS handshakes are performed at test time.
test-fast:
	go test ./internal/tlsserver/

# Full integration tests — real TLS handshakes against the test fixture
# certs. Requires that the certs have been generated; the dependency
# below auto-generates them on first run.
test-integration: $(CA_CERT)
	go test -tags=integration -v ./internal/tlsserver/

# Run the complete suite: unit + integration.
test: $(CA_CERT) test-fast test-integration

# Regenerate the DCAP golden file. Run after intentionally changing
# the DCAP XML format. Review the diff in testdata/golden/dcap.xml
# before committing.
test-update-golden:
	go test ./internal/tlsserver/ -args -update

# Manually regenerate the test cert fixtures. The integration test
# target depends on these existing, but you can run this directly to
# refresh them (e.g., if they expire).
gen-test-certs:
	bash $(TESTDATA)/gen-test-certs.sh

# Auto-generate certs on first run. Make's dependency tracking ensures
# this only happens when the cert is missing.
$(CA_CERT):
	@echo "Test certs missing — generating..."
	@bash $(TESTDATA)/gen-test-certs.sh

clean:
	rm -rf bin/
	rm -rf $(CERTS)/
