#!/bin/bash

# Run this on the Raspberry Pi (Or any client) pointed at server
# running on desktop WSL.  Verify through Wireshark
printf 'GET /dcap HTTP/1.1\r\nHost: csip-test-server\r\n\r\n' | \
openssl s_client -connect 192.168.0.188:11111 \
  -cert ~/csip-tls-test/certs/client-cert.pem \
  -key ~/csip-tls-test/certs/client-key.pem \
  -CAfile ~/csip-tls-test/certs/ca-cert.pem \
  -cipher 'ECDHE-ECDSA-AES128-CCM8@SECLEVEL=0' \
  -tls1_2 \
  -servername csip-test-server