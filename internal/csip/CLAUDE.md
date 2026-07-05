# CSIP / IEEE 2030.5 Northbound Stack

**TASK-082 (2026-07-05):** the walker (`discovery/`) and scheduler (`scheduler/`) moved out
of this package to `internal/csipref/{discovery,scheduler}` — they are this repo's own
deliberately-independent implementation of the CSIP client-side logic (conformance referee
value; see `internal/csipref`'s own CLAUDE.md and AD-003(f) in
`docs/refactor/02_ARCHITECTURE_DECISIONS.md`). What remains here is identity + DNS-SD, which
are not part of that decision — they're the LFDI/SFDI derivation and mDNS browse that any
CSIP client (referee or product) needs, not spec-interpretation logic with a self-confirmation
hazard.

## Packages
```
identity/   LFDI = leftmost 160 bits of SHA-256(cert DER). SFDI = first 36 bits decimal.
dnssd/      mDNS browse for _ieee2030._tls._tcp. TXT "path=X" overrides /dcap default.
```

MUP (MirrorUsagePoint) telemetry flow moved to `internal/csipref/CLAUDE.md` along with the
walker — see there.

## DNS-SD
`dnssd.Browse(ctx)` returns `[]Server{Host, Port, DCAPPath}`.
Works Pi-to-Pi on a switch (mDNS multicast). Times out cleanly in WSL2 — use `--server` flag there.
