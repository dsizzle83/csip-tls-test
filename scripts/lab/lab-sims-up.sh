#!/usr/bin/env bash
# lab-sims-up.sh — the simulators for the lexa-gw LOCAL development loop.
#
#   scripts/lab/lab-sims-up.sh [up|down|status|reset]
#
# ── WHY THIS DOES NOT JUST CALL scripts/bench-sims-up.sh ───────────────────
#
# It was written to, and could not. bench-sims-up.sh hardcodes the two SIMAPI
# ports (modsim 6020, mbapsdev 6031) — they are not env-overridable, and
# sim/simapi binds the wildcard address, so they cannot be separated by address
# either. A developer host that is ALSO serving the bench board already holds
# 5020/6020/8021/6031/11113/11114, and a lab that reused them would either fail
# to start or, worse, silently attach the local loop to the sims a live bench
# campaign is grading. So the lab runs its own set on its own port block.
#
# The LAUNCH POSTURE is bench-sims-up.sh's, knob for knob and default for
# default — same env var names, same evidence-grade values — because the whole
# value of the lab is that a verdict here means the same thing as a verdict
# there. Every one of these is load-bearing:
#
#   *-keylog builds + SIMS_KEYLOG   without them the capture cannot be
#                     decrypted and every citation-dependent case loses its
#                     transcript.
#   GRIDSIM_NO_TICKETS / MBAPS_NO_TICKETS   force a FULL mTLS handshake on
#                     every gateway dial. A resumed TLS 1.3 handshake carries no
#                     Certificate message (RFC 8446 §2.2), so without this
#                     RBAC-011 and every client-certificate citation is
#                     unavailable.
#   GRIDSIM_IDLE_S=30 closes idle CSIP sessions, so each poll is its own
#                     observable session instead of one spanning the whole run.
#   GRIDSIM_POLL_S=60 advertises a uniform pollRate. WITHOUT IT the built-ins
#                     apply (300 /dcap, 900 /tm, 60 control lists) and a
#                     poll_rate_mode=honor DUT paces its WHOLE walk at 900 s, so
#                     every wait-for-fetch case times out. Omitting it once
#                     collapsed 64 of 79 CSIP verdicts.
#   SIM_FLEET=2       one configured DER — the frozen RC0 single-DER scope and
#                     the audit's one-to-one topology. mbapsdev still runs: the
#                     DUT does not dial it in this profile, but certify's own
#                     -mbapsdev rows do.
#   no aggregator     the lab's DUT listens on the product's own :802 (the host
#                     sysctl grants it; see lexa-gw scripts/lab/lib.sh), so the
#                     old "wrong port" reason is gone — but the loop is still
#                     NOT started here. It is a second northbound controller
#                     writing the same DER a case is measuring, and every
#                     register observed under two writers is a fact about two
#                     writers. Its GW_HOST also defaults to the bench board.
#
# ── ADDRESSES ──────────────────────────────────────────────────────────────
# sims 127.0.0.20, DUT 127.0.0.2, harness 127.0.0.1. Distinct addresses are not
# cosmetic: certify decides a captured frame's direction by comparing its source
# against the DUT's address, and on 127.0.0.1-for-everything every frame looks
# like it came from the DUT.
#
# `reset` is a full down/up, deliberately: the audit's Layer 2 forbids sharing
# authority, tickets, event history or register state between profiles, and the
# only way to be certain is a fresh process, not an admin poke.
#
# Processes are stopped by PID FILE ONLY, never `pkill` by name — this host runs
# the same binaries for the bench and for other agents' worktrees.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$HERE"

LAB="${LAB:-$HOME/.lexa-lab}"
SIM_ADDR="${LAB_SIM_ADDR:-127.0.0.20}"
LOG="${LAB_SIMS_LOG:-$LAB/log/sims}"

# The lab port block. Deliberately disjoint from the bench's (5020/6020/8021/
# 6031/11113/11114) so both can run on one host at the same time.
GRIDSIM_PORT="${GRIDSIM_PORT:-21113}"
GRIDSIM_ADMIN="${GRIDSIM_ADMIN:-21114}"
MODSIM_PORT="${MODSIM_PORT:-15020}"
MODSIM_API="${MODSIM_API:-16020}"
MBAPS_PORT="${MBAPS_PORT:-18021}"
MBAPSDEV_API="${MBAPSDEV_API:-16031}"

SIM_FLEET="${SIM_FLEET:-2}"
GRIDSIM_NO_TICKETS="${GRIDSIM_NO_TICKETS:-1}"
MBAPS_NO_TICKETS="${MBAPS_NO_TICKETS:-1}"
GRIDSIM_IDLE_S="${GRIDSIM_IDLE_S:-30}"
GRIDSIM_POLL_S="${GRIDSIM_POLL_S:-60}"
SIMS_KEYLOG="${SIMS_KEYLOG:-$LAB/run/lab-sims.keylog}"
# The census device serves the FULL DER model set (707-710 trip models on top
# of the 7xx set), matching bench-sims-up.sh's CENSUS_DER_MODELS default — the
# reduced fixture was being measured as a product gap it never was.
DER_MODELS="${DER_MODELS:-full}"
MODSIM_WMAX="${MODSIM_WMAX:-8000}"
# 2000 W, not 6000: internal/authority's LXR-013 reserves an uncontrollable
# device's FULL nameplate out of the site ceiling, and a 6000 W second device
# alone exceeds the 5000 W DERP-SP-001 default, zeroing every controllable
# device's budget. bench-sims-up.sh carries the same value and the same reason.
MBAPS_WMAX="${MBAPS_WMAX:-2000}"
MODSIM_SERIAL="${MODSIM_SERIAL:-LAB-MODSIM-01}"
MBAPS_SERIAL="${MBAPS_SERIAL:-LAB-MBAPS-01}"

WOLFSSL_SYSROOT="${WOLFSSL_SYSROOT:-$HOME/.local/wolfssl-amd64}"
WOLFSSL_KEYLOG_SYSROOT="${WOLFSSL_KEYLOG_SYSROOT:-$HOME/.local/wolfssl-amd64-keylog}"
export CGO_CFLAGS="${CGO_CFLAGS:--I$WOLFSSL_SYSROOT/include}"
export CGO_LDFLAGS="${CGO_LDFLAGS:--L$WOLFSSL_SYSROOT/lib -lm}"

M="$HERE/certs/mbaps"
mkdir -p "$LOG" "$(dirname "$SIMS_KEYLOG")"

note() { printf '   %s\n' "$*"; }
fail() { printf 'FATAL %s\n' "$*" >&2; exit 1; }

build_sims() {
	[ -x bin/modsim ] || { note "building bin/modsim"; go build -o bin/modsim ./sim/modsim; }
	if [ -d "$WOLFSSL_KEYLOG_SYSROOT/include" ]; then
		[ -x bin/server-keylog ] || { note "building bin/server-keylog"; make -s server-keylog; }
		[ -x bin/mbapsdev-keylog ] || { note "building bin/mbapsdev-keylog"; make -s mbapsdev-keylog; }
		GRIDSIM_BIN="${GRIDSIM_BIN:-./bin/server-keylog}"
		MBAPS_BIN="${MBAPS_BIN:-./bin/mbapsdev-keylog}"
	else
		echo "lab-sims: no keylog sysroot at $WOLFSSL_KEYLOG_SYSROOT — falling back to the plain sims." >&2
		echo "          Captured TLS will NOT decrypt; every citation-dependent case loses its" >&2
		echo "          transcript. Build it once: bash scripts/build-wolfssl-keylog-sysroot.sh" >&2
		[ -x bin/server ] || make -s build-server
		[ -x bin/mbapsdev ] || make -s build-mbapsdev
		GRIDSIM_BIN="${GRIDSIM_BIN:-./bin/server}"
		MBAPS_BIN="${MBAPS_BIN:-./bin/mbapsdev}"
	fi
}

# port_holder PORT — pid of any listener on PORT (address-blind: the lab claims
# whole ports, and a wildcard listener elsewhere on this host would shadow a
# lab bind).
# No `| head -1`: this script runs under `pipefail`, and a `head` that exits
# early makes its upstream die of SIGPIPE, which pipefail reports as a failed
# pipeline. awk consumes its input and prints the first match instead.
port_holder() {
	ss -tlnpH "sport = :$1" 2>/dev/null |
		awk 'match($0, /pid=[0-9]+/) && !done { print substr($0, RSTART+4, RLENGTH-4); done=1 }'
}

start() { # name port cmd...
	local name="$1" port="$2"; shift 2
	local pf="$LOG/$name.pid" holder
	holder="$(port_holder "$port" || true)"
	if [ -n "$holder" ]; then
		if [ -f "$pf" ] && [ "$holder" = "$(cat "$pf" 2>/dev/null)" ]; then
			note "= $name already running (pid $holder, :$port)"; return 0
		fi
		fail "$name NOT started — :$port is held by pid $holder ($(ps -o args= -p "$holder" 2>/dev/null | cut -c1-70)). The lab port block must be free; override with ${name^^}_PORT."
	fi
	"$@" >"$LOG/$name.log" 2>&1 &
	echo $! >"$pf"
	sleep 0.4
	if kill -0 "$(cat "$pf")" 2>/dev/null; then
		note "+ started $name  pid=$(cat "$pf")  :$port  log=$LOG/$name.log"
	else
		note "!! $name exited immediately — $LOG/$name.log:"; tail -5 "$LOG/$name.log" | sed 's/^/       /'
		fail "$name failed to start"
	fi
}

sims_up() {
	for f in "$M/ca-cert.pem" "$M/dev-ca.pem" "$M/dev-server-cert.pem" "$M/dev-server-key.pem"; do
		[ -r "$f" ] || fail "missing $f — run 'make gen-mbaps-certs' ONCE (regenerating invalidates every gateway leaf already issued)"
	done
	build_sims
	echo "lab-sims: up on $SIM_ADDR   keylog -> $SIMS_KEYLOG   logs -> $LOG"

	start modsim "$MODSIM_PORT" ./bin/modsim \
		-port "$MODSIM_PORT" -bind "$SIM_ADDR" -api-port "$MODSIM_API" \
		-advanced -der-models "$DER_MODELS" -wmax "$MODSIM_WMAX" -serial "$MODSIM_SERIAL"

	local mbaps_args=(-listen "$SIM_ADDR:$MBAPS_PORT" -model inverter -wmax "$MBAPS_WMAX"
		-serial "$MBAPS_SERIAL" -api-port "$MBAPSDEV_API"
		-ca "$M/dev-ca.pem" -cert "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem")
	if [ "$MBAPS_NO_TICKETS" != 0 ]; then mbaps_args+=(-no-tickets); fi
	case "$MBAPS_BIN" in *keylog) mbaps_args+=(-keylog "$SIMS_KEYLOG") ;; esac
	start mbapsdev "$MBAPS_PORT" "$MBAPS_BIN" "${mbaps_args[@]}"

	local grid_args=(-listen "$SIM_ADDR:$GRIDSIM_PORT" -admin "$SIM_ADDR:$GRIDSIM_ADMIN"
		-ca "$M/ca-cert.pem" -cert-chain "$M/dev-server-cert.pem" -key "$M/dev-server-key.pem")
	if [ "$GRIDSIM_NO_TICKETS" != 0 ]; then grid_args+=(-no-tickets); fi
	if [ -n "$GRIDSIM_IDLE_S" ]; then grid_args+=(-idle-timeout-s "$GRIDSIM_IDLE_S"); fi
	if [ -n "$GRIDSIM_POLL_S" ]; then grid_args+=(-poll-rate-s "$GRIDSIM_POLL_S"); fi
	case "$GRIDSIM_BIN" in *keylog) grid_args+=(-keylog "$SIMS_KEYLOG") ;; esac
	if [ "$SIM_FLEET" = 4 ]; then grid_args+=(-fleet 4 -subscription); fi
	start gridsim "$GRIDSIM_PORT" "$GRIDSIM_BIN" "${grid_args[@]}"

	sims_status
	cat <<EOS

Point the lab at these with (lexa-gw/scripts/lab/lib.sh already defaults to them):
  LAB_GRIDSIM_PORT=$GRIDSIM_PORT LAB_GRIDSIM_ADMIN_PORT=$GRIDSIM_ADMIN
  LAB_MODSIM_PORT=$MODSIM_PORT LAB_MODSIM_API_PORT=$MODSIM_API
  LAB_MBAPSDEV_PORT=$MBAPS_PORT LAB_MBAPSDEV_API_PORT=$MBAPSDEV_API
EOS
}

sims_down() {
	local name pf pid
	echo "lab-sims: down"
	for name in gridsim mbapsdev modsim; do
		pf="$LOG/$name.pid"
		[ -f "$pf" ] || continue
		pid="$(cat "$pf" 2>/dev/null || true)"
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			for _ in $(seq 1 25); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
			if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid" 2>/dev/null || true; fi
			note "stopped $name (pid $pid)"
		fi
		rm -f "$pf"
	done
}

sims_status() {
	local name pf pid
	printf '   %-10s %-8s %s\n' SIM PID ENDPOINT
	for name in gridsim mbapsdev modsim; do
		pf="$LOG/$name.pid"; pid="-"
		if [ -f "$pf" ] && kill -0 "$(cat "$pf" 2>/dev/null || echo 0)" 2>/dev/null; then pid="$(cat "$pf")"; fi
		case "$name" in
		gridsim) printf '   %-10s %-8s https://%s:%s   admin http://%s:%s\n' "$name" "$pid" "$SIM_ADDR" "$GRIDSIM_PORT" "$SIM_ADDR" "$GRIDSIM_ADMIN" ;;
		modsim) printf '   %-10s %-8s tcp://%s:%s   api http://%s:%s\n' "$name" "$pid" "$SIM_ADDR" "$MODSIM_PORT" "$SIM_ADDR" "$MODSIM_API" ;;
		mbapsdev) printf '   %-10s %-8s mbaps://%s:%s   api http://%s:%s\n' "$name" "$pid" "$SIM_ADDR" "$MBAPS_PORT" "$SIM_ADDR" "$MBAPSDEV_API" ;;
		esac
	done
}

case "${1:-up}" in
up) sims_up ;;
down) sims_down ;;
status) sims_status ;;
reset) sims_down; sims_up ;;
-h | --help) sed -n '2,55p' "${BASH_SOURCE[0]}" ;;
*) echo "usage: $0 [up|down|status|reset]" >&2; exit 2 ;;
esac
