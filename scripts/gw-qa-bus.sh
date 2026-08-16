#!/usr/bin/env bash
# gw-qa-bus.sh — G3 internal-bus (MQTT) hostile-QA check. Runs the pure-stdlib
# probe qa-bus-probe.py ON the gateway (the broker is loopback-only, so it can
# only be reached on-box) and asserts the internal control bus is defended in
# depth:
#   (1) anonymous CONNECT refused,
#   (2) bogus-cred CONNECT refused,
#   (3) a real service is ACL-confined to its topic lane — its in-lane
#       SUBSCRIBE is GRANTED (and, when the lane has a retained document,
#       proven LIVE by receiving it), its out-of-lane SUBSCRIBE is REFUSED
#       (SUBACK 0x80, or a broker close observed as EOF), and NO message from
#       the out-of-lane filter is ever delivered.
#
# The bus is the gateway's INTERNAL control plane (reconcile reports, mode/
# intent, mbaps writes). Its first defense is that mosquitto binds
# `listener 1883 localhost` — NOT network-reachable — so this probe runs on the
# board over loopback; there is no off-box bus attack surface to drive from the
# desktop. Usage: scripts/gw-qa-bus.sh   (GW_SSH=cc93 by default)
#
# ── WHAT THIS CHECK PROVES, AND WHAT IT DOES NOT ─────────────────────────────
#
# The probe speaks raw MQTT 3.1.1, so it CAN read the per-filter SUBACK return
# code — the one place on the wire a broker states its subscribe decision. Two
# limits are worth stating here rather than in a report footnote, because an
# earlier version of this header asserted more than the probe could support:
#
#   * "Refused / disconnected" used to be treated as interchangeable evidence.
#     They are not. mosquitto's answer to an ACL-denied SUBSCRIBE from a v3.1.1
#     client is SUBACK 0x80; a CLOSE is a different, stricter act and is only
#     believed when the socket actually reaches EOF. Anything else — a packet
#     that is not a SUBACK, or silence — decides nothing and now exits 2
#     (INCONCLUSIVE), never 0. The old probe read a single packet after the
#     out-of-lane SUBSCRIBE and called anything-but-a-SUBACK a disconnect; on
#     this bench the packet it usually read was the RETAINED lexa/mode document
#     its own in-lane subscription had just earned, so the check reported PASS
#     without ever seeing the broker's answer. It scored a broker that GRANTED
#     the out-of-lane lane, and delivered from it, exactly the same as one that
#     refused it.
#
#   * A grant is the broker's word; a delivered message is the proof. The probe
#     therefore watches for deliveries on both filters: receiving one in lane is
#     LIVENESS, receiving one out of lane is a LEAK and fails on its own. There
#     is no active publish→receive loop, and that is a property of the ACL, not
#     an omission: systemd/mosquitto/acl is deny-by-default and single-writer,
#     so no subject holds both a read and a write grant on any one topic, and
#     forging a document onto a lane a live service consumes (lexa/mode, the
#     desired documents) would actuate the gateway. Receiving the retained
#     document a granted subscription is entitled to is the strongest end-to-end
#     evidence available without publishing into a live control plane.
#
# Exit: 0 = every invariant held. 1 = an invariant was VIOLATED. 2 = the check
# could not decide (unreachable board, missing credential, silent broker, or a
# deployment whose ACL does not match the lanes probed).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH="${GW_SSH:-cc93}"
PROBE="$HERE/scripts/qa-bus-probe.py"
[ -r "$PROBE" ] || { echo "missing $PROBE"; exit 2; }

# The subject and its two lanes. lexa-cloudlink is a good ACL subject: it may
# READ lexa/mode, while the whole lexa/desired/# family belongs to lexa-mode
# alone (single-writer) with no read grant for cloudlink anywhere. The OUT lane
# is the wildcard rather than one leaf on purpose — the leak check needs a
# filter that WOULD deliver something if the ACL let it, and lexa-mode retains
# a document per device under lexa/desired/<class>/<device>.
SUBJECT="${BUS_SUBJECT:-lexa-cloudlink}"
IN_LANE="${BUS_IN_LANE:-lexa/mode}"
OUT_LANE="${BUS_OUT_LANE:-lexa/desired/#}"
PASSFILE="${BUS_PASSFILE:-/etc/lexa/secrets/${SUBJECT#lexa-}-mqtt.pass}"
ACLFILE="${BUS_ACLFILE:-/etc/mosquitto/lexa-acl}"

echo "gw-qa-bus: probing the internal MQTT bus on $SSH (loopback broker)"
echo "gw-qa-bus: subject=$SUBJECT in-lane=$IN_LANE out-lane=$OUT_LANE"

# ── broker-side cross-check: read the DEPLOYED ACL ───────────────────────────
# The probe measures what the broker DOES; this reads what it was TOLD to do,
# from the file mosquitto actually loaded. It exists because a probe aimed at
# the wrong lane passes for the wrong reason: if the deployed ACL never granted
# the in-lane read, or already grants the out-of-lane one, the live result means
# something different from what it looks like.
#
# The out-of-lane test is a coarse prefix/wildcard test, not full MQTT filter
# covering — an exotic filter could cover the lane by a route this misses. That
# is why this is a CROSS-CHECK and the live probe is the evidence.
acl_rc=0
acl_block="$(ssh "$SSH" "sudo cat '$ACLFILE' 2>/dev/null || cat '$ACLFILE' 2>/dev/null" 2>/dev/null \
  | awk -v u="$SUBJECT" '$1=="user"{inb=($2==u); next} inb && $1=="topic"{print $2, $3}')"
if [ -z "$acl_block" ]; then
  echo "gw-qa-bus: ACL cross-check SKIPPED — $ACLFILE unreadable over ssh, or it declares no"
  echo "           block for user $SUBJECT. The live probe below still decides on its own."
else
  in_granted=0; out_granted=""
  out_prefix="${OUT_LANE%%[+#]*}"; out_prefix="${out_prefix%/}"
  while read -r verb filt; do
    case "$verb" in read|readwrite) ;; *) continue ;; esac
    [ "$filt" = "$IN_LANE" ] && in_granted=1
    case "$filt" in
      "#"|"lexa/#"|"$out_prefix"|"$out_prefix"/*) out_granted="$verb $filt" ;;
    esac
  done <<EOF
$acl_block
EOF
  if [ -n "$out_granted" ]; then
    echo "gw-qa-bus: ACL cross-check FAIL — the deployed ACL grants $SUBJECT '$out_granted',"
    echo "           which covers the out-of-lane filter $OUT_LANE. The lane is not confined"
    echo "           in configuration, whatever the live probe reports."
    acl_rc=1
  elif [ "$in_granted" = 0 ]; then
    echo "gw-qa-bus: ACL cross-check INCONCLUSIVE — the deployed ACL gives $SUBJECT no read"
    echo "           grant on $IN_LANE, so an in-lane refusal below would be correct behaviour"
    echo "           rather than a defect. Re-aim the probe at a lane this subject really owns."
    acl_rc=2
  else
    echo "gw-qa-bus: ACL cross-check OK — $SUBJECT is granted read $IN_LANE and nothing covering $OUT_LANE"
  fi
fi

# ── live probe on the board ──────────────────────────────────────────────────
scp -q "$PROBE" "$SSH:/tmp/qa-bus-probe.py" || {
  echo "gw-qa-bus: could not copy the probe to $SSH — nothing was measured"; exit 2; }
rc=0
ssh "$SSH" "PW=\$(cat '$PASSFILE' 2>/dev/null); \
  if [ -z \"\$PW\" ]; then echo \"$SUBJECT password not provisioned at $PASSFILE\" >&2; rm -f /tmp/qa-bus-probe.py; exit 2; fi; \
  BUS_PROBE_USER='$SUBJECT' BUS_PROBE_IN_LANE='$IN_LANE' BUS_PROBE_OUT_LANE='$OUT_LANE' \
  python3 /tmp/qa-bus-probe.py \"\$PW\"; r=\$?; rm -f /tmp/qa-bus-probe.py; exit \$r" || rc=$?
echo "gw-qa-bus: probe exit=$rc (0=pass 1=violated 2=undecided)"

# The run's verdict is the WORST of the two halves: a configuration finding is
# not cancelled by a live pass, and an undecided live probe is not upgraded by a
# clean-looking ACL file.
worst=0
for r in "$acl_rc" "$rc"; do
  case "$r" in
    1) worst=1 ;;
    2) [ "$worst" = 1 ] || worst=2 ;;
    0) ;;
    *) [ "$worst" = 1 ] || worst=2 ;;   # any other exit: undecided, never a pass
  esac
done
case "$worst" in
  0) echo "gw-qa-bus: PASS" ;;
  1) echo "gw-qa-bus: FAIL" ;;
  *) echo "gw-qa-bus: INCONCLUSIVE (nothing here says the bus is confined)" ;;
esac
exit "$worst"
