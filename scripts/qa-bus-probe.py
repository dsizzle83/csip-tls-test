#!/usr/bin/env python3
# qa-bus-probe.py — G3 internal-bus (MQTT) hostile probe. Runs ON the gateway
# (the broker is loopback-only: `listener 1883 localhost`, so it is NOT reachable
# off-box — that bind is the first line of defense). Proves the mosquitto broker
# that carries the gateway's internal control bus enforces:
#   1. auth required        — anonymous CONNECT is refused (allow_anonymous false)
#   2. bad creds rejected   — a bogus username/password CONNECT is refused
#   3. ACL topic-isolation  — a REAL service (lexa-cloudlink) may SUBSCRIBE to a
#                             topic in its lane (lexa/mode) but is REFUSED a lane
#                             it does not own (lexa/desired/#, lexa-mode's), and
#                             NO message from the refused lane is ever delivered
# Pure stdlib (busybox board has no MQTT CLI).
#
# Exit 0 = every invariant held. 1 = an invariant was VIOLATED. 2 = the probe
# could not DECIDE (the broker said nothing where an answer was required, or the
# deployment does not match what this probe assumes). 2 is deliberately not the
# same as 0: an undecided isolation check is not evidence of isolation.
#
#
# ── WHAT A SUBACK CAN AND CANNOT PROVE (read before trusting a PASS) ─────────
#
# This probe speaks MQTT 3.1.1 on a raw socket, so unlike a paho/mosquitto_sub
# caller it CAN see the per-filter SUBACK return code, which is the only place
# on the wire a broker states its subscribe decision. Two things follow, and the
# earlier version of this file asserted the first while quietly getting the
# second wrong:
#
#   * A SUBACK return code IS the broker's grant decision. 0x00/0x01/0x02 is a
#     granted QoS; 0x80 is "failure", which for mosquitto with an acl_file means
#     the ACL refused this filter for this user. (0x87 "not authorized" is an
#     MQTT 5 reason code. This probe sends a v3.1.1 CONNECT — protocol level 4 —
#     so a v5-only code cannot appear here and is not tested for. If this probe
#     is ever taught MQTT 5, that is the code to add.)
#
#   * A SUBACK is NOT proof that messages flow. It is the broker's word about a
#     filter at subscribe time; a subscription can be granted and still deliver
#     nothing (wrong filter, wrong bridge, a broker that answers and forgets).
#     The ONLY end-to-end proof a subscription is live is receiving a message on
#     it, so this probe now watches for deliveries in BOTH directions:
#       - in lane:  a message arriving proves the grant is real (LIVE). The
#                   gateway's control plane is retained-state driven
#                   (systemd/mosquitto/lexa.conf), so a granted lexa/mode
#                   subscription gets the retained mode document immediately.
#       - out lane: any message arriving is a LEAK and fails the probe on its
#                   own, whatever the SUBACK said. This is the property that
#                   actually matters — a return code is a promise, a delivered
#                   payload is a breach.
#
# ── THE READ BUG THIS REPLACES (why the old PASS was not evidence) ───────────
#
# The previous _suback_rc() sent a SUBSCRIBE and read exactly ONE packet, then
# treated "not a SUBACK" as "the broker disconnected us, which is mosquitto's
# stricter form of an ACL refusal". Neither half held:
#
#   * The next packet after the second SUBSCRIBE is usually NOT its SUBACK. The
#     first (in-lane, GRANTED) subscription earns the retained lexa/mode
#     document, which arrives on the same socket and gets read as the answer to
#     the out-of-lane SUBSCRIBE. Not a SUBACK -> scored as a disconnect ->
#     scored as the ACL acting -> PASS. On the live bench, where lexa/mode is
#     retained by design, that was the LIKELY path: the out-of-lane check
#     reported success without ever seeing the broker's answer to it.
#   * mosquitto's default answer to an ACL-denied SUBSCRIBE from a v3.1.1 client
#     is SUBACK 0x80, not a disconnect. The disconnect branch was the loose one,
#     and it was the branch a retained message walked straight into.
#   * A silent broker raised socket.timeout out of recv() and killed the script
#     with a traceback and exit 1 — reported as a FAILED invariant rather than
#     an undecided one.
#
# So: packets are now dispatched (PUBLISHes recorded, PINGRESP/UNSUBACK ignored)
# until the SUBACK whose packet identifier MATCHES the SUBSCRIBE we sent; a
# closed socket is proven by EOF and nothing else; and a timeout is INCONCLUSIVE.
#
# ── WHAT IS STILL NOT OBSERVABLE FROM HERE ───────────────────────────────────
#
#   * "No leak observed" is only as strong as the traffic available to leak. If
#     nothing is retained under the out-of-lane filter (a fresh boot with no
#     desired documents yet), a granted subscription would deliver nothing
#     either, and the leak check proves nothing — it is reported as OBSERVED /
#     NOT OBSERVED, never as an independent pass, and the SUBACK is what decides
#     that lane. The reverse is not symmetric: an observed leak is conclusive.
#   * This probe judges ONE subject against ONE in-lane and ONE out-of-lane
#     filter. It is a spot check on the ACL, not a proof of the whole matrix;
#     the deployed ACL file is the authority, and scripts/gw-qa-bus.sh
#     cross-checks this probe's two filters against it before believing either
#     verdict.
#   * Nothing here observes the WRITE side of the ACL. A subject that cannot
#     subscribe to a lane may still be able to publish into it; that needs its
#     own probe.

import os
import socket
import struct
import sys
import time

# Verdict statuses, worst-last: the run's exit code is decided by the worst one.
PASS, INCONCLUSIVE, FAIL = "PASS", "INCONCLUSIVE", "FAIL"
_RANK = {PASS: 0, INCONCLUSIVE: 1, FAIL: 2}
_EXIT = {PASS: 0, INCONCLUSIVE: 2, FAIL: 1}

# MQTT control packet types (high nibble of byte 0).
_CONNACK, _PUBLISH, _SUBACK = 2, 3, 9


class Closed(Exception):
    """The peer closed the connection. Distinct from Timeout on purpose: a
    close is an observed act by the broker, a timeout is the absence of one."""


class Timeout(Exception):
    """Nothing arrived inside the window. Never evidence of a decision."""


def _mkstr(b):
    return struct.pack("!H", len(b)) + b


def _remlen(n):
    """MQTT's variable-length "remaining length" encoding. Our packets fit in
    one byte today; encoding it properly costs three lines and removes a
    silent corruption the day a filter or credential grows past 127 bytes."""
    out = b""
    while True:
        d = n % 128
        n //= 128
        out += bytes([d | (0x80 if n > 0 else 0)])
        if n == 0:
            return out


def topic_matches(filt, topic):
    """MQTT filter matching (+ single level, # multi level), enough for the
    filters this probe subscribes. Used to attribute a delivered PUBLISH to the
    lane it arrived on — which is what makes the leak check specific."""
    fs, ts = filt.split("/"), topic.split("/")
    for i, f in enumerate(fs):
        if f == "#":
            return True
        if i >= len(ts):
            return False
        if f != "+" and f != ts[i]:
            return False
    return len(ts) == len(fs)


class Session:
    """One live MQTT connection, with a packet dispatcher.

    Every read goes through pump(), which records PUBLISH deliveries as it
    goes. That is the whole point: deliveries are evidence (liveness in lane, a
    leak out of lane), so they must never be consumed as if they were the
    answer to a SUBSCRIBE."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""
        self.deliveries = []  # [(topic, payload_len)] in arrival order

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    # ── wire ────────────────────────────────────────────────────────────────
    def _recv(self, n, deadline):
        while len(self.buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Timeout()
            self.s.settimeout(remaining)
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                raise Timeout()
            except OSError:
                raise Closed()
            if not chunk:
                raise Closed()
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_packet(self, deadline):
        b0 = self._recv(1, deadline)[0]
        mult, rl = 1, 0
        for _ in range(4):  # remaining length is at most 4 bytes
            d = self._recv(1, deadline)[0]
            rl += (d & 0x7F) * mult
            if not (d & 0x80):
                break
            mult *= 128
        body = self._recv(rl, deadline) if rl else b""
        return b0 >> 4, b0 & 0x0F, body

    def _note_publish(self, flags, body):
        if len(body) < 2:
            return None
        tlen = struct.unpack("!H", body[:2])[0]
        topic = body[2:2 + tlen].decode("utf-8", "replace")
        rest = body[2 + tlen:]
        if (flags >> 1) & 0x03:  # QoS > 0 carries a packet identifier
            rest = rest[2:]
        self.deliveries.append((topic, len(rest)))
        return topic

    def send(self, pkt):
        self.s.sendall(pkt)

    # ── dispatch ────────────────────────────────────────────────────────────
    def pump(self, deadline, want_pid=None, stop_on=None):
        """Read packets until one of:
             ("suback", rc)      the SUBACK for want_pid (or any, if None)
             ("delivered", topic) a PUBLISH matching the stop_on filter
             ("closed", None)     the broker closed the connection
             ("timeout", None)    the deadline passed with no such answer
        PUBLISHes are always recorded before anything else is decided."""
        while True:
            try:
                ptype, flags, body = self._read_packet(deadline)
            except Closed:
                return ("closed", None)
            except Timeout:
                return ("timeout", None)
            if ptype == _PUBLISH:
                topic = self._note_publish(flags, body)
                if stop_on is not None and topic is not None and topic_matches(stop_on, topic):
                    return ("delivered", topic)
                continue
            if ptype == _SUBACK:
                if len(body) < 3:
                    continue  # malformed; keep reading rather than guess
                pid = struct.unpack("!H", body[:2])[0]
                if want_pid is not None and pid != want_pid:
                    continue  # somebody else's answer — not ours to read
                return ("suback", body[2])  # one filter per SUBSCRIBE here
            # PINGRESP, UNSUBACK, anything else: not evidence either way.

    def subscribe(self, topic, pid, deadline):
        """Send a QoS-0 SUBSCRIBE for exactly one filter and return pump()'s
        classification of the broker's answer to THIS packet identifier."""
        payload = struct.pack("!H", pid) + _mkstr(topic) + bytes([0])
        self.send(bytes([0x82]) + _remlen(len(payload)) + payload)
        return self.pump(deadline, want_pid=pid)

    def observe(self, seconds, stop_on=None):
        """Watch the socket for `seconds`, recording deliveries. Returns the
        first delivery matching stop_on, or None."""
        deadline = time.monotonic() + seconds
        kind, detail = self.pump(deadline, want_pid=None, stop_on=stop_on)
        return detail if kind == "delivered" else None

    def deliveries_matching(self, filt):
        return [t for (t, _) in self.deliveries if topic_matches(filt, t)]


def connect(host, port, user=None, pw=None, cid=b"qa-bus-probe", timeout=5.0):
    """Open one MQTT 3.1.1 CONNECT. Returns (connack_rc, Session|None); rc is
    None when the broker closed the connection without answering at all."""
    flags = 0x02  # clean session
    payload = _mkstr(cid)
    if user is not None:
        flags |= 0x80
        payload += _mkstr(user)
        if pw is not None:
            flags |= 0x40
            payload += _mkstr(pw)
    body = _mkstr(b"MQTT") + bytes([4, flags]) + struct.pack("!H", 30) + payload
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None, None
    sess = Session(sock)
    try:
        sess.send(bytes([0x10]) + _remlen(len(body)) + body)
        ptype, _, cbody = sess._read_packet(time.monotonic() + timeout)
    except (Closed, Timeout, OSError):
        sess.close()
        return None, None
    if ptype != _CONNACK or len(cbody) < 2:
        sess.close()
        return None, None
    return cbody[1], sess


def check_lane_isolation(host, port, user, pw, in_lane, out_lane, wait):
    """The ACL topic-isolation invariant, as evidence rather than assertion.

    Returns (status, [printable lines]). Split out from main() so the self-test
    can drive it against scripted brokers — every classification below has a
    case there, including the two the old one-packet read got wrong."""
    lines = []
    rc, sess = connect(host, port, user.encode(), pw.encode())
    lines.append("3. %-28s -> CONNACK rc=%s (want 0; valid service cred)" % (user + " CONNECT", rc))
    if rc != 0 or sess is None:
        lines.append("   cannot probe the lanes without a session for %s" % user)
        return INCONCLUSIVE, lines
    try:
        # ── in lane: granted, and (ideally) proven live by a delivery ───────
        kind, rcode = sess.subscribe(in_lane.encode(), 1, time.monotonic() + wait)
        if kind != "suback":
            lines.append("   SUB %-22s -> %s before any SUBACK — the broker never stated a "
                         "decision, so neither can this probe" % (in_lane + " (in lane)", kind.upper()))
            return INCONCLUSIVE, lines
        if rcode not in (0x00, 0x01, 0x02):
            lines.append("   SUB %-22s -> SUBACK=0x%02x (REFUSED). This deployment's ACL is "
                         "narrower than this probe assumes: a subject that cannot read its own "
                         "lane cannot demonstrate lane ISOLATION. Not a defect — an assumption "
                         "mismatch. Fix the probe's in-lane filter, or the grant."
                         % (in_lane + " (in lane)", rcode))
            return INCONCLUSIVE, lines
        live = sess.observe(wait, stop_on=in_lane)
        lines.append("   SUB %-22s -> SUBACK=0x%02x (granted), delivery: %s"
                     % (in_lane + " (in lane)", rcode,
                        ("LIVE — %s received" % live) if live else
                        "NOT OBSERVED in %.1fs (grant is the broker's word only; a retained "
                        "document may simply not exist yet)" % wait))

        # ── out of lane: refused, and nothing delivered ─────────────────────
        kind, rcode = sess.subscribe(out_lane.encode(), 2, time.monotonic() + wait)
        status = PASS
        if kind == "suback" and rcode == 0x80:
            lines.append("   SUB %-22s -> SUBACK=0x80 (refused by the ACL)" % (out_lane + " (OUT lane)"))
        elif kind == "closed":
            lines.append("   SUB %-22s -> broker CLOSED the connection (EOF observed, not "
                         "inferred) — a refusal stricter than 0x80" % (out_lane + " (OUT lane)"))
            return status, lines  # no socket left to watch for a leak
        elif kind == "suback":
            lines.append("   SUB %-22s -> SUBACK=0x%02x (GRANTED). The subject holds a read grant "
                         "on a lane it does not own." % (out_lane + " (OUT lane)", rcode))
            status = FAIL
        else:
            lines.append("   SUB %-22s -> %s: no SUBACK and no close inside %.1fs. Silence is not "
                         "a refusal — undecided." % (out_lane + " (OUT lane)", kind.upper(), wait))
            return INCONCLUSIVE, lines

        leaked = sess.deliveries_matching(out_lane)
        if not leaked:
            sess.observe(wait, stop_on=out_lane)
            leaked = sess.deliveries_matching(out_lane)
        if leaked:
            lines.append("   LEAK: %d message(s) from the refused lane were DELIVERED: %s. "
                         "Whatever the SUBACK said, data crossed the lane." % (len(leaked), ", ".join(leaked[:4])))
            status = FAIL
        else:
            lines.append("   no out-of-lane delivery in %.1fs%s" % (
                wait,
                "" if status == FAIL else
                " (corroborating, not independent: with nothing retained under this filter a "
                "GRANTED subscription would also deliver nothing)"))
        return status, lines
    finally:
        sess.close()


def main(argv):
    host = os.environ.get("BUS_PROBE_HOST", "127.0.0.1")
    port = int(os.environ.get("BUS_PROBE_PORT", "1883"))
    user = os.environ.get("BUS_PROBE_USER", "lexa-cloudlink")
    in_lane = os.environ.get("BUS_PROBE_IN_LANE", "lexa/mode")
    # lexa/desired/# rather than one leaf: the leak check needs a filter that
    # WOULD deliver something if the ACL let it, and lexa-mode retains its
    # desired documents under lexa/desired/<class>/<device>.
    out_lane = os.environ.get("BUS_PROBE_OUT_LANE", "lexa/desired/#")
    wait = float(os.environ.get("BUS_PROBE_WAIT", "2.0"))

    worst = PASS

    def record(status):
        return status if _RANK[status] > _RANK[worst] else worst

    rc, sess = connect(host, port)  # anonymous
    if sess:
        sess.close()
    print("1. anonymous CONNECT           -> rc=%s (want !=0 or no CONNACK; 5=not authorized)" % rc)
    worst = record(PASS if rc != 0 else FAIL)

    rc, sess = connect(host, port, b"attacker", b"nope")
    if sess:
        sess.close()
    print("2. bogus-cred CONNECT          -> rc=%s (want !=0 or no CONNACK)" % rc)
    worst = record(PASS if rc != 0 else FAIL)

    pw = argv[1] if len(argv) > 1 else ""
    if pw:
        status, lines = check_lane_isolation(host, port, user, pw, in_lane, out_lane, wait)
        for ln in lines:
            print(ln)
        print("   lane isolation: %s" % status)
        worst = record(status)
    else:
        print("3. (ACL-isolation check NOT RUN — no service password supplied)")
        worst = record(INCONCLUSIVE)

    print("BUS-PROBE:", worst)
    return _EXIT[worst]


# ── self-test ────────────────────────────────────────────────────────────────
#
# Every classification above, driven against a scripted broker on loopback. The
# cases marked "old probe scored this PASS" are the ones that make this file
# worth changing: they are indistinguishable from a real refusal to a reader
# that consumes one packet and calls anything-but-a-SUBACK a disconnect.

def _selftest():
    import threading

    class FakeBroker(threading.Thread):
        """Answers one client from a script keyed by SUBSCRIBE packet id.
        Actions: ("suback", rc) | ("publish", topic) | ("close",) | ("silent",)"""

        def __init__(self, script, connack=0):
            threading.Thread.__init__(self, daemon=True)
            self.script, self.connack = script, connack
            self.srv = socket.socket()
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv.bind(("127.0.0.1", 0))
            self.srv.listen(1)
            self.port = self.srv.getsockname()[1]

        def run(self):
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            sess = Session(conn)
            try:
                sess._read_packet(time.monotonic() + 5)  # CONNECT
                conn.sendall(bytes([0x20, 0x02, 0x00, self.connack]))
                if self.connack != 0:
                    return
                while True:
                    ptype, _, body = sess._read_packet(time.monotonic() + 5)
                    if ptype != 8:  # SUBSCRIBE
                        continue
                    pid = struct.unpack("!H", body[:2])[0]
                    for act in self.script.get(pid, [("silent",)]):
                        if act[0] == "suback":
                            conn.sendall(bytes([0x90, 0x03]) + struct.pack("!H", pid) + bytes([act[1]]))
                        elif act[0] == "publish":
                            topic = act[1].encode()
                            payload = b"{}"
                            body2 = _mkstr(topic) + payload
                            conn.sendall(bytes([0x31]) + _remlen(len(body2)) + body2)
                        elif act[0] == "close":
                            conn.close()
                            return
            except (Closed, Timeout, OSError, IndexError, struct.error):
                pass
            finally:
                sess.close()
                self.srv.close()

    IN, OUT = "lexa/mode", "lexa/desired/#"
    cases = [
        ("refused with SUBACK 0x80",
         {1: [("suback", 0x00)], 2: [("suback", 0x80)]}, PASS, "refused by the ACL"),
        ("refused, with the in-lane retained document arriving first "
         "(old probe read that PUBLISH as the out-lane answer)",
         {1: [("suback", 0x00), ("publish", "lexa/mode")], 2: [("suback", 0x80)]}, PASS, "LIVE"),
        ("GRANTED out of lane and delivering desired documents "
         "(old probe scored this PASS)",
         {1: [("suback", 0x00), ("publish", "lexa/mode")],
          2: [("suback", 0x00), ("publish", "lexa/desired/battery/bat-704")]}, FAIL, "LEAK"),
        ("GRANTED out of lane with nothing retained to leak",
         {1: [("suback", 0x00)], 2: [("suback", 0x00)]}, FAIL, "GRANTED"),
        ("refused by an outright close",
         {1: [("suback", 0x00)], 2: [("close",)]}, PASS, "CLOSED"),
        ("broker silent on the out-of-lane SUBSCRIBE (old probe: traceback)",
         {1: [("suback", 0x00)], 2: [("silent",)]}, INCONCLUSIVE, "Silence is not"),
        ("in-lane grant missing — assumption mismatch, not a defect",
         {1: [("suback", 0x80)]}, INCONCLUSIVE, "narrower than this probe assumes"),
    ]

    failures = 0
    for name, script, want, want_sub in cases:
        b = FakeBroker(script)
        b.start()
        status, lines = check_lane_isolation("127.0.0.1", b.port, "lexa-cloudlink", "pw", IN, OUT, 0.25)
        text = "\n".join(lines)
        ok = status == want and want_sub in text
        failures += 0 if ok else 1
        # The case NAME carries the reasoning (which broker behaviour, and which
        # of them the old one-packet read got wrong), so it is printed whole.
        print("%-4s %s  [got=%s want=%s]" % ("ok" if ok else "FAIL", name, status, want))
        if not ok:
            print(text)
    print("SELFTEST:", "PASS" if failures == 0 else "FAIL (%d)" % failures)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        sys.exit(_selftest())
    sys.exit(main(sys.argv))
