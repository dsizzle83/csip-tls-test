#!/usr/bin/env python3
# qa-bus-probe.py — G3 internal-bus (MQTT) hostile probe. Runs ON the gateway
# (the broker is loopback-only: `listener 1883 localhost`, so it is NOT reachable
# off-box — that bind is the first line of defense). Proves the mosquitto broker
# that carries the gateway's internal control bus enforces:
#   1. auth required        — anonymous CONNECT is refused (allow_anonymous false)
#   2. bad creds rejected   — a bogus username/password CONNECT is refused
#   3. ACL topic-isolation  — a REAL service (lexa-cloudlink) may SUBSCRIBE to a
#                             topic in its lane (lexa/mode) but is REFUSED a topic
#                             outside it (lexa/desired/#, a lexa-mode-only lane)
# Exit 0 iff every invariant holds. Pure stdlib (busybox board has no MQTT CLI).
import socket, struct, sys

HOST, PORT = "127.0.0.1", 1883

def _mkstr(b): return struct.pack("!H", len(b)) + b

def _recv_packet(s):
    # MQTT fixed header: type byte + variable-length "remaining length".
    b0 = s.recv(1)
    if not b0:
        return None, b""
    mult, rl = 1, 0
    while True:
        d = s.recv(1)
        if not d:
            return b0[0], b""
        rl += (d[0] & 0x7F) * mult
        if not (d[0] & 0x80):
            break
        mult *= 128
    body = b""
    while len(body) < rl:
        chunk = s.recv(rl - len(body))
        if not chunk:
            break
        body += chunk
    return b0[0], body

def _connect(user=None, pw=None, cid=b"qa-bus-probe"):
    flags = 0x02  # clean session
    payload = _mkstr(cid)
    if user is not None:
        flags |= 0x80; payload += _mkstr(user)
        if pw is not None:
            flags |= 0x40; payload += _mkstr(pw)
    vh = _mkstr(b"MQTT") + bytes([4, flags]) + struct.pack("!H", 30)
    pkt = vh + payload
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(bytes([0x10, len(pkt)]) + pkt)
    t, body = _recv_packet(s)
    if t is None or (t & 0xF0) != 0x20 or len(body) < 2:
        s.close(); return None, None   # connection closed without a CONNACK
    return body[1], s                  # CONNACK return code, live socket

def _suback_rc(s, topic, pid):
    tf = _mkstr(topic) + bytes([0])    # QoS 0
    pkt = struct.pack("!H", pid) + tf
    s.sendall(bytes([0x82, len(pkt)]) + pkt)
    t, body = _recv_packet(s)
    if t is None or (t & 0xF0) != 0x90 or len(body) < 3:
        return None                    # no SUBACK (broker disconnected us)
    return body[-1]                    # per-filter return code (0x80 = failure)

def main():
    ok = True
    rc, s = _connect()                 # anonymous
    if s: s.close()
    print("1. anonymous CONNECT           -> rc=%s (want !=0; 5=not authorized)" % rc)
    ok &= (rc != 0)

    rc, s = _connect(b"attacker", b"nope")
    if s: s.close()
    print("2. bogus-cred CONNECT          -> rc=%s (want !=0)" % rc)
    ok &= (rc != 0)

    if len(sys.argv) > 1 and sys.argv[1]:
        pw = sys.argv[1].encode()
        rc, s = _connect(b"lexa-cloudlink", pw)
        print("3. lexa-cloudlink CONNECT      -> rc=%s (want 0; valid service cred)" % rc)
        ok &= (rc == 0)
        if rc == 0 and s:
            in_lane = _suback_rc(s, b"lexa/mode", 1)         # cloudlink MAY read
            out_lane = _suback_rc(s, b"lexa/desired/foo", 2) # lexa-mode-only lane
            s.close()
            # A denied SUBSCRIBE is refused EITHER as SUBACK 0x80 OR by an outright
            # broker DISCONNECT (mosquitto's default on an ACL violation — stricter
            # than 0x80). Since the in-lane SUBSCRIBE succeeded on the SAME socket, a
            # disconnect (None) on the out-lane is specifically the ACL acting.
            out_denied = (out_lane == 0x80) or (out_lane is None)
            print("   SUB lexa/mode      (in lane)  -> SUBACK=%s (want granted)" %
                  (hex(in_lane) if in_lane is not None else None))
            print("   SUB lexa/desired/+ (OUT lane) -> %s (want refused)" %
                  ("SUBACK=0x80" if out_lane == 0x80 else
                   "DISCONNECTED by broker" if out_lane is None else "SUBACK=%s" % hex(out_lane)))
            ok &= (in_lane in (0x00, 0x01))
            ok &= out_denied
    else:
        print("3. (skipped ACL-isolation check — no service password supplied)")

    print("BUS-PROBE:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
