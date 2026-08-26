# simapi — the simulator control plane

**API version 1.1.0.** Every simulator binary in `sim/` embeds this HTTP +
WebSocket server. It is how a test, a GUI or a conformance row makes a
simulated device behave in a particular way, and how it finds out what the
device did.

`GET /version` reports the version and the endpoints *this* simulator
implements, so a caller can tell "this sim is too old" from "this sim does not
do that" — two different reasons for the same 501.

```
GET http://<sim>:6020/version
{"api_version":"1.1.0","endpoints":["GET /version","GET /state", …]}
```

Versioning is semantic: **MINOR** goes up when endpoints or fields are *added*
(a caller written against an older minor keeps working); **MAJOR** when an
existing endpoint's meaning changes.

| version | what landed |
|---|---|
| 1.0.0 | `/state` `/inject` `/control` `/fault` `/registers` `/ws` `/logs`; every mutation answered `204 No Content` |
| 1.1.0 | `/version` `/reset` `/ledger` `/poll` `/poll/wait`; mutations answer `{"api_version","epoch"}`; `POST /fault` gains `next_response` and `unit_id`; `POST /inject` gains `registers` / `clear_registers`, and `unimplemented` covers every SunSpec datatype |

---

## Why 1.1.0 exists: the epoch, and the end of the sleep

Every row of the SunSpec Modbus **client** conformance procedures has the same
shape — make the server do something, wait for the client under test to meet
it, judge what crossed the wire. The client is an autonomous gateway on its own
ticker; the bench cannot make it poll. Until 1.1.0 the middle step was
`time.Sleep(n * pollInterval)` and the last step was "search the capture for
anything that looks like it". Both are guesses, and a guess that is too short
judges a window the provocation never reached while one that is long enough to
be safe sweeps in the *next* row's traffic. Neither failure shows up in the
verdict.

1.1.0 replaces the guess with three primitives:

```
POST /reset                → {"epoch": 7}     the device is at a known baseline AS OF 7
POST /fault  {...}         → {"epoch": 8}     the provocation is in force AS OF 8
GET  /poll/wait?epoch=12   → {"reached":true} the client has finished poll cycle 12
GET  /ledger?since_epoch=8 → the transactions that happened under the provocation
```

**Nothing in this API sleeps.** `/poll/wait` blocks on the client's own
behaviour and on the caller's context, and on nothing else.

### The two counters both called "epoch"

There are two, they are unrelated, and the difference matters:

- **the control-plane epoch** — `POST /reset`, `POST /inject`, `POST /control`
  and `POST /fault` each return it, `GET /ledger?since_epoch=` fences on it. It
  is the simulator's *state version*: it increments once per **accepted**
  mutation. A refused request does not move it. The free-running animation does
  not move it either — deliberately, because a counter that advanced several
  times a second on its own could never be a fence.
- **the poll-cycle ordinal** — what `GET /poll/wait?epoch=N` waits for. The
  parameter is spelled `epoch` because that is the name the contract fixes;
  `poll` is accepted as the clearer synonym and means the same thing.

---

## Endpoints

### `GET /state`

JSON snapshot of the simulator's decoded state. Unchanged from 1.0.0.

### `POST /inject`

Override a value. Unchanged bodies keep working; three keys are worth knowing.

```jsonc
{"W_W": 4500.0, "Cloud_pct": 70}                 // classic field overrides
{"insert_model": {"id": 65000, "len": 4}}        // splice an unregistered model (ERR-3)
{"clear_insert_model": true}
{"unimplemented": [{"addr": 40190, "type": "int16"}]}   // seed a not-implemented sentinel
{"clear_unimplemented": true}
{"registers": [{"addr": 40234, "value": 5000}]}  // NEW in 1.1.0 — raw register poke
{"registers": [{"addr": 40234, "delta": -500}]}  //   …or move it by a raw delta
{"clear_registers": true}                        //   restore every poked address
```

**`unimplemented`** now covers **every** SunSpec datatype, not the eight it
shipped with:

```
int16 uint16 count acc16 enum16 bitfield16 sunssf pad
int32 uint32 acc32 enum32 bitfield32 ipaddr float32 eui48
int64 uint64 acc64 float64
string ipv6addr          (width from the optional "len"; string defaults to 1, ipv6addr to 8)
```

The words written are the SunSpec Device Information Model Specification's own
table (`sim/southbound/sentinel.go`). A seeded point is restored by
`{"clear_unimplemented":true}` or by `POST /reset`. Seeding a point the
animation actively updates is transient — pause the animation first
(`POST /control {"cmd":"pause"}`) or pick a static point.

**`registers`** is the raw poke. The caller names an **address**, not a field.
It exists because the write rows have to provoke the client into writing, and
the only provocation available is divergence: move the control register out
from under the client and see whether its reconciler puts it back. That works
only if the register moved is the one the client actually owns — and the
address is learned from the client's own traffic, out of the ledger's record of
its `FC 0x10` writes. Prior values are captured on first touch, so a re-poke
does not overwrite the true original and `clear_registers` always restores the
pristine contents.

`value` is a 16-bit word (negatives are two's-complement, so `-1200` means what
it says on a signed point); `delta` adds to whatever the register holds right
now. Exactly one of the two per entry.

### `POST /control`

`{"cmd":"pause"|"resume"|"reset"}`, `{"speed":N}`, `{"reversion_scale":N}`.
Unchanged from 1.0.0.

### `POST /fault`

Arm or clear a fault. Every simulator advertises its own kinds and refuses the
rest **by name**. Two kinds are new in 1.1.0, both served by the wire tap.

#### `next_response` — the one-shot

```jsonc
{"kind":"next_response","action":"drop",  "on_fc":3, "on_addr":[40070,40195]}
{"kind":"next_response","action":"short", "on_fc":3, "truncate_bytes":2}
{"kind":"next_response","action":"delay", "on_fc":3, "delay_ms":9000}
{"kind":"next_response","clear":true}
```

Everything else in the fault vocabulary arms a *condition* and waits for the
client to walk into it. This arms against the **next matching request**, so the
fault lands inside a transaction the bench can name — which is the difference
between PROT-1's provocation landing inside attributed traffic and landing in
the gap between two requests, where it spent every campaign to date.

- `action` (required): `drop` swallows the response and leaves the connection
  **open**, so the client waits out its own read timeout; `short` writes the
  MBAP header plus `truncate_bytes` of PDU while leaving the length field
  promising the rest; `delay` holds the response for `delay_ms` and then writes
  it in full.
- `on_fc` restricts the match to one function code (0 or absent = any).
- `on_addr` is `[start, end)` — the request must **overlap** it. One element
  means a single register; absent means any address.
- `delay_ms` is capped at 60 000: the response pump is serialised per
  connection, so a longer hold is a wedged bench rather than a fault.
- The arm is **consumed by the request that matches it**. The transaction after
  it is answered normally, which the acknowledgement's epoch lets you prove.

The acknowledgement's `epoch` is the fence: `GET /ledger?since_epoch=<that>`
returns exactly the transactions the one-shot could have touched.

#### `unit_id` — re-address the device

```jsonc
{"kind":"unit_id","unit_id":7}
{"kind":"unit_id","clear":true}
```

While armed the device answers **only** the given unit id and returns exception
`0x0B GATEWAY TARGET DEVICE FAILED TO RESPOND` to every other — exactly what a
Modbus/TCP gateway does for a unit it does not front, and the device behind the
gate never hears the request at all. This is §2.4.3 CLI-3's setup step ("run
Server 1 with a different Unit ID") as a runtime lever.

It is **not** the older `unit_id_confusion` fault, which makes the device refuse
every unit id including its own.

### `POST /reset` — a known device, and the epoch it is true from

```jsonc
{"baseline":"as-built"}
{"baseline":"as-built","poll_anchor":{"addr":40070,"count":125}}
{}                                              // as-built, anchor untouched
```

```jsonc
{
  "api_version": "1.1.0",
  "epoch": 12,
  "result": {
    "baseline": "as-built",
    "cleared": ["relocation → base 40000","targeted exception","not-implemented sentinels",
                "spliced model","poked registers","device faults (…)","wire-tap faults (…)",
                "poll-cycle accounting"],
    "baselines": ["as-built"],
    "poll_anchor": {"addr":40070,"count":125},
    "poll_anchor_source": "declared"
  }
}
```

A reset restores a **captured register image** — registers and write-protection
alike — and clears every fault layer first, in that order: a layer that owns
registers puts them back as it clears, and doing that after the image was
rewritten would land on top of it. `as-built` is captured at startup, after
every construction-time lever (`-base`, `-wmax-setting`, the model set, the
serial and firmware overrides) and before any client can dial in, so a reset
restores *this invocation's* device rather than some canonical one.

`cleared` is reported rather than assumed: "nothing is armed" is a claim a
conformance row relies on, so it belongs in the bundle rather than in the
reader's trust. An unknown baseline is refused with the names that do exist —
never a silent fall-back, which would leave a row measuring a device it did not
ask for and reporting the result as a product finding.

`poll_anchor` optionally **declares** the read that delimits a poll cycle (see
below) instead of letting the tap learn it. An all-zero value clears a
declaration and returns the tap to learning.

### `GET /poll` and `GET /poll/wait` — the barrier

```
GET /poll                               report now, block on nothing
GET /poll/wait?epoch=12&timeout=10s     block until poll cycle 12 has completed
GET /poll/wait?poll=12                  the same thing, spelled unambiguously
```

```jsonc
{
  "api_version": "1.1.0",
  "reached": true,
  "want": 12,
  "epoch": 8,
  "poll": {
    "completed": 12,
    "open": 13,
    "open_reads": 1,
    "open_pending": 0,
    "anchor": {"unit_id":1,"addr":40070,"count":125},
    "anchor_locked": true,
    "anchor_source": "learned",
    "sessions": 3,
    "abandoned": 1,
    "rule": "a poll cycle is the interval between two consecutive arrivals of the cycle anchor …"
  },
  "tap": {"connections":3,"requests":184,"responses":183,"dropped":1,"ledger_entries":184, …}
}
```

**`reached` is the answer, and the status is always 200.** "The client has not
polled yet" is an observation, not an endpoint failure. Each request bounds
itself with `timeout` (default 10 s, capped at 5 min; a bare number is read as
seconds, so `timeout=30` and `timeout=30s` agree), which keeps it well inside a
caller's own HTTP read timeout. A caller that needs longer loops on it. A caller
that disconnects cancels the wait immediately — the handler follows the request
context, not only its own timeout.

#### What a poll cycle *is*

> A poll cycle is the interval between two consecutive arrivals of the **cycle
> anchor** — the one read request the client repeats every cycle. Cycle *N* is
> **complete** when the anchor opening cycle *N+1* has arrived **and** every
> transaction of cycle *N* has been resolved at the sim's wire layer.

The second clause is what makes the barrier usable as a fence: when
`/poll/wait` returns for cycle *N*, every transaction of cycle *N* is already in
the ledger, and a caller can grade immediately with nothing still in flight.

The cost is inherent and worth stating: a cycle's completion is observable only
when the next one starts, so the barrier trails the client by up to one poll
interval. That is not a safety margin — it is the earliest instant at which
"the cycle contained nothing further" is a fact rather than a bet.

The rule is derived from what lexa-gw's southbound client actually does, with
citations in `sim/southbound/poll.go`. The load-bearing observations:

- **The model chain is not re-walked per cycle.** `lexa-proto/sunspec/reader.go`
  scans once and caches the block layout; the `SunS` probe at 40000/0/50000 and
  the id/length walk happen once per **TCP session**, at open and at every
  reconnect. A rule that waited for a chain walk would wait forever.
- **Exactly one measurement-model read happens every cycle**, at the block's
  cached base address, issued first, and it is the only read whose failure
  drops the session.
- **Everything else is conditional**: the 125-register continuation for a long
  model, the M704 readbacks when a control document stands, the 300-second
  settings refresh, the battery metrics read, the rate-limited freshness probe.
  A cycle is two transactions or six, so **counting transactions cannot work**.

The tap **learns** the anchor rather than being told: it locks onto the first
read key to reach three occurrences. Three, not two, because a key can repeat
once for an innocent reason (a session-open read that a slow-cadence refresher
happens to repeat) and never again, while the real anchor keeps coming. That
costs about two poll intervals after a reconnect and removes the whole class of
mistake. A bench that already knows its client can skip the learning with
`poll_anchor` on `POST /reset`.

`anchor`, `anchor_source` and `rule` are in every response so a bundle records
the definition alongside the number, rather than asking a reader to trust that
the tool got it right.

A cycle interrupted by a reconnect is **abandoned**, not completed, and its
ordinal is reused — so `completed` is both the count of finished cycles and the
ordinal of the last one, and "wait for cycle `completed+1`" always names a cycle
that can exist.

### `GET /ledger` — the sim's own account of every transaction

```
GET /ledger
GET /ledger?since_epoch=8
GET /ledger?since_seq=412&limit=100
```

```jsonc
{
  "api_version": "1.1.0",
  "epoch": 8,
  "poll": { … the same poll state as GET /poll … },
  "entries": [
    {
      "seq": 413, "epoch": 8, "poll": 12, "conn": 3, "peer": "69.0.0.2:41234",
      "txn_id": 1871, "unit_id": 1, "fc": 3, "addr": 40070, "count": 125,
      "request":  "074f0000000601030…",
      "response": "074f000000fb0103f8…",
      "outcome": "answered",
      "request_at": "2026-08-26T01:22:41.113Z",
      "response_at": "2026-08-26T01:22:41.118Z",
      "latency_ms": 4.6
    }
  ],
  "total": 1, "next_seq": 413, "high_seq": 413, "evicted": 0, "truncated": false
}
```

The ledger is written by the sim's **wire layer**, independently of anything
the device under test logs — the product does not write it, cannot influence
it, and does not know it exists. It is not a substitute for the pcap; it is what
lets a row know, before it opens the capture, whether the thing it provoked
actually happened and which transactions it happened to.

**Fields.** `seq` is the paging cursor. `epoch` is the control-plane epoch in
force when the **request** arrived — the fence. `poll` is the cycle ordinal the
request fell inside (0 = before the first cycle the tracker recognised). `conn`
numbers the client connection in accept order, so a reconnect is visible here
with no capture at all. `request` and `response` are the complete ADUs in hex,
MBAP header included; `response` is what was **delivered to the client**, so a
truncated response is recorded truncated and a dropped one is empty.

**`outcome`** is the sim's own classification, not an inference from the
client's reaction:

| outcome | meaning |
|---|---|
| `answered` | a well-formed response was written in full |
| `exception` | the device answered with an exception PDU; `exception` carries the code |
| `dropped` | a one-shot swallowed the response; the connection stayed open |
| `truncated` | a one-shot wrote a prefix, length field untouched |
| `delayed` | a one-shot held it and then wrote it in full; see `latency_ms` |
| `abandoned` | the connection ended with the request outstanding |

`fault` names the armed one-shot that shaped a transaction, when one did — so a
reader can tell a provoked failure from a device that simply failed.

**Append-only.** An entry is appended once, when its transaction resolves, and
never edited. An in-flight transaction is not there yet. A reader who fetched
entries up to `seq` N will never see a different answer for them later. The
entry is recorded *before* the bytes are written to the socket, deliberately: a
successful write is not a delivery receipt (it means the bytes reached the send
buffer, which is as much as the sim can ever know), and recording afterwards
would cost the one property the ledger exists for — that a caller holding the
response also holds its ledger entry, with no race against the tap's own
bookkeeping.

**Bounded, and honest about it.** The ring holds `-ledger-capacity` entries
(default 20 000, several hours of steady-state polling). `evicted` counts what
has aged out over the sim's life. `truncated` says whether **this query's**
window could have reached into what is gone — not merely that something has
been evicted, because a flag that went true within minutes of a bench coming up
would be a flag nobody could act on. A reset does **not** truncate the ledger:
a reset clears provocations, not evidence.

**Paging.** `next_seq` is the cursor to pass as `since_seq` to continue; it is
the query's own cursor when nothing matched, so a polling caller never rewinds.
`high_seq` is the highest sequence ever assigned, so a caller can tell "nothing
happened" from "nothing that matched happened".

---

## The wire tap

`/ledger`, `/poll`, `/poll/wait`, `next_response` and `unit_id` are all served
by an MBAP-aware pass-through relay in front of the Modbus server
(`sim/southbound/tap.go`).

**It is on by default** — `modsim -tap=false` disables it — which is the
opposite of the two adversary relays beside it (`-mangle`, `-protofault`). The
reason is what they are for. Those exist to corrupt, and a shared bench must
never be silently reframed. This one exists to *witness*: with nothing armed it
forwards every byte of every frame verbatim, in order, in both directions, and
`sim/southbound/tap_test.go` pins that byte-for-byte against the device's own
copy of what it received and sent.

Three capabilities follow from being in the byte path, and none is available
anywhere else in the sim: the MBAP **transaction identifier** (the register-map
request handler never sees it), the request/response **pair with both
timestamps** (which makes "the client asked and got no answer" a recordable
fact rather than an absence), and the **one-shot**.

With `-mangle` or `-protofault` also in play the chain is

```
client → tap :5020 → mangler|protorelay :15020 → device :25020
```

The tap stands **closest to the client** deliberately: the ledger's purpose is
to record what the device under test actually received, mangling included, not
what the sim originally composed.

With `-tap=false`, `/ledger` and `/poll[/wait]` answer **501 with a reason**
and the two tap fault kinds are refused **by name** — so a row reports
SKIP-with-reason rather than reading an empty ledger as "the client did
nothing".

---

## Acknowledgements and status codes

| endpoint | success | notes |
|---|---|---|
| `POST /inject` `/control` `/fault` `/reset` | `200` + `{"api_version","epoch"[,"result"]}` | `204 No Content` on a sim that registered no epoch counter — byte-identical to 1.0.0 |
| `GET /poll` `/poll/wait` | `200` always | `reached` carries the answer |
| `GET /ledger` `/state` `/registers` `/version` | `200` | |
| any | `400` | the body or a query parameter was refused, with the reason in the body. **A refused mutation does not move the epoch** |
| any | `501` | this sim does not implement that endpoint, with the reason |
| any | `405` | wrong method |

All endpoints send `Access-Control-Allow-Origin: *`.
