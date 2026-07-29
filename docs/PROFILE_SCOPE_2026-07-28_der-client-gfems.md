# Profile scope: DER Client, GFEMS posture (owner decision, 2026-07-28)

**Supersedes
[`PROFILE_SCOPE_2026-07-28_der-aggregator-client.md`](PROFILE_SCOPE_2026-07-28_der-aggregator-client.md),
taken earlier the same day.** That document is kept, not deleted: its §3 is the
row-by-row inventory of what each of the twenty-two aggregator rows can and
cannot demonstrate, and its §4 is the errata table. Both survive this change
intact — what changed is whether those rows are *claimed*, not what they do.

The CSIP conformance catalog's applicability column tracks §4's **DER Client**
column again. It tracked **DER Client** until the morning of 2026-07-28, then
**DER Aggregator Client**, and now **DER Client** once more. A column that moves
twice in a day is worth explaining rather than diffing, which is what this file
is for: every `applicability_reason` in `testdata/catalog/catalog.json` for a
`CSIP-CONF-v1.3` row points here.

The justification document is **lexa-gw `docs/conformance/PICS_CSIP.md`** (rev.
b, 2026-07-28) — §1.1 for the claim, §1.2 for the twenty-two rows, §1.3 for the
scenario axis, §7 for the aggregation architecture the claim rests on. That
document is the product's PICS and is authoritative for anything about the
gateway's behaviour; this file is authoritative for what the *harness catalog*
does about it.

---

## 1. The decision

**The DUT is certified against the CTP §4 DER CLIENT column, in the Generating
Facility EMS (GFEMS) posture**: a gateway that manages the DERs behind **one**
point of interconnection and presents to the utility as a **single 2030.5
client**.

The decision is the owner's. It is recorded here as a decision, not derived: no
amount of reading the standard tells you which profile a vendor chooses to
certify. What the standard tells you is what follows from the choice, and §4 is
where that is written down.

Four facts about the product make this column the accurate measurement target
rather than merely the cheaper one:

* **One PCC.** The gateway sits at a single point of interconnection. CSIP's
  aggregator fronts a fleet **across facilities**, with per-EndDevice
  registration and 2030.5-layer fan-out to EndDevices the utility provisions
  individually.
* **One client identity.** Product decision **D3.1**: one EndDevice, one LFDI,
  with every admitted DER exposed as a `DER` instance beneath it — *not* N
  EndDevices with N certificates (`lexa-gw docs/DER_MODELING.md`, pinned by
  `TestD3SingleEndDeviceSingleLFDI`).
* **The fan-out is below the boundary.** Control fan-out to the inverters
  happens **inside** that one EndDevice (D3.2), not across EndDevices the
  utility provisions. *"The gateway is the aggregated device, not the
  aggregator"* (`lexa-gw docs/DER_MODELING.md:11`, PICS §7). This is the same
  fact the superseded decision read the other way round: fanning controls out to
  multiple inverters is real, and it is not what the CTP's aggregator column
  measures.
* **The decision pack already committed to this shape.** `lexa-gw
  docs/UTILITY_DECISION_PACK.md` §1 names the certification load of Scenario 1 /
  Direct as *"None beyond Direct/GFEMS profile"* (`:53`). Claiming the
  aggregator column would have measured the product against a topology it does
  not build **and** contradicted its own decision pack.

## 2. Nothing is lost by claiming the narrower column

CTP §4 is a three-column table (Server, DER Client, DER Aggregator Client):
*"Tests marked with an X in the following table are required for a conforming
implementation for each profile."*

Across the 79 `CSIP-CONF-v1.3` rows the two client columns **nest strictly**:

| Relationship | Rows |
|---|---|
| X in **both** client columns | 48 |
| X in the **aggregator** column only | 22 |
| X in the **DER Client** column only | **0** |

The aggregator's required set is the client's required set **plus** exactly
those twenty-two. Every check required by this claim would also have been
required by the abandoned one; the reverse is not true, and that difference is
the whole of the change.

This is machine-checked rather than asserted. `profile_conformance` on each
catalog row is a transcription of the printed matrix, and
`TestProfileScopeIsTheDERClientColumn`
(`internal/certify/suitecsip/register_test.go`) fails if the applicable set ever
stops being the DER Client column exactly — in **either** direction — and fails
separately if a row ever appears that is required of a DER Client and not of a
DER Aggregator Client, because that is the day the superset argument above stops
holding.

## 3. The twenty-two rows: outside the claim, inside the run

| Group | Rows |
|---|---|
| Aggregator operations | AGG-001 … AGG-012 |
| Subscription / notification | CORE-018, CORE-019 |
| Error handling | ERR-002 |
| Model maintenance | MAINT-001, MAINT-003, MAINT-004, MAINT-005 |
| Utility-server aggregator model | UTIL-002, UTIL-003, UTIL-004 |

The catalog marks all twenty-two `applicable: false`. **Their checks stay
registered and keep running.** That is this tool's standing treatment of an
implemented-but-inapplicable row — five rows in other documents were already in
that position before this change, and `certify -list` has always counted them
under Implemented rather than N/A — and it is the treatment these twenty-two get
for three reasons:

1. **The criteria are real evaluators, not stubs.** Per-EndDevice Response
   fan-out and its negative (`critResponseFanOut`, `critNoResponseFanOut`),
   errata-corrected supersession status (`critSupersessionStatus`,
   `critNoSupersession`), Subscription POST and Notification answer
   (`critSubscriptionPosted`, `critNotificationAnswered`) — all in
   `internal/certify/suitecsip/criteria_agg.go`.
2. **The bench builds the fixtures they were written against.** `sim/server
   -fleet` serves the CTP Figure-15 topology and `-subscription` serves the
   Subscription/Notification function set. Both are **off by default**, with the
   default tree pinned byte-identical by `sim/gridsim/golden_default_test.go`,
   so an informative lever cannot silently re-measure certified evidence.
3. **A check that runs is worth more than a check that was deleted.** A reader
   who needs to know how this gateway behaves under a four-EndDevice fan-out has
   nowhere else to look. Deleting the code, or rebinding it to the
   not-applicable stub, would have been the cheap answer to a bookkeeping
   asymmetry.

**Read those verdicts as informative, including the negative ones.** With
`-subscription` on, a DUT that ignores an advertised `SubscriptionListLink`
produces a real **FAIL** — asserted deliberately by
`internal/certify/suitecsip/fleetbench_test.go`. That FAIL is evidence about a
capability this product does not claim. It gates nothing.

### What the catalog records, precisely

| Field | Value | Why |
|---|---|---|
| `applicable` | `false` | §4 leaves the row blank in the claimed column. It is not required of this DUT. |
| `dut_role` | `csip-client` — **unchanged** | The row is outside the *claim*, not outside the client *surface*. Its check still drives IEEE 2030.5 as a client. Demoting it to `not-applicable` would say the opposite of what the registration does, and would drop it from a `-role csip-client` selection that will still execute it. |
| `applicability_reason` | says **INFORMATIVE** in as many words | The bundle prints the reason. A reader who sees `applicable: false` and nothing else will assume the row was skipped. |
| registration | unchanged, in `registerAggregator` | See above. |

`TestAggregatorRowsAreInapplicableButStillImplemented` pins all four.

The other twenty-two-row question — *what does each one actually drive on the
bench?* — is answered row by row in the superseded document's §3, and its §4
maps every erratum that changes an observable to the code that honours it. Read
§3 as the informative-evidence inventory it now is.

## 4. Scenario designation — the two axes now agree

| Axis | Position | Recorded at |
|---|---|---|
| Connection scenario (a **utility's** interconnection designation) | **Scenario 1 — Direct DER Communications** | CSIP Implementation Guide v2.1 §3.2; `lexa-gw docs/UTILITY_DECISION_PACK.md` §1, product decision **D3** |
| CTP §4 profile column (a **vendor's** scope choice) | **DER Client**, GFEMS posture | §1 above; PICS §1.1 |

The previous revision of the PICS recorded these two as being in conflict: the
profile column pointed at an aggregator and the decision pack at Scenario 1.
This decision resolves it. They remain different axes and a submission still has
to state both — Scenario 2 (Aggregator Mediated) is what would require N
EndDevices, N certificates, per-device PIN issuance and **mandatory**
Subscription/Notification, none of which is partially done — but they no longer
have to be reconciled.

**Recommendation of record:** obtain the utility's written scenario designation
before booking a laboratory session (PICS §1.3). The purpose is now to *confirm*
the designation this claim assumes rather than to resolve a conflict, but a
claim that assumes a designation nobody has put in writing is still a scope
decision made by default.

## 5. Subscription: an intent, recorded so it is not read as a claim

The owner intends to implement **Subscription/Notification — the
CORE-018/CORE-019 function set — in place of pure polling**, as an **optional
capability under the DER Client profile**. This is legitimate and changes
nothing about the claim: no CTP row penalises capability beyond the column
claimed, and CORE-018/CORE-019 are simply not required of a DER Client. Nor is
it a step toward Scenario 2; it is an optional capability under Scenario 1.

As of `lexa-gw` build `d73d036` **the surface does not exist** — repository-wide
searches for `Subscription`, `Notification`, `SubscriptionList` and
`NotificationList` return no type, no handler, no route, and the `subscribable`
attribute is parsed off resources and never acted on (PICS §1.2(a), §3.2).
Product decision **D4** selects polling and defers subscription delivery until a
target utility programme requires it, because an inbound HTTPS listener is a new
trust boundary on a product whose integration posture is *"no inbound WAN port
to firewall open"*.

So CORE-018, CORE-019 and ERR-002 are expected to read **negative** today. When
the capability ships they become informative rows that can pass rather than
informative rows that must fail, and the profile claim is unaffected either way.
Their `applicability_reason` records this intent, because a reader who finds
three failing subscription rows and no context will reasonably conclude the
product is trying and failing to do something it has not started.

## 6. What this decision does **not** change

* **The six rows that are inapplicable regardless of profile.** CORE-001,
  CORE-002, CORE-004 and UTIL-001 test a 2030.5 **server**; MAINT-002 is made
  optional by Annex A Errata I seq 32; COMM-001 is optional for all device types
  by its own Purpose. All six are blank in **all three** §4 columns — required
  of nobody — so no profile choice can move them. They are the six bound to the
  `notApplicable` stub in `register.go`, and that list did not change.
* **The three rows that are applicable but required of nobody.** BASIC-013
  (`opModFixedW`), BASIC-014 (`opModTargetW`) and CORE-023 (added by Annex A seq
  33, *"Adding a new test (Optional)"*, absent from the printed matrix) are
  optional evidence this bench can produce. Their reasons say **OPTIONAL** in as
  many words and the test enforces it.
* **Any check, anywhere.** No check was weakened, deleted or unregistered. All
  seventy-nine `CSIP-CONF-v1.3` uids remain registered. The only thing that
  moved is what the catalog claims.

*Applicable* and *required* remain different questions, and the catalog keeps
them apart: `applicable` records whether the case is claimed for this product;
`profile_conformance` records what §4 demands. A row can be applicable and
optional, or inapplicable and exercised, and a reader who conflates them will
mis-read the coverage table.

## 7. Counts

| | Before (aggregator claim) | After (DER Client / GFEMS) |
|---|---|---|
| `CSIP-CONF-v1.3` cases | 79 | 79 |
| …selected as applicable | 73 | **51** |
| …registered (implemented) | 79 | 79 |
| …inapplicable **and** registered | 6, all on the `notApplicable` stub | **28**: the same 6 on the stub, plus 22 bound to real checks |
| …applicable with no check | 0 | **0** |
