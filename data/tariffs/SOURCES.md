# Tariff sources — July 2025 residential rates

Research performed 2026-07-12/13 (rates are **historical**, in effect July 2025).
Confidence levels per `docs/dashboard-v2/CONTRACTS.md` §1: **filed** = the actual rate
sheet / EFL / tariff book was read; **published** = a utility page or secondary source
quoting the rate; **estimated** = reconstructed from adjacent-period data (basis stated).

---

## east-texas-tx (Tyler — Oncor TDU, deregulated ERCOT retail)

### `tx-flat-12-2025` — East Texas 12-Month Fixed (composite) — **estimated**
A composite of a typical fixed-rate REP plan, not one specific EFL. The **delivery side
is filed-quality**: Oncor's official 2025 residential rate sheet
(<https://www.oncor.com/content/dam/oncorwww/documents/partners/rep/Oncor%20Residential%20Rates.pdf.coredownload.pdf>)
gives, for 2025-05-13 → 2025-08-31: fixed $4.23/mo ($1.43 customer charge + $2.80
metering) and volumetric 5.1248 ¢/kWh (Distribution 2.5344 + TCRF 1.8796 + Nuclear
Decommissioning 0.0199 + EECRF 0.1137 + DCRF 0.5772); corroborated by BKV Energy's
historical TDU-charge table
(<https://bkvenergy.com/learning-center/historical-tdu-delivery-charges/>). The
**energy charge (10.0 ¢/kWh) is estimated**: published July-2025 Oncor-area average
all-in retail was 15.47 ¢/kWh
(<https://www.electricchoice.com/electricity-prices-by-state/texas/dallas/>; EIA Texas
July-2025 residential average ≈ 15.36 ¢), minus the filed Oncor delivery (~5.55 ¢/kWh
at 1000 kWh) ⇒ ~9.9-10.0 ¢ retail energy. No July-2025-dated flat EFL was retrievable
in 2026 (REPs overwrite EFL PDFs in place; no archive snapshots); real 2025-era named
plans (Reliant Secure Advantage 12, Gexa Eco Saver Plus) matched this all-in level but
were only quotable from 2026 pages or carry bill-credit structures that don't map to a
flat rate. REP base charge assumed $0. All-in at 1000 kWh/mo: **~15.5 ¢/kWh**.
Weakest number: the 10.0 ¢ energy charge (residual of an average, not a filed EFL rate).

### `tx-txu-free-nights-2025` — TXU Free Nights & Solar Days 12 (8 pm) — **estimated**
Structure and rates from a **filed TXU EFL** for "Free Nights & Solar Days 12 (8 pm)",
Oncor territory, dated 2024-06-11
(<https://bkvenergy.com/wp-content/uploads/2024/06/June-11th-TXU-Energy-Electricity-Facts-Label.pdf>):
free Nights **8:00 pm–4:59 am every day** (the EFL credits 100% of BOTH the energy
charge AND TDU delivery during nights), Solar Days energy charge **26.30 ¢/kWh**, base
charge $9.95/mo, EFL average 19.5 ¢/kWh @ 1000 kWh. Marked **estimated** (not filed)
because the EFL is June-2024-dated and a mid-2025 EFL was not retrievable; the plan's
availability and ~19.5–19.8 ¢ all-in were corroborated as of 2025-04-09 by
<https://homeenergyclub.com/texas-electricity-companies/txu-energy/free-nights-and-solar-days>.
Encoding: Oncor volumetric (5.1248 ¢, filed, July 2025) is folded into the day rate
(26.30 + 5.1248 = 31.4248 ¢) rather than `riders_usd_per_kwh`, so nights are genuinely
free as the EFL specifies; `fixed_monthly_usd` = $9.95 TXU + $4.23 Oncor. Weakest
number: the 26.30 ¢ day rate (13 months older than the target period; TXU repriced
EFLs during 2025 and the mid-2025 value could differ by 1–3 ¢).

### TX solar buyback — **omitted (honestly)**
TXU Solar Saver / Rhythm-style buyback plans were researched, but only 2026-dated EFLs
and pages were retrievable, with wide, unverifiable spreads for the 2025 import/export
rates. Per the provenance rules, omitted rather than guessed.

---

## los-angeles-ca (LADWP — municipal, Zone 1)

Both LADWP files are **estimated** — precise reconstructions for the Jul–Sep 2025
factor quarter, anchored by two numbers read directly from LADWP's own filed board
letters and validated against independent published totals to ≤0.3 ¢. LADWP total
rate = base energy charge (fixed since the 2016 incremental ordinance's final step)
+ quarterly adjustment factors. Filed anchors (both PDFs fetched and read):
composite **ECAF = $0.11212/kWh eff 2025-07-01** and **$0.10499 eff 2025-01-01**
(LADWP board letters, "Energy Cost Adjustment Expenditures…", ladwp.com
`/sites/default/files/2025-07/…July 1, 2025.pdf` and `/2025-03/…January 1, 2025.pdf`).
Non-ECAF factors (ESA + RCA + IRCA) = $0.04655/kWh, derived as USURDB's Q1-2025
adjustment snapshot ($0.15154) minus the filed Jan-2025 ECAF. Validation: base +
Apr-Jun ECAF ($0.10968, stated in the July letter) + $0.04655 reproduces solar.com's
published June-2025 Zone 1 tier totals (22.8 / 28.6 / 37.3 ¢) to the rounding digit
(<https://www.solar.com/learn/understanding-ladwp-electric-rates/>).

### `la-ladwp-r1a-2025` — R-1(A) Standard, tiered, Zone 1 summer — **estimated**
Base tiers $0.07142 / $0.13001 / $0.21702 (summer Tier 3) from OpenEI USURDB entries
sourced to LADWP's official rate summary
(<https://apps.openei.org/IURDB/rate/view/67c0b2c8997764b245041d4f> eff 2025-01-01,
<https://apps.openei.org/IURDB/rate/view/631ba5d4757e95617e6d6128> eff 2022-09-01 —
the 2025 entry miscurates summer Tier 3 as = Tier 2; the 2022-23 entry carries the
correct seasonal split, and the base rates are identical across both). July-2025
totals: **23.01 / 28.87 / 37.57 ¢/kWh** at monthly breakpoints 350 / 1050 kWh (Zone 1;
billed bi-monthly at 2× thresholds). Encoded per schema as tier-1 period rate + tier
adders (+5.859 ¢, +14.560 ¢). Fixed charge $7.90/mo = Power Access Charge at Tier 2
(PAC is $2.30/$7.90/$22.70 by highest tier reached — USURDB + 
<https://nrgcleanpower.com/learning-center/preparing-for-ladwp-utility-rates-in-2024/>);
$10/mo minimum charge not encodable in schema. All-in at 500 kWh/mo: **~26.3 ¢/kWh**.
Weakest number: the $0.04655 non-ECAF factor residual (derived, not itemized —
LADWP's per-factor 2025 breakdown page and rates.ladwp.com were unreachable).

### `la-ladwp-r1b-tou-2025` — R-1(B) Time-of-Use, Zone 1 summer — **estimated**
Base rates High Peak $0.15858 / Low Peak $0.10018 / Base $0.07274 (summer) and the
TOU schedule from USURDB
(<https://apps.openei.org/IURDB/rate/view/631baa48457a9a20fb253929> eff 2022-09-01,
<https://apps.openei.org/IURDB/rate/view/67c0dfb895d465db010bceeb> eff 2025-01-01).
Windows (corroborated by <https://tou.tools/utilities/los-angeles-department-of-water-power/>
and solar.com): weekdays High Peak 13:00–17:00, Low Peak 10:00–13:00 & 17:00–20:00,
Base 20:00–10:00; weekends all Base. July-2025 totals with the same +$0.15867 factor
stack: **31.73 / 25.89 / 23.14 ¢/kWh** — consistent with published approximations
(~31 / 22–27 / ~23 ¢). Service charge $12.00/mo. The ordinance's EV discount
(−2.5 ¢/kWh on a designated charging block) is not encoded. Weakest numbers: the
factor residual (as above) and the summer weekend Base rate (the 2022-23 USURDB entry
maps July weekends to the low-season base row $0.07664 — likely a curation slip;
encoded at the summer base $0.07274, ±0.4 ¢).

### LADWP export — net metering — **published**
LADWP residential solar is true retail-rate net metering (credits at the full
tier/period rate, roll over indefinitely; LADWP is a municipal utility exempt from
CPUC NEM-3.0 and has not adopted net billing).
<https://www.energysage.com/local-data/net-metering/ladwp/>,
<https://programs.dsireusa.org/system/program/detail/4855>.

---

## haverhill-ma (National Grid — Massachusetts Electric)

### `ma-ngrid-r1-basic-2025` — R-1 + Basic Service — **filed**
Every number read from National Grid's filed documents. Supply: residential Basic
Service **fixed 14.672 ¢/kWh** for the 2025-02-01 → 2025-07-31 block (rises to
15.484 ¢ on 2025-08-01) —
<https://www.nationalgridus.com/media/pdfs/billing-payments/electric-rates/ma/resitable.pdf>,
confirmed on Sheet 5 of the July-2025 delivery tariff. Delivery: **M.D.P.U. No.
1-25-I, eff. 2025-07-01**
(<https://www.nationalgridus.com/media/pdfs/billing-payments/electric-rates/ma/2025/0725meco.pdf>):
$10.00/mo customer charge + 20.257 ¢/kWh total (Net Distribution 8.939, Net Transition
−0.036, Net Transmission 5.798, Energy Efficiency 2.879, Renewables 0.050, Net Metering
Recovery Surcharge 1.724, Distributed Solar/SMART 0.729, EV Program 0.174 — components
sum exactly to the printed total). Delivery changed twice over summer 2025 (May had a
one-time service-quality credit; June 20.267 ¢), hence the file's effective range is
July only. Encoding: period rate 29.373 ¢ = supply + net-metering-creditable delivery
(distribution + transmission + transition); riders 5.556 ¢ = non-creditable riders —
so `net_metering` export credits exactly the real MA Class I rate while import sums to
the filed **34.93 ¢/kWh all-in**. Net metering status (Class I, cap raised to 25 kW AC
Feb 2025) is published: <https://www.mass.gov/info-details/net-metering-guide>.
Weakest number: none material; the creditable-vs-non-creditable rider split follows
standard MA Class I practice rather than a single printed table.

### `ma-haverhill-aggregation-2025` — Haverhill Community Choice + NG delivery — **filed**
Haverhill's municipal aggregation (consultant Colonial Power Group; supplier First
Point Power). Supply **$0.14377/kWh**, fixed for all rate classes Nov-2023 → Nov-2026
meter reads, per the program's official consumer notification
(<https://colonialpowergroup.com/wp-content/uploads/2023/10/Haverhill-2023.10-Consumer-Notification-NEW-RATETERM.pdf>);
the official change-in-law notice
(<https://colonialpowergroup.com/wp-content/uploads/2025/07/Haverhill-2025.08-Public-Notice-CHANGE-IN-LAW.pdf>)
confirms it rose to $0.15101 only with the **August 2025** meter reads — so July 2025
= 14.377 ¢. Delivery identical to `ma-ngrid-r1-basic-2025` (filed July-2025 M.D.P.U.
1-25-I). All-in **34.63 ¢/kWh**. Same net-metering encoding split. Weakest point:
supply-portion netting for competitive-supply customers is administratively handled by
the supplier; simplified here to full net metering.

### MA EV/TOU rate — **omitted (honestly)**
National Grid MA had **no residential whole-home TOU or EV tariff in 2025** — R-1 is
flat. The "Off-Peak Charging Program"
(<https://www.nationalgridus.com/electric-vehicle-hub/Programs/Massachusetts/Off-Peak-Charging-Program>)
is a rebate on EV-charging kWh only ($0.05/kWh off-peak Jun–Sep), explicitly "does not
impact what you are charged on your bill" — encoding it as a whole-home TOU rate would
overstate savings, so it was left out.
