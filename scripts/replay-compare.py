#!/usr/bin/env python3
"""Compare a Bench Replay tick-log against the dashboard's modeled scenarios.

The dashboard's "3-Month Cost Sim" runs three *modeled* policies over a synthetic
summer (seed -> mulberry32 PRNG): Dumb, EV Peak-Rate Deferral, and the Smart hub
("ideal"). A Bench Replay drives that exact same environment into the real Pi
sims + hub and records the realized result to replay-ticklog-*.csv.

This script regenerates the seed's environment (bit-exact, via gen_env in
replay-launch.py), re-runs the modeled policies in Python so the cost basis is
identical, computes the *actual* bench cost from the CSV's net-grid column, and
plots all of them on one cumulative-cost chart. It also adds a "No DER" baseline:
a home that just consumes its load (+ EV on plug-in) with no solar and no battery.

Usage:
    replay-compare.py <ticklog.csv> [--seed N] [--out FILE.png]
The seed defaults to 99 (the standard bench-replay seed); it must match the run.
"""
import sys, csv, importlib.util, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))

# ── Reuse the bit-exact env generator from the launcher ──────────────────────
_spec = importlib.util.spec_from_file_location("replay_launch",
                                               os.path.join(HERE, "replay-launch.py"))
_rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rl)
gen_env = _rl.gen_env

# ── Constants (mirror cmd/dashboard/dashboard.html) ──────────────────────────
DT, TPD = 0.25, 96
BAT_KWH, BAT_KW = 13.5, 5.0
BAT_RES, CHG_EFF = 1.35, 0.92
EV_KW, EV_CHG_EFF = 7.2, 0.90
RATE_PEAK, RATE_PARTIAL, RATE_OFF, EXPORT_CREDIT = 0.38, 0.18, 0.10, 0.07
INF = float("inf")

def rate_at(h):  return RATE_PEAK if 16 <= h < 21 else RATE_PARTIAL if 7 <= h < 16 else RATE_OFF
def is_peak(h):  return 16 <= h < 21
def is_off(h):   return h < 7 or h >= 21

def new_state():
    return dict(soc=BAT_KWH*0.5, evDef=0.0, evKWh=0.0, imp=0.0, exp=0.0,
                cost=0.0, credit=0.0, curt=0.0, vio=0, cons=0, cum=[])

def settle(st, grid, e, pv_out):
    if grid > 0:
        st["cost"] += grid * DT * e["price"]; st["imp"] += grid * DT
    else:
        st["credit"] += -grid * DT * EXPORT_CREDIT; st["exp"] += -grid * DT
    if e["expCap"] < INF or e["impCap"] < INF or e["genCap"] < INF:
        st["cons"] += 1; TOL = 0.05
        if -grid > e["expCap"]+TOL or grid > e["impCap"]+TOL or pv_out > e["genCap"]+TOL:
            st["vio"] += 1

# ── Policies ─────────────────────────────────────────────────────────────────
def step_dumb(st, e):
    ev = min(EV_KW, st["evDef"]/DT) if (e["evHome"] and st["evDef"] > 0) else 0.0
    st["evDef"] -= ev*DT; st["evKWh"] += ev*DT
    settle(st, e["load"]+ev-e["pv"], e, e["pv"])

def step_loadonly(st, e):
    # No solar, no battery: a bare home. EV still charges on plug-in (a load).
    ev = min(EV_KW, st["evDef"]/DT) if (e["evHome"] and st["evDef"] > 0) else 0.0
    st["evDef"] -= ev*DT; st["evKWh"] += ev*DT
    settle(st, e["load"]+ev, e, 0.0)

def step_deferral(st, e):
    ev = min(EV_KW, st["evDef"]/DT) if (e["evHome"] and st["evDef"] > 0 and e["isOff"]) else 0.0
    st["evDef"] -= ev*DT; st["evKWh"] += ev*DT
    settle(st, e["load"]+ev-e["pv"], e, e["pv"])

def step_smart(st, e):
    pv_out = min(e["pv"], e["genCap"]); st["curt"] += (e["pv"]-pv_out)*DT
    ev = min(EV_KW, st["evDef"]/DT) if (e["evHome"] and st["evDef"] > 0 and e["isOff"]) else 0.0
    net = e["load"] + ev - pv_out
    room = (BAT_KWH-st["soc"]) / (DT*CHG_EFF)
    avail = max(0.0, (st["soc"]-BAT_RES)/DT)
    dis = ch = 0.0
    if net > 0 and e["isPeak"]:
        dis = min(net, BAT_KW, avail); net -= dis
    elif net < 0:
        ch = min(-net, BAT_KW, room); net += ch
    if -net > e["expCap"]:
        extra = min(-net-e["expCap"], BAT_KW-ch, room-ch)
        if extra > 0: ch += extra; net += extra
        if -net > e["expCap"]:
            cut = -net-e["expCap"]; pv_out -= cut; st["curt"] += cut*DT; net += cut
    if net > e["impCap"]:
        need = net-e["impCap"]; cut_ev = min(ev, need); ev -= cut_ev; net -= cut_ev
        need = net-e["impCap"]
        if need > 0:
            d2 = min(need, BAT_KW-dis, avail-dis)
            if d2 > 0: dis += d2; net -= d2
    st["soc"] += ch*DT*CHG_EFF - dis*DT
    st["evDef"] -= ev*DT; st["evKWh"] += ev*DT
    settle(st, net, e, pv_out)

# ── Build per-tick caps from the env's discrete DER events ────────────────────
def build_caps(env, days):
    N = days*TPD
    expCap = [INF]*N; impCap = [INF]*N; genCap = [INF]*N
    for ev in env["events"]:
        d = ev["day"]
        for i in range(TPD):
            h = i*DT
            if ev["start"] <= h < ev["end"]:
                t = d*TPD + i
                if ev["type"] == "exportCap": expCap[t] = min(expCap[t], ev["limit"])
                if ev["type"] == "importCap": impCap[t] = min(impCap[t], ev["limit"])
                if ev["type"] == "genLimit":  genCap[t] = min(genCap[t], ev["limit"])
    return expCap, impCap, genCap

def run_models(seed, days):
    env = gen_env(seed, days)
    expCap, impCap, genCap = build_caps(env, days)
    states = {k: new_state() for k in ("dumb", "loadonly", "deferral", "smart")}
    steppers = dict(dumb=step_dumb, loadonly=step_loadonly,
                    deferral=step_deferral, smart=step_smart)
    for d in range(days):
        for i in range(TPD):
            t = d*TPD + i; h = i*DT
            arr = env["evArrive"][t]
            if arr > 0:
                for st in states.values(): st["evDef"] += arr/EV_CHG_EFF
            e = dict(pv=env["pv"][t], load=env["load"][t], evHome=env["evHome"][t] == 1,
                     isPeak=is_peak(h), isOff=is_off(h), price=rate_at(h),
                     expCap=expCap[t], impCap=impCap[t], genCap=genCap[t])
            for k, st in states.items():
                steppers[k](st, e)
        for st in states.values():
            st["cum"].append(round(st["cost"]-st["credit"], 2))
    return env, states

# ── Realized bench cost from the CSV (same tariff basis) ──────────────────────
def bench_cum(csv_path, days):
    rows = list(csv.DictReader(open(csv_path)))
    cum = []; cost = 0.0
    for d in range(days):
        for i in range(TPD):
            t = d*TPD + i
            if t >= len(rows): break
            r = rows[t]; h = i*DT
            net = float(r["net_grid_kW(+imp/-exp)"])
            if net > 0: cost += net*DT*rate_at(h)
            else:       cost += net*DT*EXPORT_CREDIT   # credit (net negative)
        cum.append(round(cost, 2))
    return cum, rows

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    csv_path = sys.argv[1]; seed = 99; out = None
    a = sys.argv[2:]; i = 0
    while i < len(a):
        if a[i] == "--seed": i += 1; seed = int(a[i])
        elif a[i] == "--out": i += 1; out = a[i]
        i += 1
    if out is None:
        out = os.path.splitext(os.path.basename(csv_path))[0] + "-compare.png"

    # days = however many full days the CSV covers
    n_rows = sum(1 for _ in open(csv_path)) - 1
    days = n_rows // TPD

    env, states = run_models(seed, days)
    bench, rows = bench_cum(csv_path, days)
    dates = env["dates"][:days]
    x = list(range(1, days+1))

    s = lambda k: states[k]
    final = {"Bench (actual hub)": bench[-1],
             "Ideal (modeled smart)": s("smart")["cum"][-1],
             "EV Deferral only": s("deferral")["cum"][-1],
             "Dumb": s("dumb")["cum"][-1],
             "No DER (load + EV only)": s("loadonly")["cum"][-1]}

    # ── Plot ──────────────────────────────────────────────────────────────────
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(13, 7))
    ax.plot(x, s("loadonly")["cum"], color="#9ca3af", lw=2, ls=":",  label=f"No DER (load + EV only) — ${final['No DER (load + EV only)']:.0f}")
    ax.plot(x, s("dumb")["cum"],     color="#f87171", lw=2,          label=f"Dumb — ${final['Dumb']:.0f}")
    ax.plot(x, s("deferral")["cum"], color="#60a5fa", lw=2,          label=f"EV Deferral only — ${final['EV Deferral only']:.0f}")
    ax.plot(x, s("smart")["cum"],    color="#34d399", lw=2.5, ls="--",label=f"Ideal (modeled smart) — ${final['Ideal (modeled smart)']:.0f}")
    ax.plot(x, bench,                color="#fbbf24", lw=2.5,        label=f"Bench (actual hub) — ${final['Bench (actual hub)']:.0f}")

    ax.set_title(f"92-Day Cumulative Net Cost — Bench Replay vs Modeled Scenarios (seed {seed})", fontsize=14)
    ax.set_xlabel("Day of summer (Jun 1 – Aug 31)")
    ax.set_ylabel("Cumulative net cost ($)")
    ax.grid(True, alpha=0.2)
    ax.legend(loc="upper left", fontsize=11, framealpha=0.3)
    # date ticks every ~10 days
    step = max(1, days//9)
    ax.set_xticks(x[::step]); ax.set_xticklabels([dates[j-1] for j in x[::step]])
    fig.tight_layout()
    fig.savefig(out, dpi=130)
    print(f"wrote {out}")

    # ── Text summary ──────────────────────────────────────────────────────────
    print(f"\nseed={seed}  days={days}  weather={env['weather']}")
    dumb_net = final["Dumb"]
    print(f"\n{'scenario':28s} {'net $':>9} {'vs dumb':>10} {'compliance':>11}")
    order = [("No DER (load + EV only)", "loadonly"), ("Dumb", "dumb"),
             ("EV Deferral only", "deferral"), ("Ideal (modeled smart)", "smart")]
    for label, k in order:
        st = states[k]; net = st["cum"][-1]
        comp = 100*(1-st["vio"]/st["cons"]) if st["cons"] else 100.0
        sav = f"{100*(dumb_net-net)/dumb_net:+.0f}%" if dumb_net else "—"
        print(f"{label:28s} {net:9.0f} {sav:>10} {comp:10.1f}%")
    # bench compliance from CSV columns
    viol = sum(int(r["violation"]) for r in rows if r["constraint"])
    cons = sum(1 for r in rows if r["constraint"])
    bcomp = 100*(1-viol/cons) if cons else 100.0
    bsav = f"{100*(dumb_net-bench[-1])/dumb_net:+.0f}%" if dumb_net else "—"
    print(f"{'Bench (actual hub)':28s} {bench[-1]:9.0f} {bsav:>10} {bcomp:10.1f}%   "
          f"({viol} viol / {cons} constrained ticks)")

if __name__ == "__main__":
    main()
