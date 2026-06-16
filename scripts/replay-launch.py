#!/usr/bin/env python3
"""Generate the dashboard's synthetic-summer env (bit-exact mulberry32 PRNG) and
optionally launch a server-side Bench Replay via the dashboard API.

This mirrors genEnv() in cmd/dashboard/dashboard.html so a long replay can be
driven without the browser.  Usage:
    replay-launch.py [seed] [--days N] [--start-day D] [--tick-ms MS] [--launch]
Without --launch it prints an env summary only.
"""
import sys, json, math, urllib.request

DT, TPD, DAYS_FULL, PV_KW = 0.25, 96, 92, 8.0
DASH = "http://69.0.0.20:8080"

def mulberry32(a):
    s = [a & 0xFFFFFFFF]
    def imul(x, y): return ((x & 0xFFFFFFFF) * (y & 0xFFFFFFFF)) & 0xFFFFFFFF
    def nxt():
        a = (s[0] + 0x6D2B79F5) & 0xFFFFFFFF
        s[0] = a
        t = imul(a ^ (a >> 15), (1 | a) & 0xFFFFFFFF)
        t = ((t + imul(t ^ (t >> 7), (61 | t) & 0xFFFFFFFF)) & 0xFFFFFFFF) ^ t
        t &= 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296.0
    return nxt

def clamp(v, lo, hi): return min(hi, max(lo, v))

def gauss(rnd, mu, sd):
    u = 0.0; v = 0.0
    while u == 0.0: u = rnd()
    while v == 0.0: v = rnd()
    return mu + sd * math.sqrt(-2*math.log(u)) * math.cos(2*math.pi*v)

def gen_env(seed, days):
    import datetime
    rnd = mulberry32(seed)
    N = days * TPD
    pv = [0.0]*N; load = [0.0]*N
    ev_home = [1]*N; ev_arrive = [0.0]*N
    dates = []; events = []
    wcount = {'clear':0,'partly':0,'rain':0}; max_heat = 0.0
    wType = 'clear'
    start = datetime.date(2026, 6, 1)
    for d in range(days):
        date = start + datetime.timedelta(days=d)
        dates.append(f"{date.month}/{date.day}")
        dow = (date.weekday() + 1) % 7   # JS getUTCDay: Sun=0..Sat=6
        weekend = dow == 0 or dow == 6
        r = rnd()
        if wType == 'clear':   wType = 'clear' if r < 0.55 else 'partly' if r < 0.85 else 'rain'
        elif wType == 'partly':wType = 'clear' if r < 0.35 else 'partly' if r < 0.75 else 'rain'
        else:                  wType = 'clear' if r < 0.30 else 'partly' if r < 0.70 else 'rain'
        heat = (78 + rnd()*17) if wType=='clear' else (73 + rnd()*14) if wType=='partly' else (66 + rnd()*9)
        wcount[wType] += 1
        if heat > max_heat: max_heat = heat
        dep = -1.0; ret = -1.0; trip = 0.0
        if not weekend:
            dep = 7 + rnd()*2; ret = 16 + rnd()*2
            trip = clamp(gauss(rnd, 11, 4), 4, 22)
        elif rnd() < 0.65:
            dep = 9 + rnd()*3; ret = dep + 3 + rnd()*4
            trip = clamp(gauss(rnd, 7, 3), 2, 14)
        cloud = 0.7
        for i in range(TPD):
            t = d*TPD + i; h = i*DT
            if wType == 'clear': wf = 0.93 + 0.07*rnd()
            elif wType == 'rain': wf = 0.10 + 0.15*rnd()
            else:
                cloud = clamp(cloud + (rnd()-0.5)*0.25, 0.25, 0.95); wf = cloud
            sr, ss = 5.4, 20.2
            elev = math.sin(math.pi*(h-sr)/(ss-sr)) if (h > sr and h < ss) else 0.0
            pv[t] = PV_KW * (elev ** 1.15) * wf
            l = 0.45 + 0.1*rnd()
            if 6 <= h < 9:  l += 0.7*math.sin(math.pi*(h-6)/3)
            if 17 <= h < 22:l += 1.0*math.sin(math.pi*(h-17)/5)
            acF = max(0, (heat-72)/22)
            if 12 <= h < 23: l += acF*2.6*math.sin(math.pi*(h-12)/11)*(0.75 + 0.5*rnd())
            load[t] = l
            if dep >= 0 and h >= dep and h < ret: ev_home[t] = 0
        if dep >= 0:
            rt = d*TPD + min(TPD-1, int(ret/DT)); ev_arrive[rt] = trip
        evts = []
        if wType != 'rain' and rnd() < (0.30 if heat > 85 else 0.10):
            s = 10.5 + rnd()*2; dur = 2 + rnd()*3
            if rnd() < 0.6: evts.append({'type':'exportCap','limit':round(1+rnd()*2,1),'start':s,'end':s+dur})
            else:           evts.append({'type':'genLimit','limit':round(PV_KW*(0.35+rnd()*0.3),1),'start':s,'end':s+dur})
        if heat > 86 and rnd() < 0.28:
            s = 16.5 + rnd()*1.5; dur = 1.5 + rnd()*2.5
            evts.append({'type':'importCap','limit':round(1.5+rnd()*1.5,1),'start':s,'end':s+dur})
        for e in evts:
            events.append({'day': d, **e})
    return {'pv':pv,'load':load,'evHome':ev_home,'evArrive':ev_arrive,
            'events':events,'dates':dates,
            'weather':wcount,'maxHeat':round(max_heat)}

def main():
    args = sys.argv[1:]
    seed = 1337
    days = DAYS_FULL; start_day = 0; tick_ms = 8000; launch = False
    i = 0
    pos = []
    while i < len(args):
        a = args[i]
        if a == '--launch': launch = True
        elif a == '--days': i += 1; days = int(args[i])
        elif a == '--start-day': i += 1; start_day = int(args[i])
        elif a == '--tick-ms': i += 1; tick_ms = int(args[i])
        else: pos.append(a)
        i += 1
    if pos: seed = int(pos[0])

    env = gen_env(seed, days)
    by_type = {}
    for e in env['events']: by_type[e['type']] = by_type.get(e['type'], 0) + 1
    print(f"seed={seed} days={days} ticks={days*TPD}  weather={env['weather']} maxHeat={env['maxHeat']}°F")
    print(f"events: {len(env['events'])}  by_type={by_type}")
    print("first 12 cap events (day/type/limit/hours):")
    for e in env['events'][:12]:
        print(f"  {env['dates'][e['day']]} (day {e['day']})  {e['type']:9s} {e['limit']:>5}kW  {e['start']:.1f}-{e['end']:.1f}h")
    # sanity: a clear-day midday PV peak should approach ~PV_KW
    peak = max(env['pv'])
    print(f"PV peak over window: {peak:.2f} kW   load peak: {max(env['load']):.2f} kW")
    est_h = days*TPD*tick_ms/1000/3600
    print(f"est wall-clock at {tick_ms} ms/tick: {est_h:.1f} h")

    if not launch:
        print("\n(dry run — add --launch to start the replay)")
        return
    payload = {'seed': seed, 'tick_ms': tick_ms, 'start_day': start_day, 'days': days, 'env': env}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(DASH + '/api/replay/start', data=data,
                                 headers={'Content-Type':'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f"\nLAUNCHED: HTTP {resp.status}  {resp.read().decode()}")

if __name__ == '__main__':
    main()
