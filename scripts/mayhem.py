#!/usr/bin/env python3
"""Headless runner for the Mayhem QA fault-injection suite.

Mayhem drives the *real bench* (all the Pis) through the worst conditions a home
DERMS hub could see and diagnoses exactly where its fault handling breaks. The
engine lives in the dashboard server (cmd/dashboard/mayhem.go); this script just
launches it, follows the run, and prints the diagnostic report — so you can run
the whole suite from a terminal or wire it into CI.

Because the engine runs server-side, it talks to every Pi for you (solar .10,
battery .11, meter .12, ev .14, gridsim + hub on .1) and restores the bench when
it finishes or you Ctrl-C. You only need to reach the dashboard.

Usage:
    scripts/mayhem.py [--dashboard URL] [--only id,id] [--sample-ms N] [--json]
    scripts/mayhem.py --list            # show scenario IDs
    scripts/mayhem.py --abort           # stop a run in progress

Exit code: 0 if no FAIL/BLIND, 1 if any FAIL or BLIND, 2 on run/connection error.

Examples:
    scripts/mayhem.py --dashboard http://69.0.0.20:8080
    scripts/mayhem.py --only perfect-storm
    scripts/mayhem.py --json > mayhem.json
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# Mirror of mayhemDriver.scenarios() — for --list and --only validation only.
SCENARIOS = [
    ("export-cap-full-battery", "Zero-export cap, full sun, battery full"),
    ("ack-before-effect", "Inverter ACKs curtailment but lags 45 s"),
    ("reject-write-curtail", "Inverter ACKs the curtailment but ignores it"),
    ("enable-gate-curtail", "Inverter echoes the limit but never enables it"),
    ("ramp-limit-curtail", "Inverter honours the limit but ramps to it slowly"),
    ("battery-wrong-sign", "Battery executes a commanded charge as a discharge"),
    ("battery-soc-refuse", "Battery accepts the discharge command but does nothing"),
    ("stale-meter", "Grid meter freezes while the world changes"),
    ("battery-empty-import-cap", "Import cap at peak with an empty battery"),
    ("curtailment-release", "Generation-limit event ends — solar must recover"),
    ("clock-jitter", "CSIP clock corrections jitter while a cap is active"),
    ("perfect-storm", "Perfect storm — everything at once"),
]

# ANSI colors per verdict (suppressed when stdout is not a TTY).
COLORS = {
    "PASS": "\033[32m", "DEGRADED": "\033[33m", "FAIL": "\033[31m",
    "BLIND": "\033[35m", "INCONCLUSIVE": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def c(text, code):
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{RESET}"


def verdict_c(v):
    return c(v, COLORS.get(v, ""))


def api(base, path, method="GET", body=None, timeout=10):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def cmd_list():
    print("Mayhem scenarios:")
    for sid, name in SCENARIOS:
        print(f"  {sid:28s} {name}")


def cmd_abort(base):
    try:
        api(base, "/api/qa/abort", method="POST")
        print("abort requested; the bench will be restored.")
    except urllib.error.URLError as e:
        print(f"abort failed: {e}", file=sys.stderr)
        return 2
    return 0


def run(base, only, sample_ms, as_json):
    # Kick off the run.
    payload = {"sample_ms": sample_ms, "only": only}
    try:
        started = api(base, "/api/qa/start", method="POST", body=payload)
    except urllib.error.HTTPError as e:
        print(f"start failed: HTTP {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 2
    except urllib.error.URLError as e:
        print(f"cannot reach dashboard at {base}: {e}", file=sys.stderr)
        return 2

    if not as_json:
        n = started.get("scenarios", "?")
        print(f"{BOLD if sys.stdout.isatty() else ''}Mayhem started{RESET if sys.stdout.isatty() else ''}: "
              f"{n} scenario(s), {started.get('sample_ms')} ms sampling, via {base}")
        print("Following the run (Ctrl-C aborts and restores the bench)…\n")

    last_idx = -1
    status = {}
    try:
        while True:
            time.sleep(1.5)
            try:
                status = api(base, "/api/qa/status")
            except urllib.error.URLError:
                continue  # transient; keep following

            if not as_json:
                idx = status.get("idx", 0)
                if idx != last_idx and status.get("running"):
                    last_idx = idx
                    print(f"  [{idx}/{status.get('total')}] {status.get('current')} …")
                # Show findings as they land.
                _print_new_findings(status)

            if not status.get("running"):
                break
    except KeyboardInterrupt:
        print("\ninterrupted — requesting abort…", file=sys.stderr)
        try:
            api(base, "/api/qa/abort", method="POST")
        except urllib.error.URLError:
            pass
        # Drain to a stopped state so the bench restore completes.
        for _ in range(20):
            time.sleep(1.0)
            try:
                status = api(base, "/api/qa/status")
            except urllib.error.URLError:
                continue
            if not status.get("running"):
                break

    if as_json:
        json.dump(status, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_report(status)

    s = status.get("summary") or {}
    bad = s.get("fail", 0) + s.get("blind", 0)
    return 1 if bad else 0


_seen_findings = set()


def _print_new_findings(status):
    # An empty Go slice marshals to JSON null, so .get(...) can return None.
    for f in (status.get("findings") or []):
        key = f.get("id")
        if key in _seen_findings:
            continue
        _seen_findings.add(key)
        print(f"    → {verdict_c(f['verdict']):>12s}  {f.get('headline','')}")


def _print_report(status):
    s = status.get("summary") or {}
    findings = status.get("findings") or []
    print("\n" + "=" * 78)
    print(c(BOLD + "MAYHEM QA REPORT" + RESET, "") if sys.stdout.isatty() else "MAYHEM QA REPORT")
    state = "aborted" if status.get("aborted") else ("FAILED: " + status["last_error"]) if status.get("last_error") else "complete"
    print(f"Run {state}. Bench restored.")
    print("=" * 78)
    print(
        f"{c('PASS', COLORS['PASS'])} {s.get('pass',0)}   "
        f"{c('DEGRADED', COLORS['DEGRADED'])} {s.get('degraded',0)}   "
        f"{c('FAIL', COLORS['FAIL'])} {s.get('fail',0)}   "
        f"{c('BLIND', COLORS['BLIND'])} {s.get('blind',0)}   "
        f"{c('INCONCLUSIVE', COLORS['INCONCLUSIVE'])} {s.get('inconclusive',0)}"
    )
    print(f"Worst breach: {s.get('worst_peak_breach_W',0):.0f} W   "
          f"Total time out of limit: {s.get('total_breach_seconds',0):.0f} s")
    if status.get("report_path"):
        print(f"Full markdown report on the dashboard host: {status['report_path']}")

    for f in findings:
        m = f.get("metrics", {})
        print("\n" + "-" * 78)
        print(f"[{verdict_c(f['verdict'])}] {f.get('name')}   ({f.get('category')} · {f.get('id')})")
        print(f"  {f.get('headline','')}")
        print(f"  peak {m.get('peak_breach_W',0):.0f} W · out-of-limit {m.get('breach_seconds',0):.0f} s · "
              f"adopted={m.get('hub_adopted')} reacted={m.get('hub_reacted')} "
              f"cannot_comply={m.get('reported_cannot_comply')} blind={m.get('hub_blind')} "
              f"errs={m.get('sample_errors',0)}/{m.get('samples',0)}")
        print(f"  represents: {f.get('hypothesis','')}")
        print(f"  expected:   {f.get('expected','')}")
        for line in f.get("diagnosis", []):
            print(f"    • {line}")
        if f.get("fix"):
            print(f"  where to look: {f['fix']}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Headless runner for the Mayhem QA suite.")
    ap.add_argument("--dashboard", default="http://localhost:8080",
                    help="dashboard base URL (default http://localhost:8080; bench is http://69.0.0.20:8080)")
    ap.add_argument("--only", default="",
                    help="comma-separated scenario IDs to run (default: all). See --list.")
    ap.add_argument("--sample-ms", type=int, default=1000, help="sampling cadence in ms (default 1000)")
    ap.add_argument("--json", action="store_true", help="emit the raw status JSON instead of a report")
    ap.add_argument("--list", action="store_true", help="list scenario IDs and exit")
    ap.add_argument("--abort", action="store_true", help="abort a run in progress and exit")
    args = ap.parse_args()

    if args.list:
        cmd_list()
        return 0
    if args.abort:
        return cmd_abort(args.dashboard)

    only = [s.strip() for s in args.only.split(",") if s.strip()]
    valid = {sid for sid, _ in SCENARIOS}
    bad = [s for s in only if s not in valid]
    if bad:
        print(f"unknown scenario id(s): {', '.join(bad)} (see --list)", file=sys.stderr)
        return 2

    return run(args.dashboard, only, args.sample_ms, args.json)


if __name__ == "__main__":
    sys.exit(main())
