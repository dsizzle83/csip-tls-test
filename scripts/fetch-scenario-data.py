#!/usr/bin/env python3
"""Fetch real hourly weather and write dashboard V2 scenario datasets.

Pulls hourly temperature + shortwave radiation from the Open-Meteo ERA5
reanalysis archive (no API key) for a small built-in catalog of scenarios and
writes `data/scenarios/<id>/{scenario.json,weather.json}` per the schema in
docs/dashboard-v2/CONTRACTS.md §2. Go loader: internal/scenariodata.

The scenario catalog (city, coords, tz, territory, blurb, period, and the
shared home/instrument defaults) is defined in-script below — this script is
the source of truth for *which* scenarios exist; scenario.json/weather.json
are generated, reproducible output, not hand-edited.

`tariff_ids`/`default_tariff_id` in each catalog entry must reference real
files in data/tariffs/ (internal/tariff validates them; the whatif engine
cross-validates scenario<->tariff territory/timezone at run time). Never
list a tariff id that doesn't exist as a committed, sourced tariff file.

Idempotent: re-running for the same scenario id re-fetches the (immutable,
historical) ERA5 data and rewrites byte-identical files, as long as
--retrieved-date is pinned (it defaults to today, so same-day reruns are
naturally idempotent).

Usage:
    scripts/fetch-scenario-data.py <scenario-id>
    scripts/fetch-scenario-data.py --all
    scripts/fetch-scenario-data.py --list
    scripts/fetch-scenario-data.py --all --retrieved-date 2026-07-12

Exit code: 0 if every requested scenario fetched + validated cleanly, 1 if
any scenario failed (fetch error or a sanity check tripped) — other
scenarios in an --all run still complete.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "data", "scenarios")

ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive"
HOURLY_VARS = "temperature_2m,shortwave_radiation"
USER_AGENT = "csip-tls-test/fetch-scenario-data (dashboard-v2)"

# Same defaults for all scenarios today (contract §2 example values) — kept
# in one place so they stay adjustable later without touching fetch logic.
HOME_DEFAULTS = {
    "profile": "single-family-3br",
    "base_kw": 0.45,
    "hvac": {"cool_setpoint_f": 75, "kw_per_degf": 0.16, "max_kw": 4.2},
}
INSTRUMENT_DEFAULTS = {
    "pv_kw": 8.0,
    "battery": {"kwh": 13.5, "kw": 5.0, "reserve_pct": 10, "round_trip_eff": 0.90},
    "ev": {
        "present": True,
        "battery_kwh": 60,
        "charger_kw": 7.2,
        "weekday_kwh": 11,
        "depart_hour": 8,
        "return_hour": 17,
    },
}

# The scenario catalog. Add entries here to grow the fleet; each becomes a
# fetchable id.
SCENARIOS = {
    "east-texas-jul2025": {
        "label": "East Texas — July 2025",
        "city": "Tyler",
        "state": "TX",
        "lat": 32.35,
        "lon": -95.30,
        "timezone": "America/Chicago",
        "territory": "east-texas-tx",
        "blurb": "Oncor delivery; deregulated ERCOT retail choice",
        "start_date": "2025-07-01",
        "end_date": "2025-07-31",
        "tariff_ids": ["tx-flat-12-2025", "tx-txu-free-nights-2025"],
        "default_tariff_id": "tx-flat-12-2025",
    },
    "los-angeles-jul2025": {
        "label": "Los Angeles — July 2025",
        "city": "Los Angeles",
        "state": "CA",
        "lat": 34.05,
        "lon": -118.24,
        "timezone": "America/Los_Angeles",
        "territory": "los-angeles-ca",
        "blurb": "LADWP municipal utility territory",
        "start_date": "2025-07-01",
        "end_date": "2025-07-31",
        "tariff_ids": ["la-ladwp-r1a-2025", "la-ladwp-r1b-tou-2025"],
        "default_tariff_id": "la-ladwp-r1a-2025",
    },
    "haverhill-jul2025": {
        "label": "Haverhill — July 2025",
        "city": "Haverhill",
        "state": "MA",
        "lat": 42.776,
        "lon": -71.077,
        "timezone": "America/New_York",
        "territory": "haverhill-ma",
        "blurb": "National Grid (Massachusetts Electric) territory",
        "start_date": "2025-07-01",
        "end_date": "2025-07-31",
        "tariff_ids": ["ma-ngrid-r1-basic-2025", "ma-haverhill-aggregation-2025"],
        "default_tariff_id": "ma-ngrid-r1-basic-2025",
    },
}


class FetchError(Exception):
    """A scenario failed to fetch or failed a sanity check."""


def build_weather_url(lat, lon, tz, start_date, end_date):
    params = {
        "latitude": lat,
        "longitude": lon,
        "start_date": start_date,
        "end_date": end_date,
        "hourly": HOURLY_VARS,
        "timezone": tz,
    }
    return ARCHIVE_URL + "?" + urllib.parse.urlencode(params)


def fetch_json(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} fetching {url}: {e.read()[:500]!r}") from e
    except urllib.error.URLError as e:
        raise FetchError(f"network error fetching {url}: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise FetchError(f"bad JSON from {url}: {e}") from e


def expected_hour_count(start_date, end_date):
    d0 = datetime.strptime(start_date, "%Y-%m-%d").date()
    d1 = datetime.strptime(end_date, "%Y-%m-%d").date()
    return ((d1 - d0).days + 1) * 24


def sanity_check(city, hours, temps, ghi, start_date, end_date):
    """Hard-fail on structural problems; return (peak_temp, peak_ghi) for reporting."""
    n_expected = expected_hour_count(start_date, end_date)
    if not (len(hours) == len(temps) == len(ghi)):
        raise FetchError(
            f"{city}: array length mismatch hours={len(hours)} temp={len(temps)} ghi={len(ghi)}"
        )
    if len(hours) != n_expected:
        raise FetchError(
            f"{city}: expected {n_expected} hours ({start_date}..{end_date}), got {len(hours)}"
        )

    # No nulls anywhere, including a trailing hour the API hasn't backfilled yet.
    null_temp_idx = [i for i, v in enumerate(temps) if v is None]
    null_ghi_idx = [i for i, v in enumerate(ghi) if v is None]
    if null_temp_idx:
        raise FetchError(
            f"{city}: null temperature_2m at {len(null_temp_idx)} hour(s), "
            f"first={hours[null_temp_idx[0]]!r} — API data not yet backfilled for this period"
        )
    if null_ghi_idx:
        raise FetchError(
            f"{city}: null shortwave_radiation at {len(null_ghi_idx)} hour(s), "
            f"first={hours[null_ghi_idx[0]]!r} — API data not yet backfilled for this period"
        )

    # Contiguous, strictly hourly, local-time timestamps covering the period exactly.
    prev = None
    for i, h in enumerate(hours):
        try:
            ts = datetime.strptime(h, "%Y-%m-%dT%H:%M")
        except ValueError as e:
            raise FetchError(f"{city}: unparseable hour string {h!r} at index {i}") from e
        if prev is not None and ts - prev != timedelta(hours=1):
            raise FetchError(f"{city}: non-contiguous hours at index {i}: {prev} -> {ts}")
        prev = ts
    first_expected = datetime.strptime(start_date, "%Y-%m-%d")
    last_expected = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(hours=23)
    if hours[0] != first_expected.strftime("%Y-%m-%dT%H:%M"):
        raise FetchError(f"{city}: first hour {hours[0]!r} != expected {first_expected}")
    if hours[-1] != last_expected.strftime("%Y-%m-%dT%H:%M"):
        raise FetchError(f"{city}: last hour {hours[-1]!r} != expected {last_expected}")

    # Plausibility: generous absolute bounds catch garbage/unit errors without
    # being a tight climate assertion (real July weather can outlier a "roughly" band).
    peak_temp = max(temps)
    min_temp = min(temps)
    peak_ghi = max(ghi)
    if not (-10.0 <= min_temp and peak_temp <= 55.0):
        raise FetchError(f"{city}: implausible temp_c range [{min_temp}, {peak_temp}]")
    if not (0.0 <= peak_ghi <= 1400.0):
        raise FetchError(f"{city}: implausible shortwave_radiation peak {peak_ghi}")

    # GHI must be ~0 deep at night and peak near midday.
    bad_night = [
        (h, g)
        for h, g in zip(hours, ghi)
        if datetime.strptime(h, "%Y-%m-%dT%H:%M").hour in (1, 2, 3) and g > 1.0
    ]
    if bad_night:
        raise FetchError(
            f"{city}: nonzero shortwave_radiation at deep night, e.g. {bad_night[0]}"
        )
    peak_idx = ghi.index(peak_ghi)
    peak_hour_of_day = datetime.strptime(hours[peak_idx], "%Y-%m-%dT%H:%M").hour
    if not (9 <= peak_hour_of_day <= 17):
        raise FetchError(
            f"{city}: GHI peak {peak_ghi} at local hour {peak_hour_of_day}, expected midday (9-17)"
        )

    return peak_temp, peak_ghi


def build_scenario_json(sid, spec):
    weather_url = build_weather_url(
        spec["lat"], spec["lon"], spec["timezone"], spec["start_date"], spec["end_date"]
    )
    return {
        "id": sid,
        "label": spec["label"],
        "location": {
            "city": spec["city"],
            "state": spec["state"],
            "lat": spec["lat"],
            "lon": spec["lon"],
            "timezone": spec["timezone"],
            "territory": spec["territory"],
            "blurb": spec["blurb"],
        },
        "period": {"start": spec["start_date"], "end": spec["end_date"]},
        "weather": {
            "source": "open-meteo-era5",
            "retrieved": spec["retrieved"],
            "source_url": weather_url,
        },
        "tariff_ids": spec.get("tariff_ids", []),
        "default_tariff_id": spec.get("default_tariff_id", ""),
        "home_defaults": HOME_DEFAULTS,
        "instrument_defaults": INSTRUMENT_DEFAULTS,
    }, weather_url


def fetch_scenario(sid, spec, out_dir, retrieved_date):
    spec = dict(spec, retrieved=retrieved_date)
    scenario_doc, weather_url = build_scenario_json(sid, spec)

    payload = fetch_json(weather_url)
    hourly = payload.get("hourly", {})
    hours = hourly.get("time", [])
    temps = hourly.get("temperature_2m", [])
    ghi = hourly.get("shortwave_radiation", [])

    peak_temp, peak_ghi = sanity_check(
        spec["city"], hours, temps, ghi, spec["start_date"], spec["end_date"]
    )

    weather_doc = {
        "timezone": spec["timezone"],
        "hours": hours,
        "ghi_wm2": ghi,
        "temp_c": temps,
    }

    scenario_dir = os.path.join(out_dir, sid)
    os.makedirs(scenario_dir, exist_ok=True)
    write_json(os.path.join(scenario_dir, "scenario.json"), scenario_doc)
    write_json(os.path.join(scenario_dir, "weather.json"), weather_doc)

    return {
        "hours": len(hours),
        "peak_temp_c": peak_temp,
        "peak_ghi_wm2": peak_ghi,
        "dir": scenario_dir,
    }


def write_json(path, doc):
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario_id", nargs="?", help="scenario id to fetch (see --list)")
    p.add_argument("--all", action="store_true", help="fetch every scenario in the catalog")
    p.add_argument("--list", action="store_true", help="list known scenario ids and exit")
    p.add_argument(
        "--retrieved-date",
        default=date.today().isoformat(),
        help="value stamped into weather.retrieved / source provenance (default: today, %(default)s)",
    )
    p.add_argument(
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        help="output root, one subdir per scenario id (default: data/scenarios)",
    )
    args = p.parse_args()

    if args.list:
        for sid in SCENARIOS:
            print(sid)
        return 0

    if args.all:
        ids = list(SCENARIOS)
    elif args.scenario_id:
        ids = [args.scenario_id]
    else:
        p.error("give a scenario id, or --all, or --list")
        return 2  # unreachable; p.error() exits

    failed = []
    for sid in ids:
        spec = SCENARIOS.get(sid)
        if spec is None:
            print(f"[FAIL] {sid}: unknown scenario id (see --list)", file=sys.stderr)
            failed.append(sid)
            continue
        try:
            result = fetch_scenario(sid, spec, args.out_dir, args.retrieved_date)
        except FetchError as e:
            print(f"[FAIL] {sid}: {e}", file=sys.stderr)
            failed.append(sid)
            continue
        print(
            f"[OK]   {sid}: {result['hours']} hours -> {result['dir']} "
            f"(peak {result['peak_temp_c']:.1f}°C, peak GHI {result['peak_ghi_wm2']:.0f} W/m²)"
        )

    if failed:
        print(f"\n{len(failed)}/{len(ids)} scenario(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
