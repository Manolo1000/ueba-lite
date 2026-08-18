"""
generate_data.py — Synthetic activity log with GROUND TRUTH labels.

Why synthetic-with-labels instead of a real log dump:
  - Reproducible: anyone can clone and run, no private data.
  - It has a KNOWN answer. Because we plant the real threats ourselves, we can
    measure precision/recall and actually *defend* a tuning choice — which is
    the whole point of an insider-threat portfolio piece.

What gets generated:
  1. A BASELINE window (default 30 days) of normal per-user behavior.
  2. A SCORING window (default 7 days) that is mostly normal, but contains:
       - 3 genuine insider-threat scenarios  (label = 1)
       - 2 benign-but-unusual events         (label = 0, but LOOKS suspicious)
     The benign-but-unusual events are the whole game: they are the false
     positives a naive detector fires on, and tuning them out without missing
     the real threats is the craft you are selling.

label column: 1 = part of an injected malicious scenario, 0 = benign.
Detectors NEVER see the label. Only evaluate.py does.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta

RNG = np.random.default_rng(42)  # deterministic output

# A few cities with coordinates, for the impossible-travel detector.
CITIES = {
    "Atlanta":   (33.75, -84.39),
    "New York":  (40.71, -74.01),
    "Chicago":   (41.88, -87.63),
    "Denver":    (39.74, -104.99),
    "Seattle":   (47.61, -122.33),
    "London":    (51.51, -0.13),
    "Singapore": (1.35, 103.82),
    "Moscow":    (55.76, 37.62),
}

# Each user has a persona: home city, typical start hour, and a baseline for
# how many files they read on a normal working day.
USERS = {
    "achdebe":  {"city": "Atlanta",  "start": 9,  "file_mean": 40},
    "bkumar":   {"city": "Chicago",  "start": 8,  "file_mean": 25},
    "cdiaz":    {"city": "Denver",   "start": 10, "file_mean": 60},
    "dlang":    {"city": "Seattle",  "start": 9,  "file_mean": 30},
    "ereyes":   {"city": "New York", "start": 8,  "file_mean": 45},
    "fokafor":  {"city": "Atlanta",  "start": 9,  "file_mean": 20},
    "gpatel":   {"city": "Chicago",  "start": 7,  "file_mean": 55},
    "hsato":    {"city": "Seattle",  "start": 10, "file_mean": 35},
    "ikwan":    {"city": "New York", "start": 9,  "file_mean": 50},
    "jmoore":   {"city": "Denver",   "start": 8,  "file_mean": 28},
}

BASELINE_DAYS = 30
SCORING_DAYS = 7


def _normal_day(user, persona, day, rows):
    """One ordinary working day for a user: a login + some file reads."""
    if day.weekday() >= 5:               # light weekend activity, sometimes none
        if RNG.random() > 0.3:
            return
    city = persona["city"]
    lat, lon = CITIES[city]
    # Login near their usual start hour.
    login_hour = persona["start"] + RNG.integers(-1, 2)
    login_hour = int(np.clip(login_hour, 0, 23))
    ts = day.replace(hour=login_hour, minute=int(RNG.integers(0, 59)))
    rows.append(_event(ts, user, "login", city, lat, lon, files=0, priv=False))
    # File reads across the workday, volume around their baseline.
    n_files = max(0, int(RNG.normal(persona["file_mean"], persona["file_mean"] * 0.2)))
    read_ts = day.replace(hour=int(np.clip(persona["start"] + RNG.integers(0, 8), 0, 23)))
    rows.append(_event(read_ts, user, "file_read", city, lat, lon, files=n_files, priv=False))


def _event(ts, user, etype, city, lat, lon, files, priv, label=0, scenario=""):
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "event_type": etype,
        "city": city,
        "lat": lat,
        "lon": lon,
        "file_count": files,
        "privileged": priv,
        "label": label,          # ground truth — detectors must not read this
        "scenario": scenario,    # human-readable tag for the writeup
    }


def generate(path="data/events.csv"):
    rows = []
    start = datetime(2026, 5, 1, 0, 0, 0)

    # --- baseline window: everyone behaves normally ---
    for d in range(BASELINE_DAYS):
        day = start + timedelta(days=d)
        for user, persona in USERS.items():
            _normal_day(user, persona, day, rows)

    # --- scoring window: mostly normal ... ---
    score_start = start + timedelta(days=BASELINE_DAYS)
    # On days we inject a scenario for a user, skip their auto-generated normal
    # activity so the scenario is the only thing happening — keeps each detector's
    # trigger clean and explainable instead of colliding with a stray login.
    suppress = {
        ("ikwan",   (score_start + timedelta(days=3)).date()),
        ("cdiaz",   (score_start + timedelta(days=4)).date()),
        ("fokafor", (score_start + timedelta(days=5)).date()),
        ("ereyes",  (score_start + timedelta(days=2)).date()),
        ("ereyes",  (score_start + timedelta(days=3)).date()),
    }
    for d in range(SCORING_DAYS):
        day = score_start + timedelta(days=d)
        for user, persona in USERS.items():
            if (user, day.date()) in suppress:
                continue
            _normal_day(user, persona, day, rows)

    # --- ... with injected activity on specific scoring-window days ---

    # THREAT 1 (malicious): impossible travel. ikwan logs in from home, then
    # 30 minutes later from Moscow — no human travels that fast.
    d3 = score_start + timedelta(days=3)
    lat, lon = CITIES["New York"]
    rows.append(_event(d3.replace(hour=9, minute=5), "ikwan", "login",
                       "New York", lat, lon, 0, False, label=1,
                       scenario="impossible_travel"))
    mlat, mlon = CITIES["Moscow"]
    rows.append(_event(d3.replace(hour=9, minute=35), "ikwan", "login",
                       "Moscow", mlat, mlon, 0, False, label=1,
                       scenario="impossible_travel"))

    # THREAT 2 (malicious): off-hours mass file access. cdiaz at 3am pulls ~10x
    # their normal volume — classic data-staging / exfil signal.
    d4 = score_start + timedelta(days=4)
    clat, clon = CITIES["Denver"]
    rows.append(_event(d4.replace(hour=3, minute=12), "cdiaz", "login",
                       "Denver", clat, clon, 0, False, label=1,
                       scenario="offhours_mass_access"))
    rows.append(_event(d4.replace(hour=3, minute=20), "cdiaz", "file_read",
                       "Denver", clat, clon, 620, False, label=1,
                       scenario="offhours_mass_access"))

    # THREAT 3 (malicious): privilege escalation. fokafor (who never has priv
    # actions in baseline) grants themselves rights and touches a lot of files.
    d5 = score_start + timedelta(days=5)
    flat, flon = CITIES["Atlanta"]
    rows.append(_event(d5.replace(hour=14, minute=2), "fokafor", "priv_change",
                       "Atlanta", flat, flon, 0, True, label=1,
                       scenario="privilege_escalation"))
    rows.append(_event(d5.replace(hour=14, minute=10), "fokafor", "file_read",
                       "Atlanta", flat, flon, 180, False, label=1,
                       scenario="privilege_escalation"))

    # BENIGN-BUT-UNUSUAL 1 (label 0): ereyes takes a legitimate business trip.
    # Logs in from Denver the day AFTER their last Atlanta login — a real
    # location change, but at a plausible travel speed. A naive "new city =
    # alert" detector FALSE-POSITIVES here. A tuned one does not.
    d2 = score_start + timedelta(days=2)
    elat, elon = CITIES["New York"]
    rows.append(_event(d2.replace(hour=21, minute=0), "ereyes", "login",
                       "New York", elat, elon, 0, False, label=0,
                       scenario="benign_business_travel"))
    dlat, dlon = CITIES["Denver"]
    rows.append(_event((d2 + timedelta(days=1)).replace(hour=10, minute=0),
                       "ereyes", "login", "Denver", dlat, dlon, 0, False,
                       label=0, scenario="benign_business_travel"))

    # BENIGN-BUT-UNUSUAL 2 (label 0): dlang works one late night, but at NORMAL
    # file volume. Off-hours alone shouldn't alert; off-hours + mass access
    # should. Tests whether the tuning requires corroboration.
    d6 = score_start + timedelta(days=6)
    dllat, dllon = CITIES["Seattle"]
    rows.append(_event(d6.replace(hour=23, minute=40), "dlang", "file_read",
                       "Seattle", dllat, dllon, 32, False, label=0,
                       scenario="benign_late_night"))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    df.to_csv(path, index=False)
    n_mal = int((df["label"] == 1).any() and df.groupby(["user"])["label"].max().sum())
    print(f"Wrote {len(df)} events to {path}")
    print(f"Injected: 3 malicious scenarios + 2 benign-but-unusual decoys")
    return df


if __name__ == "__main__":
    generate()
