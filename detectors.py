"""
detectors.py — Detection layer.

Each detector compares scoring-window activity against a user's baseline and
emits signals: (user, date, detector, raw_value, severity 0..1).

The detector MECHANICS here are fairly standard — the judgment you're selling
lives in score.py, where you decide how these signals combine, how much to
trust each one, and where to draw the alert line. But the detectors do carry
one important idea worth defending: each one is designed to be *specific*.
Off-hours activity alone is weak evidence (people work late); off-hours PLUS
volume is strong. The mass-access detector keys on deviation from the user's
own baseline, not a global threshold, so a naturally high-volume user isn't
perpetually flagged. That specificity is what keeps false positives down.

Note: the same logic expresses cleanly as Splunk SPL correlation searches
(stats by user, eventstats for baselines, geostats for travel). Prototyped in
Python here for portability; in a Splunk shop these become scheduled searches.
"""

import math
import pandas as pd


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance between two points, in km."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def detect_impossible_travel(scoring, max_speed_kmh=900.0):
    """Consecutive logins implying travel faster than a commercial flight."""
    out = []
    logins = scoring[scoring["event_type"] == "login"].sort_values("timestamp")
    for user, g in logins.groupby("user"):
        g = g.sort_values("timestamp")
        prev = None
        for _, row in g.iterrows():
            if prev is not None and row["city"] != prev["city"]:
                hours = (row["timestamp"] - prev["timestamp"]).total_seconds() / 3600.0
                dist = _haversine_km(prev["lat"], prev["lon"], row["lat"], row["lon"])
                speed = dist / hours if hours > 0 else float("inf")
                if speed > max_speed_kmh:
                    # severity scales with how impossible it is, capped at 1.
                    sev = min(1.0, speed / (max_speed_kmh * 5))
                    out.append({
                        "user": user, "date": row["timestamp"].date(),
                        "detector": "impossible_travel",
                        "raw_value": round(speed, 0), "severity": round(sev, 2),
                    })
            prev = row
    return out


def detect_off_hours(scoring, baselines):
    """Activity outside the user's established active-hours band."""
    out = []
    for _, row in scoring.iterrows():
        p = baselines.get(row["user"])
        if not p:
            continue
        lo, hi = p["hour_lo"], p["hour_hi"]
        # widen the normal band a little so ordinary variance isn't flagged
        if row["hour"] < (lo - 1) or row["hour"] > (hi + 1):
            # how far outside, normalized to a quarter-day
            dist = min(abs(row["hour"] - lo), abs(row["hour"] - hi))
            out.append({
                "user": row["user"], "date": row["timestamp"].date(),
                "detector": "off_hours",
                "raw_value": int(row["hour"]), "severity": round(min(1.0, dist / 6), 2),
            })
    return out


def detect_mass_access(scoring, baselines, z_threshold=3.0):
    """Daily file volume far above the user's OWN normal (z-score based)."""
    out = []
    reads = scoring[scoring["event_type"] == "file_read"]
    daily = reads.groupby(["user", "date"])["file_count"].sum().reset_index()
    for _, row in daily.iterrows():
        p = baselines.get(row["user"])
        if not p or p["file_std"] <= 0:
            continue
        z = (row["file_count"] - p["file_mean"]) / p["file_std"]
        if z > z_threshold:
            out.append({
                "user": row["user"], "date": row["date"],
                "detector": "mass_access",
                "raw_value": int(row["file_count"]), "severity": round(min(1.0, z / 10), 2),
            })
    return out


def detect_privilege_change(scoring, baselines):
    """Privileged actions, weighted up for users who never had them in baseline."""
    out = []
    priv = scoring[scoring["privileged"] == True]  # noqa: E712
    for _, row in priv.iterrows():
        p = baselines.get(row["user"])
        novel = p is not None and not p["ever_privileged"]
        out.append({
            "user": row["user"], "date": row["timestamp"].date(),
            "detector": "privilege_change",
            "raw_value": 1, "severity": 1.0 if novel else 0.5,
        })
    return out


def run_all(scoring, baselines) -> pd.DataFrame:
    signals = []
    signals += detect_impossible_travel(scoring)
    signals += detect_off_hours(scoring, baselines)
    signals += detect_mass_access(scoring, baselines)
    signals += detect_privilege_change(scoring, baselines)
    return pd.DataFrame(signals, columns=["user", "date", "detector",
                                          "raw_value", "severity"])
