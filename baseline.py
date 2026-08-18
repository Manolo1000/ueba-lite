"""
parse_logs.py + baseline.py combined — Ingest and profiling layers.

parse_logs: normalize the raw log into a typed events DataFrame and split it
into the baseline window (what "normal" looks like) and the scoring window
(what we're judging).

baseline: build a per-user behavioral profile from the baseline window. This is
the "U" and "E" in UEBA — you can't spot abnormal until you've defined normal,
and normal is PER USER (gpatel reading 55 files is fine; fokafor reading 55 is
not). Plumbing, but conceptually the heart of behavior analytics.
"""

import pandas as pd


def load_events(path="data/events.csv") -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["date"] = df["timestamp"].dt.date
    df["hour"] = df["timestamp"].dt.hour
    return df


def split_windows(df: pd.DataFrame, baseline_days: int = 30):
    """Everything before the cutoff trains the baseline; the rest is scored."""
    cutoff = df["timestamp"].min().normalize() + pd.Timedelta(days=baseline_days)
    baseline = df[df["timestamp"] < cutoff].copy()
    scoring = df[df["timestamp"] >= cutoff].copy()
    return baseline, scoring


def build_baselines(baseline: pd.DataFrame) -> dict:
    """
    Per-user normal profile:
      - active_hours: the band of hours they normally operate in (min/max seen)
      - file_mean / file_std: their normal daily file-read volume
      - home_cities: the set of locations they normally log in from
      - ever_privileged: whether they ever perform privileged actions
    """
    profiles = {}
    for user, g in baseline.groupby("user"):
        logins = g[g["event_type"] == "login"]
        reads = g[g["event_type"] == "file_read"]
        daily_files = reads.groupby("date")["file_count"].sum()
        # Active-hours band is built from ALL activity (logins AND file reads),
        # otherwise a normal 2pm file read looks "off-hours" against a 9am login
        # baseline — a classic self-inflicted false positive.
        profiles[user] = {
            "hour_lo": int(g["hour"].quantile(0.05)) if len(g) else 0,
            "hour_hi": int(g["hour"].quantile(0.95)) if len(g) else 23,
            "file_mean": float(daily_files.mean()) if len(daily_files) else 0.0,
            "file_std": float(daily_files.std(ddof=0)) if len(daily_files) > 1 else 1.0,
            "home_cities": set(logins["city"].unique()),
            "ever_privileged": bool(g["privileged"].any()),
        }
    return profiles


if __name__ == "__main__":
    df = load_events()
    base, score = split_windows(df)
    profs = build_baselines(base)
    print(f"{len(base)} baseline events, {len(score)} scoring events")
    for u, p in list(profs.items())[:3]:
        print(u, "hours", (p["hour_lo"], p["hour_hi"]),
              "files ~", round(p["file_mean"], 1), "from", p["home_cities"])
