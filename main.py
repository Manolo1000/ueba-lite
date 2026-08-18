"""
main.py — Orchestrator. generate (optional) -> parse -> baseline -> detect ->
score -> evaluate. Writes an alert queue and prints a detection scorecard.

Usage:
    python generate_data.py          # once, to create data/events.csv
    python main.py
"""

import os
import pandas as pd

from baseline import load_events, split_windows, build_baselines
from detectors import run_all
from score import score_alerts
from evaluate import print_report


def run(events_path="data/events.csv", out_dir="output"):
    events = load_events(events_path)
    baseline, scoring = split_windows(events)
    profiles = build_baselines(baseline)

    signals = run_all(scoring, profiles)
    alerts = score_alerts(signals)

    os.makedirs(out_dir, exist_ok=True)
    alerts.to_csv(os.path.join(out_dir, "alerts.csv"), index=False)

    print(f"{len(scoring)} scoring events -> {len(signals)} raw signals "
          f"-> {int(alerts['alert'].sum())} alerts")
    print("\nTop of alert queue:")
    cols = ["user", "date", "risk_score", "detectors", "alert"]
    print(alerts.head(8)[cols].to_string(index=False))

    # The part that sells it: how good is the tuning, measured?
    print_report(alerts, events)
    print(f"\nWrote {out_dir}/alerts.csv")
    return alerts


if __name__ == "__main__":
    run()
