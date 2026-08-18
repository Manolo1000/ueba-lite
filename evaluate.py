"""
evaluate.py — The feedback loop that makes your tuning defensible.

Because the data has ground-truth labels, we can score your detection like a
real classifier: of the user-days you alerted on, how many were truly malicious
(precision), and of the truly malicious user-days, how many did you catch
(recall)? This is the number that turns "I built a UEBA thing" into "I tuned it
to catch 3/3 real threats at 1 false positive, and here's the tradeoff curve."

Granularity: a (user, date) is TRULY malicious if it contained any label==1
event. An ALERT is correct if it lands on such a user-day.
"""

import pandas as pd


def truth_by_user_day(events: pd.DataFrame) -> set:
    """Set of (user, date) that actually contained injected malicious activity."""
    mal = events[events["label"] == 1]
    return set(zip(mal["user"], mal["date"]))


def evaluate(alerts: pd.DataFrame, events: pd.DataFrame) -> dict:
    truth = truth_by_user_day(events)
    fired = set(zip(alerts.loc[alerts["alert"], "user"],
                    alerts.loc[alerts["alert"], "date"]))

    tp = len(fired & truth)
    fp = len(fired - truth)
    fn = len(truth - fired)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": round(precision, 2), "recall": round(recall, 2),
        "f1": round(f1, 2),
        "missed": sorted(truth - fired),      # real threats you didn't catch
        "false_alarms": sorted(fired - truth),  # noise you'd have paged on
    }


def print_report(alerts, events):
    m = evaluate(alerts, events)
    print("\n=== Detection performance vs. ground truth ===")
    print(f"  Precision: {m['precision']}   Recall: {m['recall']}   F1: {m['f1']}")
    print(f"  Caught {m['true_positives']} real threats, "
          f"{m['false_positives']} false alarms, missed {m['false_negatives']}.")
    if m["false_alarms"]:
        print(f"  False alarms on: {m['false_alarms']}")
    if m["missed"]:
        print(f"  MISSED: {m['missed']}")
    return m
