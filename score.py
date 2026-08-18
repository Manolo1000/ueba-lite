"""
score.py — THE TUNING ENGINE.  *** THIS ONE IS YOURS. ***
===========================================================================
detectors.py finds things. This file decides which of those things are worth
waking a human for. That decision — the false-positive tuning — is the entire
craft of insider-threat analysis, and it's what you're selling. When an
interviewer asks "how did you keep this from drowning the analyst in noise?",
the answer has to be yours.

The logic below is a DELIBERATELY NAIVE placeholder so the pipeline runs today.
Replacing it is the project. Use evaluate.py to measure every change: it tells
you exactly how many real threats you catch vs. how many false alarms you raise
at any setting. That feedback loop is the thing to show off.

Decisions that are yours to make and defend:

  1. WEIGHTING. Not all detectors are equal evidence. Impossible travel is
     hard to explain away; off-hours activity is weak on its own. How much do
     you trust each? (DETECTOR_WEIGHTS below.)

  2. AGGREGATION. When one user-day trips several detectors, is that a sum, a
     max, or something that rewards CORROBORATION (off-hours AND mass access
     together is far more than either alone)? Your call — and corroboration is
     the strongest false-positive killer you have.

  3. THE ALERT LINE. Where do you cut? Too low and the analyst quits reading;
     too high and you miss the real one. evaluate.py quantifies this tradeoff
     so you can pick a defensible point instead of a vibe.

  4. Where it goes blind: a slow, patient insider who stays just under every
     threshold. Name that limitation — it's the most senior thing you can say.
===========================================================================
"""

import pandas as pd


# ---- naive knobs you will replace with a defended model ----
DETECTOR_WEIGHTS = {
    "impossible_travel": 1.0,
    "privilege_change":  0.9,
    "mass_access":       0.8,
    "off_hours":         0.4,   # weak alone — should really need corroboration
}
ALERT_THRESHOLD = 0.4          # DELIBERATELY LOOSE — a single weak signal
                               # (e.g. off_hours alone) trips it, which is why
                               # this naive version has false positives. Fixing
                               # that is your job. tune me against evaluate.py.


def score_alerts(signals: pd.DataFrame) -> pd.DataFrame:
    """
    Collapse per-detector signals into one risk score per (user, date),
    then flag alerts. PLACEHOLDER aggregation: weighted sum of severities.
    Replace with your real model (try rewarding corroboration).
    """
    if signals.empty:
        return pd.DataFrame(columns=["user", "date", "risk_score",
                                     "detectors", "alert"])

    signals = signals.copy()
    signals["weighted"] = signals.apply(
        lambda r: r["severity"] * DETECTOR_WEIGHTS.get(r["detector"], 0.5), axis=1
    )

    rows = []
    for (user, date), g in signals.groupby(["user", "date"]):
        # NAIVE: just add them up. A better model might multiply a corroboration
        # bonus when >1 distinct detector fires on the same user-day.
        risk = round(g["weighted"].sum(), 2)
        rows.append({
            "user": user, "date": date, "risk_score": risk,
            "detectors": ", ".join(sorted(g["detector"].unique())),
            "alert": risk >= ALERT_THRESHOLD,
        })

    out = pd.DataFrame(rows).sort_values("risk_score", ascending=False)
    return out.reset_index(drop=True)
