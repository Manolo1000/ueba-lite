# ueba-lite

A small **User & Entity Behavior Analytics** engine for insider-threat detection:
it baselines each user's normal behavior, flags deviations (off-hours access,
impossible travel, mass file reads, privilege changes), and — the part that
matters — **measures its own false-positive rate against ground truth** so the
detection can be *tuned*, not just demonstrated.

> **Status:** detectors and evaluation working end-to-end on labeled synthetic
> data. Tuning model in active development.
> Run: `python generate_data.py` then `python main.py`.

---

## Why this exists

An insider-threat analyst doesn't struggle to *find* anomalies — logs are full of
them. The job is deciding which handful are worth investigating without drowning
in false alarms. So the interesting problem isn't detection, it's **tuning**: how
do you catch the real thing while ignoring the employee who legitimately worked
late or traveled for business?

To make tuning *measurable*, this runs on synthetic data with ground-truth labels
— a 30-day normal baseline, three genuine insider-threat scenarios, and two
benign-but-unusual decoys designed to fool a naive detector. Because the answer
is known, every tuning change produces a real precision/recall number.

## How it works

```
generate ──▶ baseline ──▶ detect ──▶ score/tune ──▶ evaluate
labeled      per-user      off-hours   combine into    precision /
synthetic    normal        travel      ranked alerts   recall vs.
activity     profiles      mass-access (YOUR tuning)   ground truth
                           priv-change
```

| Detector | Fires on |
|---|---|
| impossible_travel | logins implying faster-than-a-flight travel |
| off_hours | activity outside the user's own normal hours (weak alone) |
| mass_access | file volume far above the user's own baseline |
| privilege_change | privileged actions, esp. by users who never had them |

## The tuning model

<!--
  TODO — WRITE THIS SECTION YOURSELF. It's what gets you the insider-threat job.
  Explain:
    - how you weight each detector (impossible travel = strong evidence;
      off-hours = weak on its own)
    - how you aggregate signals, and why rewarding CORROBORATION crushes false
      positives (off-hours + mass-access together >> either alone)
    - where you set the alert line, and the precision/recall tradeoff at that
      point (quote the numbers from evaluate.py)
    - where the model goes blind: the slow, patient insider who stays just under
      every threshold. Naming this is the most senior thing you can say.
  See score.py — the current logic is a deliberately loose placeholder that
  scores ~0.6 precision. Getting it to 1.0 without losing recall is the project.
-->

## Results (fill in after tuning)

<!--
  TODO — the money table. Something like:
    naive model:  precision 0.60, recall 1.00  (2 false alarms)
    tuned model:  precision 1.00, recall 1.00  (0 false alarms)
  and one sentence on the single change that got you there.
-->

## Quickstart

```bash
git clone <your-repo-url> && cd ueba-lite
python -m venv .venv && .venv\Scripts\Activate.ps1     # Windows
pip install -r requirements.txt
python generate_data.py
python main.py
```

## Note on Splunk

The detections are written in Python for portability, but each maps to a Splunk
SPL correlation search (`stats`/`eventstats` for baselining, `geostats` for
travel). Prototyped here; in a Splunk shop these become scheduled searches.

## Limitations

<!-- TODO — synthetic data, coarse user-day granularity, no entity relationships,
     the low-and-slow blind spot. Honesty here reads as maturity. -->
