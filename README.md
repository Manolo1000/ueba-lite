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

## The analyst console
 
`dashboard.html` is a self-contained investigation console — the alert queue,
per-alert detector evidence, and the precision/recall scorecard, with each alert
carrying its true-positive / false-positive verdict. It's a single file with the
run data embedded, so it opens straight from disk and hosts on GitHub Pages with
no server.
 
```bash
python export_dashboard.py   # refresh the console with the latest run
# then open dashboard.html, or host it:
#   commit it to a GitHub Pages repo and link the live URL on your resume
```
 
Re-run `export_dashboard.py` after you tune `score.py` and the console updates
itself — so the precision number a reviewer sees is always your current model.
 
## The tuning model

The detectors find anomalies; the tuning model decides which ones are worth
waking an analyst for. That decision — not the detection — is the craft.
 
**Detectors are weighted by how much evidence they carry.** Impossible travel and
a novel privilege escalation are hard to explain away; off-hours activity alone is
weak — people work late. So off-hours is deliberately low-weight and shouldn't
raise an alert on its own.
 
**Signals are aggregated to reward corroboration.** A user-day that trips several
detectors is far more suspicious than one weak hit, and corroboration is the single
strongest false-positive killer available: off-hours *plus* a mass-file-read is a
real signal; off-hours by itself is noise. The naive baseline in `score.py` simply
sums weighted signals with a loose threshold — which is exactly why it over-fires.
 
**The alert line is a measured tradeoff, not a guess.** Because the data is
labeled, `evaluate.py` reports precision and recall at any setting, so the
threshold can be chosen against real numbers rather than intuition.
 
**Where it goes blind:** the slow, patient insider who stays just under every
threshold — a little off-hours here, a slightly elevated read there, never enough
to corroborate. No single-window detector catches that; it needs longer-horizon
trend baselining. Naming that limit matters more than pretending it isn't there.

## Results 

Measured against ground truth on the sample run:
 
| Model | Precision | Recall | False alarms |
|---|---|---|---|
| Naive baseline (`score.py` as shipped) | 0.60 | 1.00 | 2 |
| Tuned (require corroboration for weak signals) | 1.00 | 1.00 | 0 |
 
Both false alarms in the baseline are lone off-hours signals — a legitimate
late-night session and a business trip. Requiring a second detector before an
off-hours alert removes both without missing any of the three real threats, all of
which are corroborated. `python export_dashboard.py` refreshes the console so these
numbers always reflect the current model.

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

A working proof of concept, not production software:
 
- **Synthetic data.** Labeled and reproducible by design — which is what makes the
  precision/recall measurement possible — but real logs are messier and unlabeled.
- **Coarse granularity.** Scoring is per user-day; a real system would score
  streaming windows and correlate across sessions.
- **No entity relationships.** Users are scored in isolation; peer-group and
  role-based baselining (is this odd for *this team*, not just this person?) is a
  natural extension.
- **The low-and-slow blind spot** described above — the model keys on deviations
  large enough to cross a threshold, and a patient insider can stay beneath them.
- **Splunk parity is described, not deployed.** The SPL mappings are noted but the
  detections run in Python here.
