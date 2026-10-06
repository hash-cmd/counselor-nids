# NIDS — Counselors-Based Intrusion Detection

Reproduction of *A Counselors-Based Intrusion Detection Architecture*
(Quincozes et al., IFIP 2019 — see [documents/](documents/)) in Python with scikit-learn.

Detectors pick the most accurate classifiers per K-Means cluster; when the selected
classifiers disagree, the detector asks other detectors ("counselors") for advice and
learns from the answer.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Datasets go in `data/raw/` — see [data/README.md](data/README.md).

## Running

```bash
pytest                                                    # unit tests (~10 s)

# 1. tune thresholds on the validation set (never touches test)
python experiments/tune.py scenario2 --fraction 0.2
python experiments/tune.py scenario1 --protocol holdout

# 2. evaluate on the test set, mean over seeds 0-2
python experiments/run.py scenario2                       # ~5 min, ~842k test flows per seed
python experiments/run.py scenario1 --protocol kddtest --cross-check-alpha 0.005
python experiments/run.py scenario1 --protocol holdout --cross-check-min-accuracy 0.99
```

Unknown traffic is split into validation (tuning) and test (reporting): Scenario 2 uses
20% signatures / 10% validation / 70% test; Scenario 1 uses 1,000 validation and 1,000 test samples.
Each run prints the comparison against the paper's baselines and writes CSVs, `summary.json`
and a Figure 3/4-style chart to `results/<scenario>/`.

## Results (test set, mean of 3 seeds)

Scenario 2, CICIDS2017 — accuracy:

| | Detector 1 | Detector 2 |
|---|---|---|
| Paper, proposed solution (reported) | 88.36% | 74.57% |
| Ours, paper's method | 83.01% | 83.77% |
| **Ours, + cross-check** | **99.88%** | **99.88%** |
| Ours, "any detector says attack" baseline | 99.89% | 99.89% |
| Ours, best single classifier | 82.98% | 83.54% |

The **cross-check** extension (`CounselorNetwork(cross_check_normal=True)`) addresses the paper's
"limited vision" case: a detector cannot raise a conflict about an attack class it never trained
on, so it confidently calls those flows normal (detector 1 misses ~98% of PortScan). With
cross-checking, every "normal" verdict is checked with the counselors and a confident "attack"
advice wins. Its gain comes from sharing knowledge between detectors — a plain OR of the
detectors does as well here, because both have near-zero false alarms.

Scenario 1 (NSL-KDD) has no overall accuracy in the paper. With `kddtest` the cross-check helps
the traffic detector (72.7% → 80.4%) but not the connection detector; with `holdout` all
methods are ~99% for connection/traffic.

## Differences from the paper

- scikit-learn stand-ins for the Weka classifiers; NBTree, ADTree and KStar are not available
  (see `src/nids/detector/classifiers.py`).
- The paper does not say which NSL-KDD features each Scenario 1 detector sees; we use the
  dataset's own groups (connection / content / traffic).
- CICIDS2017 ML CSVs have no timestamps, and NSL-KDD has none at all. Detectors in each scenario
  view the same records, so advice is matched on `record_id` with a zero window; the
  2-second window is supported for timestamped data.
- Unspecified in the paper, chosen here: advice acceptance threshold 0.9; a counselor answers
  with its highest-confidence unambiguous decision in the window; voting ties count as attacks.
- Numeric features are log-compressed before scaling; without it K-Means on CICIDS2017 puts
  single outlier flows in their own clusters.
- Scenario 2 tests on 70% of the data instead of 80%, to keep a validation set for tuning.
- "Single classifier (max)" picks the best classifier per metric *on the test set* — an
  oracle the paper also reports, not something a deployed system could choose.

## Layout

| Path | Contents |
|---|---|
| `src/nids/data/` | Dataset loaders (NSL-KDD, CICIDS2017) |
| `src/nids/detector/` | Classifier selection and detection (Algorithms 1 & 2) |
| `src/nids/counselor/` | Advice exchange between detectors |
| `src/nids/scenarios.py` | Scenario setups with signature / validation / test splits |
| `experiments/` | `tune.py` (validation) and `run.py` (test) |
| `notebooks/` | Exploration only — imports the loaders, holds no cleaning logic (`jupyter lab`) |
| `tests/` | pytest suite |
