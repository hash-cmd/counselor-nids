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
pytest                                                   # unit tests (~10 s)
python experiments/scenario1_nsl_kdd.py                  # Scenario 1, NSL-KDD (~15 s)
python experiments/scenario2_cicids2017.py --fraction 0.1  # Scenario 2, quick run (~30 s)
python experiments/scenario2_cicids2017.py               # Scenario 2, full ~1M flows
```

Each run prints the comparison against the paper's baselines and writes CSVs, `summary.json`
and a Figure 3/4-style chart to `results/<scenario>/`. See `--help` for thresholds.

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

## Layout

| Path | Contents |
|---|---|
| `src/nids/data/` | Dataset loaders (NSL-KDD, CICIDS2017) |
| `src/nids/detector/` | Classifier selection and detection (Algorithms 1 & 2) |
| `src/nids/counselor/` | Advice exchange between detectors |
| `experiments/` | Scripts reproducing the paper's Scenario 1 and 2 |
| `notebooks/` | Exploration only — imports the loaders, holds no cleaning logic (`jupyter lab`) |
| `tests/` | pytest suite |
