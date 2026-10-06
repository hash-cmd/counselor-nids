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

## Layout

| Path | Contents |
|---|---|
| `src/nids/data/` | Dataset loaders (NSL-KDD, CICIDS2017) |
| `src/nids/detector/` | Classifier selection and detection (Algorithms 1 & 2) |
| `src/nids/counselor/` | Advice exchange between detectors |
| `experiments/` | Scripts reproducing the paper's Scenario 1 and 2 |
| `tests/` | pytest suite |
