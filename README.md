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
pip install -e ".[dev]"          # includes the web API deps; add ",live" for live capture
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

# 3. self-learning over a time-ordered stream (~70 s at 20%)
python experiments/self_learning.py --fraction 0.2                   # with cross-check
python experiments/self_learning.py --fraction 0.2 --no-cross-check  # paper's conflicts only
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

### Self-learning

Streaming the Scenario 2 test flows in time order and retraining after each chunk on the
advised samples (paper Figure 1, steps 8.A-C), each detector's **own** accuracy — before any
advice — rises on attacks it was never trained on (20% sample, seed 0):

| Standalone accuracy | Frozen | Self-learning, cross-check | Self-learning, conflicts only |
|---|---|---|---|
| Detector 2 on DoS Hulk (chunk 1) | 5.66% | 99.74% | 73.33% |
| Detector 1 on PortScan (chunk 9) | 32.51% | 99.87% | 32.18% |

With the paper's conflict-only advice, detector 1 never learns PortScan: it is confidently
wrong on those flows, so it never asks. `notebooks/02_results.ipynb` plots every chunk.

## Distributed system

The same detectors run as independent services over Redis, following the paper's Figure 1:

| Service | Role |
|---|---|
| `nids extract` | **Extractor** — replays a flow CSV, or captures live traffic, into the Unknown Samples stream |
| `nids observe` | **Observer** — routes each batch to the detectors subscribed to its data source |
| `nids detect` | **Detector** — classifies its inbox, requests advice from the others over Redis, answers their requests, optionally retrains (`--retrain-every N`) |
| `nids monitor` | live counters: accuracy, detection rate, conflicts, advice, cross-checks |

Attack decisions are published to the `nids:alerts` stream.

**Natively** (needs a Redis server):

```bash
nids train scenario2 --fraction 0.05     # models/*.joblib + data/replay/scenario2.csv (unseen flows)
nids observe &
nids detect models/detector1.joblib --sources cicids2017 --cross-check &
nids detect models/detector2.joblib --sources cicids2017 --cross-check &
nids extract data/replay/scenario2.csv --source cicids2017 --wait-for 2
nids monitor --once
```

**With Docker, headless** (models are trained inside the image so they match its library versions):

```bash
docker-compose run --rm train
docker-compose --profile headless up redis observer detector1 detector2 extractor monitor
```

Both give 99.58% accuracy and 99.28% detection rate on the 42,112 replayed flows.

### Live traffic

```bash
pip install -e ".[live]"
sudo .venv/bin/nids extract --live eth0 --source cicids2017      # or: --live capture.pcap
```

Flows come from the Python `cicflowmeter` (run through `nids.service.flowmeter`, because the
package's own CLI is broken in 0.5.0) and are converted to CICIDS2017 names and units
(`src/nids/data/flow_features.py`). The Python port computes some features differently
from the Java CICFlowMeter the models were trained on (e.g. packet counts), so accuracy on
live traffic has **not** been measured and will be lower than the experiments.

## Dashboard (Django API + Next.js)

A web dashboard shows the detection as it happens: start/stop a replay, per-detector stats,
throughput, how each decision was made (unanimous / counselor advice / cross-check / fallback)
and the stream of attack alerts, plus a results page with the experiment charts.

```
detector services --Redis--> Django API (DRF + Channels) --REST + WebSocket--> Next.js
```

| API | |
|---|---|
| `POST /api/auth/token/`, `/api/auth/token/refresh/` | JWT login (simplejwt) |
| `GET /api/auth/me/` | current user |
| `GET /api/detectors/` | live counters per detector + replay state |
| `GET /api/alerts/?limit=&after=` | latest attack decisions |
| `GET /api/results/` | experiment comparisons and self-learning curves |
| `GET /api/replay/`, `POST /api/replay/start/`, `POST /api/replay/stop/` | replay control |
| `ws://…/ws/live/?token=<access>` | stats every second, new alerts, reset on a new replay |

The API starts a replay by launching the Observer, one detector service per model in `models/`
and an Extractor as subprocesses — the same services as the command line.

**Locally** (needs Redis, and `nids train scenario2` run once):

```bash
cd backend
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver            # API + WebSocket on :8000 (Daphne)
cd ../frontend && npm install && npm run dev   # dashboard on :3000
```

**With Docker:**

```bash
docker-compose run --rm train
docker-compose run --rm api python manage.py createsuperuser
docker-compose up                     # dashboard on http://localhost:3000
```

Backend settings come from environment variables (or `backend/.env`): `DJANGO_SECRET_KEY`,
`DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `NIDS_REDIS_URL`, `NIDS_ROOT`,
`DJANGO_DB_PATH`. Tests: `cd backend && python manage.py test monitoring`.

## CSE-CIC-IDS2018

`nids.data.cse_cic_ids2018.load_cse_cic_ids2018` loads the 2018 data with CICIDS2017 column
names and real timestamps. It is set aside for later work and not used by the experiments.

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
| `src/nids/data/` | Dataset loaders (NSL-KDD, CICIDS2017, CSE-CIC-IDS2018) and feature-name mapping |
| `src/nids/detector/` | Classifier selection and detection (Algorithms 1 & 2) |
| `src/nids/counselor/` | Advice exchange between detectors |
| `src/nids/scenarios.py` | Scenario setups with signature / validation / test splits |
| `src/nids/service/` | Distributed services: extractor, observer, detector, monitor, live capture |
| `src/nids/cli.py` | `nids` command |
| `experiments/` | `tune.py` (validation), `run.py` (test), `self_learning.py` |
| `notebooks/` | `01` explores the datasets, `02` plots the results — no logic of their own |
| `backend/` | Django API: REST endpoints, JWT auth, WebSocket live feed, replay control |
| `frontend/` | Next.js dashboard |
| `Dockerfile`, `docker-compose.yml` | Container setup |
| `tests/` | pytest suite |
