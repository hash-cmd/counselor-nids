# NIDS — Counselors-Based Intrusion Detection

Reproduction of *A Counselors-Based Intrusion Detection Architecture*
(Quincozes et al., IFIP 2019 — see [docs/paper/](docs/paper/)) in Python with scikit-learn.

Detectors pick the most accurate classifiers per K-Means cluster; when the selected
classifiers disagree, the detector asks other detectors ("counselors") for advice and
learns from the answer.

## Quick start

```bash
./start.sh setup              # once: Python env, packages, database, login user, models, demo capture
./start.sh                    # dashboard on http://localhost:3000 — start replays from the browser
./start.sh live eth0          # Snort + ML on a network interface, plus the dashboard (asks for sudo)
./start.sh live capture.pcap  # the same on a recorded capture
./start.sh --prod             # production servers (Daphne, optimised build, DEBUG off); also: --prod live wlan0
```

Needs Python 3.11+, Node, Redis (started for you if installed but not running) and, for the
Snort side, Snort 3. Ctrl+C stops everything; logs are in `logs/`. Training the models needs
the datasets in `data/raw/` (see [docs/datasets.md](docs/datasets.md)).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"          # includes the web API deps; add ",live" for live capture
```

Datasets go in `data/raw/` — see [docs/datasets.md](docs/datasets.md).

## Running

```bash
pytest                                                    # unit tests (~10 s)

# 1. tune thresholds on the validation set (never touches test)
python experiments/tune.py scenario2 --fraction 0.2
python experiments/tune.py scenario1 --protocol holdout

# 2. evaluate on the test set, mean over seeds 0-2
python experiments/evaluate.py scenario2                       # ~5 min, ~842k test flows per seed
python experiments/evaluate.py scenario1 --protocol kddtest --cross-check-alpha 0.005
python experiments/evaluate.py scenario1 --protocol holdout --cross-check-min-accuracy 0.99

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

Flows come from the Python `cicflowmeter`, run through `nids.capture.flowmeter`, which works
around two bugs in cicflowmeter 0.5.0: its CLI passes arguments in the wrong order, and a flow
without forward packets crashes its flow-writing thread (live capture would silently stop).
Live traffic is analysed by the **live detectors** (below), not the CSV-trained ones. See
[docs/live-testing.md](docs/live-testing.md) for testing on your own network.

## Dashboard (Django API + Next.js)

A web dashboard shows the detection as it happens:

| Page | |
|---|---|
| **Overview** | traffic controls, headline numbers with a plain-language verdict and severity breakdown, the top-risk attackers, ML vs Snort detections over time, who flagged each flow, attack types and Snort rules, latest alerts |
| **Alerts** | every flagged flow once, each with a **severity** (Critical/High/Medium/Low) and a plain explanation; an **Attackers** view grouping alerts by source IP into ranked "attack stories" (scan → brute force → …) with behavioural threat scoring (escalating / persistent / multi-target); filter, full-history server-side search, and a Print/PDF report |
| **Detectors** | each ML detector: counters, throughput, how decisions were made (unanimous / counselor advice / cross-check / fallback) |
| **Results** | the experiment comparisons and self-learning curves |

The dashboard is written for a non-expert (AI / rule checker rather than ML / Snort), with a
grouped collapsible sidebar. A header **bell** raises desktop/sound notifications on new
high-severity alerts; an attacker's **Block this IP** action generates a ready-to-paste
firewall command (it never runs anything privileged, and warns on local addresses).

**Offline IP reputation** (optional): `python scripts/fetch_blocklists.py` downloads public
blocklists into `data/blocklists/`; the dashboard then badges known-bad source IPs. The
lookup is local (`GET /api/reputation/`), so no address ever leaves the machine; with no
lists installed the feature is simply inactive.

Live data comes over one WebSocket shared by all pages. A capture started with
`./start.sh live wlan0` shows up as "Live capture running".

```
detector services --Redis--> Django API (DRF + Channels) --REST + WebSocket--> Next.js
```

| API | |
|---|---|
| `POST /api/auth/login/`, `/refresh/`, `/logout/` | dashboard login: sets / renews / clears httpOnly cookies |
| `POST /api/auth/token/`, `/api/auth/token/refresh/` | JWT tokens for scripts (Bearer header) |
| `GET /api/auth/me/` | current user |
| `GET /api/detectors/` | live counters per detector + replay state |
| `GET /api/alerts/?limit=&after=` | latest attack decisions |
| `GET /api/incidents/?source=&q=&limit=&offset=` | flagged flows with ML and Snort verdicts, over the full history |
| `GET /api/results/` | experiment comparisons and self-learning curves |
| `GET /api/reputation/?ips=` | which of the given IPs are on the local blocklists (offline) |
| `GET /api/replay/`, `POST /api/replay/start/`, `POST /api/replay/stop/` | replay control |
| `ws://…/ws/live/` | stats every second, new alerts, reset on a new replay (cookie, or `?token=` for scripts) |

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
echo "DJANGO_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" > .env
docker-compose run --rm train
docker-compose run --rm api python manage.py createsuperuser
docker-compose up                     # dashboard on http://localhost:3000
```

**Security.** The session lives in httpOnly, SameSite=Strict cookies (JavaScript never sees a
token); state-changing requests also need an `X-NIDS-Client` header; login is limited to 10
attempts a minute per client (`LOGIN_RATE`). With `DJANGO_DEBUG=0` the API refuses to start
without a real `DJANGO_SECRET_KEY` (32+ characters) and sends security headers. Serving beyond
localhost: put an HTTPS reverse proxy in front and set `AUTH_COOKIE_SECURE=1`,
`SECURE_SSL_REDIRECT=1`, `SECURE_HSTS_SECONDS`, `DJANGO_ALLOWED_HOSTS` and
`CORS_ALLOWED_ORIGINS`. Docker needs `DJANGO_SECRET_KEY` in a `.env` file next to
`docker-compose.yml`. Scripts can still use `POST /api/auth/token/` and a Bearer header.

Backend settings come from environment variables (or `backend/.env`): `DJANGO_SECRET_KEY`,
`DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `NIDS_REDIS_URL`, `NIDS_ROOT`,
`DJANGO_DB_PATH`. Tests: `cd backend && python manage.py test api`.

## Snort alongside the ML

Snort and the ML detectors analyse the **same traffic** — a packet capture or a live
interface. Every Snort alert is linked to the flow it belongs to, and the ML detectors give
their verdict on that flow through the same advice request they use with each other:

| Agreement | Meaning |
|---|---|
| **Confirmed** | Snort flagged it and the ML says attack |
| **Disputed** | Snort flagged it, the ML says normal (a possible Snort false alarm, or an attack the ML was never trained on) |
| **ML only** | the ML flagged a flow Snort had no alert for |

```
packets ──> Snort (snort/nids.lua, snort/rules/nids.rules) ──> alert_json ─┐
        └─> flow extractor ──> ML detectors ──> verdicts ──────────────────┴─> correlator ──> Redis ──> dashboard
```

- An alert is linked by connection (both IPs, ports, protocol, either direction) and time:
  the alert must fall inside the flow's start-to-end window (`src/nids/services/flow_index.py`).
- Host-level alerts — a port scan stands for many probe connections — are linked to every
  flow between the two hosts within ±30 s.
- Detectors are specialists, so the ML verdict is *attack* if any detector with acceptable
  accuracy says so (the same reasoning as cross-checking).

```bash
nids observe --exit-on-end &
nids detect models/live/live_dos.joblib --sources live --cross-check --exit-on-end &
nids detect models/live/live_access.joblib --sources live --cross-check --exit-on-end &
nids snort --pcap data/pcap/real-attacks-2018.pcap &
nids extract --live data/pcap/real-attacks-2018.pcap --source live --wait-for 2
```

Or pick the capture in the dashboard and tick **Run Snort on the same traffic**. Live:
`sudo nids snort --interface eth0` next to `sudo nids extract --live eth0 ...`; with an
existing Snort, `nids snort --follow /var/log/snort/alert_json.txt` (it needs the `seconds`,
address, port and `proto` fields in `alert_json`).

On `real-attacks-2018.pcap` — real CSE-CIC-IDS2018 traffic from the late part of each attack,
which the live detectors never trained on — the whole system (flow meter, live detectors,
Snort, correlator) flags:

| Traffic | Flows | ML (live detectors) | Snort | Either |
|---|---|---|---|---|
| DoS GoldenEye | 2,046 | 100.0% | 4.4% | 100.0% |
| DoS Hulk | 4,153 | 99.6% | 30.5% | 99.6% |
| DoS SlowHTTPTest | 4,450 | 100.0% | 99.6% | 100.0% |
| DoS Slowloris | 1,352 | 56.7% | 0.0% | 56.7% |
| FTP brute force | 5,040 | 100.0% | 99.6% | 100.0% |
| SSH brute force | 359 | 98.3% | 76.3% | 98.9% |
| Web attacks | 4 | 4 of 4 | 0 | 4 of 4 |
| **Normal (false alarms)** | 1,768 | **0.0%** | **0.0%** | **0.0%** |

The ML confirms 11,077 of Snort's 11,079 alerts and catches the DoS attacks Snort's rules
miss; Snort adds its payload rules. Slowloris is the weak spot, and varies between runs
(57-67%): the flow meter times flows out by wall clock, so slow connections split differently.

`demo-attacks.pcap` is **synthetic** (generated packets): Snort catches its attacks but the
live detectors, trained on real traffic, flag none of them — a reminder that the ML only knows
what it was trained on.

Snort tuning (`snort/`): inspectors' built-in protocol-anomaly alerts are off (they flagged
TLS sessions seen mid-stream as attacks — 35% of normal flows on the real capture); only the
port-scan alerts (gid 122, except "open port") are on, and scan reports from port 53 are
ignored (DNS answers looked like a UDP port scan). The FTP/SSH brute-force rules use a wide
120 s window (10 and 15 connections) so **low-and-slow** guessing — paced to slip under a
short-window threshold — is still caught; a fast burst falls inside the same window, so this
only adds coverage. Verified: it flags a 12-attempt-over-88 s brute force that a 20-in-10 s
rule misses, fires on none of a benign FTP session (control + passive-data connections), and
still flags only the attackers (not the benign workstation) on `real-attacks-2018.pcap`. Snort
is not in the Docker image (Debian has no package), so in Docker pcap replays run with the ML only.

The table above uses the project's 34 rules (`snort/rules/nids.rules`) only. `./start.sh setup`
also downloads the 4,017 **Snort 3 community rules** (exploits, malware, C2, policy) into
`snort/rules/community/`, which `nids.lua` loads when present; `NIDS_SNORT_COMMUNITY=0` leaves
them out. On `real-attacks-2018.pcap` they add 859 alerts to Snort's 11,079:

| Community rule | Alerts | On |
|---|---|---|
| OS-LINUX Challenge ACK provocation (sid 40063) | 651 | the Slowloris attacker — the DoS the ML is weakest on |
| INDICATOR-SHELLCODE ssh CRC32 overflow filler (1325) | 13 | the SSH brute-force attacker |
| POLICY-OTHER Windows Terminal server request (1448) | 165 | internet hosts connecting to the workstation's RDP port |
| OS-WINDOWS SMB anonymous IPC share access (42340) | 29 | internet hosts probing the workstation's SMB port |
| PROTOCOL-ICMP Destination Unreachable (404) | 1 | — |

The last three are on traffic the dataset labels normal: the lab's workstation was reachable
from the internet, and these are outside scanners rather than the planned attacks. Against
the dataset's labels they count as false alarms (195 alerts); on your own network, expect the
RDP and SMB policy rules to fire on ordinary Windows use.

## Wider coverage: detector 3 (CSE-CIC-IDS2018)

Detectors 1 and 2 know DoS, DDoS and PortScan (CICIDS2017). Detector 3 learns brute force,
botnet and web attacks from CSE-CIC-IDS2018 and joins the counselors network
(`models/detector3.joblib`, used for flow-record replays):

```bash
python experiments/wider_coverage.py --skip infiltration --benign2017 0.2 --save
```

| CSE-CIC-IDS2018 test | Detectors 1+2 | 1+2+3 |
|---|---|---|
| Bot | 0.2% | 99.9% |
| FTP / SSH brute force | 0.0% | ~100% |
| Web brute force / XSS / SQL injection | 7-11% | 44% / 77% / 31% |
| Benign (false alarms) | 5.23% | 5.24% |

On the CICIDS2017 test, adding detector 3 changes nothing (accuracy 99.59% → 99.58%, false
alarms 0.17% → 0.17%). Infiltration is left out: its flows look like normal traffic in this
dataset, and learning them raised false alarms from 0.17% to 6.2%. This set-up was chosen
after seeing the test results (the reasons are principled, but a fresh validation set would
be stricter).

`load_cse_cic_ids2018` reads the files in chunks and samples benign flows to fit in memory.
Note the CSV timestamps are a 12-hour clock without AM/PM.

## Live detectors (Python flow meter)

Live capture computes features with the Python cicflowmeter, which differs from the Java
CICFlowMeter behind the published CSVs in 71 of 154 feature medians (packet lengths include
headers, flags and windows are counted differently, flows split differently). **The
CSV-trained detectors flag 0% of brute-force flows computed this way.** So live mode and
packet-capture replays use two detectors trained on flows computed the live way, from the
dataset's raw captures:

```bash
python scripts/live_detectors/fetch_captures.py   # ~1.3 GB: single hosts' captures via HTTP range requests
python scripts/live_detectors/build_dataset.py    # attack windows found in the packets; Python flow meter; labels
python scripts/live_detectors/train.py            # models/live/live_dos.joblib, live_access.joblib
python scripts/live_detectors/make_demo_capture.py   # data/pcap/real-attacks-2018.pcap (held-out minutes)
```

(`./start.sh setup` runs these.) Test on the later 30% of each attack, by time:

| Test flows | live_dos | live_access | Counselor network |
|---|---|---|---|
| DoS SlowHTTPTest / FTP brute force | 100% / 100% | 100% / 99.99% | 100% / 100% |
| DoS Hulk / GoldenEye / Slowloris | 99.8% / 98.9% / 94.9% | 23% / 10% / 0% | 99.7% / 98.9% / 93.6% |
| SSH brute force / web attacks | 0% / 0% | 99.6% / 100% | 99.6% / 89.4% |
| **Benign (false alarms)** | 0.14% | 0.02% | **0.02%** |

Two things keep live false alarms down, both at inference time (the models are unchanged, so
the experiment numbers above are untouched; both are proven on the 339k-flow live set):

- **Connection-only flows are not sent to the ML.** A port scan, a failed connection or a
  bare SYN flood exchanges no payload; the detectors never trained on such flows and only
  emit best-guess false alarms for them (one scan produced ~50k). `carries_payload` in
  `services/live_capture.py` drops them — 0 of every attack type and 0 benign flows in the
  live set are affected — while they are still indexed so Snort (which detects scans) can
  link its alerts. Disable with `nids extract --live … --keep-empty-flows`.
- **Unresolved-conflict guesses are treated as normal** (`--suppress-fallback`, on for the
  live detectors in `start.sh` and pcap replays). When a detector's classifiers disagree and
  no counselor can advise, the "attack" fallback is a blind guess — it causes the live
  false alarms (e.g. on HTTPS) yet accounts for 16 of ~190k real detections; suppressing it
  takes benign false alarms from 0.02% to 0.00% at a 0.01-point cost in detection.

Limits: one attacker per attack type in one lab network; no live botnet, DDoS or infiltration
detector (no single victim capture). Scans and payload exploits are Snort's job, not the ML's.
Watch the false-alarm rate on your own network (docs/live-testing.md).

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

## Project layout

```
nids/
├── start.sh                one command to set up and run everything
├── pyproject.toml          the nids Python package and its dependencies
├── docker-compose.yml      container stack (redis, api, web; headless services)
├── docker/                 api.Dockerfile, web.Dockerfile
├── docs/                   paper/ (the source paper), datasets.md, live-testing.md
├── src/nids/               the core library and the `nids` command
│   ├── datasets/           loaders: NSL-KDD, CICIDS2017, CSE-CIC-IDS2018; feature-name mapping
│   ├── capture/            pcap reading and slicing, remote-zip fetching, the flow meter runner
│   ├── detector/           classifier selection and detection (Algorithms 1 and 2), training
│   ├── counselor/          advice exchange between detectors
│   ├── services/           Redis services: extractor, observer, detector, live capture,
│   │                       Snort bridge and flow index, monitor
│   ├── scenarios.py        the paper's scenarios with signature / validation / test splits
│   ├── evaluation.py       metrics and the paper's baselines
│   ├── reporting.py        result files and comparison charts
│   └── cli.py              `nids train | extract | observe | detect | snort | monitor | reset`
├── experiments/            research: tune.py (validation), evaluate.py (test), self_learning.py,
│                           wider_coverage.py (detector 3)
├── scripts/                data pipelines: make_synthetic_capture.py, live_detectors/
│                           (fetch_captures → build_dataset → train → make_demo_capture)
├── backend/                Django API: config/ (settings, ASGI), api/ (REST views, WebSocket
│                           live feed, replay control, results; auth/ for cookie and token login)
├── frontend/               Next.js dashboard: src/app (pages), src/components/{ui,charts,panels},
│                           src/lib (API client, auth, live feed)
├── snort/                  Snort 3 config and rules used next to the ML
├── notebooks/              dataset exploration and result plots (no logic of their own)
└── tests/                  pytest suite, mirroring src/nids
```

Not in git (created locally): `data/` (raw datasets, replay files, captures, processed
flows — see [docs/datasets.md](docs/datasets.md)), `models/` (trained detectors; `models/live/`
for the live ones), `results/` (experiment outputs), `logs/` (service logs).
