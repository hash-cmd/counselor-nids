# Counselor NIDS

A network intrusion detection system for live traffic. Two independent checks watch the same
traffic:

- **AI detectors.** Three specialist machine-learning detectors, each trained on a different
  family of attacks. When one is unsure, it asks the others for advice (the counselor
  architecture of Quincozes et al., IFIP 2019).
- **Snort 3.** Signature rules that look inside the traffic for known attack patterns.

Every Snort alert is linked to the connection it belongs to and checked against the AI's
verdict. A web dashboard shows what was caught, who is attacking and how much to trust each
alert.

## Quick start

```bash
./start.sh setup              # once: Python env, packages, database, login user, Snort rules
./start.sh live wlan0         # watch a network interface (asks for sudo once), plus the dashboard
./start.sh                    # dashboard only, on http://localhost:3000 (test with recordings)
./start.sh --prod live wlan0  # the same with production servers (Daphne, optimised build, DEBUG off)
```

You need Python 3.11+, Node, Redis (started for you if it's installed) and Snort 3 for the
rule checker. Ctrl+C stops everything, and logs are in `logs/`.

- To run it permanently, as services that start at boot and restart on failure, see
  [docs/deployment.md](docs/deployment.md).
- To check how it behaves on your own network, see [docs/live-testing.md](docs/live-testing.md).
- Full documentation: [docs/Counselor-NIDS-Documentation.pdf](docs/Counselor-NIDS-Documentation.pdf); how every part
  is built and works, step by step in plain words: [docs/Counselor-NIDS-How-It-Is-Built.pdf](docs/Counselor-NIDS-How-It-Is-Built.pdf).

## How it works

![System design](docs/system-design.png)

What happens to each connection, step by step: [docs/logic-flow.png](docs/logic-flow.png).

```
                ┌─> flow meter ─> Observer ─> AI detectors ──┐
network (wlan0) ┤                                            ├─> correlator ─> Redis ─> API ─> dashboard
                └─> Snort 3 (snort/nids.lua, rules) ─────────┘          └─> alert journal (logs/journal/)
```

| Service | Role |
|---|---|
| `nids extract --live IFACE` | captures traffic; the Python cicflowmeter turns packets into connection flows |
| `nids observe` | routes each batch of flows to the detectors |
| `nids detect MODEL` | one AI detector: classifies flows, asks the others for advice, answers their requests |
| `nids snort --interface IFACE` | runs Snort on the same traffic and links each alert to its flow and the AI's verdict |
| `nids journal` | keeps every alert on disk, to measure false alarms over days |
| `nids health` | lists the services that are alive (exit 1 if any is down) |

**The detectors.** Each detector clusters traffic (K-Means), then for every cluster picks the
most accurate of five classifiers (naive Bayes, decision trees, random forest). If its
classifiers disagree on a connection, it asks the other detectors (its counselors) and takes
confident advice. With cross-check on, a "normal" verdict is also checked with the others, so
an attack one specialist never learned is still caught by the specialist that did.

| Detector | Model | Knows |
|---|---|---|
| Flood detector | `models/live/live_dos.joblib` | DoS: GoldenEye, Slowloris, Hulk, SlowHTTPTest |
| Break-in detector | `models/live/live_access.joblib` | FTP/SSH password guessing, website attacks |
| Botnet detector | `models/live/live_bot.joblib` | infected hosts calling their command-and-control server |

**Snort and the AI together.** Each Snort alert is linked to its connection (both addresses
and ports, the protocol and the time). A port-scan alert is linked to every connection between
the two hosts within ±30 s. The AI then gives its verdict on that connection:

| Agreement | Meaning |
|---|---|
| **Confirmed** | Snort and the AI both say attack |
| **Disputed** | Snort says attack, the AI says normal: a possible Snort false alarm, or an attack the AI never learned |
| **AI only** | the AI flagged a connection Snort had no alert for |

## Detection results

On `real-attacks-2018.pcap`, the whole system runs on real attack traffic it never trained
on. The recording holds the late minutes of every CSE-CIC-IDS2018 attack, and the test covers
the flow meter, the AI detectors, Snort with the project's rules, and alert linking.
Reproduce it with `python scripts/live_detectors/evaluate_capture.py --no-community`.

| Traffic | Flows | AI | Snort | Either |
|---|---|---|---|---|
| DoS GoldenEye | 1,822 | 99.1% | 4.9% | 99.1% |
| DoS Hulk | 2,861 | 99.9% | 48.2% | 99.9% |
| DoS SlowHTTPTest | 4,450 | 100.0% | 99.8% | 100.0% |
| DoS Slowloris | 760 | 34.7% | 0.0% | 34.7% |
| FTP brute force | 5,040 | 100.0% | 99.8% | 100.0% |
| SSH brute force | 359 | 98.3% | 88.9% | 98.9% |
| Web attacks | 4 | 4 of 4 | 4 of 4 | 4 of 4 |
| Botnet | 540 | 99.6% | 0.0% | 99.6% |
| **Normal (false alarms)** | 1,570 | **0.0%** | **0.3%** | **0.3%** |

On the test split, the latest 20% of every attack, the detectors catch **99.1%** of attack
flows, with false alarms on **2 of 5,192** normal flows (0.04%).

- **The two checks cover each other.** The AI catches the floods and the botnet that Snort's
  rules miss. Snort covers website attacks with its payload rules.
- **Slowloris is the weak spot,** and how much of it is caught depends on the attack's phase:
  85% of test flows across the attack, 60% of the complete last five minutes, and 35% of the
  last three, when the attack winds down (above). With the community rules on, Snort's
  Challenge-ACK rule lifts the last three minutes to 69.5% "either". Retraining on correctly
  measured connections (see [Retraining](#retraining-the-detectors)) raised it from 56% to 85%
  on the test split, and from 50% to 60% on the last five minutes.
- **Website attacks are Snort's job.** The AI has only ~150 website-attack training flows,
  too few to rely on, so the project's rules lead:
  - SQL injection: UNION SELECT; a quote followed by an AND/OR comparison; ORDER BY column
    probing; `information_schema`;
  - cross-site scripting: `<script`, event handlers, `javascript:`, in the URL or a form;
  - website login brute force: 20 password posts from one source in 60 s.

  On the whole 2018 website-attack capture they alert on **188 of the attacker's 207
  connections (90.8%)**, and on nothing else.
- **A botnet host it never saw.** On a third infected host whose traffic was never used for
  training (`cross_host.py`), the system catches **99.8%** of its 15,238 botnet flows, with
  false alarms on **2 of its 4,307** normal flows.

**Keeping false alarms down on live traffic:**

- **Connection-only flows don't go to the AI.** Port scans, failed connections and bare SYN
  floods carry no data. The detectors never trained on such flows and only guess on them (one
  scan produced ~50,000 false alarms), so they're left to Snort's scan detection.
- **Unresolved disagreements count as normal.** When a detector's classifiers disagree and no
  counselor can advise, its "attack" fallback is a blind guess, so `--suppress-fallback` drops
  it.
- **Measure it on your network.** The Overview's false-alarm panel reports alarms per 1,000
  connections from the alert journal. Mark your own attack tests there, so they aren't counted.

**Limits.** The detectors learned from one lab, with one attacker per attack type, and the
botnet detector knows one botnet family (Ares). They don't cover DDoS or infiltration yet.
Port scans and payload exploits are Snort's job.

## Snort configuration

`snort/nids.lua` loads the project's 42 rules (`snort/rules/nids.rules`). It also loads the
4,017 Snort 3 community rules that `./start.sh setup` downloads into `snort/rules/community/`;
`NIDS_SNORT_COMMUNITY=0` leaves them out.

- **Checksums are not checked.** Network cards fill checksums in themselves (offloading), so
  a machine's own outgoing packets, and ~40% of the 2018 website-attack capture, look broken
  to Snort, which used to drop them. Until this was turned off, Snort raised no
  website-attack alert at all on that capture.
- **Inspector anomaly alerts are off.** They flagged TLS sessions seen mid-stream as attacks.
  Only the port-scan alerts (gid 122, except "open port") are on, and scan reports from port
  53 are ignored, because DNS answers looked like UDP scans.
- **Brute-force rules use a wide window.** The FTP and SSH rules allow 10 and 15 connections
  in 120 s, so slow guessing paced to slip under a short-window threshold is still caught.
- **Informational community rules are suppressed:** pings, ICMP errors, 1-minute DNS TTLs and
  UPnP discovery. They fired ~3,800 times on a normal workstation. The RDP and SMB policy
  rules stay on, because they flag exposed services.
- With an existing Snort, `nids snort --follow /var/log/snort/alert_json.txt` links its alerts
  instead. It needs the `seconds`, address, port and `proto` fields in `alert_json`.

## Dashboard

| Page | |
|---|---|
| **Overview** | what is being watched and the health of every service; headline numbers with a plain-language verdict; top-risk attackers; AI vs Snort detections over time; false alarms on your network, with attack-test marking; latest alerts |
| **Alerts** | every flagged connection once, with a severity and a plain explanation. An **Attackers** view groups alerts by source into ranked attack stories, with full-history search and a Print/PDF report |
| **Detectors** | each AI detector's counters and how its decisions were made: on its own, from a counselor's advice, double-checked, or a best guess |
| **Test with recordings** | replay a recorded capture through the AI and Snort, apart from live monitoring |
| **Results** | the detectors' test results per attack type |

- The dashboard is written for non-experts: "AI" and "rule checker" rather than "ML" and
  "Snort".
- A header **bell** raises desktop and sound notifications for new high-severity alerts.
- **Block this IP** writes out a ready-to-paste firewall command. It never runs anything
  itself.
- **Offline IP reputation:** `python scripts/fetch_blocklists.py` downloads public
  blocklists, and the dashboard then marks known-bad sources. The lookup is local, so no
  address leaves the machine.

| API | |
|---|---|
| `POST /api/auth/login/`, `/refresh/`, `/logout/` | dashboard login with httpOnly cookies |
| `POST /api/auth/token/`, `/api/auth/token/refresh/` | JWT tokens for scripts (Bearer header) |
| `GET /api/detectors/` | detector counters, breakdowns, live-capture state, service health |
| `GET /api/alerts/`, `GET /api/incidents/` | AI alerts; flagged connections with AI and Snort verdicts |
| `GET /api/snort/` | Snort alerts and how they compare with the AI |
| `GET /api/journal/`, `POST /api/journal/tests/` | false alarms over days; mark attack tests |
| `GET /api/results/` | detector test results |
| `GET /api/reputation/?ips=` | which IPs are on the local blocklists |
| `GET /api/replay/`, `POST /api/replay/start/`, `/stop/` | test replays of recordings |
| `ws://…/ws/live/` | live stats, alerts and health every second |

**Security:**

- The session lives in httpOnly, SameSite=Strict cookies.
- State-changing requests need an `X-NIDS-Client` header.
- Login is limited to 10 attempts a minute per client.
- With `DJANGO_DEBUG=0`, the API refuses to start without a real `DJANGO_SECRET_KEY`, and it
  sends security headers.

To serve the dashboard beyond localhost, put an HTTPS proxy in front and set
`AUTH_COOKIE_SECURE=1`, `DJANGO_ALLOWED_HOSTS` and `CORS_ALLOWED_ORIGINS`
([docs/deployment.md](docs/deployment.md)).

**Docker** runs only the dashboard, for test replays. Snort isn't in the image, and
monitoring a network needs the host:

```bash
echo "DJANGO_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" > .env
docker-compose run --rm api python manage.py createsuperuser
docker-compose up                     # dashboard on http://localhost:3000
```

## Retraining the detectors

Live capture measures connections with the Python cicflowmeter. Its measurements differ from
the Java CICFlowMeter behind the public dataset CSVs in 71 of 154 features, and detectors
trained on those CSVs caught 0% of brute-force attacks measured the live way. So the detectors
are trained on the datasets' **raw packet recordings**, run through the same flow meter as
live capture:

```bash
.venv/bin/pip install -e ".[train]"
python scripts/live_detectors/fetch_captures.py     # ~1.3 GB of CSE-CIC-IDS2018 single-host captures
python scripts/live_detectors/build_dataset.py      # attack windows found in the packets; flow meter; labels
python scripts/live_detectors/build_cicids2017.py   # optional second lab: all CICIDS2017 captures (~50 GB)
python scripts/live_detectors/train.py              # 80% earliest flows to train, 20% latest to test
python scripts/live_detectors/cross_host.py         # botnet test on an infected host never trained on
python scripts/live_detectors/make_demo_capture.py  # data/pcap/real-attacks-2018.pcap (held-out minutes)
python scripts/live_detectors/evaluate_capture.py   # whole-system test on a recording
```

Data sources and layout are in [docs/datasets.md](docs/datasets.md).

- **Recordings are measured by their own clock.** The flow meter used to end connections by
  the computer's clock even when reading a recording. Every open connection then looked years
  old and was cut wherever the timer fired, so slow attacks were split at random and results
  changed between runs. Recordings now use packet time only, the way live capture already
  measured.
- **Promotion gate.** `train.py` tests the installed detectors on the same test flows, and
  installs the new ones only if false alarms don't rise and no attack type's detection drops
  by more than 2 points. Attack types the installed detectors never learned must reach 80%.
  `--force` overrides the gate, and `--only live_bot` retrains one detector and keeps the
  others.
- **Model integrity.** Model files are pickles, and loading one runs code. Promotion writes
  `models/live/SHA256SUMS`, and live mode refuses to load any model that doesn't match it.

## Project layout

```
nids/
├── start.sh                set up and run everything
├── pyproject.toml          the nids Python package and its dependencies
├── deploy/                 systemd units and their installer (install-systemd.sh)
├── docker-compose.yml      dashboard in containers (redis, api, web); docker/ holds the images
├── docs/                   deployment.md, live-testing.md, datasets.md; system-design and logic-flow diagrams
├── models/live/            the AI detectors (shipped), manifest.json, SHA256SUMS
├── snort/                  Snort 3 configuration and the project's rules
├── src/nids/               the core library and the `nids` command
│   ├── capture/            flow meter runner, pcap reading and slicing, remote-zip fetching
│   ├── detector/           classifier selection and detection, training
│   ├── counselor/          advice exchange between detectors
│   ├── datasets/           flow-feature names and paths
│   ├── services/           capture, observer, detectors, Snort bridge, journal, health, monitor
│   └── cli.py              `nids extract | observe | detect | snort | journal | health | monitor | reset`
├── scripts/                live_detectors/ (training pipeline), fetch_blocklists.py
├── backend/                Django API: REST, WebSocket live feed, replays, login
└── frontend/               Next.js dashboard
```

Not in git (created locally): `data/` (captures and processed flows), `results/` (test
results), `logs/` (service logs and the alert journal).
