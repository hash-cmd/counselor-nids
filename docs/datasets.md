# Datasets

Raw files used to reproduce *A Counselors-Based Intrusion Detection Architecture* (Quincozes et al., 2019).

## `data/raw/nsl-kdd/` — Scenario 1 (heterogeneous detectors)

Source: https://github.com/defcom17/NSL_KDD (mirror of the UNB NSL-KDD release)

| File | Rows |
|---|---|
| `KDDTrain+.txt` | 125,973 |
| `KDDTrain+_20Percent.txt` | 25,192 |
| `KDDTest+.txt` | 22,544 |
| `KDDTest-21.txt` | 11,850 |

No header row. 43 columns: the 41 KDD features, then `label` (e.g. `normal`, `neptune`, `teardrop`), then `difficulty`.

## `data/raw/cicids2017/` — Scenario 2 (homogeneous detectors)

Source: https://huggingface.co/datasets/c01dsnap/CIC-IDS2017 (mirror of the official
`MachineLearningCSV.zip`; the official server cicresearch.ca was unreachable).
SHA-256 of every CSV matches the mirror's LFS object ids.

79 columns (78 CICFlowMeter features + ` Label`). Column names have leading spaces.
This is the *MachineLearningCSV* variant, so there is **no `Timestamp`, `Flow ID` or IP columns**.
Those are only in `GeneratedLabelledFlows.zip`.

Files relevant to the paper:

| File | Labels |
|---|---|
| `Wednesday-workingHours.pcap_ISCX.csv` | BENIGN, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, Heartbleed |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | BENIGN, DDoS |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | BENIGN, PortScan |

Other days (Tuesday brute force, Thursday web attacks/infiltration, Friday morning bot,
Monday benign-only) are included for completeness.

Known quirks: `Flow Bytes/s` and `Flow Packets/s` contain `NaN`/`Infinity`; web-attack
labels contain a non-UTF-8 dash byte (`Web Attack \x96 Brute Force`).

Cite: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset
and Intrusion Traffic Characterization", ICISSP 2018.

## `data/raw/cse-cic-ids2018/` — detector 3 (wider coverage); not used by the paper's scenarios

Source: official public bucket `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`
(https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com). 10 CSVs, 6.5 GB; sizes match the bucket listing.

80 columns with a real `Timestamp` column (unlike the CICIDS2017 ML CSVs). Column names differ
from 2017 (`Dst Port`, `Tot Fwd Pkts`, ...), so it needs its own loader.

Known quirks:
- `Thuesday-20-02-2018_*.csv` (sic) is 4 GB and has 84 columns: extra `Flow ID`, `Src IP`, `Src Port`, `Dst IP`.
- The header row repeats inside some files (`Wednesday-28-02-2018`: 33 extra, `Thursday-01-03-2018`: 25,
  `Friday-16-02-2018`: 1) — drop rows where `Label == "Label"`.

## `data/raw/cse-cic-ids2018-pcap/` — raw captures for the live detectors

Single hosts' packet captures from the dataset's `Original Network Traffic and Log data/`
(fetched with `scripts/live_detectors/fetch_captures.py`, ~1.3 GB, out of 40-60 GB archives).
pcapng files are converted to classic pcap.

## Generated folders

| Folder | Made by | Contents |
|---|---|---|
| `data/replay/` | `nids train scenario2` | unseen CICIDS2017 flows for replays |
| `data/pcap/` | `scripts/make_synthetic_capture.py`, `scripts/live_detectors/make_demo_capture.py` | captures for the dashboard (each with a `.txt` description) |
| `data/processed/live/` | `scripts/live_detectors/build_dataset.py` | flows computed by the Python flow meter, per capture |
