# Datasets

Raw files used to reproduce *A Counselors-Based Intrusion Detection Architecture* (Quincozes et al., 2019).

## `raw/nsl-kdd/` — Scenario 1 (heterogeneous detectors)

Source: https://github.com/defcom17/NSL_KDD (mirror of the UNB NSL-KDD release)

| File | Rows |
|---|---|
| `KDDTrain+.txt` | 125,973 |
| `KDDTrain+_20Percent.txt` | 25,192 |
| `KDDTest+.txt` | 22,544 |
| `KDDTest-21.txt` | 11,850 |

No header row. 43 columns: the 41 KDD features, then `label` (e.g. `normal`, `neptune`, `teardrop`), then `difficulty`.

## `raw/cicids2017/` — Scenario 2 (homogeneous detectors)

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

## `raw/cse-cic-ids2018/` — reserved for later work (not used by the paper)

Source: official public bucket `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`
(https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com). 10 CSVs, 6.5 GB; sizes match the bucket listing.

80 columns with a real `Timestamp` column (unlike the CICIDS2017 ML CSVs). Column names differ
from 2017 (`Dst Port`, `Tot Fwd Pkts`, ...), so it needs its own loader.

Known quirks:
- `Thuesday-20-02-2018_*.csv` (sic) is 4 GB and has 84 columns: extra `Flow ID`, `Src IP`, `Src Port`, `Dst IP`.
- The header row repeats inside some files (`Wednesday-28-02-2018`: 33 extra, `Thursday-01-03-2018`: 25,
  `Friday-16-02-2018`: 1) — drop rows where `Label == "Label"`.
