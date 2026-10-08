# Datasets

Raw packet recordings used to train and test the AI detectors (`scripts/live_detectors/`).
They're only needed to retrain. The trained detectors ship in `models/live/`.

## `data/raw/cse-cic-ids2018-pcap/`: CSE-CIC-IDS2018 captures

These are single hosts' packet captures from the dataset's `Original Network Traffic and Log
data/`, in the public bucket `s3://cse-cic-ids2018/` (https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com).
`scripts/live_detectors/fetch_captures.py` fetches only the hosts it needs, about 1.3 GB
out of the 40–60 GB day archives, using HTTP range requests. pcapng files are converted to
classic pcap.

| Capture | Used for |
|---|---|
| `Wednesday-14-02-2018_UCAP172.31.69.25` | FTP and SSH brute force (victim server) |
| `Wednesday-14-02-2018_capPC1-172.31.64.34` | normal traffic of an ordinary workstation |
| `Thursday-15-02-2018_UCAP172.31.69.25` | DoS GoldenEye, Slowloris |
| `Friday-16-02-2018_UCAP172.31.69.25-part1` | DoS SlowHTTPTest, Hulk |
| `Thursday-22-02-2018_UCAP172.31.69.28` | website attacks (brute force, XSS, SQL injection) |
| `Friday-02-03-2018_capEC2AMAZ-O4EL3NG-172.31.69.26`, `.12` | Ares botnet-infected hosts |
| `Friday-02-03-2018_capEC2AMAZ-O4EL3NG-172.31.69.14` | held-out infected host (`cross_host.py`) |

The attackers' addresses and attack windows are found in the packets themselves
(`build_dataset.py`). The CSV timestamps can't be used for this: they're a 12-hour clock
without AM/PM.

## `data/raw/cicids2017-pcap/`: CICIDS2017 captures (optional second lab)

These are the five full-day captures, about 50 GB:

- `Monday-WorkingHours.pcap`
- `Tuesday-WorkingHours.pcap`
- `Wednesday-workingHours.pcap`
- `Thursday-WorkingHours.pcap`
- `Friday-WorkingHours.pcap`

To get them:

1. Go to https://www.unb.ca/cic/datasets/ids-2017.html and click **Download this dataset**.
   It asks you to fill in a short form first.
2. Download the files from the PCAPs folder **one at a time**. The server allows one download
   per session, and it can't resume a broken download.

`build_cicids2017.py` labels the attacks from CIC's published schedule.

Cite: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset
and Intrusion Traffic Characterization", ICISSP 2018.

## Generated folders

| Folder | Made by | Contents |
|---|---|---|
| `data/processed/live/` | `build_dataset.py`, `build_cicids2017.py` | flows computed by the Python flow meter, per capture |
| `data/pcap/` | `make_demo_capture.py` | recordings for the dashboard's Test page (each with a `.txt` description) |
| `data/blocklists/` | `scripts/fetch_blocklists.py` | public IP blocklists for offline reputation |
