# Testing on your own network

Live mode runs Snort and the ML detectors on the same network interface. This guide checks
that it works on your machine and measures how many false alarms it raises on your normal
traffic — the number the lab results cannot tell you.

## 1. Find your interface

```bash
ip link            # e.g. wlan0 (Wi-Fi) or eth0 (cable)
```

## 2. Start live mode

```bash
./start.sh live wlan0
```

It asks for your sudo password once (capturing packets needs root; only Snort and the flow
extractor run as root). Open http://localhost:3000. The header shows **Detecting** and the
Overview's Traffic card shows **Live capture running**.

The ML uses the **live detectors** in `models/live/` — trained on features computed by the
same Python flow meter that live mode uses. If the Traffic card warns that there are none,
run `./start.sh setup` first.

## 3. Use your machine normally for 15–30 minutes

Browse, stream, update packages. A flow reaches the detectors when its connection ends or
times out, so expect a delay of up to a couple of minutes.

## 4. Read the false alarms

Your normal traffic should produce few incidents. On the **Alerts** page:

- **ML only** incidents on ordinary browsing are false alarms from the ML.
- **Snort only** incidents are Snort's (its rules in `snort/rules/nids.rules` plus the
  community rules in `snort/rules/community/`). Policy rules such as "Terminal server
  request attempt" fire on ordinary RDP use; run with `NIDS_SNORT_COMMUNITY=0` to compare
  against the project's rules alone.
- Click an incident for its source, destination and which detector raised it, and mark it
  **Not an attack** or **Real attack**. Your verdict takes it out of the counts. When you have
  marked a few, choose **Teach the AI** on the AI detectors page: the detectors learn from them
  behind a safety check, and running detectors switch to the improved model by themselves.
- On **AI detectors**, the *rule checker as a counselor* panel shows how many of the
  detectors' doubts Snort settled, and how much the AI has come to trust each Snort rule.
  Rules that fire on your ordinary traffic (often Windows policy rules) should drift below
  90% and stop counting as advice. Trust is kept in `logs/snort-trust.json`: delete it to
  start afresh, or run with `NIDS_SNORT_COUNSELOR=0` to compare without Snort's advice.

Note the numbers on the Overview (flows analysed, flagged by the ML, Snort alerts). The
logs are in `logs/` — send those and the numbers if anything looks wrong.

## 5. Check detection without attacking anything

Replay a recording of real attacks from the dashboard: **Test with recordings** →
`real-attacks-2018.pcap` → **Start test**. It holds floods, password guessing, website
attacks and botnet traffic recorded in a test lab, so nothing is sent anywhere — Snort and the
detectors just read the file. (Build it once with `scripts/live_detectors/make_demo_capture.py`.)

Only test attack tools against machines you own and are allowed to test.

## 6. Measure the false-alarm rate over several days (the real test)

The lab numbers and a few minutes of live capture can't tell you how noisy the system is on
*your* traffic over time. To find out, leave it running and read the numbers:

1. `./start.sh live wlan0` and use your network normally for a few days (browsing, streaming,
   video calls, package updates, backups — the full range of what you do). Restarting is
   fine: live mode keeps every alert in `logs/journal/` (one file per day), across runs.
2. Write down when you ran any attack tests on purpose, so they are not counted.
3. Read the numbers at any time:

   ```bash
   .venv/bin/nids journal-report --exclude 2026-10-09T14:00 2026-10-09T14:30
   ```

   It reports hours watched, connections checked, connections the ML flagged (per 1,000
   connections and per hour, by detector and by connection), and Snort's alerts with whether
   the ML agreed. With no attacks running, every ML alert outside the excluded times is a
   false alarm. `--exclude START END` can be repeated.
4. A healthy result is a handful of false alarms per day or fewer. If a particular normal
   activity trips the AI repeatedly, `top_connections` shows the source and destination —
   that's the signal for what to retrain on or which Snort rule to tune.

This is the honest gap the experiments leave open, and the only way to know whether to trust
the live detectors on your network.

## Stopping

Ctrl+C in the terminal stops everything, including the root capture processes.
