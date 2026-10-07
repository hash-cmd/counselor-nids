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
- Click an incident for its source, destination and which detector raised it.

Note the numbers on the Overview (flows analysed, flagged by the ML, Snort alerts). The
logs are in `logs/` — send those and the numbers if anything looks wrong.

## 5. Check detection without attacking anything

Replay the recorded attack capture from the dashboard: Overview → **Packet capture + Snort**
→ `demo-attacks.pcap` → **Start replay**. It contains a scan, web attacks, a SYN flood and
an SSH brute force against addresses that do not exist on your network, so nothing is sent
anywhere — Snort and the detectors just read the file.

Only test attack tools against machines you own and are allowed to test.

## 6. Measure the false-alarm rate over several days (the real test)

The lab numbers and a few minutes of live capture can't tell you how noisy the system is on
*your* traffic over time. To find out, leave it running and read the numbers:

1. `./start.sh live wlan0` and use your network normally for a few days (browsing, streaming,
   video calls, package updates, backups — the full range of what you do).
2. Each day, note the Overview's headline — connections checked, flagged by the AI, and the
   severity breakdown — and skim the **Alerts** page. On ordinary traffic almost everything
   should be **Low**; investigate any **ML only** alert on normal browsing as a false alarm.
3. A healthy result is a handful of false alarms per day or fewer. If a particular normal
   activity trips the AI repeatedly, note the source/port and the attack type it was called —
   that's the signal for what to retrain on or which Snort rule to tune.

This is the honest gap the experiments leave open, and the only way to know whether to trust
the live detectors on your network.

## Stopping

Ctrl+C in the terminal stops everything, including the root capture processes.
