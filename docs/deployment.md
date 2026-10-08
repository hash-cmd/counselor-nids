# Running it as a service

`./start.sh live wlan0` is for trying the system: it runs in a terminal and stops with it.
To monitor a machine all the time, install it as systemd services. They start at boot,
restart any part that crashes, and are health-checked every minute.

## Install

Run `./start.sh setup` first. It installs the Python environment and packages, creates the
dashboard login, and puts the live detectors in place. Then:

```bash
sudo deploy/install-systemd.sh wlan0       # your interface: `ip link` lists them
```

The installer:

- writes settings to `/etc/nids/nids.env` and a secret key to `backend/.env`;
- builds the dashboard for production;
- installs one unit per part, and starts them all under `nids.target`.

The dashboard runs on <http://localhost:3000>.

To remove everything: `sudo deploy/install-systemd.sh --uninstall`. The settings in
`/etc/nids/` are kept.

| Unit | What it runs |
|---|---|
| `nids-capture` | traffic capture and flow meter (`nids extract --live`) |
| `nids-observer` | routes flows to the detectors |
| `nids-detector@<model>` | one per file in `models/live/` |
| `nids-snort` | Snort on the same interface, linked to the ML verdicts |
| `nids-journal` | the false-alarm record in `logs/journal/` |
| `nids-api`, `nids-web` | Daphne API on :8000, Next.js dashboard on :3000 |
| `nids-health.timer` | `nids health` every minute |

## How it stays up

- **Restarts.** Every unit restarts 5 s after a crash. Restarting capture starts a new run,
  with record ids from 0 again. The observer, detectors and Snort bridge are tied to it
  (`PartOf`), so they restart with it and never mix two runs.
- **Network drops.** If the interface goes down (Wi-Fi drops), capture waits for it and
  resumes on its own. This is not counted as a crash.
- **Least privilege.** Nothing runs as root. Every service runs as the user who owns the
  project folder. Capture and Snort get only `CAP_NET_RAW` and `CAP_NET_ADMIN`, and every
  unit sets `NoNewPrivileges`.
- **Model integrity.** Model files are pickles, and loading one runs code. Each detector
  checks `models/live/SHA256SUMS` before it starts, and refuses to run if a model was
  changed.

## Is it healthy?

Every service sends a heartbeat to Redis every second or so.

- **On the dashboard:** the *Live monitoring* panel shows one chip per part. A part that has
  been silent for 15 s, or a Snort process that has exited, shows as **down**.
- **On the command line:**

  ```
  $ .venv/bin/nids health
  capture                  ok    last seen    0.4s ago  target=wlan0 state=capturing
  detector:live_access     ok    last seen    0.2s ago
  ...
  ```

  It exits with 1 if any part is down, and 2 if Redis is unreachable, so monitoring tools
  and scripts can use it directly. The timer runs it every minute: `journalctl -u nids-health`
  shows each failure.

## Logs

| What | Where | Kept |
|---|---|---|
| Services under systemd | the system journal: `journalctl -u 'nids-*' -f` | journald's own rotation |
| Services under `./start.sh` | `logs/<service>.log` | over 20 MB at start, moved to `.log.1` (one old copy kept) |
| Alert journal (false alarms) | `logs/journal/<day>.jsonl` | 365 days (`nids journal --keep-days N`) |

## Serving the dashboard to other machines

The API and the dashboard listen on localhost only. To reach them from other machines:

1. Put an HTTPS reverse proxy in front of them (nginx or Caddy).
2. Set `AUTH_COOKIE_SECURE=1`, and the real addresses in `CORS_ALLOWED_ORIGINS` and
   `NEXT_PUBLIC_API_URL`, in `/etc/nids/nids.env`.
3. Run the installer again, so the dashboard is rebuilt with the new API address.

The login cookies are `httpOnly`. State-changing requests need a custom header as a CSRF
guard.
