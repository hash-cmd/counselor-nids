"""Capture real attack-tool traffic and turn it into labelled training flows (fix #3).

The lab datasets hold one tool per attack (FTP-Patator, the lab's Slowloris...). Live attackers use
other tools — nmap, curl, hydra, slowhttptest — whose flows look different, which is why the
lab-trained detectors missed them on 2026-11-25. This script runs those tools against a local
target on the loopback interface, captures each attack to its own pcap, runs the project's flow
meter on it, and labels every flow with the attack it came from. The output merges into the
training set (``--append-to``) so the detectors learn the live tools' flow shapes too.

Loopback only: it attacks ``127.0.0.1`` and captures ``lo``, so nothing leaves the host and no
monitored interface or study recording is touched. Needs root (to capture) and the attack tools
on PATH (nmap, curl, slowhttptest; ssh for the SSH burst). Run it on an idle host.

    sudo python scripts/live_detectors/capture_attacks.py --out data/processed/live/live_tool_attacks.pkl
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

from build_dataset import flowmeter  # noqa: E402
from nids.datasets.paths import PROJECT_ROOT  # noqa: E402


def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def capture(iface: str, pcap: Path, bpf: str, attack, settle: float = 2.0):
    """Capture ``iface`` to ``pcap`` while ``attack()`` runs; ``bpf`` limits what is recorded."""
    tcpdump = subprocess.Popen(["tcpdump", "-i", iface, "-w", str(pcap), "-q", bpf],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        attack()
    finally:
        time.sleep(settle)
        tcpdump.terminate()
        tcpdump.wait()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--victim", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8099)
    ap.add_argument("--out", type=Path, default=PROJECT_ROOT / "data/processed/live/live_tool_attacks.pkl")
    ap.add_argument("--work", type=Path, default=Path("/tmp/nids-attack-capture"))
    ap.add_argument("--append-to", type=Path, help="also concatenate the result into this flows pickle")
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    V, P = args.victim, args.http_port
    U = f"http://{V}:{P}/"

    # throwaway HTTP server on loopback for the web and slow attacks
    root = args.work / "webroot"; root.mkdir(exist_ok=True)
    (root / "index.html").write_text("<html><body><form action=/login method=post>ok</form></body></html>")
    http = subprocess.Popen([sys.executable, "-m", "http.server", str(P), "--bind", V],
                            cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    def port_scan():
        run(["nmap", "-Pn", "-sT", "-T4", "-p1-1024", V])

    def http_flood():
        end = time.time() + 12
        procs = []
        while time.time() < end:
            procs = [p for p in procs if p.poll() is None]
            while len(procs) < 20:
                procs.append(subprocess.Popen(["curl", "-s", "-o", "/dev/null", "-m", "3", f"{U}?_={time.time()}"],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            time.sleep(0.05)

    def sqli():
        for _ in range(15):
            for q in ("id=1%20UNION%20SELECT%20user,pass%20FROM%20users",
                      "id=1'%20OR%20'1'='1", "q=1;SELECT%20*%20FROM%20information_schema.tables"):
                run(["curl", "-s", "-o", "/dev/null", "-m", "4", f"{U}?{q}"])

    def xss():
        for _ in range(15):
            for q in ("q=<script>alert(1)</script>", "x=<img%20src=x%20onerror=alert(1)>",
                      "u=javascript:alert(document.cookie)"):
                run(["curl", "-s", "-o", "/dev/null", "-m", "4", f"{U}?{q}"])

    def web_brute():
        for i in range(40):
            run(["curl", "-s", "-o", "/dev/null", "-m", "4", "-X", "POST", f"{U}login",
                 "-d", f"username=admin&password=guess{i}"])

    def slowloris():
        if not _have("slowhttptest"):
            print("  slowhttptest not installed — skipping Slowloris", flush=True)
            return
        run(["slowhttptest", "-c", "300", "-H", "-i", "10", "-r", "40", "-t", "GET",
             "-u", U, "-x", "24", "-p", "3", "-l", "25"])

    jobs = [
        ("PortScan", f"host {V} and tcp", port_scan),
        ("DoS-Hulk", f"host {V} and tcp port {P}", http_flood),         # HTTP request flood
        ("Web-attack", f"host {V} and tcp port {P}", sqli),
        ("Web-attack", f"host {V} and tcp port {P}", xss),
        ("Web-attack", f"host {V} and tcp port {P}", web_brute),
        ("DoS-Slowloris", f"host {V} and tcp port {P}", slowloris),
    ]

    frames = []
    try:
        for i, (label, bpf, attack) in enumerate(jobs):
            pcap = args.work / f"{i}_{label}.pcap"
            print(f"[{label}] capturing…", flush=True)
            capture(args.iface, pcap, bpf, attack)
            if not pcap.exists() or pcap.stat().st_size < 100:
                print(f"  no traffic captured for {label}", flush=True); continue
            flows = flowmeter(pcap, args.work / f"{i}_{label}.csv")
            if flows.empty:
                print(f"  no flows for {label}", flush=True); continue
            flows["label"] = label
            flows["capture"] = f"live-tool-{label}"
            frames.append(flows)
            print(f"  {len(flows)} flows labelled {label}", flush=True)
    finally:
        http.terminate(); http.wait()

    if not frames:
        sys.exit("no attack flows captured")
    out = pd.concat(frames, ignore_index=True)
    out["is_attack"] = out["label"] != "Benign"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    out.to_pickle(args.out)
    print(f"\nwrote {len(out)} flows to {args.out}")
    print(out["label"].value_counts().to_string())
    if args.append_to and args.append_to.exists():
        base = pd.read_pickle(args.append_to)
        pd.concat([base, out], ignore_index=True).to_pickle(args.append_to)
        print(f"appended to {args.append_to} (now {len(base) + len(out)} flows)")


def _have(tool: str) -> bool:
    from shutil import which
    return which(tool) is not None


if __name__ == "__main__":
    main()
