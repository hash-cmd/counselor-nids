"""Widen the ML's coverage with a third detector trained on CSE-CIC-IDS2018.

The CICIDS2017 detectors know DoS, DDoS and PortScan. Detector 3 learns the attack
types they never saw — brute force, botnet, web attacks, infiltration — from the 2018
dataset, and joins the counselors network. Two questions, both on held-out data:

  A. 2018 test traffic: which attack types are caught with and without detector 3?
  B. 2017 test traffic (data/replay/scenario2.csv): does adding detector 3 raise false
     alarms or lose accuracy on the traffic the first two were built for?

Detector 3 is saved to models/ (and so joins the services and dashboard) only with --save.

    python experiments/coverage.py                 # evaluate
    python experiments/coverage.py --save          # evaluate, then add models/detector3.joblib
"""

import argparse
import gc
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from nids.counselor import CounselorNetwork
from nids.data import cicids2017 as cic
from nids.data.cse_cic_ids2018 import NEW_ATTACKS, load_new_attacks
from nids.data.paths import PROJECT_ROOT
from nids.detector.classifiers import SCENARIO2
from nids.evaluation import metrics
from nids.experiments import RESULTS_DIR, build_detector

MODELS = PROJECT_ROOT / "models"


def network_verdict(detectors, samples: pd.DataFrame, min_accuracy: float) -> np.ndarray:
    """What the system reports: a flow is an attack if any detector's final verdict says so."""
    for d in detectors:
        d.clear_history()
    finals = CounselorNetwork(detectors, min_accuracy, window=0, cross_check_normal=True).run(
        samples, samples["record_id"])
    return np.logical_or.reduce([f["prediction"].to_numpy(dtype=bool) for f in finals.values()])


def per_label(samples: pd.DataFrame, verdicts: dict[str, np.ndarray]) -> pd.DataFrame:
    rows = {}
    for label, group in samples.groupby("label"):
        idx = samples.index.get_indexer(group.index)
        rows[label] = {"flows": len(group), **{name: float(v[idx].mean()) for name, v in verdicts.items()}}
    return pd.DataFrame(rows).T.sort_values("flows", ascending=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--benign-fraction", type=float, default=0.1, help="share of 2018 benign flows loaded")
    parser.add_argument("--signature-share", type=float, default=0.2)
    parser.add_argument("--test-size", type=int, default=150_000)
    parser.add_argument("--min-accuracy", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--skip", nargs="*", default=[], choices=list(NEW_ATTACKS),
                        help="attack groups to leave out of detector 3's training")
    parser.add_argument("--benign2017", type=float, default=0.0,
                        help="also train on this share of CICIDS2017 Monday (all benign; never tested on)")
    parser.add_argument("--save", action="store_true", help="write models/detector3.joblib")
    args = parser.parse_args()

    old = [joblib.load(MODELS / f"detector{i}.joblib") for i in (1, 2)]
    features = old[0].features

    print("loading CSE-CIC-IDS2018 (new attack types + benign sample)…", flush=True)
    flows = load_new_attacks(args.benign_fraction, args.seed)
    signatures, unknown = train_test_split(flows, train_size=args.signature_share,
                                           stratify=flows["label"], random_state=args.seed)
    del flows
    gc.collect()
    # keep every rare web-attack flow in the test set; sample the rest
    rare = unknown["label"].isin(NEW_ATTACKS["web"][1])
    rest = unknown[~rare]
    rest = rest.sample(min(len(rest), args.test_size), random_state=args.seed)
    test18 = pd.concat([unknown[rare], rest]).sort_values("timestamp", kind="stable")
    test18["record_id"] = np.arange(len(test18))
    del unknown, rest
    gc.collect()

    skipped = [label for group in args.skip for label in NEW_ATTACKS[group][1]]
    signatures = signatures[~signatures["label"].isin(skipped)]
    if args.benign2017 > 0:
        monday = cic.load_cicids2017(["monday"]).sample(frac=args.benign2017, random_state=args.seed)
        monday = monday.assign(label="Benign")[[*features, "label", "is_attack"]]
        signatures = pd.concat([signatures[[*features, "label", "is_attack"]], monday], ignore_index=True)
        print(f"added {len(monday):,} CICIDS2017 Monday benign flows to detector 3's signatures")

    print(f"training detector3 on {len(signatures):,} signatures…", flush=True)
    detector3 = build_detector("detector3", signatures, features, SCENARIO2,
                               n_clusters=signatures["label"].nunique(), stratify="label", seed=args.seed)
    del signatures
    gc.collect()

    # A. 2018 test traffic
    y18 = test18["is_attack"].to_numpy()
    verdicts18 = {
        "detectors 1+2": network_verdict(old, test18, args.min_accuracy),
        "detectors 1+2+3": network_verdict([*old, detector3], test18, args.min_accuracy),
    }
    table_a = per_label(test18, verdicts18)
    summary_a = {name: metrics(y18, v) for name, v in verdicts18.items()}

    # B. 2017 test traffic the first two detectors were built for
    test17 = pd.read_csv(PROJECT_ROOT / "data" / "replay" / "scenario2.csv")
    test17 = test17[test17["label"] != "Heartbleed"].reset_index(drop=True)
    y17 = test17["is_attack"].to_numpy()
    verdicts17 = {
        "detectors 1+2": network_verdict(old, test17, args.min_accuracy),
        "detectors 1+2+3": network_verdict([*old, detector3], test17, args.min_accuracy),
    }
    table_b = per_label(test17, verdicts17)
    summary_b = {name: metrics(y17, v) for name, v in verdicts17.items()}

    pct = lambda v: f"{v:.2%}"  # noqa: E731
    print("\n=== A. CSE-CIC-IDS2018 test — share of flows flagged as attack (Benign row = false alarms)")
    print(table_a.to_string(formatters={c: pct for c in verdicts18} | {"flows": "{:,.0f}".format}))
    print(pd.DataFrame(summary_a).T.map(pct).to_string())
    print("\n=== B. CICIDS2017 test — share of flows flagged as attack (BENIGN row = false alarms)")
    print(table_b.to_string(formatters={c: pct for c in verdicts17} | {"flows": "{:,.0f}".format}))
    print(pd.DataFrame(summary_b).T.map(pct).to_string())

    out = RESULTS_DIR / "coverage"
    out.mkdir(parents=True, exist_ok=True)
    table_a.to_csv(out / "cse2018_by_label.csv")
    table_b.to_csv(out / "cicids2017_by_label.csv")
    (out / "summary.json").write_text(json.dumps({"cse2018": summary_a, "cicids2017": summary_b,
                                                  "args": vars(args)}, indent=2))
    print("\nresults written to", out)

    if args.save:
        detector3.clear_history()
        joblib.dump(detector3, MODELS / "detector3.joblib", compress=3)
        print("saved", MODELS / "detector3.joblib", "— the services and dashboard now use three detectors")


if __name__ == "__main__":
    main()
