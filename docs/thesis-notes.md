# Thesis notes — positioning, scope, limitations

Drafts to lift into the thesis. Written to be defensible, not promotional: the goal is that
an examiner finds the related work already cited and the limitations already stated.

---

## 0. Motivation / problem statement (for the introduction)

**The real-world problem — the deployment gap.**
Machine-learning intrusion detectors score almost perfectly in the lab and in vendor demos,
yet routinely fail once installed on a real organisation's network: they either miss real
attacks or bury a small security team under false alarms. The reason is well established — a
model trained on one network does not transfer to another (the cross-dataset collapse reported
by Cantone et al., 2024, and others). In practice this leaves an organisation with three poor
options: pay for expensive manual tuning, buy a managed service, or disable the ML and rely on
signatures alone.

Two things make this hard to fix in the field:
1. **Nobody can label a live network's traffic.** Supervised retraining needs labelled
   examples of that network's own normal and attack traffic, which almost no organisation has.
2. **Most organisations have no ML expertise** to retrain or tune a detector even if they could.

**A concrete scenario (use in the intro):**
> A small company installs an ML-based IDS. In the vendor demo it caught 99% of attacks. On the
> company's own network it drowns its two-person security team in false alarms and misses a real
> intrusion. The company has no labelled data from its network and no ML specialists. Today their
> only realistic choice is to turn the ML off and trust Snort alone.

**What this project does about it.**
Almost every organisation already runs a signature engine (Snort), whose rules behave the same
on every network. This work uses that existing, network-independent tool as a built-in *teacher*
so the ML detector **adapts to the organisation's own network by itself** — no labelling, no ML
expertise, no vendor. Snort advises the detectors when they are unsure, their points of
agreement become training labels for that specific network, and each Snort rule's trust is
tuned to how reliable it proves to be *there*.

**Real-world objectives (motivated by the problem above):**
1. **Reduce the false-alarm burden on a new network**, so a small team is not overwhelmed
   (Snort advice on conflicts; adaptive trust down-weights rules that misfire on this network;
   an analyst "teach the AI" loop for the rest).
2. **Recover the detection accuracy lost to the deployment gap**, catching attacks the
   lab-trained model would otherwise miss on the new network (self-labelling from Snort–AI
   agreement).
3. **Require zero labelling and zero ML expertise from the operator** — the system adapts
   itself; the operator only runs it and occasionally confirms a verdict.
4. **Make the decisions legible to a non-expert operator** ("AI" vs "rule checker",
   Confirmed/Disputed, attackers, false alarms per day).
5. **Demonstrate the adaptation is real across genuinely different networks** (the 2018↔2017
   experiment is the *evidence*, not the end in itself).
6. **Show it runs live, in real time, on real traffic** — not only offline.

> Framing note: the cross-dataset experiment is a *proxy* for "deploying on a new organisation's
> network." The home-network run (~2% false alarms, all from benign HTTPS/push traffic, then
> reduced by the feedback loop) and the live cross-device attack test are the small real-world
> case studies that turn "plausible" into "demonstrated." Lead with the operational problem;
> present the datasets as evidence and the live runs as the real-world demonstration.

---

## 1. Related work and the explicit delta

Every ingredient of this system has prior art; the contribution is the **synthesis and the
specific mechanisms**, not any single idea. State it that way.

**Counselor networks (the base architecture — not ours).**
The multi-detector architecture in which an uncertain classifier consults others is the
*counselors network* of Quincozes et al. (2019; *Int. J. Network Management*, 2020). We adopt
it as our baseline and credit it as such.
*Our delta:* we extend it with **advisors** — counselors that give advice but classify nothing
themselves — and make a signature engine (Snort) the first such advisor.

**Cross-dataset generalisation of NIDS (the problem — established).**
That flow-based ML detectors score near-perfectly within one dataset and collapse across
datasets is well documented: Cantone et al. (2024, arXiv:2402.10974) report near-chance
cross-dataset accuracy across four datasets; Kılıç & Şengül (IEEE Access, 2026) report
macro-F1 falling from ~0.90 to ~0.12 from CICIDS2017 to CSE-CIC-IDS2018; an NDSS 2023 poster
reports ~30% average AUROC drop.
*Our delta:* these works *measure* the collapse (or align features / use a few target labels).
We propose a **mechanism to adapt with zero target labels** and demonstrate it bidirectionally.

**Signature alerts as labels for ML (closest prior art — must cite).**
Using Snort/Suricata alerts as (weak) labels to train ML has been done — e.g. a probing-attack
case study combines Snort/Suricata alerts with other label sources; a thesis trains XGBoost on
Snort alert reports to reduce Snort's false positives. More broadly, semi-supervised and
co-training IDS use model confidence or a second view to label unlabelled traffic.
*Our delta:* (1) labels require **independent Snort–AI agreement** (the AI's verdict is not
itself caused by Snort's advice, so Snort cannot confirm itself); (2) a **forgetting gate** on
the legitimately-labelled source lab rejects any retrain that degrades or forgets a known
attack; (3) the labels drive **cross-network adaptation**, not one-network alert triage; and
(4) each Snort rule carries an **adaptive trust** updated from AI agreement, so unreliable
rules on the new network are automatically down-weighted.

**Hybrid signature + anomaly/ML IDS (well-trodden, for context).**
Pairing Snort with ML/anomaly detection is classic. Those designs run the two detectors in
parallel or in layers.
*Our delta:* Snort is not a parallel detector here but a **conflict-time advisor inside the
ensemble**, consulted only when the ML classifiers disagree, and a **source of self-labels**
for adaptation — a different role from parallel hybrids.

> One-line novelty claim: *While counselor networks, cross-dataset evaluation, Snort-derived
> labels, and hybrid IDS have each been studied separately, their integration — a signature
> engine as a conflict-time, trust-weighted advisor that also self-labels for zero-label
> cross-network adaptation, behind a non-forgetting gate — has not, to our knowledge, been
> reported.*

---

## 2. Scope of the generalisation claim (state this explicitly)

The two evaluation datasets, CICIDS2017 and CSE-CIC-IDS2018, are **both from the Canadian
Institute for Cybersecurity**, with related testbeds and the same CICFlowMeter lineage. They
are therefore *independently collected but of the same family*. The demonstrated result is
**cross-dataset generalisation within the CIC family**, which is a weaker claim than
generalisation to arbitrary, structurally different networks (e.g. UNSW-NB15 or a live
enterprise capture).

Write the claim at that strength, and list a third, structurally-different dataset as the
first item of future work. Over-claiming "any network" is the easiest point to attack.

---

## 3. Dataset labelling — a methodological strength, not a liability

CICIDS2017 is known to contain labelling errors in its **published flow CSVs** (Engelen et
al., WTMC 2021; Lanvin et al., 2023). This project does **not** use those CSV labels. Instead,
every flow is labelled from the **original packet captures plus CIC's published attack
schedule** (attacker, victim, time window), and the timezone of that schedule was verified
against the packets before building (the attacker's packet bursts align minute-for-minute with
the schedule under ADT/UTC−3). Consequently the known CSV label errors **do not propagate**
into our training or evaluation. State this explicitly — it converts a commonly-cited dataset
weakness into a reason to trust these results *more* than CSV-based studies.

---

## 4. Limitations and future work (constructive draft)

**Generalisation is shown within one dataset family.** Both datasets originate from the same
institution. Extending the evaluation to a structurally different dataset (UNSW-NB15,
CIC-IDS-2019) or a real network is the primary next step and would strengthen the
generalisation claim from "within-family" to "cross-domain".

**Encrypted traffic.** Signature content-matching (and the SQL-injection/XSS detection) needs
visible application-layer payloads, which modern TLS traffic hides. Flow-level features
(volumes, timing, flags) still support detection of floods, port scans, DDoS and botnet
beaconing over encrypted channels, but payload-dependent web-attack detection does not transfer
to HTTPS. Encrypted-traffic analysis is future work.

**Adversarial robustness is untested.** Like ML-based NIDS in general, the detectors may be
vulnerable to evasion (traffic shaping, padding, timing perturbation). This work does not
evaluate adversarial resistance; a controlled evasion study is future work.

**Throughput and scale are uncharacterised.** The system is validated for *accuracy*, not
*capacity*. Its sustained packets-per-second and flow-processing rate under load, and behaviour
when the capture drops packets, have not been measured. A production deployment (deferred) would
quantify these.

**Attack coverage is bounded by the datasets.** The detectors address DoS/DDoS, brute force,
web attacks, botnet and port scan. Data exfiltration, lateral movement, and novel/zero-day
attacks outside these families are not represented; the anomaly-style detection of genuinely
unseen attacks is not a claim of this work.

**Self-labelling could, in principle, inherit Snort's blind spots.** Because some labels come
from Snort agreement, the detectors could learn to reproduce Snort's gaps (e.g. attacks Snort
cannot see). This is mitigated by the *independent*-agreement requirement, the cross-check, and
the forgetting gate, and is **measured** by the `blind_spot.csv` analysis (per-attack Snort
coverage vs the change in detection after adaptation) and the `+self` ablation (self-training
with no Snort). Report those results as the empirical answer to this concern.

**Engineering scope.** The capture path handles IPv4 Ethernet, including 802.1Q/QinQ VLAN tags;
IPv6 is not yet parsed (future work). Models are Python pickles (integrity-checked by SHA-256
before loading, but a safer serialization format is future work). The Redis instance the system
launches binds to loopback only; to serve the dashboard beyond localhost, place it behind an
authenticated HTTPS proxy.

---

## 5. Pre-submission checklist

- [ ] Run `build_cicids2017.py` → `train.py` (both labs) → `adapt.py --source 2018 --target 2017`
      **and** `--source 2017 --target 2018`. (This is the core evidence.)
- [ ] Report the `full` vs `ai` McNemar result (both directions) with 95% intervals.
- [ ] Report the `+self` ablation and `blind_spot.csv` (answers "is it Snort, and does it learn
      blind spots?").
- [ ] Add the related-work citations in §1 and the delta paragraph.
- [ ] Scope the generalisation claim (§2); add a third dataset if time permits.
- [ ] Add the labelling note (§3) and the limitations (§4).
- [ ] (Before any production test) bind Redis to localhost; add a throughput number.
