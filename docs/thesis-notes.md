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

## 4b. Aligning the objectives with what was built

The "Trustworthy and Explainable" abstract matches the system on the Snort cross-check,
agreement-based adaptation, the promotion and forgetting gates, and the whole trustworthiness
theme. Two items needed reconciling; both are now addressed.

**Explainability (Objective 6, RQ5, "explanation coverage" in Objective 7).** The system now
has an explicit mechanism: `src/nids/services/explain.py` turns every alert into a structured,
human-readable reason — which detector recognised it (the attack family), how it decided (on
its own, by a counselor's advice, or double-checked), which Snort rule matched, and the
Confirmed/Disputed/AI-only agreement status. `explain.coverage()` measures **explanation
coverage** (the share of alerts carrying a valid reason), reported by `nids journal-report`.
By construction every ML alert names a detector and every Snort alert a rule, so coverage is
total — which is itself the result to state: *unlike a black-box classifier, every alert the
architecture raises carries a reason (100% explanation coverage)*. If the examiner expects a
model-internal method, add SHAP/LIME on the ML detectors as the stronger, optional step and
scope the claim accordingly.

**Objective 1 / RQ1 / H1 — "detectors each trained on a different dataset" and their conflict.**
The implemented detectors are **specialists by attack family** (Flood, Break-in, Botnet),
trained on the same lab and split by attack — not one-per-dataset. "Conflict" in this system is
a detector's classifiers disagreeing so that it must consult the others. Reword to match:

> **Objective 1 (reworded).** Implement a baseline counsellor network of specialist ML
> detectors (each specialising in one attack family) and measure how often a detector cannot
> decide on its own and must consult the others (the conflict/consultation rate), and how far a
> counsellor trained on one network degrades when moved to a different one.
>
> **RQ1 (reworded).** To what extent do the counsellor network's detectors fail to decide on
> their own (conflict rate), and how much does a lab-trained counsellor's accuracy drop on a
> different network (the deployment gap)?
>
> **H1₀ / H1₁.** Moving a lab-trained counsellor to a different network does **not** / **does**
> significantly change its detection performance.

The **conflict rate** is now measured: `adapt.py` records `conflict_rate` per configuration and
step in `curve.csv` (the fraction of connections where some detector's resolution is not
`unanimous`), and the live Detectors page already shows the same breakdown (sure on its own /
asked a colleague / double-checked / best guess). The cross-network degradation is the headline
2018↔2017 result.

**Metrics (Objective 7).** `evaluation.metrics` now reports **precision, recall, F1 and MCC**
(MCC and **PR-AUC** are the imbalance-robust pair) alongside detection and false-alarm rates (so
`train.py` and `adapt.py` output them), the **conflict rate** and **PR-AUC** are in `curve.csv`,
**Cohen's kappa** for the Snort-AI agreement is in `pseudo_labels.csv`, **performance retention**
is what the forgetting gate checks, and **explanation coverage** comes from `explain.coverage()`.

## 4c. Mathematical formulations added (for the methodology chapter)

- **Adaptive trust = Beta reputation.** Each Snort rule's trust is the posterior mean of a Beta
  prior: `trust = (p0·w + agreements) / (w + agreements + disagreements)` with an informative
  prior `p0 = 0.9`, weight `w = 20` (`RuleTrust`). Optional **forgetting** fades old evidence:
  `alpha <- lambda·alpha + agree`, `beta <- lambda·beta + disagree` (`--rule-decay` lambda; 1.0
  keeps everything). This gives both a trust score and an implied confidence (evidence count).
- **Cohen's kappa** `kappa = (po - pe)/(1 - pe)` measures Snort-AI agreement beyond chance —
  reported per chunk, so the pseudo-label signal is shown to be more than coincidence.
- **MCC** `(/(TP·TN - FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)))` and **PR-AUC** (average
  precision) are reported because accuracy misleads on imbalanced traffic.

## 4d. The formal decision layer — built, and what testing it showed

`src/nids/counselor/decision.py` now implements the full alternative decision layer as tested
units, and `scripts/live_detectors/decision_layer.py` runs it end-to-end:

- **Calibration** (Platt / isotonic) — Brier improves markedly per detector (e.g. live_access
  0.52 → 0.09 against its own family). Done.
- **Detector trust** — Beta reputation for the AI counselors, online, with decay
  (`DetectorTrust`); reflects reliability (live_bot 1.0, live_dos 0.90, live_access 0.45). Done.
- **Fusion** — a real design finding: **log-odds pooling is wrong for this architecture.** The
  detectors are *specialists* (disjoint attack families), not redundant predictors of "attack",
  so log-odds averaging lets one specialist's "not my family" cancel another's detection (it
  flagged everything). The correct fusion is **noisy-OR**, `P = 1 − Π(1 − wᵢpᵢ)` (`fuse_noisy_or`).
- **Cost-sensitive threshold** `p* = C_FP/(C_FP+C_FN)` — done.
- **Importance weighting** and **Page-Hinkley drift** — done, demonstrated in `--stream`.

**Result (the honest ablation):** with correct noisy-OR fusion the decision layer catches
slightly *more* attacks (99.8% vs 96.8%) but at a large false-alarm cost (29.7% vs 0.02%), so
MCC falls. Like the detector-trust ablation, the sophisticated alternative **underperforms** the
deployed counselor voting with suppress-fallback — which justifies the existing design. Present
the decision layer as an evaluated alternative, not the main path, and report this trade-off.

Not adopted, with reasons to state:
- **Elastic Weight Consolidation** is a gradient/neural-net method (Fisher information over
  parameters); the detectors are tree ensembles + naive Bayes, so EWC does not apply — the
  **gate-based** forgetting prevention is the correct tool for this model family.
- **Log-odds pooling** specifically: tested and found unsound for disjoint specialists (above);
  kept in the module as a general primitive but not used for the detectors.

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
- [ ] Reword Objective 1 / RQ1 / H1 to the attack-family specialists + conflict rate (§4b).
- [ ] Report precision / recall / F1, the conflict rate (`curve.csv`), performance retention,
      and explanation coverage (`explain.coverage()` / `nids journal-report`) for Objective 7.
- [ ] State the explainability mechanism and its coverage (§4b); add SHAP/LIME only if needed.
- [ ] (Before any production test) bind Redis to localhost; add a throughput number.
