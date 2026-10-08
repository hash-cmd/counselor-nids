"""Snort as a counselor — a signature-based advisor in the counselors network.

The paper's counselors are all machine-learning detectors. Here Snort joins them: when a
detector's classifiers disagree on a connection, or it judged the connection normal and
cross-checks it, Snort's verdict on that same connection is advice like any other. Snort
only ever says "attack" — silence is not evidence of normal traffic (it cannot see floods
or botnets, for instance) — so it advises only on connections it alerted on.

How much a counselor's advice is worth is its accuracy. For Snort that is per rule, kept by
``RuleTrust``: a fixed value, or (adaptive trust) a Beta estimate updated from how often the
AI agrees with each rule on the network being watched. Callers count a disagreement only when
the AI flagged nothing from the alert's source, so a rule is not punished for catching what
the AI cannot see.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping

import numpy as np


class RuleTrust:
    """Trust in each Snort rule: the posterior mean of a Beta prior (``prior`` with weight
    ``prior_weight`` pseudo-observations) updated with agreements and disagreements."""

    def __init__(self, prior: float = 0.9, prior_weight: float = 20.0):
        self.prior, self.prior_weight = prior, prior_weight
        self.agree: dict[str, int] = defaultdict(int)
        self.disagree: dict[str, int] = defaultdict(int)

    def update(self, rule: str, agree: int = 0, disagree: int = 0) -> None:
        self.agree[rule] += agree
        self.disagree[rule] += disagree

    def score(self, rule: str) -> float:
        a, d = self.agree.get(rule, 0), self.disagree.get(rule, 0)
        return (self.prior * self.prior_weight + a) / (self.prior_weight + a + d)

    def table(self) -> dict[str, dict]:
        rules = set(self.agree) | set(self.disagree)
        return {r: {"agree": self.agree.get(r, 0), "disagree": self.disagree.get(r, 0),
                    "trust": round(self.score(r), 4)} for r in sorted(rules)}


class SnortCounselor:
    """Advice from Snort alerts that were linked to connections.

    ``alerts`` maps a connection's timestamp (the record id when advice is matched exactly,
    as in live mode) to the rules that fired on it. The advice for a connection is
    "attack", with the trust of the most trusted of those rules.
    """

    name = "snort"

    def __init__(self, alerts: Mapping[float, Iterable[str]], trust: RuleTrust | None = None):
        self.alerts = {float(k): tuple(v) for k, v in alerts.items() if v}
        self.trust = trust or RuleTrust()

    def advise_many(self, timestamps: np.ndarray, window: float = 0.0):
        timestamps = np.asarray(timestamps, dtype=float)
        found = np.zeros(len(timestamps), dtype=bool)
        confidence = np.zeros(len(timestamps))
        for i, t in enumerate(timestamps):
            rules = self.alerts.get(float(t))
            if rules:
                found[i] = True
                confidence[i] = max(self.trust.score(r) for r in rules)
        return found, found.copy(), confidence
