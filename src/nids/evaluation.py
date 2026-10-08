"""Detection metrics, with the statistics to tell a real difference from chance.

``wilson`` gives a confidence interval for a rate (detection rate, false-alarm rate): the
Wilson score interval, which stays inside [0, 1] and behaves well for rates near 0 or 1
and for small counts, unlike the textbook normal approximation.

``mcnemar`` compares two systems judged on the same connections. Only the connections
where exactly one of them is right carry information: b = only A right, c = only B right.
If the systems were equally good, b and c would differ only by chance; the test gives the
probability (p-value) of a difference at least this large under that assumption. It uses
the exact binomial test when b + c is small and the chi-square test with continuity
correction otherwise.
"""

import numpy as np
from scipy import stats


def metrics(y_true, y_pred) -> dict[str, float]:
    y_true, y_pred = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    return {
        "accuracy": float(np.mean(y_true == y_pred)),
        "detection_rate": float(np.mean(y_pred[y_true])) if y_true.any() else float("nan"),
        "false_alarm_rate": float(np.mean(y_pred[~y_true])) if (~y_true).any() else float("nan"),
    }


def wilson(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """Confidence interval (low, high) for the rate successes / total."""
    if total == 0:
        return float("nan"), float("nan")
    z = stats.norm.ppf(1 - (1 - confidence) / 2)
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def metrics_with_intervals(y_true, y_pred, confidence: float = 0.95) -> dict[str, float]:
    """``metrics`` plus Wilson intervals: detection_rate_low/high, false_alarm_rate_low/high."""
    y_true, y_pred = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    out = metrics(y_true, y_pred)
    out["detection_rate_low"], out["detection_rate_high"] = wilson(
        int((y_pred & y_true).sum()), int(y_true.sum()), confidence)
    out["false_alarm_rate_low"], out["false_alarm_rate_high"] = wilson(
        int((y_pred & ~y_true).sum()), int((~y_true).sum()), confidence)
    return out


def mcnemar(y_true, pred_a, pred_b, exact_below: int = 25) -> dict:
    """McNemar's test of systems A and B on the same samples.

    Returns b (only A right), c (only B right), the test used, the statistic and the
    two-sided p-value. p < 0.05: the difference is unlikely to be chance."""
    y_true = np.asarray(y_true, dtype=bool)
    a_right = np.asarray(pred_a, dtype=bool) == y_true
    b_right = np.asarray(pred_b, dtype=bool) == y_true
    b, c = int((a_right & ~b_right).sum()), int((~a_right & b_right).sum())
    if b + c == 0:
        return {"b": 0, "c": 0, "test": "none", "statistic": 0.0, "p_value": 1.0}
    if b + c < exact_below:
        p = stats.binomtest(b, b + c, 0.5).pvalue
        return {"b": b, "c": c, "test": "exact binomial", "statistic": float(min(b, c)), "p_value": float(p)}
    statistic = (abs(b - c) - 1) ** 2 / (b + c)
    return {"b": b, "c": c, "test": "chi-square (continuity corrected)", "statistic": float(statistic),
            "p_value": float(stats.chi2.sf(statistic, 1))}
