"""Detection metrics."""

import numpy as np


def metrics(y_true, y_pred) -> dict[str, float]:
    y_true, y_pred = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    return {
        "accuracy": float(np.mean(y_true == y_pred)),
        "detection_rate": float(np.mean(y_pred[y_true])) if y_true.any() else float("nan"),
        "false_alarm_rate": float(np.mean(y_pred[~y_true])) if (~y_true).any() else float("nan"),
    }
