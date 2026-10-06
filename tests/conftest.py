import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification

from tests.helpers import FEATURES


@pytest.fixture
def blobs():
    """Small, easily separable binary dataset with a record_id timestamp."""
    X, y = make_classification(
        n_samples=600, n_features=6, n_informative=4, n_redundant=0,
        class_sep=3.0, random_state=0,
    )
    df = pd.DataFrame(X, columns=FEATURES)
    df["is_attack"] = y.astype(bool)
    df["record_id"] = np.arange(len(df))
    return df
