import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler


def signed_log1p(X):
    return np.sign(X) * np.log1p(np.abs(X))


def build_preprocessor(categorical: list[str] = ()) -> Pipeline:
    """One-hot encode categorical columns, log-compress and standardise the rest,
    drop constant features.

    K-Means and k-NN use Euclidean distance. Flow features (bytes, durations, rates)
    span many orders of magnitude; without the log, a handful of extreme flows end up
    as their own K-Means clusters and every other sample falls into one cluster.
    """
    numeric = make_pipeline(FunctionTransformer(signed_log1p, feature_names_out="one-to-one"),
                            StandardScaler())
    encode = ColumnTransformer(
        [("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(categorical))],
        remainder=numeric,
    )
    return Pipeline([("encode", encode), ("drop_constant", VarianceThreshold())])
