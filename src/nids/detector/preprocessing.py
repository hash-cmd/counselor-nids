from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def build_preprocessor(categorical: list[str] = ()) -> Pipeline:
    """One-hot encode categorical columns, standardise the rest, drop constant features.

    Scaling matters here: K-Means and k-NN both use Euclidean distance, so unscaled
    features with large ranges (byte counts, durations) would dominate.
    """
    encode = ColumnTransformer(
        [("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), list(categorical))],
        remainder=StandardScaler(),
    )
    return Pipeline([("encode", encode), ("drop_constant", VarianceThreshold())])
