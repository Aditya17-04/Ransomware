"""
features/preprocessor.py
────────────────────────
Feature Normalisation
=====================
Wraps a scikit-learn scaler to provide a stateful ``fit`` / ``transform``
interface that the :class:`~features.aggregator.FeatureAggregator` uses at
inference time and that :class:`~models.trainer.ModelTrainer` uses at
training time.

The fitted scaler is persisted alongside the model artefact so that the
same normalisation parameters are applied to both training and live data.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler

from src.utils.logger import get_logger

log = get_logger(__name__)

_SCALER_REGISTRY: dict[str, type] = {
    "standard": StandardScaler,
    "minmax":   MinMaxScaler,
    "robust":   RobustScaler,
}

_SCALER_FILENAME = "scaler.joblib"


class FeaturePreprocessor:
    """
    Stateful feature normaliser.

    Parameters
    ----------
    config : dict
        The ``features`` section of the master configuration.
    model_dir : str
        Directory where the fitted scaler artefact is persisted.
    """

    def __init__(self, config: dict[str, Any], model_dir: str = "models/saved") -> None:
        scaler_name = config.get("scaler", "standard").lower()
        if scaler_name not in _SCALER_REGISTRY:
            log.warning(
                "Unknown scaler '%s'; defaulting to 'standard'.", scaler_name
            )
            scaler_name = "standard"
        self._scaler_cls = _SCALER_REGISTRY[scaler_name]
        self._scaler: Any = self._scaler_cls()
        self._fitted = False
        self._model_dir = Path(model_dir)

    # ── Public API ────────────────────────────────────────────────────────────

    def fit(self, X: np.ndarray) -> "FeaturePreprocessor":
        """Fit the scaler on the training matrix *X* of shape (n_samples, n_features)."""
        self._scaler.fit(X)
        self._fitted = True
        log.info("FeaturePreprocessor fitted on %d samples.", X.shape[0])
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Normalise *X*.  The scaler is fitted on first call if not already fitted,
        using *X* itself as a single-sample reference (identity transform effectively).
        """
        if not self._fitted:
            log.warning(
                "Scaler not yet fitted — fitting on current sample (identity normalisation)."
            )
            self.fit(X)
        return self._scaler.transform(X)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Convenience method: fit then transform *X* in one call."""
        self.fit(X)
        return self._scaler.transform(X)

    def save(self) -> str:
        """Persist the fitted scaler to *model_dir/scaler.joblib*."""
        if not self._fitted:
            raise RuntimeError("Cannot save an unfitted scaler.")
        self._model_dir.mkdir(parents=True, exist_ok=True)
        path = self._model_dir / _SCALER_FILENAME
        joblib.dump(self._scaler, path)
        log.info("Scaler saved to %s.", path)
        return str(path)

    def load(self) -> "FeaturePreprocessor":
        """Load a previously saved scaler from *model_dir/scaler.joblib*."""
        path = self._model_dir / _SCALER_FILENAME
        if not path.exists():
            raise FileNotFoundError(
                f"Scaler artefact not found at '{path}'.  "
                "Run training first to generate it."
            )
        self._scaler = joblib.load(path)
        self._fitted = True
        log.info("Scaler loaded from %s.", path)
        return self
