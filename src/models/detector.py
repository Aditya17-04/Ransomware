"""
models/detector.py
──────────────────
Real-Time Threat Detector
==========================
Loads the trained model artefact and scaler, then classifies each incoming
:class:`~features.aggregator.FeatureVector` with sub-millisecond latency.

Inference path
──────────────
  FeatureVector (23 dims, already scaled by the aggregator)
       │
       ▼
  model.predict_proba(vector)   →  [p_benign, p_suspicious, p_malicious]
       │
       ▼
  ThreatResult  (label, confidence, probabilities, metadata)

The :class:`~engine.decision_engine.DecisionEngine` consumes
:class:`ThreatResult` objects and decides which response to trigger.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from src.features.aggregator import FeatureVector
from src.utils.logger import get_logger

log = get_logger(__name__)

_MODEL_FILENAME  = "threat_model.joblib"
_SCALER_FILENAME = "scaler.joblib"
_CLASS_NAMES     = ["Benign", "Suspicious", "Malicious"]


# ── Inference result ─────────────────────────────────────────────────────────

@dataclass
class ThreatResult:
    """Inference output for a single feature-vector window."""
    timestamp:    float
    label:        str                  # "Benign" | "Suspicious" | "Malicious"
    label_id:     int                  # 0 | 1 | 2
    confidence:   float                # probability of the predicted class
    probabilities: dict[str, float]    # {class_name: probability, …}
    feature_vector: FeatureVector
    inference_ms:  float               # wall-clock inference latency

    @property
    def is_malicious(self) -> bool:
        return self.label_id == 2

    @property
    def is_suspicious(self) -> bool:
        return self.label_id == 1

    def __str__(self) -> str:
        probs = "  ".join(
            f"{k}={v:.3f}" for k, v in self.probabilities.items()
        )
        return (
            f"[{self.label:>11s}] conf={self.confidence:.4f}  "
            f"({probs})  latency={self.inference_ms:.2f}ms"
        )


# ── Detector ─────────────────────────────────────────────────────────────────

class ThreatDetector:
    """
    Thread-safe, low-latency inference wrapper around the trained model.

    The model and scaler are loaded once at construction time.  All subsequent
    calls to :meth:`predict` are stateless and safe for concurrent use.

    Parameters
    ----------
    model_dir : str | Path
        Directory containing ``threat_model.joblib`` and ``scaler.joblib``.
    """

    def __init__(self, model_dir: str | Path = "models/saved") -> None:
        self._model_dir = Path(model_dir)
        self._model: Any | None = None
        self._scaler: Any | None = None
        self._loaded = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> "ThreatDetector":
        """Load model and scaler artefacts from disk."""
        model_path  = self._model_dir / _MODEL_FILENAME
        scaler_path = self._model_dir / _SCALER_FILENAME

        if not model_path.exists():
            raise FileNotFoundError(
                f"Model artefact not found at '{model_path}'.  "
                "Run 'python -m src.models.trainer' to train the model first."
            )

        log.info("Loading threat model from '%s'.", model_path)
        self._model = joblib.load(model_path)

        if scaler_path.exists():
            log.info("Loading scaler from '%s'.", scaler_path)
            self._scaler = joblib.load(scaler_path)
        else:
            log.warning(
                "Scaler artefact not found at '%s'.  "
                "Predictions will use raw (unscaled) features.", scaler_path
            )

        self._loaded = True
        log.info("ThreatDetector ready (%s).", type(self._model).__name__)
        return self

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, fv: FeatureVector) -> ThreatResult:
        """
        Classify a single :class:`FeatureVector`.

        Parameters
        ----------
        fv : FeatureVector
            A 23-dim feature vector produced by the aggregator.

        Returns
        -------
        ThreatResult
        """
        if not self._loaded:
            self.load()

        t0 = time.perf_counter()
        X = fv.vector.reshape(1, -1)

        # Apply scaler only if the aggregator hasn't already (i.e. no
        # preprocessor was wired into the aggregator).
        if self._scaler is not None:
            try:
                X = self._scaler.transform(X)
            except Exception as exc:
                log.warning("Scaler transform failed during inference: %s", exc)

        proba = self._model.predict_proba(X)[0]      # shape (3,)
        label_id   = int(np.argmax(proba))
        confidence = float(proba[label_id])
        label      = _CLASS_NAMES[label_id]
        latency_ms = (time.perf_counter() - t0) * 1000.0

        result = ThreatResult(
            timestamp=fv.timestamp,
            label=label,
            label_id=label_id,
            confidence=confidence,
            probabilities={
                _CLASS_NAMES[i]: round(float(p), 6) for i, p in enumerate(proba)
            },
            feature_vector=fv,
            inference_ms=round(latency_ms, 3),
        )

        log.debug("Inference: %s", result)
        return result

    def batch_predict(self, feature_vectors: list[FeatureVector]) -> list[ThreatResult]:
        """Classify a batch of feature vectors in one forward pass."""
        if not feature_vectors:
            return []
        if not self._loaded:
            self.load()

        t0 = time.perf_counter()
        X = np.vstack([fv.vector for fv in feature_vectors])

        if self._scaler is not None:
            try:
                X = self._scaler.transform(X)
            except Exception as exc:
                log.warning("Batch scaler transform failed: %s", exc)

        proba_matrix = self._model.predict_proba(X)           # (N, 3)
        label_ids    = np.argmax(proba_matrix, axis=1)
        total_ms     = (time.perf_counter() - t0) * 1000.0
        per_ms       = total_ms / len(feature_vectors)

        results: list[ThreatResult] = []
        for i, fv in enumerate(feature_vectors):
            proba     = proba_matrix[i]
            label_id  = int(label_ids[i])
            results.append(ThreatResult(
                timestamp=fv.timestamp,
                label=_CLASS_NAMES[label_id],
                label_id=label_id,
                confidence=float(proba[label_id]),
                probabilities={
                    _CLASS_NAMES[j]: round(float(p), 6)
                    for j, p in enumerate(proba)
                },
                feature_vector=fv,
                inference_ms=round(per_ms, 3),
            ))
        return results
