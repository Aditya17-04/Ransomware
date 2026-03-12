"""
tests/test_engine.py
─────────────────────
Unit tests for the Decision Engine, ML Detector, Model Trainer, and
Response Action modules.

Run with:
    pytest tests/test_engine.py -v
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from src.engine.decision_engine import AlertRecord, DecisionEngine
from src.features.aggregator import FeatureVector
from src.models.detector import ThreatDetector, ThreatResult
from src.models.trainer import (
    ModelTrainer,
    _CLASS_NAMES,
    _FEATURE_COLUMNS,
    _generate_synthetic_dataset,
)


# ════════════════════════════════════════════════════════════════════════════
# Helpers / fixtures
# ════════════════════════════════════════════════════════════════════════════

def _make_config(dry_run: bool = True) -> dict:
    return {
        "system": {
            "log_level": "DEBUG",
            "log_dir":   "logs",
            "model_dir": "models/saved",
            "data_dir":  "data",
            "version":   "1.0.0",
        },
        "telemetry": {"window_seconds": 5},
        "features": {
            "normalize": True,
            "scaler":    "standard",
            "vector_size": 23,
        },
        "model": {
            "algorithm": "random_forest",
            "classes": _CLASS_NAMES,
            "lightgbm": {
                "num_leaves": 31, "max_depth": -1, "n_estimators": 10,
                "learning_rate": 0.1, "min_child_samples": 5,
                "colsample_bytree": 0.8, "subsample": 0.8,
                "reg_alpha": 0.0, "reg_lambda": 0.0,
                "class_weight": "balanced", "n_jobs": 1, "random_state": 0,
            },
            "random_forest": {
                "n_estimators": 10, "max_depth": 5,
                "min_samples_split": 2, "min_samples_leaf": 1,
                "class_weight": "balanced", "n_jobs": 1, "random_state": 0,
            },
            "training": {
                "test_size": 0.2,
                "cross_val_folds": 2,
                "synthetic_samples": 300,
            },
        },
        "decision": {
            "thresholds": {"suspicious": 0.60, "high_alert": 0.85},
            "cooldown_seconds": 5,
            "dry_run": dry_run,
        },
        "response": {
            "kill_process": {"force": True},
            "network_isolation": {
                "rule_prefix": "TEST-BLOCK",
                "auto_remove_after_seconds": 0,
            },
            "file_protection": {
                "protected_dirs": [],
                "vss_backup": False,
                "revoke_write_on_alert": True,
            },
        },
    }


def _make_feature_vector(meta: dict | None = None) -> FeatureVector:
    return FeatureVector(
        timestamp=time.time(),
        vector=np.zeros(23, dtype=float),
        metadata=meta or {},
    )


def _make_threat_result(label: str, confidence: float, fv: FeatureVector | None = None) -> ThreatResult:
    label_id = _CLASS_NAMES.index(label)
    proba = [0.0, 0.0, 0.0]
    proba[label_id] = confidence
    # Distribute complement across other classes
    remainder = (1.0 - confidence) / 2.0
    for i in range(3):
        if i != label_id:
            proba[i] = remainder
    return ThreatResult(
        timestamp=time.time(),
        label=label,
        label_id=label_id,
        confidence=confidence,
        probabilities={_CLASS_NAMES[i]: proba[i] for i in range(3)},
        feature_vector=fv or _make_feature_vector(),
        inference_ms=0.5,
    )


# ════════════════════════════════════════════════════════════════════════════
# Synthetic dataset generator
# ════════════════════════════════════════════════════════════════════════════

class TestSyntheticDataset:
    def test_shape(self):
        df = _generate_synthetic_dataset(300)
        assert len(df) == 300
        assert "label" in df.columns
        assert len(df.columns) == len(_FEATURE_COLUMNS) + 1

    def test_class_balance(self):
        df = _generate_synthetic_dataset(999)
        counts = df["label"].value_counts()
        assert set(counts.index) == {0, 1, 2}
        # Each class should have at least 30% of floor(999/3)=333 samples
        assert all(c >= 300 for c in counts)

    def test_no_nan_values(self):
        df = _generate_synthetic_dataset(600)
        assert not df.isnull().any().any()

    def test_entropy_range_for_malicious(self):
        df = _generate_synthetic_dataset(600)
        mal = df[df["label"] == 2]
        # Malicious samples should have high mean entropy
        assert mal["file_entropy_mean"].mean() >= 7.0


# ════════════════════════════════════════════════════════════════════════════
# ModelTrainer
# ════════════════════════════════════════════════════════════════════════════

class TestModelTrainer:
    def test_trains_and_returns_model(self, tmp_path):
        cfg = _make_config()
        cfg["system"]["model_dir"] = str(tmp_path / "models")
        cfg["system"]["data_dir"]  = str(tmp_path / "data")

        trainer = ModelTrainer(cfg)
        model, preprocessor = trainer.run()

        assert model is not None
        assert preprocessor is not None
        assert (tmp_path / "models" / "threat_model.joblib").exists()
        assert (tmp_path / "models" / "scaler.joblib").exists()

    def test_model_can_predict(self, tmp_path):
        cfg = _make_config()
        cfg["system"]["model_dir"] = str(tmp_path / "models")
        cfg["system"]["data_dir"]  = str(tmp_path / "data")

        trainer = ModelTrainer(cfg)
        model, _ = trainer.run()

        X = np.zeros((1, 23))
        preds = model.predict(X)
        assert preds.shape == (1,)
        assert preds[0] in [0, 1, 2]


# ════════════════════════════════════════════════════════════════════════════
# ThreatDetector
# ════════════════════════════════════════════════════════════════════════════

class TestThreatDetector:
    def _trained_detector(self, tmp_path) -> ThreatDetector:
        cfg = _make_config()
        cfg["system"]["model_dir"] = str(tmp_path)
        cfg["system"]["data_dir"]  = str(tmp_path / "data")
        trainer = ModelTrainer(cfg)
        trainer.run()
        det = ThreatDetector(model_dir=str(tmp_path))
        det.load()
        return det

    def test_predict_returns_threat_result(self, tmp_path):
        det = self._trained_detector(tmp_path)
        fv = _make_feature_vector()
        result = det.predict(fv)
        assert isinstance(result, ThreatResult)
        assert result.label in _CLASS_NAMES
        assert 0.0 <= result.confidence <= 1.0

    def test_probabilities_sum_to_one(self, tmp_path):
        det = self._trained_detector(tmp_path)
        fv = _make_feature_vector()
        result = det.predict(fv)
        total = sum(result.probabilities.values())
        assert total == pytest.approx(1.0, abs=1e-6)

    def test_batch_predict_length(self, tmp_path):
        det = self._trained_detector(tmp_path)
        fvs = [_make_feature_vector() for _ in range(5)]
        results = det.batch_predict(fvs)
        assert len(results) == 5

    def test_inference_ms_positive(self, tmp_path):
        det = self._trained_detector(tmp_path)
        result = det.predict(_make_feature_vector())
        assert result.inference_ms >= 0.0

    def test_model_not_found_raises(self, tmp_path):
        det = ThreatDetector(model_dir=str(tmp_path / "nonexistent"))
        with pytest.raises(FileNotFoundError):
            det.load()


# ════════════════════════════════════════════════════════════════════════════
# DecisionEngine
# ════════════════════════════════════════════════════════════════════════════

class TestDecisionEngine:
    def _engine(self) -> DecisionEngine:
        return DecisionEngine(_make_config(dry_run=True))

    def test_benign_result_not_recorded(self):
        engine = self._engine()
        result = _make_threat_result("Benign", confidence=0.92)
        alert = engine.evaluate(result)
        assert alert is None
        assert len(engine.alert_history) == 0

    def test_below_suspicious_threshold_ignored(self):
        engine = self._engine()
        result = _make_threat_result("Suspicious", confidence=0.50)
        alert = engine.evaluate(result)
        assert alert is None

    def test_suspicious_alert_raised(self):
        engine = self._engine()
        result = _make_threat_result("Suspicious", confidence=0.70)
        alert = engine.evaluate(result)
        assert alert is not None
        assert alert.level == "Suspicious"
        assert len(engine.alert_history) == 1

    def test_high_alert_triggers_response_chain(self):
        engine = self._engine()
        result = _make_threat_result("Malicious", confidence=0.95)
        alert = engine.evaluate(result)
        assert alert is not None
        assert alert.level == "HighAlert"
        # All three response categories should appear in the action list
        action_str = " ".join(alert.actions_taken)
        assert "KillProcess" in action_str
        assert "NetworkBlock" in action_str
        assert "RevokeWrite" in action_str

    def test_cooldown_prevents_duplicate_response(self):
        engine = self._engine()
        fv = _make_feature_vector(meta={"pid": 9999})

        r1 = _make_threat_result("Malicious", confidence=0.95, fv=fv)
        r2 = _make_threat_result("Malicious", confidence=0.95, fv=fv)

        a1 = engine.evaluate(r1)
        a2 = engine.evaluate(r2)

        assert a1 is not None
        assert a2 is None    # cooldown suppressed second alert

    def test_history_grows(self):
        engine = self._engine()
        for _ in range(3):
            result = _make_threat_result("Suspicious", confidence=0.70)
            engine.evaluate(result)
        assert len(engine.alert_history) == 3

    def test_threshold_boundary_suspicious(self):
        engine = self._engine()
        # Exactly at the suspicious threshold → should NOT trigger
        result = _make_threat_result("Suspicious", confidence=0.6)
        # Our config: suspicious ≥ 0.60, high_alert ≥ 0.85
        # At exactly 0.60 it should trigger suspicious
        alert = engine.evaluate(result)
        # The check is conf < thresh_suspicious → 0.60 < 0.60 is False → alert raised
        assert alert is not None
        assert alert.level == "Suspicious"

    def test_shutdown_does_not_raise(self):
        engine = self._engine()
        engine.shutdown()   # Should complete without exception


# ════════════════════════════════════════════════════════════════════════════
# Response modules (dry-run, subprocess is mocked)
# ════════════════════════════════════════════════════════════════════════════

class TestProcessKillerDryRun:
    def test_dry_run_returns_true(self):
        from src.engine.response.process_killer import ProcessKiller
        killer = ProcessKiller({"force": True}, dry_run=True)
        # PID 99999 — almost certainly doesn't exist; dry-run should still return True
        assert killer.kill(99999, reason="test") is True


class TestNetworkIsolatorDryRun:
    def test_block_ip_dry_run(self):
        from src.engine.response.network_isolator import NetworkIsolator
        isolator = NetworkIsolator(
            {"rule_prefix": "TEST", "auto_remove_after_seconds": 0},
            dry_run=True,
        )
        assert isolator.block_ip("1.2.3.4", 4444, reason="test") is True

    def test_unblock_ip_dry_run(self):
        from src.engine.response.network_isolator import NetworkIsolator
        isolator = NetworkIsolator(
            {"rule_prefix": "TEST", "auto_remove_after_seconds": 0},
            dry_run=True,
        )
        assert isolator.unblock_ip("1.2.3.4", 4444) is True


class TestFileProtectorDryRun:
    def test_revoke_write_dry_run(self):
        from src.engine.response.file_protector import FileProtector
        protector = FileProtector(
            {"protected_dirs": [], "vss_backup": False, "revoke_write_on_alert": True},
            dry_run=True,
        )
        assert protector.revoke_write("C:\\SomeDir", reason="test") is True

    def test_vss_snapshot_dry_run(self):
        from src.engine.response.file_protector import FileProtector
        protector = FileProtector(
            {"protected_dirs": [], "vss_backup": True, "revoke_write_on_alert": True},
            dry_run=True,
        )
        guid = protector.create_vss_snapshot("C:")
        assert guid == "DRY-RUN-GUID"

    def test_vss_disabled_returns_none(self):
        from src.engine.response.file_protector import FileProtector
        protector = FileProtector(
            {"protected_dirs": [], "vss_backup": False, "revoke_write_on_alert": True},
            dry_run=False,
        )
        assert protector.create_vss_snapshot("C:") is None
