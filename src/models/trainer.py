"""
models/trainer.py
─────────────────
Model Training Pipeline
========================
Trains a multi-class threat classifier (LightGBM or Random Forest) on a
labelled dataset of feature vectors and persists the trained artefact.

Dataset format
──────────────
CSV with the following columns:
    cpu_total_pct, cpu_privileged_pct, interrupts_per_sec,
    cache_faults_per_sec, page_faults_per_sec, pages_per_sec,
    context_switches_per_sec, syscalls_per_sec,
    file_total_events, file_deletes, file_renames, file_writes,
    file_entropy_mean, file_entropy_max, file_susp_ext_count,
    net_bytes_out, net_bytes_in, net_connections, net_unique_ips,
    net_bl_port_hits, net_beacon_score, net_exfil_flag, net_active_flows,
    label   ← 0=Benign, 1=Suspicious, 2=Malicious

If no dataset CSV is provided, a *synthetic* dataset is generated for
demonstration purposes.  The synthetic generator creates statistically
plausible feature distributions for each class.

Usage (CLI)
──────────
    python -m src.models.trainer --config config/config.yaml
    python -m src.models.trainer --dataset data/cic_ids_features.csv
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from src.features.preprocessor import FeaturePreprocessor
from src.utils.config_loader import load_config
from src.utils.logger import configure_root_logger, get_logger

log = get_logger(__name__)

_MODEL_FILENAME  = "threat_model.joblib"
_FEATURE_COLUMNS = [
    # HPC (8)
    "cpu_total_pct", "cpu_privileged_pct", "interrupts_per_sec",
    "cache_faults_per_sec", "page_faults_per_sec", "pages_per_sec",
    "context_switches_per_sec", "syscalls_per_sec",
    # File (7)
    "file_total_events", "file_deletes", "file_renames", "file_writes",
    "file_entropy_mean", "file_entropy_max", "file_susp_ext_count",
    # Network (8)
    "net_bytes_out", "net_bytes_in", "net_connections", "net_unique_ips",
    "net_bl_port_hits", "net_beacon_score", "net_exfil_flag", "net_active_flows",
]
_LABEL_COLUMN = "label"
_CLASS_NAMES = ["Benign", "Suspicious", "Malicious"]


# ── Synthetic data generator (demonstration & unit tests) ─────────────────────

def _generate_synthetic_dataset(n_samples: int, seed: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic labelled dataset with realistic per-class distributions.

    The distributions are inspired by published research on ransomware behaviour
    telemetry (CIC-IDS2017, CIC-IDS2018, and custom lab captures).
    """
    rng = np.random.default_rng(seed)
    n_per_class = n_samples // 3
    extra = n_samples - 3 * n_per_class

    def _benign(n: int) -> np.ndarray:
        return np.column_stack([
            rng.uniform(5, 40, n),           # cpu_total_pct
            rng.uniform(1, 10, n),            # cpu_privileged_pct
            rng.uniform(100, 2000, n),        # interrupts_per_sec
            rng.uniform(5, 50, n),            # cache_faults_per_sec
            rng.uniform(0.5, 10, n),          # page_faults_per_sec
            rng.uniform(0, 2, n),             # pages_per_sec
            rng.uniform(200, 3000, n),        # context_switches_per_sec
            rng.uniform(1000, 20000, n),      # syscalls_per_sec
            rng.uniform(0, 5, n),             # file_total_events
            rng.uniform(0, 1, n),             # file_deletes
            rng.uniform(0, 1, n),             # file_renames
            rng.uniform(0, 4, n),             # file_writes
            rng.uniform(2.0, 5.5, n),         # file_entropy_mean
            rng.uniform(4.0, 6.5, n),         # file_entropy_max
            np.zeros(n),                      # file_susp_ext_count
            rng.uniform(1e3, 1e6, n),         # net_bytes_out
            rng.uniform(1e3, 5e5, n),         # net_bytes_in
            rng.integers(1, 20, n).astype(float),  # net_connections
            rng.integers(1, 10, n).astype(float),  # net_unique_ips
            np.zeros(n),                      # net_bl_port_hits
            rng.uniform(0, 0.1, n),           # net_beacon_score
            np.zeros(n),                      # net_exfil_flag
            rng.integers(1, 15, n).astype(float),  # net_active_flows
        ])

    def _suspicious(n: int) -> np.ndarray:
        return np.column_stack([
            rng.uniform(40, 70, n),
            rng.uniform(10, 25, n),
            rng.uniform(2000, 8000, n),
            rng.uniform(50, 200, n),
            rng.uniform(10, 50, n),
            rng.uniform(2, 10, n),
            rng.uniform(3000, 10000, n),
            rng.uniform(20000, 80000, n),
            rng.uniform(5, 30, n),
            rng.uniform(1, 5, n),
            rng.uniform(1, 8, n),
            rng.uniform(4, 22, n),
            rng.uniform(5.5, 7.0, n),
            rng.uniform(6.5, 7.5, n),
            rng.integers(0, 3, n).astype(float),
            rng.uniform(1e6, 3e6, n),
            rng.uniform(5e5, 2e6, n),
            rng.integers(20, 80, n).astype(float),
            rng.integers(10, 40, n).astype(float),
            rng.integers(0, 3, n).astype(float),
            rng.uniform(0.1, 0.5, n),
            np.zeros(n),
            rng.integers(15, 60, n).astype(float),
        ])

    def _malicious(n: int) -> np.ndarray:
        return np.column_stack([
            rng.uniform(70, 100, n),         # CPU maxed by crypto
            rng.uniform(25, 60, n),          # high privileged time (kernel)
            rng.uniform(8000, 30000, n),     # interrupt storm
            rng.uniform(200, 1000, n),       # cache thrash
            rng.uniform(50, 300, n),
            rng.uniform(10, 50, n),
            rng.uniform(10000, 50000, n),    # ctx-switch storm
            rng.uniform(80000, 500000, n),   # syscall flood (mass file ops)
            rng.uniform(30, 200, n),         # high-freq file events
            rng.uniform(5, 50, n),           # mass deletions
            rng.uniform(5, 50, n),           # mass renames
            rng.uniform(20, 150, n),
            rng.uniform(7.0, 8.0, n),        # near-max entropy (encrypted)
            rng.uniform(7.5, 8.0, n),
            rng.integers(3, 15, n).astype(float),   # ransomware extensions
            rng.uniform(3e6, 5e7, n),        # data exfil
            rng.uniform(2e6, 1e7, n),
            rng.integers(80, 300, n).astype(float),
            rng.integers(40, 150, n).astype(float),
            rng.integers(1, 10, n).astype(float),   # C2 port hits
            rng.uniform(0.5, 1.0, n),        # strong beacon signal
            np.ones(n),                      # exfil flag set
            rng.integers(60, 250, n).astype(float),
        ])

    n_b = n_per_class + extra
    X = np.vstack([_benign(n_b), _suspicious(n_per_class), _malicious(n_per_class)])
    y = np.hstack([
        np.zeros(n_b, dtype=int),
        np.ones(n_per_class, dtype=int),
        np.full(n_per_class, 2, dtype=int),
    ])

    # Shuffle
    idx = rng.permutation(len(y))
    df = pd.DataFrame(X[idx], columns=_FEATURE_COLUMNS)
    df[_LABEL_COLUMN] = y[idx]
    return df


# ── Model builder ─────────────────────────────────────────────────────────────

def _build_model(config: dict[str, Any]) -> Any:
    algo = config["model"]["algorithm"].lower()

    if algo == "lightgbm":
        try:
            import lightgbm as lgb
            p = config["model"]["lightgbm"]
            return lgb.LGBMClassifier(
                num_leaves=p["num_leaves"],
                max_depth=p["max_depth"],
                n_estimators=p["n_estimators"],
                learning_rate=p["learning_rate"],
                min_child_samples=p["min_child_samples"],
                colsample_bytree=p["colsample_bytree"],
                subsample=p["subsample"],
                reg_alpha=p["reg_alpha"],
                reg_lambda=p["reg_lambda"],
                class_weight=p["class_weight"],
                n_jobs=p["n_jobs"],
                random_state=p["random_state"],
                verbose=-1,
            )
        except ImportError:
            log.warning("LightGBM not installed — falling back to Random Forest.")
            algo = "random_forest"

    if algo == "random_forest":
        p = config["model"]["random_forest"]
        return RandomForestClassifier(
            n_estimators=p["n_estimators"],
            max_depth=p["max_depth"],
            min_samples_split=p["min_samples_split"],
            min_samples_leaf=p["min_samples_leaf"],
            class_weight=p["class_weight"],
            n_jobs=p["n_jobs"],
            random_state=p["random_state"],
        )

    raise ValueError(f"Unknown algorithm '{algo}'.")


# ── Main trainer class ────────────────────────────────────────────────────────

class ModelTrainer:
    """
    Orchestrates end-to-end model training.

    Parameters
    ----------
    config : dict
        Full application configuration dict.
    dataset_path : str | None
        Optional path to a labelled CSV.  If *None* a synthetic dataset is
        generated according to *config.model.training.synthetic_samples*.
    """

    def __init__(
        self,
        config: dict[str, Any],
        dataset_path: str | None = None,
    ) -> None:
        self._cfg = config
        self._dataset_path = dataset_path
        self._model_dir = Path(config["system"]["model_dir"])
        self._model_dir.mkdir(parents=True, exist_ok=True)
        self._preprocessor = FeaturePreprocessor(
            config["features"], str(self._model_dir)
        )

    def run(self) -> tuple[Any, FeaturePreprocessor]:
        """Train, evaluate, and persist the model.  Returns (model, preprocessor)."""

        # 1. Load or generate dataset
        df = self._load_dataset()
        X = df[_FEATURE_COLUMNS].values
        y = df[_LABEL_COLUMN].values
        log.info(
            "Dataset: %d samples — class distribution: %s",
            len(y),
            {_CLASS_NAMES[c]: int((y == c).sum()) for c in range(3)},
        )

        # 2. Normalise features
        X_scaled = self._preprocessor.fit_transform(X)

        # 3. Train / test split
        test_size = self._cfg["model"]["training"]["test_size"]
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=test_size, stratify=y,
            random_state=self._cfg["model"]["lightgbm"]["random_state"],
        )

        # 4. Build and train model
        model = _build_model(self._cfg)
        log.info("Training %s model…", type(model).__name__)
        model.fit(X_train, y_train)

        # 5. Evaluate
        self._evaluate(model, X_test, y_test)

        # 6. Cross-validation
        n_folds = self._cfg["model"]["training"]["cross_val_folds"]
        log.info("Running %d-fold stratified cross-validation…", n_folds)
        cv_scores = cross_val_score(
            model, X_scaled, y,
            cv=StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42),
            scoring="f1_macro",
            n_jobs=-1,
        )
        log.info(
            "CV F1-macro: %.4f ± %.4f",
            cv_scores.mean(), cv_scores.std()
        )

        # 7. Persist artefacts
        model_path = self._model_dir / _MODEL_FILENAME
        joblib.dump(model, model_path)
        self._preprocessor.save()
        log.info("Model saved to %s", model_path)

        return model, self._preprocessor

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_dataset(self) -> pd.DataFrame:
        if self._dataset_path and Path(self._dataset_path).exists():
            log.info("Loading dataset from '%s'.", self._dataset_path)
            df = pd.read_csv(self._dataset_path)
            # Validate columns
            missing = [c for c in _FEATURE_COLUMNS + [_LABEL_COLUMN] if c not in df.columns]
            if missing:
                raise ValueError(f"Dataset is missing required columns: {missing}")
            return df

        n = self._cfg["model"]["training"]["synthetic_samples"]
        log.info(
            "No dataset path provided — generating %d synthetic samples.", n
        )
        df = _generate_synthetic_dataset(n)
        # Save for reproducibility
        data_dir = Path(self._cfg["system"]["data_dir"])
        data_dir.mkdir(parents=True, exist_ok=True)
        out = data_dir / "synthetic_features.csv"
        df.to_csv(out, index=False)
        log.info("Synthetic dataset persisted to '%s'.", out)
        return df

    def _evaluate(self, model: Any, X_test: np.ndarray, y_test: np.ndarray) -> None:
        y_pred = model.predict(X_test)
        report = classification_report(
            y_test, y_pred, target_names=_CLASS_NAMES
        )
        log.info("Classification report:\n%s", report)
        cm = confusion_matrix(y_test, y_pred)
        log.info("Confusion matrix (rows=actual, cols=predicted):\n%s", cm)


# ── CLI entry-point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the AI-RIDS threat model.")
    parser.add_argument("--config",  default="config/config.yaml")
    parser.add_argument("--dataset", default=None, help="Path to labelled CSV dataset")
    args = parser.parse_args()

    cfg = load_config(args.config)
    configure_root_logger(
        level=cfg["system"]["log_level"],
        log_dir=cfg["system"]["log_dir"],
    )

    trainer = ModelTrainer(cfg, dataset_path=args.dataset)
    trainer.run()
