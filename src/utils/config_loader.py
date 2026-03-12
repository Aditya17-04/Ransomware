"""
utils/config_loader.py
──────────────────────
Loads and validates the YAML configuration file, providing a typed,
dot-accessible dictionary throughout the application.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.yaml"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Load the YAML configuration file.

    Parameters
    ----------
    path : str | Path | None
        Explicit path to a config file.  If *None* the bundled
        ``config/config.yaml`` is used.

    Returns
    -------
    dict
        Fully resolved configuration dictionary.

    Raises
    ------
    FileNotFoundError
        If the configuration file cannot be found.
    yaml.YAMLError
        If the file contains invalid YAML.
    """
    config_path = Path(path) if path else _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as fh:
        cfg: dict[str, Any] = yaml.safe_load(fh)

    _validate(cfg)
    return cfg


# ── Internal validation ───────────────────────────────────────────────────────

def _validate(cfg: dict[str, Any]) -> None:
    """Lightweight sanity-check on the loaded configuration."""
    required_top_keys = ["system", "telemetry", "features", "model", "decision", "response"]
    for key in required_top_keys:
        if key not in cfg:
            raise ValueError(
                f"Missing required top-level config key: '{key}'. "
                "Check config/config.yaml for correctness."
            )

    thresh = cfg["decision"]["thresholds"]
    if not (0.0 < thresh["suspicious"] < thresh["high_alert"] <= 1.0):
        raise ValueError(
            "Decision thresholds must satisfy: "
            "0 < suspicious < high_alert ≤ 1.0"
        )

    feature_size = cfg["features"]["vector_size"]
    if feature_size < 1:
        raise ValueError("features.vector_size must be ≥ 1")
