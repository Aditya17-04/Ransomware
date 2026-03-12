"""
main.py
───────
AI-RIDS — Real-Time Ransomware & Intrusion Detection System
============================================================
Main application entry-point.

Usage
─────
  # First, train the model (generates synthetic data if no CSV is provided)
  python -m src.models.trainer --config config/config.yaml

  # Then start the real-time detection daemon
  python src/main.py --config config/config.yaml

  # Dry-run mode (log actions but don't execute kill/block/chmod)
  python src/main.py --dry-run

  # Train and run in one command
  python src/main.py --train-first

Architecture overview
─────────────────────

  ┌─────────────────────────────────────────────────────────────┐
  │                      AI-RIDS Daemon                          │
  │                                                              │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
  │  │  HPCMonitor  │  │  FileMonitor │  │  NetworkMonitor  │  │
  │  │  (thread)    │  │  (thread)    │  │  (thread)        │  │
  │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
  │         │ hpc_queue       │ file_queue         │ net_queue  │
  │         └────────────────►│◄───────────────────┘            │
  │                    ┌──────▼────────┐                        │
  │                    │FeatureAggregator│  (sliding window 5s) │
  │                    └──────┬────────┘                        │
  │                           │ FeatureVector (23 dims)         │
  │                    ┌──────▼────────┐                        │
  │                    │ThreatDetector │  (LightGBM / RF)       │
  │                    └──────┬────────┘                        │
  │                           │ ThreatResult + confidence       │
  │                    ┌──────▼────────┐                        │
  │                    │DecisionEngine │  threshold 0.85        │
  │                    └──────┬────────┘                        │
  │                           │ AlertRecord                     │
  │              ┌────────────┼────────────┐                   │
  │      ┌───────▼──┐  ┌──────▼───┐  ┌────▼─────────┐         │
  │      │Kill Proc │  │Net Block │  │ File Protect │         │
  │      └──────────┘  └──────────┘  └──────────────┘         │
  └─────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import argparse
import queue
import signal
import sys
import time
from pathlib import Path
from typing import Any

from src.engine.decision_engine import DecisionEngine
from src.features.aggregator import FeatureAggregator, FeatureVector
from src.features.preprocessor import FeaturePreprocessor
from src.models.detector import ThreatDetector
from src.models.trainer import ModelTrainer
from src.telemetry.file_monitor import FileMonitor
from src.telemetry.hpc_monitor import HPCMonitor
from src.telemetry.network_monitor import NetworkMonitor
from src.utils.config_loader import load_config
from src.utils.logger import configure_root_logger, get_logger

log = get_logger(__name__)

# ── Graceful shutdown ─────────────────────────────────────────────────────────
_SHUTDOWN = False


def _handle_signal(signum: int, frame: Any) -> None:
    global _SHUTDOWN
    log.info("Shutdown signal received (%d).", signum)
    _SHUTDOWN = True


# ── Application orchestrator ──────────────────────────────────────────────────

class AIRIDS:
    """
    Full application lifecycle manager.

    Parameters
    ----------
    config : dict
    dry_run : bool
        Override *config.decision.dry_run* when *True*.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool = False) -> None:
        self._cfg = config
        if dry_run:
            self._cfg["decision"]["dry_run"] = True
            log.info("DRY-RUN mode active — response actions will be logged only.")

        # ── Telemetry queues ──────────────────────────────────────────────────
        self._hpc_q  = queue.Queue(maxsize=500)
        self._file_q = queue.Queue(maxsize=2000)
        self._net_q  = queue.Queue(maxsize=500)

        # ── Telemetry monitors ────────────────────────────────────────────────
        self._hpc_mon  = HPCMonitor(config["telemetry"]["hpc"],     self._hpc_q)
        self._file_mon = FileMonitor(config["telemetry"]["file"],    self._file_q)
        self._net_mon  = NetworkMonitor(config["telemetry"]["network"], self._net_q)

        # ── Detector ──────────────────────────────────────────────────────────
        self._detector = ThreatDetector(config["system"]["model_dir"])
        self._detector.load()

        # ── Preprocessor (injected into aggregator for online normalisation) ──
        preprocessor = FeaturePreprocessor(
            config["features"], config["system"]["model_dir"]
        )
        try:
            preprocessor.load()
        except FileNotFoundError:
            log.warning(
                "Scaler not found — running without online normalisation. "
                "Train the model first for best accuracy."
            )
            preprocessor = None  # type: ignore[assignment]

        # ── Decision engine ───────────────────────────────────────────────────
        self._engine = DecisionEngine(config)

        # ── Feature aggregator ────────────────────────────────────────────────
        self._aggregator = FeatureAggregator(
            config=config,
            hpc_queue=self._hpc_q,
            file_queue=self._file_q,
            net_queue=self._net_q,
            on_vector=self._on_feature_vector,
            preprocessor=preprocessor,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        log.info("=" * 70)
        log.info(" AI-RIDS v%s — Starting …", self._cfg["system"]["version"])
        log.info("=" * 70)

        # Register OS signal handlers
        signal.signal(signal.SIGINT,  _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        # Start all subsystems
        if self._cfg["telemetry"]["hpc"]["enabled"]:
            self._hpc_mon.start()
        if self._cfg["telemetry"]["file"]["enabled"]:
            self._file_mon.start()
        if self._cfg["telemetry"]["network"]["enabled"]:
            self._net_mon.start()

        self._aggregator.start()

        log.info("All subsystems started.  Monitoring for threats…")
        self._run_loop()

    def _run_loop(self) -> None:
        """Block the main thread, printing a periodic status line."""
        try:
            while not _SHUTDOWN:
                time.sleep(10)
                alert_count = len(self._engine.alert_history)
                high_alerts = sum(
                    1 for a in self._engine.alert_history
                    if a.level == "HighAlert"
                )
                log.info(
                    "Status — alerts=%d  high_alerts=%d",
                    alert_count, high_alerts,
                )
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        log.info("Shutting down AI-RIDS…")
        self._aggregator.stop()
        self._hpc_mon.stop()
        self._file_mon.stop()
        self._net_mon.stop()
        self._engine.shutdown()
        log.info(
            "AI-RIDS stopped.  Total alerts: %d",
            len(self._engine.alert_history),
        )

    # ── Feature-vector callback ───────────────────────────────────────────────

    def _on_feature_vector(self, fv: FeatureVector) -> None:
        """
        Called by the FeatureAggregator once per window (every 5 s).
        Runs the detector → decision engine pipeline.
        """
        try:
            result = self._detector.predict(fv)
            alert  = self._engine.evaluate(result)
            if alert:
                self._log_alert_table(alert)
        except Exception as exc:
            log.error("Pipeline error: %s", exc, exc_info=True)

    def _log_alert_table(self, alert: Any) -> None:
        """Print a formatted alert summary to the console."""
        sep = "─" * 70
        lines = [
            sep,
            f"  ALERT LEVEL   : {alert.level}",
            f"  Label         : {alert.label}",
            f"  Confidence    : {alert.confidence:.6f}",
            f"  Probabilities : {alert.probabilities}",
            f"  PID           : {alert.pid}",
            f"  Remote IP     : {alert.remote_ip}",
            f"  Remote Port   : {alert.remote_port}",
            f"  Actions       :",
        ]
        for action in alert.actions_taken:
            lines.append(f"      • {action}")
        lines.append(sep)
        for line in lines:
            log.warning(line)


# ── CLI entry-point ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-RIDS — Real-Time Ransomware & Intrusion Detection System"
    )
    parser.add_argument(
        "--config", default="config/config.yaml",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Log response actions but do not execute them",
    )
    parser.add_argument(
        "--train-first", action="store_true",
        help="Train the model before starting the detection daemon",
    )
    parser.add_argument(
        "--dataset", default=None,
        help="Optional labelled CSV dataset for training",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    configure_root_logger(
        level=cfg["system"]["log_level"],
        log_dir=cfg["system"]["log_dir"],
    )

    if args.train_first:
        log.info("Training mode requested — running model trainer…")
        trainer = ModelTrainer(cfg, dataset_path=args.dataset)
        trainer.run()
        log.info("Training complete.  Starting detection daemon…")

    app = AIRIDS(cfg, dry_run=args.dry_run)
    app.start()


if __name__ == "__main__":
    main()
