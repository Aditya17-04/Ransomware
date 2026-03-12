"""
engine/decision_engine.py
──────────────────────────
Threat Decision Engine
=======================
The Decision Engine is the final stage of the AI-RIDS pipeline.  It receives
:class:`~models.detector.ThreatResult` objects from the
:class:`~models.detector.ThreatDetector` and — based on configurable
confidence thresholds — decides whether to:

  • Emit an informational **Benign** log entry.
  • Raise a **Suspicious** alert.
  • Trigger the full **High Alert** response chain.

High Alert Response Chain  (confidence ≥ 0.85)
───────────────────────────────────────────────
  1. Kill Process        — Terminate the offending PID immediately.
  2. Network Isolation   — Block the remote IP/port via Windows Firewall.
  3. File Protection     — Revoke write permissions on critical dirs +
                           create a Volume Shadow Copy for recovery.

Cooldown
────────
To prevent alert storms for a single incident the engine enforces a per-PID
cooldown period.  A new high-alert action will not be re-triggered for the
same PID within *cooldown_seconds* after the last alert.

Metadata extraction
───────────────────
The engine parses network metadata from the :class:`~features.aggregator.FeatureVector`
to extract the best candidate PID and remote IP for response targeting.
Because the feature vector captures window-level aggregates rather than
per-process data, the engine falls back to the top-CPU process when the
vector metadata does not contain an explicit PID.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from src.engine.response.file_protector import FileProtector
from src.engine.response.network_isolator import NetworkIsolator
from src.engine.response.process_killer import ProcessKiller
from src.models.detector import ThreatResult
from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Alert record ──────────────────────────────────────────────────────────────

@dataclass
class AlertRecord:
    """Immutable audit record for one triggered alert."""
    timestamp:     float
    level:         str          # "Suspicious" | "HighAlert"
    label:         str
    confidence:    float
    probabilities: dict[str, float]
    pid:           int | None
    remote_ip:     str | None
    remote_port:   int | None
    actions_taken: list[str]    # human-readable list of executed actions
    metadata:      dict[str, Any] = field(default_factory=dict)


# ── Decision Engine ───────────────────────────────────────────────────────────

class DecisionEngine:
    """
    Evaluates :class:`~models.detector.ThreatResult` objects and triggers
    appropriate response actions.

    Parameters
    ----------
    config : dict
        Full application configuration dict.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        dc = config["decision"]
        rc = config["response"]

        self._thresh_suspicious: float = dc["thresholds"]["suspicious"]
        self._thresh_high_alert: float = dc["thresholds"]["high_alert"]
        self._cooldown:          float = float(dc.get("cooldown_seconds", 30))
        self._dry_run:           bool  = dc.get("dry_run", False)

        # ── Response sub-modules ──────────────────────────────────────────────
        self._killer    = ProcessKiller(rc["kill_process"],       self._dry_run)
        self._isolator  = NetworkIsolator(rc["network_isolation"], self._dry_run)
        self._protector = FileProtector(rc["file_protection"],    self._dry_run)

        # Cooldown tracking: pid → last_fired_timestamp
        self._cooldowns: dict[int, float] = {}

        # In-memory alert history (trimmed to last 1000 entries)
        self._alert_history: list[AlertRecord] = []

    # ── Public interface ──────────────────────────────────────────────────────

    def evaluate(self, result: ThreatResult) -> AlertRecord | None:
        """
        Evaluate a :class:`ThreatResult` and conditionally trigger responses.

        Parameters
        ----------
        result : ThreatResult

        Returns
        -------
        AlertRecord | None
            An :class:`AlertRecord` if any alert was triggered, else *None*.
        """
        conf  = result.confidence
        label = result.label

        # ── Benign ────────────────────────────────────────────────────────────
        if conf < self._thresh_suspicious or result.label_id == 0:
            log.debug(
                "BENIGN  conf=%.4f  label=%s  latency=%.2fms",
                conf, label, result.inference_ms,
            )
            return None

        # ── Suspicious ───────────────────────────────────────────────────────
        if conf < self._thresh_high_alert:
            log.warning(
                "SUSPICIOUS  conf=%.4f  label=%s  latency=%.2fms",
                conf, label, result.inference_ms,
            )
            record = AlertRecord(
                timestamp=result.timestamp,
                level="Suspicious",
                label=label,
                confidence=conf,
                probabilities=result.probabilities,
                pid=None,
                remote_ip=None,
                remote_port=None,
                actions_taken=["Suspicious alert raised — no automated action."],
                metadata=result.feature_vector.metadata,
            )
            self._record_alert(record)
            return record

        # ── High Alert ────────────────────────────────────────────────────────
        log.critical(
            "HIGH ALERT  conf=%.4f  label=%s  latency=%.2fms  — Triggering response chain.",
            conf, label, result.inference_ms,
        )

        pid       = self._identify_top_pid(result)
        remote_ip = self._extract_remote_ip(result)
        remote_port = self._extract_remote_port(result)

        # Cooldown check
        if pid is not None and self._in_cooldown(pid):
            log.warning(
                "PID %d is in cooldown — suppressing duplicate response.", pid
            )
            return None

        actions = self._execute_response_chain(pid, remote_ip, remote_port, result)

        if pid is not None:
            self._cooldowns[pid] = time.time()

        record = AlertRecord(
            timestamp=result.timestamp,
            level="HighAlert",
            label=label,
            confidence=conf,
            probabilities=result.probabilities,
            pid=pid,
            remote_ip=remote_ip,
            remote_port=remote_port,
            actions_taken=actions,
            metadata=result.feature_vector.metadata,
        )
        self._record_alert(record)
        return record

    @property
    def alert_history(self) -> list[AlertRecord]:
        """Read-only view of all recorded alerts."""
        return list(self._alert_history)

    def shutdown(self) -> None:
        """Clean up firewall rules added during the session."""
        log.info("DecisionEngine: cleaning up firewall rules.")
        self._isolator.remove_all_rules()

    # ── Response chain ────────────────────────────────────────────────────────

    def _execute_response_chain(
        self,
        pid:         int | None,
        remote_ip:   str | None,
        remote_port: int | None,
        result:      ThreatResult,
    ) -> list[str]:
        """
        Execute all configured response actions and return a list of
        human-readable action descriptions for the audit record.
        """
        actions: list[str] = []

        # Step 1 — Kill process
        if pid is not None:
            label_str = f"AI-RIDS: {result.label} (conf={result.confidence:.3f})"
            ok = self._killer.kill(pid, reason=label_str)
            actions.append(
                f"KillProcess(pid={pid}) → {'OK' if ok else 'FAILED'}"
            )
        else:
            actions.append("KillProcess → SKIPPED (no PID identified)")
            log.warning("High alert raised but no specific PID identified.")

        # Step 2 — Network isolation
        if remote_ip:
            ok = self._isolator.block_ip(
                remote_ip, remote_port,
                reason=f"AI-RIDS High Alert conf={result.confidence:.3f}",
            )
            actions.append(
                f"NetworkBlock(ip={remote_ip}, port={remote_port}) "
                f"→ {'OK' if ok else 'FAILED'}"
            )
        else:
            actions.append("NetworkBlock → SKIPPED (no remote IP identified)")

        # Step 3 — File protection
        protect_results = self._protector.protect_all_critical_dirs(
            reason=f"AI-RIDS High Alert {result.label}"
        )
        all_ok = all(protect_results)
        actions.append(
            f"RevokeWrite(critical_dirs={len(protect_results)}) "
            f"→ {'OK' if all_ok else 'PARTIAL/FAILED'}"
        )

        vss_guid = self._protector.create_vss_snapshot()
        actions.append(
            f"VSSSnapshot → {'OK guid=' + vss_guid if vss_guid else 'FAILED'}"
        )

        log.warning(
            "Response chain complete: %s", " | ".join(actions)
        )
        return actions

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _identify_top_pid(self, result: ThreatResult) -> int | None:
        """
        Return the PID most likely responsible for the alert.

        Strategy (in priority order):
          1. Use a PID embedded in the feature metadata (future telemetry can
             include per-process attribution).
          2. Return the process with the highest CPU utilisation (heuristic).
        """
        pid = result.feature_vector.metadata.get("pid")
        if pid is not None:
            return int(pid)

        # Heuristic: highest CPU consumer is most likely the ransomware
        try:
            procs = sorted(
                psutil.process_iter(["pid", "cpu_percent", "name"]),
                key=lambda p: p.info.get("cpu_percent") or 0.0,
                reverse=True,
            )
            for proc in procs:
                # Ignore system-critical PIDs
                if proc.info["pid"] in (0, 4):
                    continue
                return proc.info["pid"]
        except Exception as exc:
            log.warning("Could not identify top-CPU PID: %s", exc)
        return None

    def _extract_remote_ip(self, result: ThreatResult) -> str | None:
        """Pull the most-likely C2 IP from the feature metadata."""
        return result.feature_vector.metadata.get("remote_ip")

    def _extract_remote_port(self, result: ThreatResult) -> int | None:
        """Pull the most-likely C2 port from the feature metadata."""
        v = result.feature_vector.metadata.get("remote_port")
        return int(v) if v is not None else None

    def _in_cooldown(self, pid: int) -> bool:
        last = self._cooldowns.get(pid)
        if last is None:
            return False
        return (time.time() - last) < self._cooldown

    def _record_alert(self, record: AlertRecord) -> None:
        self._alert_history.append(record)
        # Trim to prevent unbounded growth
        if len(self._alert_history) > 1000:
            self._alert_history = self._alert_history[-1000:]
