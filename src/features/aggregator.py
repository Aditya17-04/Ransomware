"""
features/aggregator.py
──────────────────────
Feature Aggregation Pipeline
=============================
The :class:`FeatureAggregator` is the central nervous system of AI-RIDS.

Architecture
────────────
                ┌──────────────┐
                │  HPCMonitor  │──→ hpc_queue
                └──────────────┘
                ┌──────────────┐
                │  FileMonitor │──→ file_queue        ──→ FeatureAggregator
                └──────────────┘                                │
                ┌──────────────┐                                ↓
                │ NetworkMonitor│──→ net_queue           FeatureVector
                └──────────────┘                                │
                                                                ↓
                                                         DetectionModel
                                                                │
                                                                ↓
                                                         DecisionEngine

Sliding Window
──────────────
Every *window_seconds* (default 5 s) the aggregator:
  1. Drains all three source queues.
  2. Computes window-level statistics (mean, max, std) across samples.
  3. Calls the :class:`~features.preprocessor.FeaturePreprocessor` to
     normalise the concatenated feature vector.
  4. Calls the :class:`~models.detector.ThreatDetector` for inference.
  5. Passes the inference result (label + confidence + metadata) to
     the :class:`~engine.decision_engine.DecisionEngine`.
"""

from __future__ import annotations

import queue
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import numpy as np

from src.telemetry.hpc_monitor import HPCSample
from src.telemetry.file_monitor import FileEvent
from src.telemetry.network_monitor import NetworkSnapshot
from src.utils.logger import get_logger

log = get_logger(__name__)


# ── Output data model ─────────────────────────────────────────────────────────

@dataclass
class FeatureVector:
    """
    A 23-dimensional normalised feature vector produced once per window.

    Layout
    ──────
    Indices  0– 7  : HPC features     (8 dims)
    Indices  8–14  : File features    (7 dims)
    Indices 15–22  : Network features (8 dims)
    """
    timestamp:  float
    vector:     np.ndarray        # shape (23,)
    metadata:   dict[str, Any]    # raw window-level statistics for auditing

    @property
    def hpc_features(self) -> np.ndarray:
        return self.vector[:8]

    @property
    def file_features(self) -> np.ndarray:
        return self.vector[8:15]

    @property
    def network_features(self) -> np.ndarray:
        return self.vector[15:23]


# ── HPC window aggregation ────────────────────────────────────────────────────

def _aggregate_hpc(samples: list[HPCSample]) -> tuple[list[float], dict]:
    """Reduce HPC samples to an 8-dim feature sub-vector (mean values)."""
    if not samples:
        return [0.0] * 8, {}

    # Transpose raw vectors so each index yields all samples for that feature
    matrix = [s.to_feature_vector() for s in samples]  # (N, 8)
    transposed = list(zip(*matrix))                     # (8, N)

    means: list[float] = [statistics.mean(col) for col in transposed]
    meta = {
        "hpc_cpu_pct_mean":        means[0],
        "hpc_priv_pct_mean":       means[1],
        "hpc_irq_rate_mean":       means[2],
        "hpc_cache_fault_mean":    means[3],
        "hpc_page_fault_mean":     means[4],
        "hpc_pages_per_sec_mean":  means[5],
        "hpc_ctx_switch_mean":     means[6],
        "hpc_syscall_rate_mean":   means[7],
        "hpc_sample_count":        len(samples),
    }
    return means, meta


# ── File-event window aggregation ─────────────────────────────────────────────

def _aggregate_file(events: list[FileEvent]) -> tuple[list[float], dict]:
    """
    Reduce file events to a 7-dim feature sub-vector.

    Feature layout
    ──────────────
    [0] total event count
    [1] delete count
    [2] rename count
    [3] write (create + modify) count
    [4] mean Shannon entropy of written files
    [5] max Shannon entropy (peak indicator)
    [6] suspicious-extension hit count
    """
    if not events:
        return [0.0] * 7, {}

    total   = len(events)
    deletes = sum(1 for e in events if e.event_type == "delete")
    renames = sum(1 for e in events if e.event_type == "rename")
    writes  = sum(1 for e in events if e.event_type in ("create", "modify"))

    entropies = [e.entropy for e in events if e.entropy > 0]
    mean_ent = statistics.mean(entropies) if entropies else 0.0
    max_ent  = max(entropies, default=0.0)

    susp_ext = sum(1 for e in events if e.is_suspicious_ext)

    vec = [
        float(total),
        float(deletes),
        float(renames),
        float(writes),
        mean_ent,
        max_ent,
        float(susp_ext),
    ]
    meta = {
        "file_total_events":      total,
        "file_deletes":           deletes,
        "file_renames":           renames,
        "file_writes":            writes,
        "file_entropy_mean":      mean_ent,
        "file_entropy_max":       max_ent,
        "file_susp_ext_count":    susp_ext,
    }
    return vec, meta


# ── Network-snapshot window aggregation ───────────────────────────────────────

def _aggregate_network(snapshots: list[NetworkSnapshot]) -> tuple[list[float], dict]:
    """Reduce network snapshots to an 8-dim feature sub-vector (last snapshot
    values, since NetworkMonitor already maintains running totals)."""
    if not snapshots:
        return [0.0] * 8, {}

    latest = snapshots[-1]
    vec = latest.to_feature_vector()
    meta = {
        "net_bytes_out":          latest.total_bytes_out,
        "net_bytes_in":           latest.total_bytes_in,
        "net_conns":              latest.total_connections,
        "net_unique_ips":         latest.unique_dst_ips,
        "net_bl_port_hits":       latest.blacklisted_port_hits,
        "net_beacon_score":       latest.beacon_score,
        "net_exfil_flag":         int(latest.exfil_flag),
        "net_active_flows":       latest.active_flows,
    }
    return [float(v) for v in vec], meta


# ── Main aggregator ────────────────────────────────────────────────────────────

class FeatureAggregator:
    """
    Drains source telemetry queues on a fixed *window_seconds* cadence,
    assembles :class:`FeatureVector` objects, and forwards them to a
    registered callback (typically the :class:`~models.detector.ThreatDetector`).

    Parameters
    ----------
    config : dict
        Top-level application configuration dict.
    hpc_queue   : queue.Queue  - HPC telemetry source
    file_queue  : queue.Queue  - File event source
    net_queue   : queue.Queue  - Network snapshot source
    on_vector   : Callable     - Called with each :class:`FeatureVector`
    preprocessor: optional normaliser implementing ``transform(vector)``
    """

    def __init__(
        self,
        config: dict[str, Any],
        hpc_queue:   queue.Queue,
        file_queue:  queue.Queue,
        net_queue:   queue.Queue,
        on_vector:   Callable[[FeatureVector], None],
        preprocessor: Any | None = None,
    ) -> None:
        self._window = config["telemetry"]["window_seconds"]
        self._hpc_q  = hpc_queue
        self._file_q = file_queue
        self._net_q  = net_queue
        self._callback   = on_vector
        self._preprocessor = preprocessor

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="FeatureAggregator", daemon=True
        )

    def start(self) -> None:
        log.info(
            "FeatureAggregator starting (window=%ss).", self._window
        )
        self._thread.start()

    def stop(self) -> None:
        log.info("FeatureAggregator stopping.")
        self._stop_event.set()
        self._thread.join(timeout=self._window + 2)

    # ── Internal loop ─────────────────────────────────────────────────────────

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self._window)
            try:
                fv = self._build_feature_vector()
                if fv is not None:
                    self._callback(fv)
            except Exception as exc:
                log.error("FeatureAggregator error: %s", exc, exc_info=True)

    def _drain(self, q: queue.Queue) -> list:
        """Non-blocking drain of all items currently in *q*."""
        items: list = []
        while True:
            try:
                items.append(q.get_nowait())
            except queue.Empty:
                break
        return items

    def _build_feature_vector(self) -> FeatureVector | None:
        hpc_samples:  list[HPCSample]       = self._drain(self._hpc_q)
        file_events:  list[FileEvent]        = self._drain(self._file_q)
        net_snapshots: list[NetworkSnapshot] = self._drain(self._net_q)

        hpc_vec,  hpc_meta  = _aggregate_hpc(hpc_samples)
        file_vec, file_meta = _aggregate_file(file_events)
        net_vec,  net_meta  = _aggregate_network(net_snapshots)

        raw = np.array(hpc_vec + file_vec + net_vec, dtype=np.float64)  # (23,)

        # Normalise if a preprocessor is available
        if self._preprocessor is not None:
            try:
                raw = self._preprocessor.transform(raw.reshape(1, -1)).flatten()
            except Exception as exc:
                log.warning("Preprocessor transform failed: %s", exc)

        combined_meta = {**hpc_meta, **file_meta, **net_meta}

        return FeatureVector(
            timestamp=time.time(),
            vector=raw,
            metadata=combined_meta,
        )
