"""
telemetry/hpc_monitor.py
────────────────────────
Hardware Performance Counter (HPC) Monitor
==========================================
Samples Windows Performance Data Helper (PDH) counters on a configurable
interval and appends normalised snapshots to an in-memory ring-buffer that
the Feature Aggregator consumes via a lock-protected queue.

Counter categories monitored
────────────────────────────
  • CPU utilisation (total & privileged-mode)
  • Hardware interrupts / second
  • Memory cache faults / page faults / pages paged in
  • Context switches & system calls / second

Side-channel / crypto-jacking signals
──────────────────────────────────────
  • Sustained high privileged-time   → kernel-level crypto routines
  • Spike in cache faults             → unusual memory-access pattern
  • Abnormal interrupt rate           → DMA or hardware-interrupt abuse
  • High system-call rate + high CPU  → mass file-encryption syscalls
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── PDH constants (winperf.h / pdh.h) ────────────────────────────────────────
PDH_FMT_DOUBLE:   int = 0x00000200
ERROR_SUCCESS:    int = 0x00000000

# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class HPCSample:
    """A single HPC telemetry snapshot."""
    timestamp:          float          # Unix epoch (seconds)
    cpu_total_pct:      float = 0.0    # % Processor Time (total)
    cpu_privileged_pct: float = 0.0    # % Privileged Time
    interrupts_per_sec: float = 0.0    # Hardware interrupts / sec
    cache_faults_per_sec: float = 0.0  # Memory cache faults / sec
    page_faults_per_sec:  float = 0.0  # Memory page faults / sec
    pages_per_sec:        float = 0.0  # Pages paged in/out / sec
    context_switches_per_sec: float = 0.0
    syscalls_per_sec:     float = 0.0

    def to_feature_vector(self) -> list[float]:
        """Return ordered feature list for the aggregator (8 dims)."""
        return [
            self.cpu_total_pct,
            self.cpu_privileged_pct,
            self.interrupts_per_sec,
            self.cache_faults_per_sec,
            self.page_faults_per_sec,
            self.pages_per_sec,
            self.context_switches_per_sec,
            self.syscalls_per_sec,
        ]


# ── PDH wrapper (Windows-only) ────────────────────────────────────────────────

class _PDHCollector:
    """
    Thin ctypes wrapper around the Windows PDH API.

    Falls back gracefully to psutil-only metrics on non-Windows platforms or
    when PDH is unavailable (e.g., inside a container).
    """

    def __init__(self, counter_paths: list[str]) -> None:
        self._available = False
        self._query:    ctypes.c_void_p | None = None
        self._handles:  list[ctypes.c_void_p] = []
        self._paths = counter_paths
        self._pdh: ctypes.WinDLL | None = None
        self._init_pdh()

    def _init_pdh(self) -> None:
        try:
            self._pdh = ctypes.windll.pdh  # type: ignore[attr-defined]
            query_handle = ctypes.c_void_p()
            ret = self._pdh.PdhOpenQueryW(None, 0, ctypes.byref(query_handle))
            if ret != ERROR_SUCCESS:
                log.warning("PDH PdhOpenQueryW failed (0x%X); using psutil fallback.", ret)
                return
            self._query = query_handle

            for path in self._paths:
                h = ctypes.c_void_p()
                ret = self._pdh.PdhAddEnglishCounterW(
                    self._query, path, 0, ctypes.byref(h)
                )
                if ret == ERROR_SUCCESS:
                    self._handles.append(h)
                else:
                    log.debug("Could not add PDH counter '%s' (0x%X).", path, ret)

            # Prime the first data collection (PDH needs two samples for rates)
            self._pdh.PdhCollectQueryData(self._query)
            time.sleep(0.5)
            self._available = len(self._handles) > 0
            log.info("PDH collector initialised with %d counters.", len(self._handles))

        except (AttributeError, OSError) as exc:
            log.warning("PDH unavailable (%s).  Using psutil fallback.", exc)

    def collect(self) -> list[float]:
        """
        Collect counter values.

        Returns a list of float values in the same order as *self._paths*,
        or an empty list on failure.
        """
        if not self._available or self._pdh is None or self._query is None:
            return []

        ret = self._pdh.PdhCollectQueryData(self._query)
        if ret != ERROR_SUCCESS:
            log.warning("PdhCollectQueryData failed (0x%X).", ret)
            return []

        class _PDH_FMT_COUNTERVALUE(ctypes.Structure):
            _fields_ = [("CStatus", ctypes.wintypes.DWORD),
                        ("doubleValue", ctypes.c_double)]

        values: list[float] = []
        for handle in self._handles:
            cv = _PDH_FMT_COUNTERVALUE()
            ret = self._pdh.PdhGetFormattedCounterValue(
                handle, PDH_FMT_DOUBLE, None, ctypes.byref(cv)
            )
            if ret == ERROR_SUCCESS:
                values.append(cv.doubleValue)
            else:
                values.append(0.0)
        return values

    def close(self) -> None:
        if self._pdh and self._query:
            try:
                self._pdh.PdhCloseQuery(self._query)
            except Exception:
                pass


# ── Main monitor class ────────────────────────────────────────────────────────

class HPCMonitor:
    """
    Background thread that periodically samples hardware performance counters
    and pushes :class:`HPCSample` objects into *output_queue*.

    Parameters
    ----------
    config : dict
        The ``telemetry.hpc`` section of the master configuration.
    output_queue : queue.Queue
        Shared queue consumed by the :class:`~features.aggregator.FeatureAggregator`.
    """

    def __init__(self, config: dict[str, Any], output_queue: queue.Queue) -> None:
        self._cfg = config
        self._queue = output_queue
        self._interval = config.get("poll_interval_ms", 500) / 1000.0
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="HPCMonitor", daemon=True
        )
        counter_paths: list[str] = config.get("counters", [])
        self._pdh = _PDHCollector(counter_paths)
        self._prev: dict[str, float] = {}

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        log.info("HPCMonitor starting (interval=%.3fs).", self._interval)
        self._thread.start()

    def stop(self) -> None:
        log.info("HPCMonitor stopping.")
        self._stop_event.set()
        self._thread.join(timeout=5)
        self._pdh.close()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                sample = self._collect_sample()
                self._queue.put_nowait(sample)
            except queue.Full:
                log.debug("HPC output queue full — dropping sample.")
            except Exception as exc:
                log.error("HPCMonitor error: %s", exc, exc_info=True)
            self._stop_event.wait(self._interval)

    def _collect_sample(self) -> HPCSample:
        ts = time.time()

        # ── PDH path ──────────────────────────────────────────────────────────
        pdh_vals = self._pdh.collect()
        if len(pdh_vals) == 8:
            return HPCSample(
                timestamp=ts,
                cpu_total_pct=pdh_vals[0],
                cpu_privileged_pct=pdh_vals[1],
                interrupts_per_sec=pdh_vals[2],
                cache_faults_per_sec=pdh_vals[3],
                page_faults_per_sec=pdh_vals[4],
                pages_per_sec=pdh_vals[5],
                context_switches_per_sec=pdh_vals[6],
                syscalls_per_sec=pdh_vals[7],
            )

        # ── psutil fallback ───────────────────────────────────────────────────
        cpu_pct    = psutil.cpu_percent(interval=None)
        cpu_times  = psutil.cpu_times_percent(interval=None)
        mem        = psutil.virtual_memory()
        swap       = psutil.swap_memory()
        ctx        = psutil.cpu_stats()

        priv_pct   = getattr(cpu_times, "system", 0.0)
        irq_pct    = getattr(cpu_times, "interrupt", 0.0)
        # Derive pseudo-rates from psutil counters using delta
        now_ctx    = ctx.ctx_switches
        now_sysc   = ctx.syscalls
        prev_ctx   = self._prev.get("ctx", now_ctx)
        prev_sysc  = self._prev.get("sysc", now_sysc)
        self._prev["ctx"]  = now_ctx
        self._prev["sysc"] = now_sysc

        ctx_rate  = max(0.0, (now_ctx  - prev_ctx ) / self._interval)
        sysc_rate = max(0.0, (now_sysc - prev_sysc) / self._interval)

        return HPCSample(
            timestamp=ts,
            cpu_total_pct=cpu_pct,
            cpu_privileged_pct=priv_pct,
            interrupts_per_sec=irq_pct * 1000,   # approximate
            cache_faults_per_sec=mem.percent,     # proxy
            page_faults_per_sec=swap.percent,     # proxy
            pages_per_sec=0.0,
            context_switches_per_sec=ctx_rate,
            syscalls_per_sec=sysc_rate,
        )
