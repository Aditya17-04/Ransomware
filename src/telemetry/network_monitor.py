"""
telemetry/network_monitor.py
────────────────────────────
Network Packet / Flow Monitor
==============================
Captures packets using Scapy (or falls back to psutil net-counters) and
maintains a per-flow state table.  At the end of each monitoring cycle it
pushes a :class:`NetworkSnapshot` into the shared queue.

Threats detected at this layer
──────────────────────────────
  • C2 beacon pattern: periodic short-interval connections to the same
    remote IP (seen in Mirai, Ryuk C2 callbacks).
  • Data exfiltration: outbound byte volume spike during an interval
    exceeding *exfil_bytes_threshold*.
  • Known-bad ports: connections to ports in *c2_port_blacklist*.
  • High connection-fan-out: single process touching many distinct IPs
    (lateral-movement indicator).

Flow key
────────
  (src_ip, dst_ip, dst_port, proto)

Thread safety
─────────────
All flow-table mutations occur inside *_lock* so the Feature Aggregator
can safely read snapshots from a different thread.
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import psutil

from src.utils.logger import get_logger

log = get_logger(__name__)

# Optional Scapy import — not available in all environments
try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    log.warning(
        "Scapy not available.  Network monitor will use psutil counters only."
    )


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """State accumulated for a single network flow."""
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    proto:      str          # "TCP" | "UDP" | "OTHER"
    bytes_sent: int = 0
    bytes_recv: int = 0
    pkt_count:  int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


@dataclass
class NetworkSnapshot:
    """Aggregated network telemetry for one monitoring window."""
    timestamp:              float
    total_bytes_out:        int   = 0
    total_bytes_in:         int   = 0
    total_connections:      int   = 0
    unique_dst_ips:         int   = 0
    blacklisted_port_hits:  int   = 0
    beacon_score:           float = 0.0   # 0–1; higher = more beacon-like
    exfil_flag:             bool  = False
    active_flows:           int   = 0

    def to_feature_vector(self) -> list[float]:
        """Return ordered feature list for the aggregator (8 dims)."""
        return [
            float(self.total_bytes_out),
            float(self.total_bytes_in),
            float(self.total_connections),
            float(self.unique_dst_ips),
            float(self.blacklisted_port_hits),
            self.beacon_score,
            float(self.exfil_flag),
            float(self.active_flows),
        ]


# ── Beacon scorer ─────────────────────────────────────────────────────────────

def _compute_beacon_score(
    flows: list[FlowRecord],
    beacon_min: float,
    beacon_max: float,
) -> float:
    """
    Heuristic beacon score in [0, 1].

    Groups flows by destination IP and checks whether repeated connections
    occur at regular (beacon-like) intervals.
    """
    if len(flows) < 3:
        return 0.0

    by_dst: dict[str, list[float]] = defaultdict(list)
    for f in flows:
        by_dst[f.dst_ip].append(f.first_seen)

    scores: list[float] = []
    for timestamps in by_dst.values():
        if len(timestamps) < 3:
            continue
        timestamps.sort()
        intervals = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        mean_iv = sum(intervals) / len(intervals)
        if not (beacon_min <= mean_iv <= beacon_max):
            continue
        # Coefficient of variation  — low CV = very regular = beacony
        variance = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        cv = (variance ** 0.5) / (mean_iv + 1e-9)
        score = max(0.0, 1.0 - cv)
        scores.append(score)

    return round(max(scores, default=0.0), 4)


# ── Main monitor class ─────────────────────────────────────────────────────────

class NetworkMonitor:
    """
    Captures and analyses network traffic.

    Parameters
    ----------
    config : dict
        The ``telemetry.network`` section of the master configuration.
    output_queue : queue.Queue
        Shared queue consumed by the Feature Aggregator.
    """

    def __init__(self, config: dict[str, Any], output_queue: queue.Queue) -> None:
        self._cfg = config
        self._queue = output_queue
        self._iface: str | None = config.get("interface")
        self._bpf: str = config.get("bpf_filter", "tcp or udp")
        self._beacon_min: float = float(config.get("beacon_interval_min", 30))
        self._beacon_max: float = float(config.get("beacon_interval_max", 300))
        self._exfil_bytes: int = int(config.get("exfil_bytes_threshold", 5_000_000))
        self._blacklist_ports: set[int] = set(config.get("c2_port_blacklist", []))

        self._lock = threading.Lock()
        self._flows: dict[tuple, FlowRecord] = {}
        self._stop_event = threading.Event()
        self._sniffer: Any = None
        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop, name="NetSnapshotWorker", daemon=True
        )

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        if _SCAPY_AVAILABLE:
            self._start_scapy_sniffer()
        else:
            # Without Scapy we poll psutil counters every second
            self._psutil_thread = threading.Thread(
                target=self._psutil_loop, name="PsutilNetWorker", daemon=True
            )
            self._psutil_thread.start()

        self._snapshot_thread.start()
        log.info(
            "NetworkMonitor started (scapy=%s, interface=%s).",
            _SCAPY_AVAILABLE, self._iface or "default",
        )

    def stop(self) -> None:
        log.info("NetworkMonitor stopping.")
        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self._snapshot_thread.join(timeout=5)

    # ── Packet processing (Scapy path) ────────────────────────────────────────

    def _start_scapy_sniffer(self) -> None:
        try:
            self._sniffer = AsyncSniffer(
                iface=self._iface,
                filter=self._bpf,
                prn=self._process_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            log.error("Failed to start Scapy sniffer: %s", exc)
            self._sniffer = None

    def _process_packet(self, pkt: Any) -> None:
        """Called by Scapy in its own thread for each captured packet."""
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        size = len(pkt)
        proto = "OTHER"
        dst_port = 0

        if pkt.haslayer(TCP):
            proto = "TCP"
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            dst_port = pkt[UDP].dport

        key = (src, dst, dst_port, proto)
        now = time.time()

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowRecord(
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dst_port,
                    proto=proto,
                    first_seen=now,
                    last_seen=now,
                )
            flow = self._flows[key]
            flow.bytes_sent += size
            flow.pkt_count += 1
            flow.last_seen = now

    # ── psutil fallback ────────────────────────────────────────────────────────

    def _psutil_loop(self) -> None:
        prev = psutil.net_io_counters()
        while not self._stop_event.is_set():
            time.sleep(1)
            try:
                curr = psutil.net_io_counters()
                delta_out = curr.bytes_sent - prev.bytes_sent
                delta_in  = curr.bytes_recv - prev.bytes_recv
                prev = curr
                key = ("local", "remote", 0, "PSUTIL")
                now = time.time()
                with self._lock:
                    if key not in self._flows:
                        self._flows[key] = FlowRecord(
                            src_ip="local", dst_ip="remote",
                            dst_port=0, proto="PSUTIL",
                            first_seen=now, last_seen=now,
                        )
                    flow = self._flows[key]
                    flow.bytes_sent += delta_out
                    flow.bytes_recv += delta_in
                    flow.pkt_count += 1
                    flow.last_seen = now
            except Exception as exc:
                log.debug("psutil net loop error: %s", exc)

    # ── Snapshot publishing ───────────────────────────────────────────────────

    def _snapshot_loop(self) -> None:
        """Publishes one NetworkSnapshot per second derived from current flows."""
        while not self._stop_event.is_set():
            self._stop_event.wait(1.0)
            try:
                snap = self._build_snapshot()
                self._queue.put_nowait(snap)
            except queue.Full:
                log.debug("Network snapshot queue full — dropping.")
            except Exception as exc:
                log.error("Snapshot loop error: %s", exc, exc_info=True)

    def _build_snapshot(self) -> NetworkSnapshot:
        now = time.time()
        with self._lock:
            flows = list(self._flows.values())
            # Evict stale flows older than 5 minutes
            self._flows = {
                k: v for k, v in self._flows.items()
                if (now - v.last_seen) < 300
            }

        total_out = sum(f.bytes_sent for f in flows)
        total_in  = sum(f.bytes_recv for f in flows)
        unique_ips = len({f.dst_ip for f in flows if f.dst_ip != "remote"})
        bl_hits = sum(1 for f in flows if f.dst_port in self._blacklist_ports)
        beacon = _compute_beacon_score(flows, self._beacon_min, self._beacon_max)
        exfil = total_out > self._exfil_bytes

        return NetworkSnapshot(
            timestamp=now,
            total_bytes_out=total_out,
            total_bytes_in=total_in,
            total_connections=len(flows),
            unique_dst_ips=unique_ips,
            blacklisted_port_hits=bl_hits,
            beacon_score=beacon,
            exfil_flag=exfil,
            active_flows=len(flows),
        )
