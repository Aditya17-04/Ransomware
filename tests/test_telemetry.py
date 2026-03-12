"""
tests/test_telemetry.py
───────────────────────
Unit tests for the three telemetry monitor modules.

Run with:
    pytest tests/test_telemetry.py -v
"""

from __future__ import annotations

import queue
import time
import math

import pytest

from src.telemetry.file_monitor import (
    FileEvent,
    FileMonitor,
    compute_shannon_entropy,
)
from src.telemetry.hpc_monitor import HPCMonitor, HPCSample
from src.telemetry.network_monitor import (
    FlowRecord,
    NetworkMonitor,
    NetworkSnapshot,
    _compute_beacon_score,
)


# ══════════════════════════════════════════════════════════════════════════════
# Shannon Entropy
# ══════════════════════════════════════════════════════════════════════════════

class TestShannonEntropy:
    def test_empty_bytes_returns_zero(self):
        assert compute_shannon_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All identical bytes → entropy = 0
        assert compute_shannon_entropy(b"\x00" * 1000) == 0.0

    def test_random_like_high_entropy(self):
        # Uniform distribution across 256 values → max entropy ≈ 8.0
        data = bytes(range(256)) * 100   # 25 600 bytes, perfectly uniform
        h = compute_shannon_entropy(data)
        assert h == pytest.approx(8.0, abs=0.01)

    def test_plaintext_low_entropy(self):
        text = b"hello world " * 500
        h = compute_shannon_entropy(text)
        assert h < 5.0

    def test_entropy_bounded(self):
        import os
        data = os.urandom(64_000)
        h = compute_shannon_entropy(data)
        assert 0.0 <= h <= 8.0


# ══════════════════════════════════════════════════════════════════════════════
# HPCSample
# ══════════════════════════════════════════════════════════════════════════════

class TestHPCSample:
    def test_feature_vector_length(self):
        sample = HPCSample(timestamp=time.time())
        vec = sample.to_feature_vector()
        assert len(vec) == 8

    def test_feature_vector_types(self):
        sample = HPCSample(
            timestamp=1.0,
            cpu_total_pct=45.2,
            cpu_privileged_pct=10.1,
            interrupts_per_sec=1234.0,
            cache_faults_per_sec=56.7,
            page_faults_per_sec=3.3,
            pages_per_sec=0.5,
            context_switches_per_sec=2500.0,
            syscalls_per_sec=15000.0,
        )
        vec = sample.to_feature_vector()
        assert all(isinstance(v, float) for v in vec)

    def test_feature_vector_values(self):
        sample = HPCSample(
            timestamp=0.0,
            cpu_total_pct=75.0,
            syscalls_per_sec=99999.0,
        )
        vec = sample.to_feature_vector()
        assert vec[0] == 75.0
        assert vec[7] == 99999.0


# ══════════════════════════════════════════════════════════════════════════════
# FileEvent
# ══════════════════════════════════════════════════════════════════════════════

class TestFileEvent:
    def _make_event(self, ext=".txt", entropy=3.0, is_susp=False, etype="modify"):
        return FileEvent(
            timestamp=time.time(),
            event_type=etype,
            path=f"C:\\Users\\test\\file{ext}",
            extension=ext,
            entropy=entropy,
            is_suspicious_ext=is_susp,
        )

    def test_normal_event(self):
        ev = self._make_event(".txt", entropy=3.5)
        assert ev.event_type == "modify"
        assert not ev.is_suspicious_ext

    def test_suspicious_extension(self):
        ev = self._make_event(".locked", entropy=7.9, is_susp=True)
        assert ev.is_suspicious_ext
        assert ev.entropy == pytest.approx(7.9)

    def test_high_entropy_threshold(self):
        ev = self._make_event(entropy=7.5)
        assert ev.entropy >= 7.2   # default suspicious threshold


# ══════════════════════════════════════════════════════════════════════════════
# NetworkSnapshot
# ══════════════════════════════════════════════════════════════════════════════

class TestNetworkSnapshot:
    def test_feature_vector_length(self):
        snap = NetworkSnapshot(timestamp=time.time())
        vec = snap.to_feature_vector()
        assert len(vec) == 8

    def test_exfil_flag_in_vector(self):
        snap = NetworkSnapshot(
            timestamp=time.time(),
            exfil_flag=True,
        )
        vec = snap.to_feature_vector()
        assert vec[6] == 1.0

    def test_feature_vector_all_floats(self):
        snap = NetworkSnapshot(
            timestamp=0.0,
            total_bytes_out=1_000_000,
            total_bytes_in=500_000,
            total_connections=42,
            unique_dst_ips=10,
            blacklisted_port_hits=2,
            beacon_score=0.75,
            exfil_flag=False,
            active_flows=8,
        )
        for v in snap.to_feature_vector():
            assert isinstance(v, float)


# ══════════════════════════════════════════════════════════════════════════════
# Beacon scorer
# ══════════════════════════════════════════════════════════════════════════════

class TestBeaconScorer:
    def _make_flows(self, dst_ip: str, timestamps: list[float]) -> list[FlowRecord]:
        flows = []
        for ts in timestamps:
            f = FlowRecord(
                src_ip="10.0.0.1", dst_ip=dst_ip,
                dst_port=443, proto="TCP",
                first_seen=ts, last_seen=ts + 0.5,
            )
            flows.append(f)
        return flows

    def test_no_flows_returns_zero(self):
        score = _compute_beacon_score([], 30, 300)
        assert score == 0.0

    def test_perfect_beacon_high_score(self):
        # Exact 60-second intervals — perfect beacon
        base = time.time()
        flows = self._make_flows("1.2.3.4", [base + i * 60 for i in range(10)])
        score = _compute_beacon_score(flows, 30, 300)
        assert score > 0.8

    def test_irregular_traffic_low_score(self):
        import random
        rng = random.Random(42)
        base = time.time()
        # Random intervals — not beacon-like
        flows = self._make_flows(
            "9.9.9.9",
            [base + rng.uniform(0, 3600) for _ in range(10)],
        )
        score = _compute_beacon_score(flows, 30, 300)
        assert score < 0.5

    def test_too_few_flows_returns_zero(self):
        base = time.time()
        flows = self._make_flows("1.1.1.1", [base, base + 60])
        score = _compute_beacon_score(flows, 30, 300)
        assert score == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# HPCMonitor (basic lifecycle without PDH)
# ══════════════════════════════════════════════════════════════════════════════

class TestHPCMonitor:
    def _make_config(self) -> dict:
        return {
            "poll_interval_ms": 100,
            "counters": [],   # empty → psutil fallback
        }

    def test_start_and_stop(self):
        q = queue.Queue()
        mon = HPCMonitor(self._make_config(), q)
        mon.start()
        time.sleep(0.3)
        mon.stop()
        # Should have produced at least one sample
        assert not q.empty()

    def test_sample_structure(self):
        q = queue.Queue()
        mon = HPCMonitor(self._make_config(), q)
        mon.start()
        time.sleep(0.5)
        mon.stop()
        sample: HPCSample = q.get_nowait()
        assert isinstance(sample.timestamp, float)
        assert 0.0 <= sample.cpu_total_pct <= 100.0


# ══════════════════════════════════════════════════════════════════════════════
# FileMonitor (basic — monitors CWD, fires no events during test)
# ══════════════════════════════════════════════════════════════════════════════

class TestFileMonitorLifecycle:
    def _make_config(self) -> dict:
        return {
            "watch_paths": [],     # triggers CWD fallback
            "entropy_threshold": 7.2,
            "suspicious_extensions": [".locked", ".enc"],
            "high_freq_threshold": 20,
            "mass_delete_threshold": 10,
        }

    def test_start_and_stop(self):
        q = queue.Queue()
        mon = FileMonitor(self._make_config(), q)
        mon.start()
        time.sleep(0.2)
        mon.stop()
        # No assertion — just verifying it doesn't raise
