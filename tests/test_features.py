"""
tests/test_features.py
──────────────────────
Unit tests for the Feature Aggregation and Preprocessing pipeline.

Run with:
    pytest tests/test_features.py -v
"""

from __future__ import annotations

import queue
import time

import numpy as np
import pytest

from src.features.aggregator import (
    FeatureAggregator,
    FeatureVector,
    _aggregate_file,
    _aggregate_hpc,
    _aggregate_network,
)
from src.features.preprocessor import FeaturePreprocessor
from src.telemetry.file_monitor import FileEvent
from src.telemetry.hpc_monitor import HPCSample
from src.telemetry.network_monitor import NetworkSnapshot


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_hpc_sample(**kwargs) -> HPCSample:
    defaults = dict(
        timestamp=time.time(),
        cpu_total_pct=30.0, cpu_privileged_pct=5.0,
        interrupts_per_sec=500.0, cache_faults_per_sec=20.0,
        page_faults_per_sec=2.0, pages_per_sec=0.1,
        context_switches_per_sec=1000.0, syscalls_per_sec=5000.0,
    )
    defaults.update(kwargs)
    return HPCSample(**defaults)


def _make_file_event(**kwargs) -> FileEvent:
    defaults = dict(
        timestamp=time.time(), event_type="modify",
        path="C:\\test\\file.txt", extension=".txt",
        entropy=3.5, is_suspicious_ext=False,
    )
    defaults.update(kwargs)
    return FileEvent(**defaults)


def _make_net_snapshot(**kwargs) -> NetworkSnapshot:
    defaults = dict(
        timestamp=time.time(), total_bytes_out=1_000_000,
        total_bytes_in=500_000, total_connections=10,
        unique_dst_ips=5, blacklisted_port_hits=0,
        beacon_score=0.0, exfil_flag=False, active_flows=8,
    )
    defaults.update(kwargs)
    return NetworkSnapshot(**defaults)


# ══════════════════════════════════════════════════════════════════════════════
# HPC aggregation
# ══════════════════════════════════════════════════════════════════════════════

class TestAggregateHPC:
    def test_empty_list_returns_8_zeros(self):
        vec, meta = _aggregate_hpc([])
        assert len(vec) == 8
        assert all(v == 0.0 for v in vec)

    def test_single_sample_passthrough(self):
        sample = _make_hpc_sample(cpu_total_pct=88.0, syscalls_per_sec=99999.0)
        vec, meta = _aggregate_hpc([sample])
        assert vec[0] == pytest.approx(88.0)
        assert vec[7] == pytest.approx(99999.0)

    def test_mean_across_samples(self):
        s1 = _make_hpc_sample(cpu_total_pct=20.0)
        s2 = _make_hpc_sample(cpu_total_pct=80.0)
        vec, _ = _aggregate_hpc([s1, s2])
        assert vec[0] == pytest.approx(50.0)

    def test_metadata_keys(self):
        _, meta = _aggregate_hpc([_make_hpc_sample()])
        assert "hpc_cpu_pct_mean" in meta
        assert "hpc_sample_count" in meta
        assert meta["hpc_sample_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# File event aggregation
# ══════════════════════════════════════════════════════════════════════════════

class TestAggregateFile:
    def test_empty_list_returns_7_zeros(self):
        vec, _ = _aggregate_file([])
        assert len(vec) == 7
        assert all(v == 0.0 for v in vec)

    def test_event_type_counts(self):
        events = [
            _make_file_event(event_type="delete"),
            _make_file_event(event_type="delete"),
            _make_file_event(event_type="rename"),
            _make_file_event(event_type="modify"),
        ]
        vec, meta = _aggregate_file(events)
        assert vec[0] == 4.0   # total
        assert vec[1] == 2.0   # deletes
        assert vec[2] == 1.0   # renames
        assert vec[3] == 1.0   # writes

    def test_entropy_statistics(self):
        events = [
            _make_file_event(entropy=3.0, event_type="modify"),
            _make_file_event(entropy=7.0, event_type="modify"),
            _make_file_event(entropy=5.0, event_type="modify"),
        ]
        vec, _ = _aggregate_file(events)
        assert vec[4] == pytest.approx(5.0)       # mean
        assert vec[5] == pytest.approx(7.0)       # max

    def test_suspicious_extension_count(self):
        events = [
            _make_file_event(is_suspicious_ext=True),
            _make_file_event(is_suspicious_ext=True),
            _make_file_event(is_suspicious_ext=False),
        ]
        vec, _ = _aggregate_file(events)
        assert vec[6] == 2.0

    def test_zero_entropy_events_excluded_from_mean(self):
        events = [
            _make_file_event(event_type="delete", entropy=0.0),  # delete
            _make_file_event(event_type="modify",  entropy=6.0),
        ]
        vec, _ = _aggregate_file(events)
        # Mean should only consider events with entropy > 0
        assert vec[4] == pytest.approx(6.0)


# ══════════════════════════════════════════════════════════════════════════════
# Network aggregation
# ══════════════════════════════════════════════════════════════════════════════

class TestAggregateNetwork:
    def test_empty_returns_8_zeros(self):
        vec, _ = _aggregate_network([])
        assert len(vec) == 8
        assert all(v == 0.0 for v in vec)

    def test_latest_snapshot_used(self):
        s1 = _make_net_snapshot(total_bytes_out=1_000)
        s2 = _make_net_snapshot(total_bytes_out=9_999_999)
        vec, _ = _aggregate_network([s1, s2])
        assert vec[0] == pytest.approx(9_999_999.0)

    def test_exfil_flag_propagated(self):
        snap = _make_net_snapshot(exfil_flag=True)
        vec, _ = _aggregate_network([snap])
        assert vec[6] == 1.0


# ══════════════════════════════════════════════════════════════════════════════
# FeaturePreprocessor
# ══════════════════════════════════════════════════════════════════════════════

class TestFeaturePreprocessor:
    _config = {"scaler": "standard", "normalize": True, "vector_size": 23}

    def test_fit_transform_shape(self):
        prep = FeaturePreprocessor(self._config, model_dir="models/saved")
        X = np.random.rand(100, 23)
        Xt = prep.fit_transform(X)
        assert Xt.shape == (100, 23)

    def test_standardised_mean_near_zero(self):
        prep = FeaturePreprocessor(self._config, model_dir="models/saved")
        X = np.random.rand(1000, 23)
        Xt = prep.fit_transform(X)
        assert np.abs(Xt.mean(axis=0)).max() < 1e-10

    def test_transform_single_row(self):
        prep = FeaturePreprocessor(self._config, model_dir="models/saved")
        X = np.random.rand(100, 23)
        prep.fit(X)
        row = X[0:1]
        out = prep.transform(row)
        assert out.shape == (1, 23)

    def test_save_and_load(self, tmp_path):
        prep = FeaturePreprocessor(
            self._config, model_dir=str(tmp_path)
        )
        X = np.random.rand(100, 23)
        prep.fit(X)
        path = prep.save()

        prep2 = FeaturePreprocessor(self._config, model_dir=str(tmp_path))
        prep2.load()
        # Both scalers should transform identically
        Xt1 = prep.transform(X[:5])
        Xt2 = prep2.transform(X[:5])
        np.testing.assert_allclose(Xt1, Xt2)

    def test_minmax_scaler(self):
        cfg = {**self._config, "scaler": "minmax"}
        prep = FeaturePreprocessor(cfg, model_dir="models/saved")
        X = np.random.rand(200, 23)
        Xt = prep.fit_transform(X)
        assert Xt.min() >= -1e-10
        assert Xt.max() <= 1.0 + 1e-10


# ══════════════════════════════════════════════════════════════════════════════
# FeatureVector
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureVector:
    def _make_fv(self) -> FeatureVector:
        return FeatureVector(
            timestamp=time.time(),
            vector=np.arange(23, dtype=float),
            metadata={},
        )

    def test_slice_properties(self):
        fv = self._make_fv()
        assert len(fv.hpc_features)     == 8
        assert len(fv.file_features)    == 7
        assert len(fv.network_features) == 8

    def test_hpc_slice_values(self):
        fv = self._make_fv()
        np.testing.assert_array_equal(fv.hpc_features, np.arange(8))

    def test_network_slice_values(self):
        fv = self._make_fv()
        np.testing.assert_array_equal(fv.network_features, np.arange(15, 23))


# ══════════════════════════════════════════════════════════════════════════════
# FeatureAggregator (integration)
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureAggregatorIntegration:
    """
    End-to-end test: push samples into queues, verify that the aggregator
    emits a correctly shaped FeatureVector.
    """

    def _make_config(self) -> dict:
        return {
            "telemetry": {"window_seconds": 0.2},
            "features": {"normalize": False, "scaler": "standard", "vector_size": 23},
        }

    def test_emits_feature_vector(self):
        hpc_q  = queue.Queue()
        file_q = queue.Queue()
        net_q  = queue.Queue()
        received: list[FeatureVector] = []

        agg = FeatureAggregator(
            config=self._make_config(),
            hpc_queue=hpc_q,
            file_queue=file_q,
            net_queue=net_q,
            on_vector=received.append,
        )

        # Pre-populate queues
        for _ in range(5):
            hpc_q.put(_make_hpc_sample())
            file_q.put(_make_file_event())
            net_q.put(_make_net_snapshot())

        agg.start()
        time.sleep(0.5)   # Wait for at least one window
        agg.stop()

        assert len(received) >= 1
        fv = received[0]
        assert isinstance(fv, FeatureVector)
        assert fv.vector.shape == (23,)
        assert fv.timestamp > 0

    def test_empty_queues_still_emit(self):
        """The aggregator must emit feature vectors even with no telemetry data."""
        hpc_q  = queue.Queue()
        file_q = queue.Queue()
        net_q  = queue.Queue()
        received: list[FeatureVector] = []

        agg = FeatureAggregator(
            config=self._make_config(),
            hpc_queue=hpc_q,
            file_queue=file_q,
            net_queue=net_q,
            on_vector=received.append,
        )
        agg.start()
        time.sleep(0.5)
        agg.stop()

        assert len(received) >= 1
        fv = received[0]
        assert np.all(fv.vector == 0.0)   # empty queues → zero vector
