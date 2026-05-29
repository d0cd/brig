"""Benchmark suite OTel emitter — verifies fail-quiet behavior when
the OTel SDK or endpoint isn't available, and that the emit path is
called with the right shape when it is.
"""

from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_bench_dir = Path(__file__).parent / "benchmarks"
if str(_bench_dir) not in sys.path:
    sys.path.insert(0, str(_bench_dir))


def _mock_benchmark(name="bench_x", group="lifecycle",
                    rounds=10, data=None, outliers=""):
    bm = types.SimpleNamespace(name=name, group=group)
    bm.stats = types.SimpleNamespace(
        rounds=rounds,
        data=data if data is not None else [0.001, 0.0015, 0.002],
        outliers=outliers,
    )
    return bm


class TestOtelEmitNoOp(unittest.TestCase):
    def test_no_endpoint_is_no_op(self):
        import otel_emit
        otel_emit._emitter = None
        with patch.dict(os.environ, {"BRIG_BENCH_OTEL_ENDPOINT": ""},
                        clear=False):
            # Just must not raise.
            otel_emit.emit(_mock_benchmark())

    def test_missing_sdk_is_no_op(self):
        import otel_emit
        otel_emit._emitter = None
        with patch.dict(os.environ,
                        {"BRIG_BENCH_OTEL_ENDPOINT": "http://x:4317"},
                        clear=False), \
             patch.dict("sys.modules", {"opentelemetry": None}):
            # Force ImportError by stubbing module to None.
            otel_emit.emit(_mock_benchmark())


class TestOtelEmitActive(unittest.TestCase):
    def test_emit_records_per_round(self):
        import otel_emit
        otel_emit._emitter = None
        fake_em = {
            "duration_ms": MagicMock(),
            "iterations": MagicMock(),
            "outliers": MagicMock(),
        }
        with patch.object(otel_emit, "_get_emitter", return_value=fake_em):
            otel_emit.emit(_mock_benchmark(
                data=[0.001, 0.002], rounds=2, outliers="0;3",
            ))
        # Two duration observations recorded.
        self.assertEqual(fake_em["duration_ms"].record.call_count, 2)
        # Iterations bumped by rounds.
        fake_em["iterations"].add.assert_called_once()
        self.assertEqual(fake_em["iterations"].add.call_args.args[0], 2)
        # Outliers parsed and forwarded.
        fake_em["outliers"].add.assert_called_once()
        self.assertEqual(fake_em["outliers"].add.call_args.args[0], 3)

    def test_no_data_no_observations(self):
        import otel_emit
        otel_emit._emitter = None
        fake_em = {
            "duration_ms": MagicMock(),
            "iterations": MagicMock(),
            "outliers": MagicMock(),
        }
        with patch.object(otel_emit, "_get_emitter", return_value=fake_em):
            otel_emit.emit(_mock_benchmark(data=[]))
        fake_em["duration_ms"].record.assert_not_called()


if __name__ == "__main__":
    unittest.main()
