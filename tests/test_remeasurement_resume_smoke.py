import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import benchmark_and_plot as bench
import run_issuer_hiding_measurements as runner


def _args():
    return SimpleNamespace(
        runs=2, warmup=1, batches=2, randomize_order=True, random_seed=20260621,
        cooldown_seconds=0.0, main_executable="mock", sentinel_k=12,
        sentinel_other_issuers=8, sentinel_component="verifyPresentationPayload_total_real",
        sentinel_max_relative_deviation=0.25, round_exclusions=[],
        frozen_provenance={
            "source_sha256": {"source": "a"}, "library_source_sha256": {"lib": "b"},
            "binary_sha256": {"main": "c", "unit": "d", "library": "e"},
            "compiler": "g++ test", "configured_compile_commands": [["compile"]],
        },
    )


def test_18_point_checkpoint_resume_skips_complete_batch_and_keeps_schedule(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(runner, "write_manifest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "manifest_data", lambda *_args, **_kwargs: {})
    args = _args()
    calls = {"n": 0, "fail_once": True}

    def fake_run_protocol(*_args, **_kwargs):
        calls["n"] += 1
        if calls["fail_once"] and calls["n"] == 37:
            raise RuntimeError("injected interruption in batch 2")
        return [
            {"component": name, "phase": bench.COMPONENT_PHASES[name], "time_ms": 1.0}
            for name in runner.ACTIVE_MEASUREMENT_COMPONENTS
        ]

    monkeypatch.setattr(bench, "run_protocol", fake_run_protocol)
    with pytest.raises(RuntimeError, match="injected interruption"):
        runner.run_interleaved_protocol(args)
    assert calls["n"] == 37  # 18 warmups + complete batch 1 + first failed run in batch 2
    schedule_before = (tmp_path / "schedule.json").read_bytes()
    checkpoint_before = json.loads((tmp_path / "batch_checkpoint.json").read_text(encoding="utf-8"))
    assert len(checkpoint_before["complete_batches"]["1"]) == 18 * len(runner.ACTIVE_MEASUREMENT_COMPONENTS)
    assert checkpoint_before["interrupted_batch"]["partial_rows"] == []

    calls["fail_once"] = False
    calls["n"] = 0
    runner.run_interleaved_protocol(args)
    assert calls["n"] == 18  # completed batch 1 and all warmups are not repeated
    assert (tmp_path / "schedule.json").read_bytes() == schedule_before
    completed = json.loads((tmp_path / "batch_checkpoint.json").read_text(encoding="utf-8"))
    assert set(completed["complete_batches"]) == {"1", "2"}
    assert completed["interrupted_batch"] is None
    assert len(completed["interruption_history"]) == 1


def test_unit_benchmark_resume_does_not_overwrite_existing_workbook(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "RESULTS_DIR", tmp_path)
    (tmp_path / "batch_checkpoint.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "unit_costs_30samples.xlsx"
    output.write_bytes(b"saved unit artifact")
    args = SimpleNamespace(skip_unit=False)
    monkeypatch.setattr(runner, "run_command", lambda *_args, **_kwargs: pytest.fail("must not overwrite"))
    runner.run_unit_benchmark(args)
    assert output.read_bytes() == b"saved unit artifact"
