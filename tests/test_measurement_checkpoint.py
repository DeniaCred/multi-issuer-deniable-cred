import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import math
import hashlib
import zipfile
import run_issuer_hiding_measurements as runner

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from measurement_checkpoint import fingerprint, load_checkpoint, save_complete_batch, save_interrupted_batch, validate_batch


def test_checkpoint_rejects_mixed_provenance_and_overwrite(tmp_path):
    path = tmp_path / "checkpoint.json"
    fp = fingerprint({"source": "a", "config": {"runs": 2}})
    data = load_checkpoint(path, fp)
    data = save_complete_batch(path, data, 1, [{"x": 1}])
    assert load_checkpoint(path, fp)["complete_batches"]["1"] == [{"x": 1}]
    with pytest.raises(ValueError, match="mismatch"):
        load_checkpoint(path, fingerprint({"source": "b"}))
    with pytest.raises(ValueError, match="already checkpointed"):
        save_complete_batch(path, data, 1, [])


def test_loading_revalidates_saved_batches_and_preserves_interruption(tmp_path):
    path = tmp_path / "checkpoint.json"
    fp = fingerprint({"source": "a"})
    point = {"num_attrs": 1, "num_other_issuers": 1}
    rows = [{"num_attrs": 1, "num_other_issuers": 1, "batch_run_id": 1, "batch_id": 1,
             "component": "issueCredential", "time_ms": 1.0}]
    data = load_checkpoint(path, fp)
    data = save_interrupted_batch(path, data, 2, "crash context")
    data = save_complete_batch(path, data, 1, rows)
    assert data["interrupted_batch"] is None
    assert data["interruption_history"][0]["error_context"] == "crash context"
    with pytest.raises(ValueError, match="missing"):
        load_checkpoint(path, fp, expected_points=[point], expected_runs={1: 2}, required_components=("issueCredential",))
    with pytest.raises(ValueError, match="Unexpected measurement run"):
        validate_batch(rows + [{**rows[0], "num_attrs": 2}], [point], 1, ("issueCredential",), 1)


def test_batch_validator_rejects_missing_duplicate_and_accepts_complete():
    points = [{"num_attrs": 2, "num_other_issuers": 1}]
    rows = [
        {"num_attrs": 2, "num_other_issuers": 1, "batch_run_id": run, "batch_id": 1,
         "component": metric, "time_ms": 1.0}
        for run in (1, 2)
        for metric in ("issueCredential", "presentProof")
    ]
    assert validate_batch(rows, points, 2, ("issueCredential", "presentProof"), 1)
    with pytest.raises(ValueError, match="missing"):
        validate_batch(rows[:-1], points, 2, ("issueCredential", "presentProof"), 1)
    with pytest.raises(ValueError, match="Duplicate"):
        validate_batch(rows + [rows[0]], points, 2, ("issueCredential", "presentProof"), 1)


@pytest.mark.parametrize("value", [True, -1.0, math.nan, math.inf, -math.inf, None])
def test_batch_validator_rejects_invalid_times(value):
    row = {"num_attrs": 2, "num_other_issuers": 1, "batch_run_id": 1, "batch_id": 1,
           "component": "issueCredential", "time_ms": value}
    with pytest.raises(ValueError, match="Invalid measurement row"):
        validate_batch([row], [{"num_attrs": 2, "num_other_issuers": 1}], 1, ("issueCredential",), 1)


def test_source_snapshot_archives_sources_and_binaries_without_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "RESULTS_DIR", tmp_path / "results")
    (tmp_path / "source.cpp").write_text("source", encoding="utf-8")
    (tmp_path / "main.bin").write_bytes(b"main binary")
    (tmp_path / "unit.bin").write_bytes(b"unit binary")
    (tmp_path / "Algorithm").mkdir()
    (tmp_path / "Algorithm" / "miracl.a").write_bytes(b"archive")
    (tmp_path / "lib.cpp").write_text("library", encoding="utf-8")
    prov = {
        "source_sha256": {"source.cpp": hashlib.sha256(b"source").hexdigest()},
        "library_source_sha256": {"lib.cpp": hashlib.sha256(b"library").hexdigest()},
        "binary_sha256": {
            "main_executable": hashlib.sha256(b"main binary").hexdigest(),
            "unit_executable": hashlib.sha256(b"unit binary").hexdigest(),
            "Algorithm/miracl.a": hashlib.sha256(b"archive").hexdigest(),
        },
        "compiler": "test", "configured_compile_commands": [["g++", "-O2"]],
        "miracl_optimization": "none",
    }
    args = SimpleNamespace(main_executable="main.bin", unit_executable="unit.bin")
    snapshot = runner.freeze_source_snapshot(prov, args)
    archive_path = tmp_path / "results/preparation/source_build_snapshot.zip"
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.read("source/source.cpp") == b"source"
        assert archive.read("artifacts/main_executable") == b"main binary"
        assert archive.read("artifacts/unit_executable") == b"unit binary"
        assert archive.read("artifacts/miracl_archive") == b"archive"
    assert runner.freeze_source_snapshot(prov, args) == snapshot
    (tmp_path / "source.cpp").write_text("changed", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Source changed"):
        runner.freeze_source_snapshot(prov, args)
