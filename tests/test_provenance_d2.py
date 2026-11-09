import hashlib
from pathlib import Path
from types import SimpleNamespace
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_issuer_hiding_measurements as runner

def test_collect_build_provenance_hashes_sources_and_binaries(tmp_path, monkeypatch):
    (tmp_path / "Algorithm").mkdir()
    source = tmp_path / "main_multi_issuer.cpp"; source.write_text("one")
    binary = tmp_path / "main.bin"; binary.write_bytes(b"binary")
    (tmp_path / "Algorithm" / "miracl.a").write_bytes(b"archive")
    args = SimpleNamespace(main_executable="main.bin", unit_executable="missing", skip_build=True)
    def fake_run(command, **kwargs):
        if command[:2] == ["g++", "--version"]: return SimpleNamespace(stdout="g++ test\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=1)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    result = runner.collect_build_provenance(args, tmp_path)
    assert result["source_sha256"]["main_multi_issuer.cpp"] == hashlib.sha256(b"one").hexdigest()
    assert result["binary_sha256"]["main_executable"] == hashlib.sha256(b"binary").hexdigest()
    assert result["binary_sha256"]["unit_executable"] is None
    assert result["binary_source_match"] == "unverified"
    assert result["git_head"] is None and result["git_dirty"] is None and result["compiler"] == "g++ test"
    assert "skip-build" in result["status_reason"]
    source.write_text("two")
    assert runner.collect_build_provenance(args, tmp_path)["source_sha256"]["main_multi_issuer.cpp"] != result["source_sha256"]["main_multi_issuer.cpp"]

def test_manifest_preserves_frozen_provenance():
    args = SimpleNamespace(runs=1, warmup=0, batches=1, cooldown_seconds=0, randomize_order=True, random_seed=1,
        round_exclusions=[], sentinel_k=1, sentinel_other_issuers=1, sentinel_component="x", sentinel_max_relative_deviation=0,
        unit_samples=1, skip_build=False, frozen_provenance={"binary_source_match":"built_this_run"})
    data = runner.manifest_data(args, "running", "now")
    assert data["build_provenance"]["binary_source_match"] == "built_this_run"

def test_failed_compiler_is_unknown_and_commands_are_complete(tmp_path, monkeypatch):
    args = SimpleNamespace(main_executable="main.bin", unit_executable="unit.bin", skip_build=True)
    def failed_compiler(command, **kwargs):
        if command[:2] == ["g++", "--version"]: return SimpleNamespace(stdout="", returncode=1)
        return SimpleNamespace(stdout="", returncode=1)
    monkeypatch.setattr(runner.subprocess, "run", failed_compiler)
    result = runner.collect_build_provenance(args, tmp_path)
    assert result["compiler"] is None
    assert result["execution_status"] == "skipped"
    commands = result["configured_compile_commands"]
    assert all("..." not in part for command in commands for part in command)
    assert commands[1][commands[1].index("-o") + 1] == "main.bin"
    assert commands[2][commands[2].index("-o") + 1] == "unit.bin"
