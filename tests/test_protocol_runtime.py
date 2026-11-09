import platform
import re
import subprocess
from pathlib import Path
import pytest

def test_rng_fingerprint_is_fresh_per_process():
    if platform.system() != "Linux": pytest.skip("WSL/Linux runtime required")
    binary = Path(__file__).resolve().parents[1] / "build" / "protocol-regression"
    if not binary.exists(): pytest.skip("protocol regression binary not built")
    outputs = [subprocess.run([str(binary), "--rng-fingerprint"], check=True, capture_output=True, text=True, timeout=20).stdout.strip() for _ in range(2)]
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in outputs)
    assert outputs[0] != outputs[1]
