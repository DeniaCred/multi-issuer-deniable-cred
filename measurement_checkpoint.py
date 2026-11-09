"""Atomic, provenance-bound checkpoints for protocol measurement batches."""
import hashlib
import json
import os
import math
from pathlib import Path


def fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_checkpoint(path, expected_fingerprint, *, expected_points=None, expected_runs=None, required_components=None):
    path = Path(path)
    if not path.exists():
        return {"fingerprint": expected_fingerprint, "complete_batches": {}, "interrupted_batch": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("fingerprint") != expected_fingerprint:
        raise ValueError("Checkpoint provenance/configuration mismatch; refusing to mix measurements")
    batches = data.get("complete_batches")
    if not isinstance(batches, dict):
        raise ValueError("Malformed checkpoint: complete_batches must be an object")
    if expected_points is not None and expected_runs is not None and required_components is not None:
        for batch_id, rows in batches.items():
            if not str(batch_id).isdigit() or int(batch_id) < 1 or not isinstance(rows, list):
                raise ValueError("Malformed checkpoint batch")
            batch_runs = expected_runs.get(int(batch_id)) if isinstance(expected_runs, dict) else expected_runs
            validate_batch(rows, expected_points, batch_runs, required_components, int(batch_id))
    return data


def validate_batch(rows, expected_points, expected_runs, required_components, expected_batch_id=None):
    expected = {
        (int(point["num_attrs"]), int(point["num_other_issuers"]), run_id)
        for point in expected_points
        for run_id in range(1, expected_runs + 1)
    }
    observed = {}
    allowed_components = set(required_components)
    for row in rows:
        try:
            key = (int(row["num_attrs"]), int(row["num_other_issuers"]), int(row["batch_run_id"]))
            value = row["time_ms"]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError("time_ms must be finite and non-negative")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid measurement row: {exc}") from exc
        component = row["component"]
        if expected_batch_id is not None and int(row.get("batch_id", -1)) != int(expected_batch_id):
            raise ValueError(f"Unexpected batch identity for {key}")
        if component not in allowed_components:
            raise ValueError(f"Unexpected measurement component {component}")
        pair = (key, component)
        if pair in observed:
            raise ValueError(f"Duplicate measurement component {component} for {key}")
        if key not in expected:
            raise ValueError(f"Unexpected measurement run {key}")
        observed[pair] = row
    missing = [(key, component) for key in expected for component in required_components if (key, component) not in observed]
    if missing:
        raise ValueError(f"Incomplete batch: {len(missing)} missing run/component measurements; first={missing[0]}")
    return True


def save_complete_batch(path, data, batch_id, rows):
    updated = dict(data)
    batches = dict(data.get("complete_batches", {}))
    key = str(int(batch_id))
    if key in batches:
        raise ValueError(f"Batch {key} is already checkpointed; refusing overwrite")
    batches[key] = rows
    updated["complete_batches"] = batches
    updated["interrupted_batch"] = None
    return save_state(path, updated)


def save_interrupted_batch(path, data, batch_id, error_context, partial_rows=()):
    updated = dict(data)
    record = {"batch_id": int(batch_id), "error_context": str(error_context), "partial_rows": list(partial_rows)}
    history = list(data.get("interruption_history", []))
    history.append(record)
    updated["interruption_history"] = history
    updated["interrupted_batch"] = record
    return save_state(path, updated)


def save_state(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return data
