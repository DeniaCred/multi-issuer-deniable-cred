import argparse
import csv
import json
import platform
import random
import re
import subprocess
import sys
import time
import statistics
from datetime import datetime
from pathlib import Path

import benchmark_and_plot as bench


DEFAULT_RESULTS_DIR = Path("results/issuer_hiding_20260610")
RESULTS_DIR = DEFAULT_RESULTS_DIR
K_VALUES = [2, 4, 6, 8, 10, 12, 16, 20, 24, 30]
Q_AXIS_OTHER_ISSUERS = [1, 3, 6, 8, 10, 14, 18, 22]
MIRACL_ARCHIVE = Path("Algorithm/miracl.a")
MIRACL_CONFIGS = [
    Path("Algorithm/mirdef.hpp"),
    Path("Algorithm/mirdef.h"),
    Path("Algorithm/MIRACL/mirdef.hpp"),
    Path("Algorithm/MIRACL/mirdef.h"),
]
LINUX_MIRACL_MACROS = {
    "MIRACL": "64",
    "mr_utype": "long",
    "mr_unsign64": "unsigned long",
    "MR_LBITS": "64",
    "MR_CPP": "",
}


def iso_now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def dedupe_columns(columns):
    seen = set()
    out = []
    for column in columns:
        if column in seen:
            continue
        seen.add(column)
        out.append(column)
    return out


RAW_COLUMNS = dedupe_columns(
    [
        "experiment_id",
        "run_started_at",
        "source_type",
        "k",
        "q_internal",
        "issuer_set_size_public",
        "issuer_set_size_user_visible",
        "formula",
        "notes",
        *bench.RAW_FIELDNAMES,
    ]
)

SUMMARY_COLUMNS = dedupe_columns(
    [
        "experiment_id",
        "run_started_at",
        "source_type",
        "k",
        "q_internal",
        "issuer_set_size_public",
        "issuer_set_size_user_visible",
        "formula",
        "notes",
        *bench.SUMMARY_FIELDNAMES,
    ]
)

SENTINEL_COLUMNS = [
    "batch_id",
    "sentinel_k",
    "sentinel_q_internal",
    "sentinel_other_issuers",
    "sentinel_component",
    "samples",
    "batch_trimmed_mean_ms",
    "sentinel_median_ms",
    "relative_deviation",
    "max_relative_deviation",
    "excluded",
]


def csv_write(path, columns, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def run_command(command):
    print(" ".join(str(part) for part in command))
    subprocess.run([str(part) for part in command], check=True)


def macro_value(text, name):
    match = re.search(rf"^\s*#define\s+{re.escape(name)}(?:\s+(.+?))?\s*$", text, re.MULTILINE)
    if not match:
        return None
    value = match.group(1)
    return "" if value is None else value.strip()


def ensure_linux_runtime():
    if platform.system() != "Linux":
        raise RuntimeError("This measurement runner is Linux/WSL-only; run it inside Linux or WSL.")


def miracl_macros(path):
    text = path.read_text(encoding="utf-8")
    return {name: macro_value(text, name) for name in LINUX_MIRACL_MACROS}


def validate_miracl_build():
    ensure_linux_runtime()
    reference = None
    for path in MIRACL_CONFIGS:
        if not path.exists():
            raise RuntimeError(f"Missing MIRACL config: {path}")
        macros = miracl_macros(path)
        for name, expected in LINUX_MIRACL_MACROS.items():
            if macros[name] != expected:
                raise RuntimeError(f"{path} must define {name} as {expected!r} for the Linux/WSL build")
        if reference is None:
            reference = macros
        elif macros != reference:
            raise RuntimeError(f"{path} does not match the active Linux MIRACL ABI configuration")

    if not MIRACL_ARCHIVE.exists():
        raise RuntimeError(f"Missing MIRACL archive: {MIRACL_ARCHIVE}")

    try:
        result = subprocess.run(
            ["nm", "-C", str(MIRACL_ARCHIVE)],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Cannot validate MIRACL archive because nm is unavailable") from exc

    if "__imp_" in result.stdout or "acrt" in result.stdout.lower():
        raise RuntimeError("Algorithm/miracl.a appears to be a non-Linux archive; rebuild with make -C Algorithm under Linux/WSL")
    if "mirsys(int, unsigned long)" not in result.stdout:
        raise RuntimeError("Algorithm/miracl.a does not match the Linux MIRACL ABI; rebuild with make -C Algorithm")


def parse_round_exclusion(spec):
    parts = str(spec).split(":")
    if len(parts) != 4:
        raise ValueError("round exclusion must use experiment_id:k:q_internal:batch_id")
    experiment_id, k, q_internal, batch_id = parts
    return {
        "experiment_id": experiment_id,
        "k": int(k),
        "q_internal": int(q_internal),
        "batch_id": int(batch_id),
    }


def row_int(row, field, fallback=None):
    value = row.get(field, fallback)
    if value in ("", None):
        return None
    return int(value)


def matches_round_exclusion(row, exclusion, current_experiment_id=None):
    experiment_id = row.get("experiment_id", current_experiment_id)
    k = row_int(row, "k", row.get("num_attrs"))
    q_internal = row_int(row, "q_internal", row.get("num_issuers"))
    batch_id = row_int(row, "batch_id")
    return (
        experiment_id == exclusion["experiment_id"]
        and k == exclusion["k"]
        and q_internal == exclusion["q_internal"]
        and batch_id == exclusion["batch_id"]
    )


def exclude_rounds(rows, exclusions, current_experiment_id=None):
    if not exclusions:
        return list(rows)
    return [
        row
        for row in rows
        if not any(matches_round_exclusion(row, exclusion, current_experiment_id) for exclusion in exclusions)
    ]


def build_binaries(args):
    if args.skip_build:
        if not args.skip_miracl_check:
            validate_miracl_build()
        return
    ensure_linux_runtime()
    run_command(["make", "-C", "Algorithm"])
    if not args.skip_miracl_check:
        validate_miracl_build()
    Path(args.main_executable).parent.mkdir(parents=True, exist_ok=True)
    Path(args.unit_executable).parent.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "g++",
            "-std=c++11",
            "-O2",
            "-o",
            args.main_executable,
            "main_multi_issuer.cpp",
            "multi_issuer.cpp",
            "trusted_authority.cpp",
            "nizk_proof.cpp",
            "or_proof.cpp",
            "Algorithm/bn_pair.cpp",
            "Algorithm/miracl.a",
            "-w",
        ]
    )
    run_command(
        [
            "g++",
            "-std=c++11",
            "-O2",
            "-o",
            args.unit_executable,
            "unit_operation_benchmark.cpp",
            "Algorithm/bn_pair.cpp",
            "Algorithm/miracl.a",
            "-w",
        ]
    )


def experiment_jobs(args):
    return [
        {
            "experiment_id": f"issuer-hiding-k-axis-{args.runs}runs",
            "notes": (
                "Issuer-hiding k-axis measurements with fixed q_internal=10; "
                "q_internal is not user-visible, and this prototype does not "
                "selectively disclose user attributes."
            ),
            "messages": K_VALUES,
            "other_issuers": [8],
            "experiment_plan": "paper-scaling",
            "attribute_axis_other_issuers": 8,
            "issuer_axis_messages": 12,
        },
        {
            "experiment_id": f"issuer-hiding-q-axis-{args.runs}runs",
            "notes": (
                "Issuer-hiding q-axis measurements; q_internal is the hidden "
                "system-side contribution count, not a user-visible policy-set size."
            ),
            "messages": [12],
            "other_issuers": Q_AXIS_OTHER_ISSUERS,
            "experiment_plan": "paper-scaling",
            "attribute_axis_other_issuers": 8,
            "issuer_axis_messages": 12,
        },
        {
            "experiment_id": f"issuer-hiding-max-k30-q24-{args.runs}runs",
            "notes": (
                "Issuer-hiding maximum parameter point with k=30 and q_internal=24; "
                "both dimensions are measured by the local prototype."
            ),
            "messages": [30],
            "other_issuers": [22],
            "experiment_plan": "cartesian",
            "attribute_axis_other_issuers": 8,
            "issuer_axis_messages": 12,
        },
    ]


def build_measurement_points(args):
    jobs = experiment_jobs(args)
    k_axis_job, q_axis_job, max_job = jobs
    points_by_key = {}

    def add_point(num_attrs, num_other_issuers, job):
        key = (int(num_attrs), int(num_other_issuers))
        if key not in points_by_key:
            points_by_key[key] = {
                "point_id": f"k{key[0]}-q{key[1] + 2}",
                "num_attrs": key[0],
                "num_other_issuers": key[1],
                "q_internal": key[1] + 2,
                "labels": [],
            }
        labels = points_by_key[key]["labels"]
        if not any(label["experiment_id"] == job["experiment_id"] for label in labels):
            labels.append({"experiment_id": job["experiment_id"], "notes": job["notes"]})

    for k in K_VALUES:
        add_point(k, 8, k_axis_job)
    for num_other_issuers in Q_AXIS_OTHER_ISSUERS:
        add_point(12, num_other_issuers, q_axis_job)
    add_point(30, 22, max_job)

    return [points_by_key[key] for key in sorted(points_by_key)]


def point_key_from_row(row):
    return (int(row["num_attrs"]), int(row["num_other_issuers"]))


def point_label_keys(points, experiment_id):
    return {
        (point["num_attrs"], point["num_other_issuers"])
        for point in points
        if any(label["experiment_id"] == experiment_id for label in point["labels"])
    }


def label_for_experiment(point, experiment_id):
    for label in point["labels"]:
        if label["experiment_id"] == experiment_id:
            return label
    return None


def expand_raw_rows_by_labels(rows, points, run_started_at):
    points_by_key = {(point["num_attrs"], point["num_other_issuers"]): point for point in points}
    expanded = []
    for row in rows:
        point = points_by_key[point_key_from_row(row)]
        for label in point["labels"]:
            q_internal = int(row["num_issuers"])
            expanded.append(
                {
                    **row,
                    "experiment_id": label["experiment_id"],
                    "run_started_at": run_started_at,
                    "source_type": "measured",
                    "k": row["num_attrs"],
                    "q_internal": q_internal,
                    "issuer_set_size_public": "N/A",
                    "issuer_set_size_user_visible": "not visible",
                    "formula": "measured",
                    "notes": label["notes"],
                }
            )
    return expanded


def batch_sort_key(value):
    try:
        return (0, int(value))
    except (TypeError, ValueError):
        return (1, str(value))


def build_sentinel_batch_report(
    rows,
    *,
    sentinel_k,
    sentinel_other_issuers,
    sentinel_component,
    max_relative_deviation,
):
    sentinel_rows = [
        row
        for row in rows
        if int(row["num_attrs"]) == int(sentinel_k)
        and int(row["num_other_issuers"]) == int(sentinel_other_issuers)
        and row["component"] == sentinel_component
    ]
    if not sentinel_rows:
        return []

    groups = {}
    for row in sentinel_rows:
        groups.setdefault(row.get("batch_id", 1), []).append(float(row["time_ms"]))

    batch_values = []
    for batch_id in sorted(groups, key=batch_sort_key):
        values = groups[batch_id]
        batch_values.append((int(batch_id), len(values), bench.trimmed_mean(values, bench.DEFAULT_TRIM_PERCENT)))

    median_value = statistics.median(value for _, _, value in batch_values)
    threshold = float(max_relative_deviation)
    report = []
    for batch_id, samples, value in batch_values:
        relative_deviation = 0.0 if median_value == 0 else abs(value - median_value) / median_value
        report.append(
            {
                "batch_id": batch_id,
                "sentinel_k": int(sentinel_k),
                "sentinel_q_internal": int(sentinel_other_issuers) + 2,
                "sentinel_other_issuers": int(sentinel_other_issuers),
                "sentinel_component": sentinel_component,
                "samples": samples,
                "batch_trimmed_mean_ms": value,
                "sentinel_median_ms": median_value,
                "relative_deviation": relative_deviation,
                "max_relative_deviation": threshold,
                "excluded": threshold > 0 and relative_deviation > threshold,
            }
        )
    return report


def exclude_batches(rows, excluded_batch_ids):
    excluded = {int(batch_id) for batch_id in excluded_batch_ids}
    if not excluded:
        return list(rows)
    return [row for row in rows if int(row.get("batch_id", 1)) not in excluded]


def enrich_rows(rows, job, run_started_at):
    enriched = []
    for row in rows:
        q_internal = row["num_issuers"]
        enriched.append(
            {
                **row,
                "experiment_id": job["experiment_id"],
                "run_started_at": run_started_at,
                "source_type": "measured",
                "k": row["num_attrs"],
                "q_internal": q_internal,
                "issuer_set_size_public": "N/A",
                "issuer_set_size_user_visible": "not visible",
                "formula": "measured",
                "notes": job["notes"],
            }
        )
    return enriched


def run_protocol_job(args, job):
    run_started_at = iso_now()
    ns = argparse.Namespace(
        executable=args.main_executable,
        scheme="OurScheme",
        messages=job["messages"],
        other_issuers=job["other_issuers"],
        experiment_plan=job["experiment_plan"],
        attribute_axis_other_issuers=job["attribute_axis_other_issuers"],
        issuer_axis_messages=job["issuer_axis_messages"],
        num_disclosed=0,
        runs=args.runs,
        warmup=args.warmup,
        batches=args.batches,
        randomize_order=args.randomize_order,
        random_seed=args.random_seed,
        cooldown_seconds=args.cooldown_seconds,
        components=bench.COMPONENT_ORDER,
    )
    raw_rows = bench.collect_benchmarks(ns)
    raw_rows = [row for row in raw_rows if row["component"] in bench.COMPONENT_ORDER]
    summary_input_rows = exclude_rounds(raw_rows, args.round_exclusions, job["experiment_id"])
    summary_rows = bench.summarize_rows(summary_input_rows)
    output_xlsx = RESULTS_DIR / f"{job['experiment_id']}.xlsx"
    bench.write_performance_workbook(
        output_xlsx,
        summary_rows,
        experiment_id=job["experiment_id"],
        run_started_at=run_started_at,
        notes=job["notes"],
        warmup_runs=args.warmup,
    )
    return enrich_rows(raw_rows, job, run_started_at), enrich_rows(summary_rows, job, run_started_at)


def run_interleaved_protocol(args):
    run_started_at = iso_now()
    points = build_measurement_points(args)
    rng = random.Random(args.random_seed)

    def run_one(point, run_id, batch_id=1, batch_run_id=None):
        records = bench.run_protocol(args.main_executable, point["num_attrs"], point["num_other_issuers"])
        return bench.build_rows(
            records,
            "OurScheme",
            point["num_attrs"],
            point["num_other_issuers"],
            0,
            run_id,
            batch_id=batch_id,
            batch_run_id=batch_run_id,
        )

    if args.warmup:
        print(f"\nWarming {len(points)} unique parameter points with {args.warmup} runs per point")
        warmup_points = list(points)
        for warmup_run in range(1, args.warmup + 1):
            if args.randomize_order:
                rng.shuffle(warmup_points)
            for point in warmup_points:
                run_one(point, run_id=warmup_run, batch_id=0, batch_run_id=warmup_run)

    base_runs, remainder = divmod(args.runs, args.batches)
    batch_sizes = [base_runs + (1 if index < remainder else 0) for index in range(args.batches)]
    raw_rows = []
    print(
        f"\nRunning {len(points)} unique parameter points in {args.batches} interleaved batches "
        f"({args.runs} measured runs per point)"
    )
    for batch_id, batch_runs in enumerate(batch_sizes, start=1):
        batch_points = list(points)
        if args.randomize_order:
            rng.shuffle(batch_points)
        print(f"\nBatch {batch_id}/{args.batches}: {batch_runs} measured runs per unique parameter point")
        for point_index, point in enumerate(batch_points, start=1):
            print(
                f"  point {point_index}/{len(batch_points)} "
                f"k={point['num_attrs']}, q_internal={point['q_internal']}"
            )
            for batch_run_id in range(1, batch_runs + 1):
                run_id = sum(batch_sizes[: batch_id - 1]) + batch_run_id
                raw_rows.extend(run_one(point, run_id=run_id, batch_id=batch_id, batch_run_id=batch_run_id))
        print(f"  completed batch {batch_id}/{args.batches}")
        if args.cooldown_seconds and batch_id < args.batches:
            print(f"  cooling down for {args.cooldown_seconds:g} seconds before next batch")
            time.sleep(args.cooldown_seconds)

    raw_rows = [row for row in raw_rows if row["component"] in bench.COMPONENT_ORDER]
    sentinel_report = build_sentinel_batch_report(
        raw_rows,
        sentinel_k=args.sentinel_k,
        sentinel_other_issuers=args.sentinel_other_issuers,
        sentinel_component=args.sentinel_component,
        max_relative_deviation=args.sentinel_max_relative_deviation,
    )
    excluded_batch_ids = {item["batch_id"] for item in sentinel_report if item["excluded"]}
    summary_unique_rows = exclude_batches(raw_rows, excluded_batch_ids)

    all_raw_rows = expand_raw_rows_by_labels(raw_rows, points, run_started_at)
    all_summary_rows = []
    for job in experiment_jobs(args):
        keys = point_label_keys(points, job["experiment_id"])
        job_rows = [row for row in summary_unique_rows if point_key_from_row(row) in keys]
        job_rows = expand_raw_rows_by_labels(job_rows, [point for point in points if (point["num_attrs"], point["num_other_issuers"]) in keys], run_started_at)
        job_rows = [row for row in job_rows if row["experiment_id"] == job["experiment_id"]]
        job_rows = exclude_rounds(job_rows, args.round_exclusions, job["experiment_id"])
        summary_rows = bench.summarize_rows(job_rows)
        enriched_summary_rows = enrich_rows(summary_rows, job, run_started_at)
        all_summary_rows.extend(enriched_summary_rows)
        bench.write_performance_workbook(
            RESULTS_DIR / f"{job['experiment_id']}.xlsx",
            summary_rows,
            experiment_id=job["experiment_id"],
            run_started_at=run_started_at,
            notes=job["notes"],
            warmup_runs=args.warmup,
        )

    return all_raw_rows, all_summary_rows, sentinel_report


def build_wide_rows(summary_rows):
    base_columns = [
        "experiment_id",
        "run_started_at",
        "source_type",
        "scheme",
        "k",
        "q_internal",
        "issuer_set_size_public",
        "issuer_set_size_user_visible",
        "num_other_issuers",
        "num_disclosed",
        "signature_bytes",
        "apk_user_visible_bytes",
        "internal_pk_directory_bytes",
        "ta_credential_bytes",
        "holder_binding_bytes",
        "proof_bytes",
        "transcript_bytes_compact",
        "transcript_bytes_serialized",
        "verifier_auth_proof_bytes",
        "verifier_auth_message_bytes",
        "presentation_transcript_real_bytes",
        "presentation_transcript_simulated_bytes",
        "notes",
    ]
    rows_by_key = {}
    for row in summary_rows:
        key = (
            row["experiment_id"],
            int(row["k"]),
            int(row["q_internal"]),
            int(row["num_other_issuers"]),
        )
        if key not in rows_by_key:
            rows_by_key[key] = {column: row.get(column, "") for column in base_columns}
        component = row["component"]
        rows_by_key[key][f"{component}_runs"] = row["runs"]
        rows_by_key[key][f"{component}_mean_ms"] = row["mean_ms"]
        rows_by_key[key][f"{component}_trimmed_mean_ms"] = row["trimmed_mean_ms"]
        rows_by_key[key][f"{component}_round_mean_ms"] = row.get("round_mean_ms", "")
        rows_by_key[key][f"{component}_round_mean_std_ms"] = row.get("round_mean_std_ms", "")
        rows_by_key[key][f"{component}_round_trimmed_mean_ms"] = row.get("round_trimmed_mean_ms", "")
        rows_by_key[key][f"{component}_round_trimmed_mean_std_ms"] = row.get("round_trimmed_mean_std_ms", "")
        rows_by_key[key][f"{component}_batch_trimmed_mean_ms"] = row.get("batch_trimmed_mean_ms", "")
        rows_by_key[key][f"{component}_batch_median_ms"] = row.get("batch_median_ms", "")
        rows_by_key[key][f"{component}_batch_mad_ms"] = row.get("batch_mad_ms", "")
        rows_by_key[key][f"{component}_median_ms"] = row["median_ms"]
        rows_by_key[key][f"{component}_p95_ms"] = row["p95_ms"]
        rows_by_key[key][f"{component}_std_ms"] = row["std_ms"]

    columns = [*base_columns]
    for component in bench.COMPONENT_ORDER:
        columns.extend(
            [
                f"{component}_runs",
                f"{component}_mean_ms",
                f"{component}_trimmed_mean_ms",
                f"{component}_round_mean_ms",
                f"{component}_round_mean_std_ms",
                f"{component}_round_trimmed_mean_ms",
                f"{component}_round_trimmed_mean_std_ms",
                f"{component}_batch_trimmed_mean_ms",
                f"{component}_batch_median_ms",
                f"{component}_batch_mad_ms",
                f"{component}_median_ms",
                f"{component}_p95_ms",
                f"{component}_std_ms",
            ]
        )
    return columns, [rows_by_key[key] for key in sorted(rows_by_key)]


def run_unit_benchmark(args):
    if args.skip_unit:
        return
    run_command(
        [
            sys.executable,
            "run_unit_benchmark.py",
            "--samples",
            str(args.unit_samples),
            "--executable",
            args.unit_executable,
            "--output-xlsx",
            RESULTS_DIR / "unit_costs_30samples.xlsx",
        ]
    )


def run_baseline_estimates(args):
    if args.skip_estimates:
        return
    run_command(
        [
            sys.executable,
            "estimate_issuer_hiding_baselines.py",
            "--unit-costs-xlsx",
            RESULTS_DIR / "unit_costs_30samples.xlsx",
            "--ours-summary-csv",
            RESULTS_DIR / "ours_summary_long.csv",
            "--output-csv",
            RESULTS_DIR / "issuer_hiding_baselines.csv",
            "--output-xlsx",
            RESULTS_DIR / "issuer_hiding_comparison_ready.xlsx",
        ]
    )


def manifest_data(args, status, started_at, finished_at=None):
    output_files = [
        "manifest.json",
        "manifest.md",
        "unit_costs_30samples.xlsx",
        "ours_raw_runs.csv",
        "ours_summary_long.csv",
        "ours_summary_wide.csv",
        "issuer_hiding_baselines.csv",
        "issuer_hiding_comparison_ready.xlsx",
        "sentinel_batches.csv",
    ]
    output_files.extend(f"{job['experiment_id']}.xlsx" for job in experiment_jobs(args))
    return {
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "runs": args.runs,
        "warmup_runs": args.warmup,
        "batches": args.batches,
        "runs_per_batch": args.runs // args.batches if args.runs % args.batches == 0 else None,
        "cooldown_seconds": args.cooldown_seconds,
        "randomize_order": args.randomize_order,
        "random_seed": args.random_seed,
        "trim_percent": bench.DEFAULT_TRIM_PERCENT,
        "round_trim_percent": bench.ROUND_TRIM_PERCENT,
        "batch_trim_percent": bench.BATCH_TRIM_PERCENT,
        "excluded_rounds": args.round_exclusions,
        "sentinel": {
            "k": args.sentinel_k,
            "q_internal": args.sentinel_other_issuers + 2,
            "other_issuers": args.sentinel_other_issuers,
            "component": args.sentinel_component,
            "max_relative_deviation": args.sentinel_max_relative_deviation,
        },
        "unit_samples": args.unit_samples,
        "parameters": {
            "k_values": K_VALUES,
            "q_internal_values": [3, 5, 8, 10, 12, 16, 20, 24],
            "num_disclosed": 0,
            "q_mapping": "q_internal = 2 + num_other_issuers",
            "user_view": "Users receive only opaque aggregate public material; q_internal and issuer identities are not user-visible.",
            "baseline_issuer_set_values": [3, 5, 8, 10, 12, 16, 20, 24],
        },
        "new_results_dir": str(RESULTS_DIR),
        "measurement_layout": "interleaved unique parameter points; shared axis points are measured once and reused by labels",
        "output_files": output_files,
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "machine": platform.machine(),
        },
        "notes": (
            "Issuer-hiding Linux/WSL rerun; comparison data are formula estimates "
            "based on local unit-operation costs, not external paper runtimes."
        ),
    }


def write_manifest(data):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "manifest.json").write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
    output_lines = "\n".join(f"- `{name}`" for name in data["output_files"])
    body = f"""# Issuer-Hiding Chapter 7 Measurement Manifest

## Status

- status: `{data['status']}`
- started_at: `{data['started_at']}`
- finished_at: `{data.get('finished_at') or ''}`
- runs: `{data['runs']}`
- warmup_runs: `{data['warmup_runs']}`
- batches: `{data['batches']}`
- runs_per_batch: `{data.get('runs_per_batch') or ''}`
- cooldown_seconds: `{data['cooldown_seconds']}`
- randomize_order: `{data['randomize_order']}`
- random_seed: `{data['random_seed']}`
- trim_percent: `{data['trim_percent']}`
- round_trim_percent: `{data['round_trim_percent']}`
- batch_trim_percent: `{data['batch_trim_percent']}`
- excluded_rounds: `{data['excluded_rounds']}`
- sentinel: `{data['sentinel']}`
- unit_samples: `{data['unit_samples']}`

## Parameters

- k: `{data['parameters']['k_values']}`
- q_internal: `{data['parameters']['q_internal_values']}`
- q mapping: `{data['parameters']['q_mapping']}`
- disclosed attributes: `{data['parameters']['num_disclosed']}`
- baseline issuer-set sizes: `{data['parameters']['baseline_issuer_set_values']}`
- user view: {data['parameters']['user_view']}

## Output Files

{output_lines}

## Environment

- platform: `{data['environment']['platform']}`
- python: `{data['environment']['python']}`
- machine: `{data['environment']['machine']}`

## Notes

{data['notes']}
"""
    (RESULTS_DIR / "manifest.md").write_text(body, encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(description="Run issuer-hiding-focused Chapter 7 measurements.")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--runs", type=int, default=200)
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--runs-per-round", type=int)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--batches", type=int, default=5)
    parser.add_argument("--cooldown-seconds", type=float, default=0.0)
    parser.add_argument("--random-seed", type=int, default=20260610)
    parser.add_argument("--no-randomize-order", dest="randomize_order", action="store_false")
    parser.set_defaults(randomize_order=True)
    parser.add_argument("--sentinel-k", type=int, default=12)
    parser.add_argument("--sentinel-other-issuers", type=int, default=8)
    parser.add_argument("--sentinel-component", default="verifyPresentationPayload_total_real")
    parser.add_argument(
        "--sentinel-max-relative-deviation",
        type=float,
        default=0.25,
        help="Exclude whole measured batches whose sentinel batch mean differs from the sentinel median by more than this fraction; use 0 to disable.",
    )
    parser.add_argument("--unit-samples", type=int, default=30)
    parser.add_argument("--main-executable", default=".wsl-build/issuer_hiding_main_multi_issuer")
    parser.add_argument("--unit-executable", default=".wsl-build/issuer_hiding_unit_operation_benchmark")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-miracl-check", action="store_true")
    parser.add_argument("--skip-unit", action="store_true")
    parser.add_argument("--skip-protocol", action="store_true")
    parser.add_argument("--skip-estimates", action="store_true")
    parser.add_argument(
        "--exclude-round",
        action="append",
        default=[],
        help="Exclude one measured round from summaries as experiment_id:k:q_internal:batch_id; raw runs are retained.",
    )
    return parser


def main(argv=None):
    global RESULTS_DIR
    args = build_parser().parse_args(argv)
    RESULTS_DIR = Path(args.results_dir)
    args.round_exclusions = [parse_round_exclusion(spec) for spec in args.exclude_round]
    if args.rounds is not None or args.runs_per_round is not None:
        if args.rounds is None or args.runs_per_round is None:
            raise ValueError("--rounds and --runs-per-round must be provided together")
        if args.rounds < 1:
            raise ValueError("--rounds must be at least 1")
        if args.runs_per_round < 1:
            raise ValueError("--runs-per-round must be at least 1")
        args.batches = args.rounds
        args.runs = args.rounds * args.runs_per_round
    if args.runs < 1:
        raise ValueError("--runs must be at least 1")
    if args.warmup < 0:
        raise ValueError("--warmup must be non-negative")
    if args.batches < 1:
        raise ValueError("--batches must be at least 1")
    if args.batches > args.runs:
        raise ValueError("--batches cannot exceed --runs")
    if args.cooldown_seconds < 0:
        raise ValueError("--cooldown-seconds must be non-negative")
    if args.sentinel_max_relative_deviation < 0:
        raise ValueError("--sentinel-max-relative-deviation must be non-negative")

    started_at = iso_now()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    write_manifest(manifest_data(args, "running", started_at))

    build_binaries(args)
    run_unit_benchmark(args)

    all_raw_rows = []
    all_summary_rows = []
    if not args.skip_protocol:
        all_raw_rows, all_summary_rows, sentinel_report = run_interleaved_protocol(args)

        csv_write(RESULTS_DIR / "ours_raw_runs.csv", RAW_COLUMNS, all_raw_rows)
        csv_write(RESULTS_DIR / "ours_summary_long.csv", SUMMARY_COLUMNS, all_summary_rows)
        wide_columns, wide_rows = build_wide_rows(all_summary_rows)
        csv_write(RESULTS_DIR / "ours_summary_wide.csv", wide_columns, wide_rows)
        csv_write(RESULTS_DIR / "sentinel_batches.csv", SENTINEL_COLUMNS, sentinel_report)

    run_baseline_estimates(args)

    finished_at = iso_now()
    write_manifest(manifest_data(args, "complete", started_at, finished_at))
    print(f"Issuer-hiding measurements written under {RESULTS_DIR}")


if __name__ == "__main__":
    main()
