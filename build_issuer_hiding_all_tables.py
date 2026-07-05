#!/usr/bin/env python3
"""Build one consolidated workbook for issuer-hiding experiment tables."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from openpyxl import Workbook, load_workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter


HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(color="FFFFFF", bold=True)
SUBTLE_FILL = PatternFill("solid", fgColor="D9EAF7")
TITLE_FONT = Font(bold=True, size=14, color="1F4E78")


FIELD_CN: dict[str, tuple[str, str]] = {
    "sheet_name": ("sheet name", ""),
    "source_file": ("source file", ""),
    "source_sheet": ("source sheet", ""),
    "table_role": ("table role", ""),
    "rows": ("row count", ""),
    "columns": ("column count", ""),
    "notes": ("notes", ""),
    "key": ("key", ""),
    "value": ("value", ""),
    "experiment_id": ("experiment id", ""),
    "run_started_at": ("run start time", ""),
    "source_type": ("data source type", "measured means local measurement; formula_estimate means formula estimate."),
    "scheme": ("scheme name", ""),
    "k": ("attribute count", "Attribute count used in this experiment chapter."),
    "q_internal": ("internal contribution count", "Internal system parameter; it is not user-visible and should not be described as a public issuer count."),
    "issuer_set_size_public": ("public issuer-set size", "Recorded as N/A when this scheme hides the information."),
    "issuer_set_size_user_visible": ("whether the issuer-set size is user visible", ""),
    "num_other_issuers": ("other issuer count", "Code-level parameter equal to q_internal - 2."),
    "num_attrs": ("attribute count", ""),
    "num_issuers": ("issuer/contributor count", "Code-level parameter; paper text should explain it together with the hiding semantics."),
    "num_disclosed": ("disclosed attribute count", "The current prototype has no selective-disclosure implementation, so this is 0 in experiments."),
    "phase": ("protocol phase", ""),
    "component": ("component name", ""),
    "runs": ("formal measurement runs", ""),
    "batches": ("batch count", ""),
    "trim_percent": ("trim percent", "Percentage used for two-sided trimming."),
    "trim_removed_each_tail": ("trimmed samples per tail", ""),
    "mean_ms": ("mean time", "Unit: ms."),
    "trimmed_mean_ms": ("trimmed mean time", "Unit: ms."),
    "median_ms": ("median time", "Unit: ms."),
    "std_ms": ("stddev", "Unit: ms."),
    "p95_ms": ("95th percentile time", "Unit: ms."),
    "p99_ms": ("99th percentile time", "Unit: ms."),
    "min_ms": ("minimum time", "Unit: ms."),
    "max_ms": ("maximum time", "Unit: ms."),
    "credential_bytes": ("credential byte count", "Unit: bytes."),
    "proof_bytes": ("proof byte count", "Unit: bytes."),
    "public_key_bytes": ("public-key byte count", "Unit: bytes."),
    "apk_user_visible_bytes": ("user-visible aggregate authentication public-key byte count", "Unit: bytes."),
    "internal_pk_directory_bytes": ("internal public-key directory byte count", "Unit: bytes; not user-visible."),
    "ta_credential_bytes": ("TA attestation byte count", "Unit: bytes."),
    "holder_binding_bytes": ("holder binding byte count", "Unit: bytes."),
    "signature_bytes": ("signature byte count", "Unit: bytes."),
    "transcript_bytes": ("presentation transcript byte count", "Unit: bytes."),
    "transcript_bytes_compact": ("compact presentation transcript byte count", "Unit: bytes."),
    "transcript_bytes_serialized": ("serialized presentation transcript byte count", "Unit: bytes."),
    "verifier_auth_proof_bytes": ("verifier authentication proof byte count", "Unit: bytes."),
    "verifier_auth_message_bytes": ("verifier authentication message byte count", "Unit: bytes."),
    "presentation_transcript_real_bytes": ("real presentation transcript byte count", "Unit: bytes."),
    "presentation_transcript_simulated_bytes": ("simulated presentation transcript byte count", "Unit: bytes."),
    "formula": ("estimate formula", "Formula or formula-source note used for comparison schemes."),
    "assumption": ("estimate assumption", ""),
    "unit_cost_source": ("unit-operation cost source", ""),
    "operation": ("base operation", ""),
    "samples": ("sample count", ""),
    "mean": ("mean", ""),
    "median": ("median", ""),
    "stdev": ("stddev", ""),
    "mean_time_ms": ("mean time", "Unit: ms."),
    "estimated_show_ms": ("estimated show time", "Unit: ms."),
    "estimated_verify_ms": ("estimated verify time", "Unit: ms."),
    "estimated_issue_ms": ("estimated issue time", "Unit: ms."),
    "estimated_transcript_bytes": ("estimated presentation transcript bytes", "Unit: bytes."),
    "estimated_public_material_bytes": ("estimated public material bytes", "Unit: bytes."),
}

NOTE_TRANSLATIONS = {}


TABLE_SPECS = [
    {
        "sheet": "Ours_Raw_Runs",
        "type": "csv",
        "path": "ours_raw_runs.csv",
        "role": "OurScheme full raw measurement details",
        "note": "Raw timing and size records for each run and component; the paper normally cites summary tables rather than this sheet.",
    },
    {
        "sheet": "Ours_Summary_Long",
        "type": "csv",
        "path": "ours_summary_long.csv",
        "role": "OurScheme long-form summary",
        "note": "One row per parameter point and component, convenient for filtering and plotting.",
    },
    {
        "sheet": "Ours_Summary_Wide",
        "type": "csv",
        "path": "ours_summary_wide.csv",
        "role": "OurScheme wide summary",
        "note": "One row per parameter point, suitable for paper figures.",
    },
    {
        "sheet": "Issuer_Baselines",
        "type": "csv",
        "path": "issuer_hiding_baselines.csv",
        "role": "issuer-hiding comparison formula estimates",
        "note": "Does not import runtimes from external papers; estimates are based on literature formulas and local unit-operation costs.",
    },
    {
        "sheet": "K_Axis",
        "type": "xlsx",
        "path": "issuer-hiding-k-axis-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "k-axis standalone results",
        "note": "Fix q_internal=10 and vary the attribute count k.",
    },
    {
        "sheet": "Q_Axis",
        "type": "xlsx",
        "path": "issuer-hiding-q-axis-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "q-axis standalone results",
        "note": "Fix k=12 and vary internal q_internal; this parameter is not user-visible.",
    },
    {
        "sheet": "Max_K30_Q24",
        "type": "xlsx",
        "path": "issuer-hiding-max-k30-q24-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "maximum-parameter standalone results",
        "note": "k=30 and q_internal=24, used for component cost analysis.",
    },
    {
        "sheet": "Compare_OurMeasured",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "OurMeasured",
        "role": "OurScheme measured table from the consolidated workbook",
        "note": "Copied from the existing comparison_ready workbook.",
    },
    {
        "sheet": "Compare_Baselines",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "IssuerHidingBaselines",
        "role": "comparison-estimate table from the consolidated workbook",
        "note": "Copied from the existing comparison_ready workbook.",
    },
    {
        "sheet": "Compare_UnitCosts",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "UnitCosts",
        "role": "unit-cost table from the consolidated workbook",
        "note": "Used to audit the formula-estimate basis.",
    },
    {
        "sheet": "Unit_Costs",
        "type": "xlsx",
        "path": "unit_costs_30samples.xlsx",
        "source_sheet": "UnitCosts",
        "role": "local unit-operation costs",
        "note": "30 samples, used for comparison-scheme formula estimates.",
    },
    {
        "sheet": "Operation_Formulas",
        "type": "xlsx",
        "path": "unit_costs_30samples.xlsx",
        "source_sheet": "OperationFormulas",
        "role": "unit-operation formula notes",
        "note": "Records notes for base operation costs.",
    },
]


def translate_note(value: Any) -> Any:
    if isinstance(value, str):
        return NOTE_TRANSLATIONS.get(value, value)
    return value


def display_header(header: str) -> str:
    if header in {"notes", "notes/notes"}:
        return "notes"
    return header


def coerce_csv_value(value: str) -> Any:
    value = translate_note(value)
    if value == "":
        return None
    if value in {"N/A", "not visible", "measured", "formula_estimate"}:
        return value
    stripped = value.strip()
    if stripped.startswith("="):
        return "'" + stripped
    try:
        if stripped.lower() in {"true", "false"}:
            return stripped.lower() == "true"
        if any(ch in stripped for ch in ".eE"):
            return float(stripped)
        return int(stripped)
    except ValueError:
        return value


def style_header_cell(cell: WriteOnlyCell) -> WriteOnlyCell:
    cell.fill = HEADER_FILL
    cell.font = HEADER_FONT
    cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    return cell


def append_header(ws, headers: list[str]) -> None:
    ws.append([style_header_cell(WriteOnlyCell(ws, value=h)) for h in headers])


def set_common_layout(ws, rows: int, cols: int, widths: dict[int, int] | None = None) -> None:
    ws.freeze_panes = "A2"
    if rows >= 1 and cols >= 1:
        ws.auto_filter.ref = f"A1:{get_column_letter(cols)}{rows}"
    for idx in range(1, cols + 1):
        width = widths.get(idx, 16) if widths else 16
        ws.column_dimensions[get_column_letter(idx)].width = width


def iter_csv_rows(path: Path) -> tuple[list[str], Iterable[list[Any]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        headers = next(reader)
        rows = [[coerce_csv_value(value) for value in row] for row in reader]
    return headers, rows


def iter_xlsx_rows(path: Path, sheet_name: str) -> tuple[list[str], list[list[Any]]]:
    wb = load_workbook(path, read_only=True, data_only=True)
    try:
        ws = wb[sheet_name]
        values = [list(row) for row in ws.iter_rows(values_only=True)]
    finally:
        wb.close()
    while values and all(v is None for v in values[-1]):
        values.pop()
    if not values:
        return [], []
    headers = ["" if v is None else str(v) for v in values[0]]
    return headers, [[translate_note(value) for value in row] for row in values[1:]]


def run_count_from_path(path: Path) -> int:
    match = re.search(r"-(\d+)runs\.xlsx$", path.name)
    return int(match.group(1)) if match else -1


def resolve_source_path(root: Path, relative_path: str) -> Path:
    source_path = root / relative_path
    if source_path.exists():
        return source_path

    fallback_pattern = re.sub(r"-\d+runs\.xlsx$", "-*runs.xlsx", source_path.name)
    if fallback_pattern != source_path.name:
        candidates = sorted(
            root.glob(fallback_pattern),
            key=lambda path: (run_count_from_path(path), path.name),
        )
        if candidates:
            return candidates[-1]

    raise FileNotFoundError(source_path)


def add_rows_sheet(wb: Workbook, spec: dict[str, str], root: Path, field_usage: dict[str, set[str]]) -> dict[str, Any]:
    ws = wb.create_sheet(spec["sheet"])
    source_path = resolve_source_path(root, spec["path"])
    if spec["type"] == "csv":
        headers, rows = iter_csv_rows(source_path)
    else:
        headers, rows = iter_xlsx_rows(source_path, spec["source_sheet"])
    append_header(ws, [display_header(header) for header in headers])
    for header in headers:
        if header:
            field_usage[header].add(spec["sheet"])
    row_count = 0
    for row in rows:
        ws.append(row)
        row_count += 1
    set_common_layout(ws, row_count + 1, len(headers))
    return {
        "sheet_name": spec["sheet"],
        "source_file": source_path.name,
        "source_sheet": spec.get("source_sheet", ""),
        "table_role": spec["role"],
        "rows": row_count,
        "columns": len(headers),
        "notes": spec["note"],
    }


def flatten_json(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        rows: list[tuple[str, Any]] = []
        for key, item in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            rows.extend(flatten_json(item, new_prefix))
        return rows
    if isinstance(value, list):
        return [(prefix, ", ".join(str(v) for v in value))]
    return [(prefix, value)]


def add_manifest_sheet(wb: Workbook, root: Path, field_usage: dict[str, set[str]]) -> dict[str, Any]:
    ws = wb.create_sheet("Manifest_Run_Notes")
    headers = ["key", "value"]
    append_header(ws, headers)
    for h in headers:
        field_usage[h].add(ws.title)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    rows = flatten_json(manifest)
    for key, value in rows:
        ws.append([key, translate_note(value)])
    set_common_layout(ws, len(rows) + 1, 2, {1: 34, 2: 80})
    return {
        "sheet_name": ws.title,
        "source_file": "manifest.json",
        "source_sheet": "",
        "table_role": "formal run configuration and status",
        "rows": len(rows),
        "columns": 2,
        "notes": "Used to confirm run counts, parameter ranges, completion status, and data-source notes.",
    }


def add_index_sheet(wb: Workbook, rows: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Index", 0)
    title = WriteOnlyCell(ws, value="Issuer-Hiding Experiment Tables Consolidated Workbook")
    title.font = TITLE_FONT
    ws.append([title])
    ws.append(["generation note", "This workbook consolidates the formal 200-run measurements, formula-estimated comparison tables, and field dictionary; smoke_2runs is excluded from the formal summary."])
    ws.append([])
    headers = ["sheet_name", "source_file", "source_sheet", "table_role", "rows", "columns", "notes"]
    append_header(ws, [display_header(header) for header in headers])
    for row in rows:
        ws.append([row.get(h, "") for h in headers])
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 36
    ws.column_dimensions["C"].width = 24
    ws.column_dimensions["D"].width = 34
    ws.column_dimensions["E"].width = 12
    ws.column_dimensions["F"].width = 10
    ws.column_dimensions["G"].width = 70
    ws.freeze_panes = "A5"
    ws.auto_filter.ref = f"A4:G{len(rows) + 4}"


def add_field_dictionary(wb: Workbook, field_usage: dict[str, set[str]]) -> None:
    ws = wb.create_sheet("Field_Dict_field dictionary", 1)
    headers = ["field", "description", "unit or important note", "appearing sheets"]
    append_header(ws, headers)
    for field in sorted(field_usage):
        cn, note = FIELD_CN.get(field, ("to be completed", "The script has no built-in description for this field; review it against the paper before filling it in."))
        ws.append([field, cn, note, ", ".join(sorted(field_usage[field]))])
    set_common_layout(ws, len(field_usage) + 1, 4, {1: 42, 2: 30, 3: 70, 4: 70})


def build_workbook(root: Path, output: Path) -> None:
    wb = Workbook(write_only=True)
    field_usage: dict[str, set[str]] = defaultdict(set)
    index_rows: list[dict[str, Any]] = []
    index_rows.append(add_manifest_sheet(wb, root, field_usage))
    for spec in TABLE_SPECS:
        index_rows.append(add_rows_sheet(wb, spec, root, field_usage))
    add_index_sheet(wb, index_rows)
    add_field_dictionary(wb, field_usage)
    wb.save(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("results/issuer_hiding_20260610"),
        help="Directory containing issuer-hiding result tables.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output workbook path.",
    )
    args = parser.parse_args()
    results_dir = args.results_dir.resolve()
    output = args.output.resolve() if args.output else results_dir / "issuer_hiding_all_tables_20260610.xlsx"
    build_workbook(results_dir, output)
    print(output)


if __name__ == "__main__":
    main()
