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
    "sheet_name": ("工作表名称", ""),
    "source_file": ("来源文件", ""),
    "source_sheet": ("来源工作表", ""),
    "table_role": ("表格用途", ""),
    "rows": ("数据行数", ""),
    "columns": ("列数", ""),
    "notes": ("说明", ""),
    "key": ("键", ""),
    "value": ("值", ""),
    "experiment_id": ("实验编号", ""),
    "run_started_at": ("运行开始时间", ""),
    "source_type": ("数据来源类型", "measured 表示本地实测；formula_estimate 表示公式推算。"),
    "scheme": ("方案名称", ""),
    "k": ("属性数量", "本章实验中的属性数量。"),
    "q_internal": ("内部贡献数量", "系统内部参数，用户不可见，不应写成公开发行方数量。"),
    "issuer_set_size_public": ("公开发行方集合规模", "若本方案隐藏该信息，则记录为 N/A。"),
    "issuer_set_size_user_visible": ("用户是否可见发行方集合规模", ""),
    "num_other_issuers": ("其他签发方数量", "代码层参数，等于 q_internal - 2。"),
    "num_attrs": ("属性数量", ""),
    "num_issuers": ("签发方/贡献方数量", "代码层参数；论文表述需结合隐藏语义解释。"),
    "num_disclosed": ("披露属性数量", "当前原型没有选择性披露实现，实验中为 0。"),
    "phase": ("协议阶段", ""),
    "component": ("组件名称", ""),
    "runs": ("正式测量轮数", ""),
    "batches": ("批次数", ""),
    "trim_percent": ("截尾比例", "两端截尾统计所用百分比。"),
    "trim_removed_each_tail": ("单侧截尾样本数", ""),
    "mean_ms": ("平均时间", "单位：ms。"),
    "trimmed_mean_ms": ("截尾平均时间", "单位：ms。"),
    "median_ms": ("中位数时间", "单位：ms。"),
    "std_ms": ("标准差", "单位：ms。"),
    "p95_ms": ("95 分位时间", "单位：ms。"),
    "p99_ms": ("99 分位时间", "单位：ms。"),
    "min_ms": ("最小时间", "单位：ms。"),
    "max_ms": ("最大时间", "单位：ms。"),
    "credential_bytes": ("凭证字节数", "单位：bytes。"),
    "proof_bytes": ("证明字节数", "单位：bytes。"),
    "public_key_bytes": ("公钥字节数", "单位：bytes。"),
    "apk_user_visible_bytes": ("用户可见聚合认证公钥字节数", "单位：bytes。"),
    "internal_pk_directory_bytes": ("内部公钥目录字节数", "单位：bytes；用户不可见。"),
    "ta_credential_bytes": ("TA 担保字节数", "单位：bytes。"),
    "holder_binding_bytes": ("持有者绑定字节数", "单位：bytes。"),
    "signature_bytes": ("签名字节数", "单位：bytes。"),
    "transcript_bytes": ("展示转录字节数", "单位：bytes。"),
    "transcript_bytes_compact": ("紧凑展示转录字节数", "单位：bytes。"),
    "transcript_bytes_serialized": ("序列化展示转录字节数", "单位：bytes。"),
    "verifier_auth_proof_bytes": ("验证者认证证明字节数", "单位：bytes。"),
    "verifier_auth_message_bytes": ("验证者认证消息字节数", "单位：bytes。"),
    "presentation_transcript_real_bytes": ("真实展示转录字节数", "单位：bytes。"),
    "presentation_transcript_simulated_bytes": ("模拟展示转录字节数", "单位：bytes。"),
    "formula": ("推算公式", "对比方案使用的公式或公式来源说明。"),
    "assumption": ("推算假设", ""),
    "unit_cost_source": ("单位操作成本来源", ""),
    "operation": ("基础操作", ""),
    "samples": ("样本数", ""),
    "mean": ("平均值", ""),
    "median": ("中位数", ""),
    "stdev": ("标准差", ""),
    "mean_time_ms": ("平均时间", "单位：ms。"),
    "estimated_show_ms": ("展示生成推算时间", "单位：ms。"),
    "estimated_verify_ms": ("验证推算时间", "单位：ms。"),
    "estimated_issue_ms": ("签发推算时间", "单位：ms。"),
    "estimated_transcript_bytes": ("展示转录推算字节数", "单位：bytes。"),
    "estimated_public_material_bytes": ("公开材料推算字节数", "单位：bytes。"),
}

NOTE_TRANSLATIONS = {
    "issuer-hiding chapter k-axis; q_internal=10 remains hidden from users; d=0 because current prototype has no selective-disclosure implementation": "签发方隐藏实验的 k 轴数据；固定 q_internal=10，且 q_internal 对用户不可见；d=0 表示当前原型尚未实现选择性披露。",
    "issuer-hiding chapter internal-q axis; q_internal is a system-side hidden contribution count, not a user-visible policy-set size": "签发方隐藏实验的内部 q 轴数据；q_internal 是系统侧隐藏的贡献数量，不是用户可见的策略集合规模。",
    "issuer-hiding chapter max point; k=30 and q_internal=24, both measured in the local prototype": "签发方隐藏实验的最大参数点；k=30 且 q_internal=24，二者均由本地原型实测。",
    "Issuer-hiding-focused rerun. Baseline data are formula estimates using local unit-operation costs; external paper runtimes are not imported.": "面向签发方隐藏实验的重测结果；对比方案数据基于本地单位操作成本进行公式推算，未导入外部论文运行时间。",
    "Does not hide the candidate issuer set from the user; it hides which member issued the credential.": "该方案不向用户隐藏候选签发方集合；其隐藏的是集合中具体哪一个成员签发了凭证。",
    "Used as the PS-based issuer-hiding baseline rather than as a multi-issuer aggregate issuance scheme.": "该方案作为基于 PS 签名的签发方隐藏基线使用，而不是作为多签发方聚合签发方案使用。",
    "Timing is left formula-only because the paper reports low-level group-operation counts that are not directly equal to this repository's scalar-multiplication unit costs.": "该项时间仅保留公式描述，因为原论文给出的是底层群运算计数，不能直接等同于本仓库的标量乘单位成本。",
    "Cached show time excludes first-time integrity verification; add IntegrityVerification when modeling first contact with a verifier.": "缓存展示时间不包含首次完整性验证；若建模验证者首次交互，应额外加入 IntegrityVerification 成本。",
    "Included to show the cost of a non-compact issuer-hiding proof style.": "该项用于体现非紧凑型签发方隐藏证明风格的开销。",
    "Kept as a formula-only core functional baseline; do not fabricate concrete timings or bytes without full element counts.": "该项作为仅保留公式的核心功能基线；在缺少完整元素计数前，不虚构具体时间或字节数。",
    "Zp random scalar generation": "Zp 随机标量生成。",
    "Usually negligible; included for SPS-EQ set-commitment estimates": "通常可忽略；为 SPS-EQ 集合承诺推算保留。",
    "Usually negligible; included for polynomial and exponent aggregation estimates": "通常可忽略；为多项式和指数聚合推算保留。",
    "Scalar inverse in the group order field": "群阶域中的标量求逆。",
    "Random curve point in G1": "G1 上的随机曲线点。",
    "Random curve point in G2": "G2 上的随机曲线点。",
    "Used for BBS/BBS+/PS/SPS-EQ G1 exponentiation terms": "用于 BBS、BBS+、PS 和 SPS-EQ 中的 G1 指数运算项。",
    "Used for public-key and verifier-side exponentiation terms": "用于公钥相关和验证者侧的指数运算项。",
    "Used when a proof equation is represented as exponentiation in GT": "用于将证明等式表示为 GT 指数运算的情况。",
    "The library prints each pairing internally; output is suppressed in this benchmark": "该库会在内部输出每次配对信息；本基准测试中已抑制该输出。",
    "Useful for BBS/PS verification equations with two pairings": "用于包含两次配对的 BBS/PS 验证等式。",
    "Useful for SPS-EQ VerifyR-style pairing-product estimates": "用于 SPS-EQ VerifyR 风格的配对乘积推算。",
    "Useful for SPS-EQ show verification upper-bound estimates": "用于 SPS-EQ 展示验证上界推算。",
    "Hashes one G1, one G2, one GT, one scalar, and one label": "对一个 G1 元素、一个 G2 元素、一个 GT 元素、一个标量和一个标签进行哈希。",
    "Used when generators are derived on demand instead of precomputed": "用于生成元按需派生而非预计算的情况。",
    "Included for completeness; most formulas here do not require it directly": "为完整性保留；此处多数公式并不直接需要该项。",
    "One signer. Multiply by q when modeling q independent issuers.": "单个签名者成本；建模 q 个独立签发方时乘以 q。",
    "T_MP2 is preferred over 2*T_P because the library has a multi-pairing path.": "优先使用 T_MP2 而不是 2*T_P，因为该库提供多配对计算路径。",
    "h = n - d hidden attributes.": "h = n - d，表示隐藏属性数量。",
    "Includes disclosed-message reconstruction and final pairing product check.": "包含披露消息重构和最终配对乘积检查。",
    "Optimized signing estimate for BBS+ credential signature.": "BBS+ 凭证签名的优化签发推算。",
    "Use as a comparable BBS+-style verification model.": "作为可比较的 BBS+ 风格验证模型使用。",
    "Approximation; mark as model estimate in the paper.": "该项为近似值；论文中应标注为模型推算。",
    "Pointcheval-Sanders multi-message signature. Multiply by q for independent credentials.": "Pointcheval-Sanders 多消息签名；建模独立凭证时乘以 q。",
    "Uses the paper's 2 pairings plus n G2 exponentiations.": "使用原论文中的两次配对加 n 次 G2 指数运算。",
    "Proof-of-knowledge estimate for hidden messages.": "隐藏消息知识证明的推算值。",
    "Proof transcript verification estimate.": "证明转录验证的推算值。",
    "Scheme 2 issuing/credential estimate; set-commitment polynomial work is represented by O(n)*T_ZMUL.": "方案 2 的签发/凭证推算；集合承诺中的多项式工作量用 O(n)*T_ZMUL 表示。",
    "VerifyR has two pairing-product equations; T_MP6 is the practical aggregate unit.": "VerifyR 包含两个配对乘积等式；T_MP6 是实际聚合计算单位。",
    "Show protocol estimate; communication is constant-size in the number of attributes.": "展示协议推算；通信量相对于属性数量为常数规模。",
    "Verify side estimate for subset opening plus proof freshness.": "验证端对子集打开和证明新鲜性的推算。",
}


TABLE_SPECS = [
    {
        "sheet": "Ours_Raw_Runs",
        "type": "csv",
        "path": "ours_raw_runs.csv",
        "role": "本方案完整原始测量明细",
        "note": "每一轮、每个组件的原始时间与大小记录；论文正文通常引用汇总表而不是此表。",
    },
    {
        "sheet": "Ours_Summary_Long",
        "type": "csv",
        "path": "ours_summary_long.csv",
        "role": "本方案长表汇总",
        "note": "每个参数点、每个组件一行，便于筛选组件和绘图。",
    },
    {
        "sheet": "Ours_Summary_Wide",
        "type": "csv",
        "path": "ours_summary_wide.csv",
        "role": "本方案宽表汇总",
        "note": "每个参数点一行，适合生成论文图表。",
    },
    {
        "sheet": "Issuer_Baselines",
        "type": "csv",
        "path": "issuer_hiding_baselines.csv",
        "role": "issuer hiding 对比方案公式推算",
        "note": "不导入外部论文运行时间；基于文献公式和本地单位操作成本推算。",
    },
    {
        "sheet": "K_Axis",
        "type": "xlsx",
        "path": "issuer-hiding-k-axis-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "k-axis 单独结果",
        "note": "固定 q_internal=10，改变属性数量 k。",
    },
    {
        "sheet": "Q_Axis",
        "type": "xlsx",
        "path": "issuer-hiding-q-axis-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "q-axis 单独结果",
        "note": "固定 k=12，改变系统内部 q_internal；该参数用户不可见。",
    },
    {
        "sheet": "Max_K30_Q24",
        "type": "xlsx",
        "path": "issuer-hiding-max-k30-q24-200runs.xlsx",
        "source_sheet": "Performance",
        "role": "最大参数点单独结果",
        "note": "k=30, q_internal=24，用于组件成本分析。",
    },
    {
        "sheet": "Compare_OurMeasured",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "OurMeasured",
        "role": "整合工作簿中的本方案实测表",
        "note": "来自已有 comparison_ready 工作簿。",
    },
    {
        "sheet": "Compare_Baselines",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "IssuerHidingBaselines",
        "role": "整合工作簿中的对比方案推算表",
        "note": "来自已有 comparison_ready 工作簿。",
    },
    {
        "sheet": "Compare_UnitCosts",
        "type": "xlsx",
        "path": "issuer_hiding_comparison_ready.xlsx",
        "source_sheet": "UnitCosts",
        "role": "整合工作簿中的单位操作成本表",
        "note": "用于审计公式推算依据。",
    },
    {
        "sheet": "Unit_Costs",
        "type": "xlsx",
        "path": "unit_costs_30samples.xlsx",
        "source_sheet": "UnitCosts",
        "role": "本地单位操作成本",
        "note": "30 samples，用于对比方案公式推算。",
    },
    {
        "sheet": "Operation_Formulas",
        "type": "xlsx",
        "path": "unit_costs_30samples.xlsx",
        "source_sheet": "OperationFormulas",
        "role": "单位操作公式说明",
        "note": "记录基础操作成本的说明。",
    },
]


def translate_note(value: Any) -> Any:
    if isinstance(value, str):
        return NOTE_TRANSLATIONS.get(value, value)
    return value


def display_header(header: str) -> str:
    if header in {"notes", "notes/备注"}:
        return "说明"
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
    ws = wb.create_sheet("Manifest_运行说明")
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
        "table_role": "正式运行配置与状态",
        "rows": len(rows),
        "columns": 2,
        "notes": "用于确认运行轮数、参数范围、完成状态和数据来源说明。",
    }


def add_index_sheet(wb: Workbook, rows: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Index_索引", 0)
    title = WriteOnlyCell(ws, value="Issuer-Hiding Experiment Tables Consolidated Workbook")
    title.font = TITLE_FONT
    ws.append([title])
    ws.append(["生成说明", "该工作簿汇总正式 200 轮测算结果、公式推算对比表和字段说明；smoke_2runs 不纳入正式汇总。"])
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
    ws = wb.create_sheet("Field_Dict_字段说明", 1)
    headers = ["field", "中文解释", "单位或重要说明", "出现的工作表"]
    append_header(ws, headers)
    for field in sorted(field_usage):
        cn, note = FIELD_CN.get(field, ("待补充", "脚本未内置该字段解释；请按论文口径审查后补充。"))
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
