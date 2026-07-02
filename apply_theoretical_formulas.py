import argparse
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import run_unit_benchmark as unit_bench


DEFAULT_UNIT_COSTS_XLSX = "results/unit_costs_wsl.xlsx"
DEFAULT_PERFORMANCE_XLSX = "results/performance_data.xlsx"
DEFAULT_OUTPUT_XLSX = "results/theoretical_comparison_wsl.xlsx"

GROUP_BYTES = {
    "Zp": 32,
    "G1": 64,
    "G2": 128,
    "GT": 384,
}

COMPARISON_COLUMNS = [
    ("scheme", "方案"),
    ("num_attrs", "属性数量"),
    ("num_issuers", "签发方总数"),
    ("num_other_issuers", "其他签发方数量"),
    ("num_disclosed", "披露属性数量"),
    ("issuer_model", "签发方模型"),
    ("signature_size_bytes", "签名大小字节"),
    ("issue_total_time_ms", "签名时间_多签发方总耗时毫秒"),
    ("raw_signature_verify_time_ms", "原始签名验证时间毫秒"),
    ("proof_size_bytes", "证明大小字节"),
    ("proof_generation_time_ms", "证明生成时间毫秒"),
    ("proof_verification_time_ms", "证明验证时间毫秒"),
    ("signature_size_formula", "签名大小公式"),
    ("issue_time_formula", "签名时间公式"),
    ("raw_verify_time_formula", "原始签名验证时间公式"),
    ("proof_size_formula", "证明大小公式"),
    ("proof_generation_time_formula", "证明生成时间公式"),
    ("proof_verification_time_formula", "证明验证时间公式"),
    ("notes", "说明"),
]

UNIT_COSTS_USED_COLUMNS = [
    ("unit_id", "单位编号"),
    ("unit_name", "单位名称"),
    ("mean_ms", "平均耗时毫秒"),
]

UNIT_COST_LABELS = {
    "T_E1": "G1标量乘",
    "T_E2": "G2标量乘",
    "T_ET": "GT幂运算",
    "T_P": "单次配对",
    "T_MP2": "2项多重配对",
    "T_MP6": "6项多重配对",
    "T_MP8": "8项多重配对",
    "T_H": "Fiat-Shamir哈希到标量",
    "T_H2G1": "哈希映射到G1",
    "T_H2G2": "哈希映射到G2",
    "T_INVZ": "标量求逆",
    "T_RZ": "随机标量生成",
    "T_R1": "随机G1元素生成",
    "T_R2": "随机G2元素生成",
    "T_ZADD": "标量模加",
    "T_ZMUL": "标量模乘",
}

FORMULA_HEADERS_CN = ["方案", "指标", "操作数公式", "需要的单位耗时", "大小公式", "说明"]
FORMULA_ROWS_CN = [
    ["BBS", "签名时间", "(n+2)*T_E1 + T_INVZ + T_H", "T_E1,T_INVZ,T_H", "G1 + Zp", "单个签发方口径；多签发方独立签发时整体乘以q。"],
    ["BBS", "原始签名验证时间", "(n+2)*T_E1 + T_MP2 + T_H", "T_E1,T_MP2,T_H", "", "使用T_MP2表示2项多重配对，比直接使用2*T_P更贴近当前库实现。"],
    ["BBS", "证明大小", "", "", "3*G1 + (h+4)*Zp", "证明大小按CFRG草案中的3个G1元素、4个固定标量和h个隐藏属性响应标量估算。"],
    ["BBS", "证明生成时间", "(n+h+8)*T_E1 + T_INVZ + (h+5)*T_RZ + T_H", "T_E1,T_INVZ,T_RZ,T_H", "", "h=n-d，表示隐藏属性数量。"],
    ["BBS", "证明验证时间", "(n+6)*T_E1 + T_MP2 + T_H", "T_E1,T_MP2,T_H", "", "包含披露消息重构和最后的配对乘积检查。"],
    ["BBS+", "签名时间", "T_E1 + 2*T_RZ", "T_E1,T_RZ", "G1 + 2*Zp", "BBS+凭证签名的优化估算口径。"],
    ["BBS+", "原始签名验证时间", "(n+1)*T_E1 + T_E2 + T_MP2", "T_E1,T_E2,T_MP2", "", "作为可比较的BBS+风格验签模型。"],
    ["BBS+", "证明大小", "", "", "3*G1 + (h+5)*Zp", "证明大小按比BBS多一个标量响应的近似口径估算。"],
    ["BBS+", "证明生成时间", "BBS单次证明生成时间 + T_E1 + T_RZ", "T_E1,T_INVZ,T_RZ,T_H", "", "近似模型，论文中应标注为理论估算。"],
    ["BBS+", "证明验证时间", "BBS单次证明验证时间 + T_E1", "T_E1,T_MP2,T_H", "", "近似模型，论文中应标注为理论估算。"],
    ["PS", "签名时间", "T_R1 + T_E1", "T_R1,T_E1", "2*G1", "Pointcheval-Sanders多消息签名单个签发方口径；独立多凭证时乘以q。"],
    ["PS", "原始签名验证时间", "T_MP2 + n*T_E2", "T_MP2,T_E2", "", "对应论文中的2次配对和n次G2指数运算。"],
    ["PS", "证明大小", "", "", "2*G1 + GT + (h+2)*Zp", "对隐藏消息的知识证明估算口径。"],
    ["PS", "证明生成时间", "3*T_E1 + (h+2)*T_P + (h+1)*T_ET + T_H", "T_E1,T_P,T_ET,T_H", "", "按隐藏属性相关证明等式估算。"],
    ["PS", "证明验证时间", "(h+2)*T_P + (h+2)*T_ET + T_H", "T_P,T_ET,T_H", "", "按证明转录验证成本估算。"],
    ["SPS-EQ", "签名时间", "4*T_E1 + T_E2 + T_INVZ + T_RZ + n*T_ZMUL", "T_E1,T_E2,T_INVZ,T_RZ,T_ZMUL", "凭证：3*G1 + G2 + 2*Zp", "Scheme 2签发/凭证估算；集合承诺中的多项式工作用n*T_ZMUL表示。"],
    ["SPS-EQ", "原始签名验证时间", "T_MP6", "T_MP6", "", "VerifyR包含配对乘积等式，这里用6项多重配对作为实践单位。"],
    ["SPS-EQ", "证明大小", "", "", "展示令牌近似：8*G1 + G2 + 2*Zp", "Scheme 2每个组织的展示通信量为常数级。"],
    ["SPS-EQ", "证明生成时间", "T_MP6 + 8*T_E1 + T_E2 + h*T_ZMUL + T_H", "T_MP6,T_E1,T_E2,T_ZMUL,T_H", "", "展示协议估算；通信量不随属性总数线性增长。"],
    ["SPS-EQ", "证明验证时间", "T_MP8 + 4*T_E1 + T_E2 + d*T_ZMUL + T_H", "T_MP8,T_E1,T_E2,T_ZMUL,T_H", "", "包含子集打开验证和新鲜性证明验证的估算。"],
]


def cell_column_index(cell_reference):
    letters = re.match(r"[A-Z]+", cell_reference).group(0)
    index = 0
    for char in letters:
        index = index * 26 + ord(char) - ord("A") + 1
    return index - 1


def read_xlsx_sheet(path, sheet_index=1):
    path = Path(path)
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as workbook_zip:
        shared_strings = []
        if "xl/sharedStrings.xml" in workbook_zip.namelist():
            shared_root = ET.fromstring(workbook_zip.read("xl/sharedStrings.xml"))
            for item in shared_root.findall("m:si", ns):
                shared_strings.append("".join(text.text or "" for text in item.findall(".//m:t", ns)))

        sheet_xml = workbook_zip.read(f"xl/worksheets/sheet{sheet_index}.xml")
        root = ET.fromstring(sheet_xml)

    rows = []
    for row in root.findall(".//m:sheetData/m:row", ns):
        values = []
        for cell in row.findall("m:c", ns):
            col_index = cell_column_index(cell.attrib["r"])
            while len(values) <= col_index:
                values.append("")

            cell_type = cell.attrib.get("t")
            if cell_type == "inlineStr":
                value = "".join(text.text or "" for text in cell.findall(".//m:t", ns))
            else:
                raw_value = cell.find("m:v", ns)
                value = raw_value.text if raw_value is not None else ""
                if cell_type == "s" and value != "":
                    value = shared_strings[int(value)]
            values[col_index] = value
        rows.append(values)
    return rows


def normalize_header(header):
    return str(header).split("/", 1)[0]


def normalize_unit_id(value):
    text = str(value).strip()
    match = re.match(r"(T_[A-Z0-9]+)", text)
    return match.group(1) if match else text


def numeric(value):
    if value == "" or value is None:
        return 0
    number = float(value)
    return int(number) if number.is_integer() else number


def read_unit_costs(path):
    rows = read_xlsx_sheet(path, sheet_index=1)
    if not rows:
        raise ValueError(f"No rows found in {path}")

    headers = [normalize_header(header) for header in rows[0]]
    unit_id_idx = headers.index("unit_id")
    mean_idx = headers.index("mean_ms")
    costs = {}
    for row in rows[1:]:
        if len(row) <= max(unit_id_idx, mean_idx) or not row[unit_id_idx]:
            continue
        costs[normalize_unit_id(row[unit_id_idx])] = float(row[mean_idx])
    return costs


def read_experiment_dimensions(path):
    rows = read_xlsx_sheet(path, sheet_index=1)
    if not rows:
        raise ValueError(f"No rows found in {path}")

    headers = [normalize_header(header) for header in rows[0]]
    required = ["num_attrs", "num_issuers", "num_other_issuers", "num_disclosed"]
    indexes = {field: headers.index(field) for field in required}
    seen = set()
    dimensions = []
    for row in rows[1:]:
        if not row:
            continue
        dimension = {
            field: int(numeric(row[indexes[field]]))
            for field in required
        }
        key = tuple(dimension[field] for field in required)
        if key in seen:
            continue
        seen.add(key)
        dimensions.append(dimension)
    return sorted(dimensions, key=lambda item: (item["num_issuers"], item["num_attrs"], item["num_disclosed"]))


def require_costs(unit_costs, names):
    missing = [name for name in names if name not in unit_costs]
    if missing:
        raise KeyError(f"Missing unit costs: {', '.join(missing)}")
    return {name: unit_costs[name] for name in names}


def round_ms(value):
    return round(float(value), 6)


def estimate_scheme_metrics(scheme, n, q, d, unit_costs):
    h = max(n - d, 0)
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    gt = GROUP_BYTES["GT"]
    zp = GROUP_BYTES["Zp"]
    c = require_costs(
        unit_costs,
        ["T_E1", "T_E2", "T_ET", "T_P", "T_MP2", "T_MP6", "T_MP8", "T_H", "T_RZ", "T_R1", "T_INVZ", "T_ZMUL"],
    )

    if scheme == "BBS":
        single_issue = (n + 2) * c["T_E1"] + c["T_INVZ"] + c["T_H"]
        single_raw_verify = (n + 2) * c["T_E1"] + c["T_MP2"] + c["T_H"]
        single_proof_gen = (n + h + 8) * c["T_E1"] + c["T_INVZ"] + (h + 5) * c["T_RZ"] + c["T_H"]
        single_proof_verify = (n + 6) * c["T_E1"] + c["T_MP2"] + c["T_H"]
        return {
            "scheme": scheme,
            "issuer_model": "q个独立签发方",
            "signature_size_bytes": q * (g1 + zp),
            "issue_total_time_ms": round_ms(q * single_issue),
            "raw_signature_verify_time_ms": round_ms(q * single_raw_verify),
            "proof_size_bytes": q * (3 * g1 + (h + 4) * zp),
            "proof_generation_time_ms": round_ms(q * single_proof_gen),
            "proof_verification_time_ms": round_ms(q * single_proof_verify),
            "signature_size_formula": "q*(G1+Zp)",
            "issue_time_formula": "q*((n+2)*T_E1 + T_INVZ + T_H)",
            "raw_verify_time_formula": "q*((n+2)*T_E1 + T_MP2 + T_H)",
            "proof_size_formula": "q*(3*G1 + (h+4)*Zp)",
            "proof_generation_time_formula": "q*((n+h+8)*T_E1 + T_INVZ + (h+5)*T_RZ + T_H)",
            "proof_verification_time_formula": "q*((n+6)*T_E1 + T_MP2 + T_H)",
            "notes": "BBS证明大小按CFRG草案的固定项和隐藏属性响应标量估算。",
        }

    if scheme == "BBS+":
        bbs_single_proof_gen = (n + h + 8) * c["T_E1"] + c["T_INVZ"] + (h + 5) * c["T_RZ"] + c["T_H"]
        bbs_single_proof_verify = (n + 6) * c["T_E1"] + c["T_MP2"] + c["T_H"]
        single_issue = c["T_E1"] + 2 * c["T_RZ"]
        single_raw_verify = (n + 1) * c["T_E1"] + c["T_E2"] + c["T_MP2"]
        single_proof_gen = bbs_single_proof_gen + c["T_E1"] + c["T_RZ"]
        single_proof_verify = bbs_single_proof_verify + c["T_E1"]
        return {
            "scheme": scheme,
            "issuer_model": "q个独立签发方",
            "signature_size_bytes": q * (g1 + 2 * zp),
            "issue_total_time_ms": round_ms(q * single_issue),
            "raw_signature_verify_time_ms": round_ms(q * single_raw_verify),
            "proof_size_bytes": q * (3 * g1 + (h + 5) * zp),
            "proof_generation_time_ms": round_ms(q * single_proof_gen),
            "proof_verification_time_ms": round_ms(q * single_proof_verify),
            "signature_size_formula": "q*(G1+2*Zp)",
            "issue_time_formula": "q*(T_E1 + 2*T_RZ)",
            "raw_verify_time_formula": "q*((n+1)*T_E1 + T_E2 + T_MP2)",
            "proof_size_formula": "q*(3*G1 + (h+5)*Zp)",
            "proof_generation_time_formula": "q*(BBS单次证明生成时间 + T_E1 + T_RZ)",
            "proof_verification_time_formula": "q*(BBS单次证明验证时间 + T_E1)",
            "notes": "BBS+证明等式使用近似模型，论文中应标注为理论估算。",
        }

    if scheme == "PS":
        single_issue = c["T_R1"] + c["T_E1"]
        single_raw_verify = c["T_MP2"] + n * c["T_E2"]
        single_proof_gen = 3 * c["T_E1"] + (h + 2) * c["T_P"] + (h + 1) * c["T_ET"] + c["T_H"]
        single_proof_verify = (h + 2) * c["T_P"] + (h + 2) * c["T_ET"] + c["T_H"]
        return {
            "scheme": scheme,
            "issuer_model": "q个独立签发方",
            "signature_size_bytes": q * (2 * g1),
            "issue_total_time_ms": round_ms(q * single_issue),
            "raw_signature_verify_time_ms": round_ms(q * single_raw_verify),
            "proof_size_bytes": q * (2 * g1 + gt + (h + 2) * zp),
            "proof_generation_time_ms": round_ms(q * single_proof_gen),
            "proof_verification_time_ms": round_ms(q * single_proof_verify),
            "signature_size_formula": "q*(2*G1)",
            "issue_time_formula": "q*(T_R1 + T_E1)",
            "raw_verify_time_formula": "q*(T_MP2 + n*T_E2)",
            "proof_size_formula": "q*(2*G1 + GT + (h+2)*Zp)",
            "proof_generation_time_formula": "q*(3*T_E1 + (h+2)*T_P + (h+1)*T_ET + T_H)",
            "proof_verification_time_formula": "q*((h+2)*T_P + (h+2)*T_ET + T_H)",
            "notes": "PS按独立凭证模型估算；如需顺序聚合PS，可另加一行单独建模。",
        }

    if scheme == "SPS-EQ":
        single_issue = 4 * c["T_E1"] + c["T_E2"] + c["T_INVZ"] + c["T_RZ"] + n * c["T_ZMUL"]
        single_raw_verify = c["T_MP6"]
        single_proof_gen = c["T_MP6"] + 8 * c["T_E1"] + c["T_E2"] + h * c["T_ZMUL"] + c["T_H"]
        single_proof_verify = c["T_MP8"] + 4 * c["T_E1"] + c["T_E2"] + d * c["T_ZMUL"] + c["T_H"]
        return {
            "scheme": scheme,
            "issuer_model": "q个独立签发方；未建模跨签发方聚合",
            "signature_size_bytes": q * (3 * g1 + g2 + 2 * zp),
            "issue_total_time_ms": round_ms(q * single_issue),
            "raw_signature_verify_time_ms": round_ms(q * single_raw_verify),
            "proof_size_bytes": q * (8 * g1 + g2 + 2 * zp),
            "proof_generation_time_ms": round_ms(q * single_proof_gen),
            "proof_verification_time_ms": round_ms(q * single_proof_verify),
            "signature_size_formula": "q*(3*G1 + G2 + 2*Zp)",
            "issue_time_formula": "q*(4*T_E1 + T_E2 + T_INVZ + T_RZ + n*T_ZMUL)",
            "raw_verify_time_formula": "q*T_MP6",
            "proof_size_formula": "q*(8*G1 + G2 + 2*Zp)",
            "proof_generation_time_formula": "q*(T_MP6 + 8*T_E1 + T_E2 + h*T_ZMUL + T_H)",
            "proof_verification_time_formula": "q*(T_MP8 + 4*T_E1 + T_E2 + d*T_ZMUL + T_H)",
            "notes": "SPS-EQ采用Scheme 2匿名凭证模型；单组织为常数大小，多签发方比较时按q个组织相乘。",
        }

    raise ValueError(f"Unknown scheme: {scheme}")


def build_theoretical_rows(dimensions, unit_costs, schemes=None):
    schemes = schemes or ["BBS", "BBS+", "PS", "SPS-EQ"]
    rows = []
    for dimension in dimensions:
        n = dimension["num_attrs"]
        q = dimension["num_issuers"]
        d = dimension["num_disclosed"]
        for scheme in schemes:
            row = estimate_scheme_metrics(scheme, n=n, q=q, d=d, unit_costs=unit_costs)
            row.update(dimension)
            rows.append(row)
    return rows


def rows_for_columns(rows, columns):
    return [[row.get(key, "") for key, _label in columns] for row in rows]


def column_labels(columns):
    return [label for _key, label in columns]


def write_theoretical_workbook(output_path, comparison_rows, unit_costs):
    unit_rows = [
        {"unit_id": key, "unit_name": UNIT_COST_LABELS.get(key, key), "mean_ms": unit_costs[key]}
        for key in sorted(unit_costs)
    ]
    unit_bench.write_xlsx(
        output_path,
        [
            ("理论对比", column_labels(COMPARISON_COLUMNS), rows_for_columns(comparison_rows, COMPARISON_COLUMNS)),
            ("使用的单位耗时", column_labels(UNIT_COSTS_USED_COLUMNS), rows_for_columns(unit_rows, UNIT_COSTS_USED_COLUMNS)),
            ("操作数公式", FORMULA_HEADERS_CN, FORMULA_ROWS_CN),
        ],
    )


def build_parser():
    parser = argparse.ArgumentParser(description="Apply unit-operation costs to BBS/BBS+/PS/SPS-EQ theoretical formulas.")
    parser.add_argument("--unit-costs-xlsx", default=DEFAULT_UNIT_COSTS_XLSX)
    parser.add_argument("--performance-xlsx", default=DEFAULT_PERFORMANCE_XLSX)
    parser.add_argument("--output-xlsx", default=DEFAULT_OUTPUT_XLSX)
    parser.add_argument("--schemes", default="BBS,BBS+,PS,SPS-EQ")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    schemes = [part.strip() for part in args.schemes.split(",") if part.strip()]
    unit_costs = read_unit_costs(args.unit_costs_xlsx)
    dimensions = read_experiment_dimensions(args.performance_xlsx)
    comparison_rows = build_theoretical_rows(dimensions, unit_costs, schemes=schemes)
    write_theoretical_workbook(args.output_xlsx, comparison_rows, unit_costs)

    print(f"wrote {args.output_xlsx}")
    print(f"dimensions={len(dimensions)} schemes={','.join(schemes)} rows={len(comparison_rows)}")
    for row in comparison_rows[: min(8, len(comparison_rows))]:
        print(
            f"{row['scheme']} n={row['num_attrs']} q={row['num_issuers']} d={row['num_disclosed']} "
            f"sig={row['signature_size_bytes']}B issue={row['issue_total_time_ms']:.6f}ms "
            f"verify={row['raw_signature_verify_time_ms']:.6f}ms proof={row['proof_size_bytes']}B "
            f"prove={row['proof_generation_time_ms']:.6f}ms proof_verify={row['proof_verification_time_ms']:.6f}ms"
        )


if __name__ == "__main__":
    main()
