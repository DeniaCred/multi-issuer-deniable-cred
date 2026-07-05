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
    ("scheme", "scheme"),
    ("num_attrs", "attribute count"),
    ("num_issuers", "issuer count"),
    ("num_other_issuers", "other issuer count"),
    ("num_disclosed", "disclosed attribute count"),
    ("issuer_model", "issuer model"),
    ("signature_size_bytes", "signature size bytes"),
    ("issue_total_time_ms", "multi-issuer issue time milliseconds"),
    ("raw_signature_verify_time_ms", "raw signature verification milliseconds"),
    ("proof_size_bytes", "proof size bytes"),
    ("proof_generation_time_ms", "proof generation milliseconds"),
    ("proof_verification_time_ms", "proof verification milliseconds"),
    ("signature_size_formula", "signature size formula"),
    ("issue_time_formula", "issue time formula"),
    ("raw_verify_time_formula", "raw signature verification time formula"),
    ("proof_size_formula", "proof size formula"),
    ("proof_generation_time_formula", "proof generation time formula"),
    ("proof_verification_time_formula", "proof verification time formula"),
    ("notes", "notes"),
]

UNIT_COSTS_USED_COLUMNS = [
    ("unit_id", "unit id"),
    ("unit_name", "unit name"),
    ("mean_ms", "mean milliseconds"),
]

UNIT_COST_LABELS = {
    "T_E1": "G1 scalar multiplication",
    "T_E2": "G2 scalar multiplication",
    "T_ET": "GT exponentiation",
    "T_P": "single pairing",
    "T_MP2": "2-term multi-pairing",
    "T_MP6": "6-term multi-pairing",
    "T_MP8": "8-term multi-pairing",
    "T_H": "Fiat-Shamir hash to scalar",
    "T_H2G1": "hash-to-G1 mapping",
    "T_H2G2": "hash-to-G2 mapping",
    "T_INVZ": "scalar inversion",
    "T_RZ": "random scalar generation",
    "T_R1": "random G1 element generation",
    "T_R2": "random G2 element generation",
    "T_ZADD": "scalar modular addition",
    "T_ZMUL": "scalar modular multiplication",
}

FORMULA_HEADERS_CN = ["scheme", "metric", "Operation-count formulas", "required unit costs", "size formula", "notes"]
FORMULA_ROWS_CN = [
    ["BBS", "issuance time", "(n+2)*T_E1 + T_INVZ + T_H", "T_E1,T_INVZ,T_H", "G1 + Zp", "Single-issuer cost; multiply by q for independent multi-issuer issuance."],
    ["BBS", "raw signature verification time", "(n+2)*T_E1 + T_MP2 + T_H", "T_E1,T_MP2,T_H", "", "Use T_MP2 for a two-term multi-pairing because it better matches the current library path than 2*T_P."],
    ["BBS", "proof size", "", "", "3*G1 + (h+4)*Zp", "Proof size is estimated from the CFRG draft as three G1 elements, four fixed scalars, and h hidden-attribute response scalars."],
    ["BBS", "proof generation time", "(n+h+8)*T_E1 + T_INVZ + (h+5)*T_RZ + T_H", "T_E1,T_INVZ,T_RZ,T_H", "", "h=n-d denotes the number of hidden attributes."],
    ["BBS", "proof verification time", "(n+6)*T_E1 + T_MP2 + T_H", "T_E1,T_MP2,T_H", "", "Includes disclosed-message reconstruction and the final pairing-product check."],
    ["BBS+", "issuance time", "T_E1 + 2*T_RZ", "T_E1,T_RZ", "G1 + 2*Zp", "Optimized estimate for BBS+ credential signing."],
    ["BBS+", "raw signature verification time", "(n+1)*T_E1 + T_E2 + T_MP2", "T_E1,T_E2,T_MP2", "", "Used as a comparable BBS+-style signature verification model."],
    ["BBS+", "proof size", "", "", "3*G1 + (h+5)*Zp", "Proof size is approximated as one scalar response larger than the BBS estimate."],
    ["BBS+", "proof generation time", "single BBS proof generation time + T_E1 + T_RZ", "T_E1,T_INVZ,T_RZ,T_H", "", "Approximate model; mark it as a theoretical estimate in the paper."],
    ["BBS+", "proof verification time", "single BBS proof verification time + T_E1", "T_E1,T_MP2,T_H", "", "Approximate model; mark it as a theoretical estimate in the paper."],
    ["PS", "issuance time", "T_R1 + T_E1", "T_R1,T_E1", "2*G1", "Pointcheval-Sanders multi-message signature at single-issuer granularity; multiply by q for independent credentials."],
    ["PS", "raw signature verification time", "T_MP2 + n*T_E2", "T_MP2,T_E2", "", "Corresponds to two pairings and n G2 exponentiations in the source paper."],
    ["PS", "proof size", "", "", "2*G1 + GT + (h+2)*Zp", "Proof-of-knowledge estimate for hidden messages."],
    ["PS", "proof generation time", "3*T_E1 + (h+2)*T_P + (h+1)*T_ET + T_H", "T_E1,T_P,T_ET,T_H", "", "Estimated from proof equations involving hidden attributes."],
    ["PS", "proof verification time", "(h+2)*T_P + (h+2)*T_ET + T_H", "T_P,T_ET,T_H", "", "Estimated as the cost of verifying the proof transcript."],
    ["SPS-EQ", "issuance time", "4*T_E1 + T_E2 + T_INVZ + T_RZ + n*T_ZMUL", "T_E1,T_E2,T_INVZ,T_RZ,T_ZMUL", "credential: 3*G1 + G2 + 2*Zp", "Scheme 2 issuance/credential estimate; polynomial work in the set commitment is represented by n*T_ZMUL."],
    ["SPS-EQ", "raw signature verification time", "T_MP6", "T_MP6", "", "VerifyR contains pairing-product equations, modeled here with a 6-term multi-pairing unit."],
    ["SPS-EQ", "proof size", "", "", "show-token approximation: 8*G1 + G2 + 2*Zp", "Scheme 2 has constant-size presentation communication per organization."],
    ["SPS-EQ", "proof generation time", "T_MP6 + 8*T_E1 + T_E2 + h*T_ZMUL + T_H", "T_MP6,T_E1,T_E2,T_ZMUL,T_H", "", "Presentation protocol estimate; communication does not grow linearly with the total number of attributes."],
    ["SPS-EQ", "proof verification time", "T_MP8 + 4*T_E1 + T_E2 + d*T_ZMUL + T_H", "T_MP8,T_E1,T_E2,T_ZMUL,T_H", "", "Includes subset-opening verification and proof-freshness verification estimates."],
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
            "issuer_model": "q independent issuers",
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
            "notes": "BBS proof size is estimated from the CFRG draft fixed terms and hidden-attribute response scalars.",
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
            "issuer_model": "q independent issuers",
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
            "proof_generation_time_formula": "q*(single BBS proof generation time + T_E1 + T_RZ)",
            "proof_verification_time_formula": "q*(single BBS proof verification time + T_E1)",
            "notes": "BBS+ proof equations use an approximate model; mark this as a theoretical estimate in the paper.",
        }

    if scheme == "PS":
        single_issue = c["T_R1"] + c["T_E1"]
        single_raw_verify = c["T_MP2"] + n * c["T_E2"]
        single_proof_gen = 3 * c["T_E1"] + (h + 2) * c["T_P"] + (h + 1) * c["T_ET"] + c["T_H"]
        single_proof_verify = (h + 2) * c["T_P"] + (h + 2) * c["T_ET"] + c["T_H"]
        return {
            "scheme": scheme,
            "issuer_model": "q independent issuers",
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
            "notes": "PS is estimated under the independent-credential model; add a separate row if sequential PS aggregation is modeled.",
        }

    if scheme == "SPS-EQ":
        single_issue = 4 * c["T_E1"] + c["T_E2"] + c["T_INVZ"] + c["T_RZ"] + n * c["T_ZMUL"]
        single_raw_verify = c["T_MP6"]
        single_proof_gen = c["T_MP6"] + 8 * c["T_E1"] + c["T_E2"] + h * c["T_ZMUL"] + c["T_H"]
        single_proof_verify = c["T_MP8"] + 4 * c["T_E1"] + c["T_E2"] + d * c["T_ZMUL"] + c["T_H"]
        return {
            "scheme": scheme,
            "issuer_model": "q independent issuers; cross-issuer aggregation is not modeled",
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
            "notes": "SPS-EQ uses the Scheme 2 anonymous-credential model; per-organization cost is constant-size and is multiplied by q for multi-issuer comparison.",
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
            ("Theoretical comparison", column_labels(COMPARISON_COLUMNS), rows_for_columns(comparison_rows, COMPARISON_COLUMNS)),
            ("Unit costs used", column_labels(UNIT_COSTS_USED_COLUMNS), rows_for_columns(unit_rows, UNIT_COSTS_USED_COLUMNS)),
            ("Operation-count formulas", FORMULA_HEADERS_CN, FORMULA_ROWS_CN),
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
