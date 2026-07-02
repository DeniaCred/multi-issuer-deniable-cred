import argparse
import csv
import os
import statistics
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape


DEFAULT_EXECUTABLE = ".wsl-build/unit_operation_benchmark"
DEFAULT_OUTPUT_XLSX = "results/unit_costs_wsl.xlsx"

UNIT_HEADERS = [
    "unit_id",
    "unit_name",
    "operation",
    "samples",
    "iterations_per_sample",
    "mean_ms",
    "median_ms",
    "std_ms",
    "min_ms",
    "max_ms",
    "notes",
]

FORMULA_HEADERS = [
    "scheme",
    "metric",
    "operation_formula",
    "required_unit_costs",
    "size_formula",
    "notes",
]

FORMULA_ROWS = [
    [
        "BBS",
        "signature_time",
        "(n+2)*T_E1 + T_INVZ + T_H",
        "T_E1,T_INVZ,T_H",
        "G1 + Zp",
        "One signer. Multiply by q when modeling q independent issuers.",
    ],
    [
        "BBS",
        "raw_signature_verify_time",
        "(n+2)*T_E1 + T_MP2 + T_H",
        "T_E1,T_MP2,T_H",
        "",
        "T_MP2 is preferred over 2*T_P because the library has a multi-pairing path.",
    ],
    [
        "BBS",
        "proof_generation_time",
        "(n+h+8)*T_E1 + T_INVZ + (h+5)*T_RZ + T_H",
        "T_E1,T_INVZ,T_RZ,T_H",
        "3*G1 + (h+4)*Zp",
        "h = n - d hidden attributes.",
    ],
    [
        "BBS",
        "proof_verification_time",
        "(n+6)*T_E1 + T_MP2 + T_H",
        "T_E1,T_MP2,T_H",
        "",
        "Includes disclosed-message reconstruction and final pairing product check.",
    ],
    [
        "BBS+",
        "signature_time",
        "T_E1 + 2*T_RZ",
        "T_E1,T_RZ",
        "G1 + 2*Zp",
        "Optimized signing estimate for BBS+ credential signature.",
    ],
    [
        "BBS+",
        "raw_signature_verify_time",
        "(n+1)*T_E1 + T_E2 + T_MP2",
        "T_E1,T_E2,T_MP2",
        "",
        "Use as a comparable BBS+-style verification model.",
    ],
    [
        "BBS+",
        "proof_generation_time",
        "BBS_proof_generation_time + T_E1 + T_RZ",
        "T_E1,T_INVZ,T_RZ,T_H",
        "3*G1 + (h+5)*Zp",
        "Approximation; mark as model estimate in the paper.",
    ],
    [
        "BBS+",
        "proof_verification_time",
        "BBS_proof_verification_time + T_E1",
        "T_E1,T_MP2,T_H",
        "",
        "Approximation; mark as model estimate in the paper.",
    ],
    [
        "PS",
        "signature_time",
        "T_R1 + T_E1",
        "T_R1,T_E1",
        "2*G1",
        "Pointcheval-Sanders multi-message signature. Multiply by q for independent credentials.",
    ],
    [
        "PS",
        "raw_signature_verify_time",
        "T_MP2 + n*T_E2",
        "T_MP2,T_E2",
        "",
        "Uses the paper's 2 pairings plus n G2 exponentiations.",
    ],
    [
        "PS",
        "proof_generation_time",
        "3*T_E1 + (h+2)*T_P + (h+1)*T_ET + T_H",
        "T_E1,T_P,T_ET,T_H",
        "2*G1 + GT + (h+2)*Zp",
        "Proof-of-knowledge estimate for hidden messages.",
    ],
    [
        "PS",
        "proof_verification_time",
        "(h+2)*T_P + (h+2)*T_ET + T_H",
        "T_P,T_ET,T_H",
        "",
        "Proof transcript verification estimate.",
    ],
    [
        "SPS-EQ",
        "signature_time",
        "4*T_E1 + T_E2 + T_INVZ + T_RZ + O(n)*T_ZMUL",
        "T_E1,T_E2,T_INVZ,T_RZ,T_ZMUL",
        "credential: 3*G1 + G2 + 2*Zp",
        "Scheme 2 issuing/credential estimate; set-commitment polynomial work is represented by O(n)*T_ZMUL.",
    ],
    [
        "SPS-EQ",
        "raw_signature_verify_time",
        "T_MP6",
        "T_MP6",
        "",
        "VerifyR has two pairing-product equations; T_MP6 is the practical aggregate unit.",
    ],
    [
        "SPS-EQ",
        "proof_generation_time",
        "T_MP6 + 8*T_E1 + T_E2 + O(n-d)*T_ZMUL + T_H",
        "T_MP6,T_E1,T_E2,T_ZMUL,T_H",
        "show token approx: 8*G1 + G2 + 2*Zp",
        "Show protocol estimate; communication is constant-size in the number of attributes.",
    ],
    [
        "SPS-EQ",
        "proof_verification_time",
        "T_MP8 + 4*T_E1 + T_E2 + O(d)*T_ZMUL + T_H",
        "T_MP8,T_E1,T_E2,T_ZMUL,T_H",
        "",
        "Verify side estimate for subset opening plus proof freshness.",
    ],
]


def build_command(executable):
    return [
        "g++",
        "-std=c++11",
        "-O2",
        "-o",
        executable,
        "unit_operation_benchmark.cpp",
        "Algorithm/bn_pair.cpp",
        "Algorithm/miracl.a",
        "-w",
    ]


def parse_tsv(stdout):
    lines = stdout.splitlines()
    try:
        start = lines.index("BEGIN_UNIT_COSTS_TSV") + 1
        end = lines.index("END_UNIT_COSTS_TSV")
    except ValueError as exc:
        raise RuntimeError("unit benchmark output did not contain TSV markers") from exc

    reader = csv.DictReader(lines[start:end], delimiter="\t")
    rows = []
    for row in reader:
        parsed = dict(row)
        for key in ["samples", "iterations_per_sample"]:
            parsed[key] = int(parsed[key])
        for key in ["mean_ms", "median_ms", "std_ms", "min_ms", "max_ms"]:
            parsed[key] = float(parsed[key])
        rows.append(parsed)
    return rows


def xlsx_col_name(index):
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def xlsx_cell(row_index, column_index, value, style_id=0):
    ref = f"{xlsx_col_name(column_index)}{row_index}"
    style = f' s="{style_id}"' if style_id else ""
    if value is None:
        value = ""
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{style}><v>{int(value)}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style}><v>{value}</v></c>'
    text = xml_escape(str(value))
    return f'<c r="{ref}" t="inlineStr"{style}><is><t>{text}</t></is></c>'


def sheet_xml(headers, rows):
    table = [headers, *rows]
    last_col = xlsx_col_name(len(headers))
    last_row = len(table)
    cols = []
    for index, header in enumerate(headers, start=1):
        width = min(max(len(header) + 2, 14), 48)
        cols.append(f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>')
    row_xml = []
    for row_index, row in enumerate(table, start=1):
        cells = [
            xlsx_cell(row_index, col_index, value, 1 if row_index == 1 else 0)
            for col_index, value in enumerate(row, start=1)
        ]
        row_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<dimension ref="A1:{last_col}{last_row}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        f'<cols>{"".join(cols)}</cols>'
        f'<sheetData>{"".join(row_xml)}</sheetData>'
        '</worksheet>'
    )


def write_xlsx(path, sheets):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, len(sheets) + 1)
    )
    workbook_sheets = "".join(
        f'<sheet name="{xml_escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
        for i, (name, _, _) in enumerate(sheets, start=1)
    )
    workbook_rels = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, len(sheets) + 1)
    )
    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            f'{sheet_overrides}'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>'
        ),
        "docProps/core.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:creator>run_unit_benchmark.py</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>'
            '</cp:coreProperties>'
        ),
        "docProps/app.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            '<Application>Python</Application>'
            '</Properties>'
        ),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets>{workbook_sheets}</sheets>'
            '</workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{workbook_rels}'
            f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '</Relationships>'
        ),
        "xl/styles.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="3"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill></fills>'
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
            '</styleSheet>'
        ),
    }
    for index, (_name, headers, rows) in enumerate(sheets, start=1):
        files[f"xl/worksheets/sheet{index}.xml"] = sheet_xml(headers, rows)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as workbook_zip:
        for filename, content in files.items():
            workbook_zip.writestr(filename, content)


def run(args):
    executable = Path(args.executable)
    if args.build:
        executable.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(build_command(str(executable)), check=True)

    completed = subprocess.run(
        [str(executable), str(args.samples)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    unit_rows = parse_tsv(completed.stdout)
    unit_sheet_rows = [[row.get(header, "") for header in UNIT_HEADERS] for row in unit_rows]
    formula_sheet_rows = FORMULA_ROWS
    write_xlsx(
        args.output_xlsx,
        [
            ("UnitCosts", UNIT_HEADERS, unit_sheet_rows),
            ("OperationFormulas", FORMULA_HEADERS, formula_sheet_rows),
        ],
    )
    print(f"wrote {args.output_xlsx}")
    for row in unit_rows:
        print(f"{row['unit_id']}: mean={row['mean_ms']:.6f} ms median={row['median_ms']:.6f} ms")


def build_parser():
    parser = argparse.ArgumentParser(description="Build and run WSL unit-operation benchmarks.")
    parser.add_argument("--build", action="store_true", help="Compile the C++ benchmark before running.")
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--executable", default=DEFAULT_EXECUTABLE)
    parser.add_argument("--output-xlsx", default=DEFAULT_OUTPUT_XLSX)
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
