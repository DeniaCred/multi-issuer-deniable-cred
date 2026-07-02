import argparse
import csv
import math
from pathlib import Path

import apply_theoretical_formulas as xlsx_reader
import run_unit_benchmark as workbook


GROUP_BYTES = {
    "Zp": 32,
    "G1": 64,
    "G2": 128,
    "GT": 384,
}

K_VALUES = [2, 4, 6, 8, 10, 12, 16, 20, 24, 30]
ISSUER_SET_VALUES = [3, 5, 8, 10, 12, 16, 20, 24]

BASELINE_COLUMNS = [
    "scheme",
    "source_type",
    "k",
    "issuer_set_size_public",
    "q_internal",
    "num_disclosed",
    "formula_assumption",
    "credential_bytes",
    "issuer_public_key_bytes",
    "verifier_policy_key_bytes",
    "user_visible_public_material_bytes",
    "presentation_transcript_bytes",
    "proof_bytes",
    "policy_setup_time_ms_est",
    "policy_verify_time_ms_est",
    "show_time_ms_est",
    "verify_time_ms_est",
    "policy_setup_formula",
    "policy_verify_formula",
    "show_time_formula",
    "verify_time_formula",
    "size_formula",
    "issuer_hiding_target",
    "user_knows_issuer_set",
    "user_knows_issuer_count",
    "multi_authority_aggregation",
    "designated_verifier_deniability",
    "notes",
]


def round_ms(value):
    if value == "" or value is None:
        return ""
    return round(float(value), 6)


def ceil_log2(value):
    return int(math.ceil(math.log(value, 2)))


def cost(unit_costs, unit_id):
    if unit_id not in unit_costs:
        raise KeyError(f"missing unit cost {unit_id}")
    return unit_costs[unit_id]


def dimensions():
    dims = []
    seen = set()

    def add(k, issuer_set_size):
        key = (k, issuer_set_size)
        if key in seen:
            return
        seen.add(key)
        dims.append({"k": k, "issuer_set_size": issuer_set_size})

    for k in K_VALUES:
        add(k, 10)
    for issuer_set_size in ISSUER_SET_VALUES:
        add(12, issuer_set_size)
    add(30, 24)
    return dims


def base_row(scheme, k, issuer_set_size, disclosed, assumption):
    return {
        "scheme": scheme,
        "source_type": "formula_estimated",
        "k": k,
        "issuer_set_size_public": issuer_set_size,
        "q_internal": "N/A",
        "num_disclosed": disclosed,
        "formula_assumption": assumption,
    }


def katz_sefranek_2026(dim, unit_costs):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    k = dim["k"]
    issuer_set_size = dim["issuer_set_size"]
    show = (2 * k + 6) * cost(unit_costs, "T_E1") + cost(unit_costs, "T_E2")
    verify = (k + 5) * cost(unit_costs, "T_E1") + 2 * cost(unit_costs, "T_E2") + 2 * cost(unit_costs, "T_P")
    policy = (issuer_set_size + 1) * g2 + 3 * zp
    proof = 3 * g1 + g2 + (k + 3) * zp
    row = base_row(
        "Katz-Sefranek 2026 BBS issuer hiding",
        k,
        issuer_set_size,
        1,
        "PKC 2026 Table 1/2 assumes one disclosed attribute; byte sizes use this repository's uncompressed element constants.",
    )
    row.update(
        {
            "credential_bytes": g1 + zp,
            "issuer_public_key_bytes": g2,
            "verifier_policy_key_bytes": policy,
            "user_visible_public_material_bytes": policy,
            "presentation_transcript_bytes": proof,
            "proof_bytes": proof,
            "policy_setup_time_ms_est": "",
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": round_ms(show),
            "verify_time_ms_est": round_ms(verify),
            "policy_setup_formula": "not converted; paper focuses on policy-key size",
            "policy_verify_formula": "",
            "show_time_formula": "(2k+6)*T_E1 + T_E2",
            "verify_time_formula": "(k+5)*T_E1 + 2*T_E2 + 2*T_P",
            "size_formula": "pk=G2; cred=G1+Zp; policy=(I+1)*G2+3*Zp; proof=3*G1+G2+(k+3)*Zp",
            "issuer_hiding_target": "single issuer hidden inside verifier policy set",
            "user_knows_issuer_set": "yes, policy-set model",
            "user_knows_issuer_count": "yes, policy size is visible",
            "multi_authority_aggregation": "no",
            "designated_verifier_deniability": "no",
            "notes": "该方案不向用户隐藏候选签发方集合；其隐藏的是集合中具体哪一个成员签发了凭证。",
        }
    )
    return row


def sanders_traore_2024_as_in_ks(dim, unit_costs):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    k = dim["k"]
    issuer_set_size = dim["issuer_set_size"]
    show = 3 * cost(unit_costs, "T_E1") + 2 * k * cost(unit_costs, "T_E2") + cost(unit_costs, "T_P")
    verify = (k + 1) * cost(unit_costs, "T_E2") + cost(unit_costs, "T_ET") + 3 * cost(unit_costs, "T_P")
    policy = (2 * k * issuer_set_size + k + 1) * g2 + (k + 2) * zp
    proof = 2 * g1 + g2 + k * zp
    row = base_row(
        "Sanders-Traore 2024 PS issuer hiding",
        k,
        issuer_set_size,
        1,
        "Formulas follow Katz-Sefranek 2026 Table 1/2 for the Sanders-Traore row; policy size is (2*k*I+k+1)*G2+(k+2)*Zp.",
    )
    row.update(
        {
            "credential_bytes": 2 * g1,
            "issuer_public_key_bytes": k * g2,
            "verifier_policy_key_bytes": policy,
            "user_visible_public_material_bytes": policy,
            "presentation_transcript_bytes": proof,
            "proof_bytes": proof,
            "policy_setup_time_ms_est": "",
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": round_ms(show),
            "verify_time_ms_est": round_ms(verify),
            "policy_setup_formula": "not converted; paper focuses on policy-key size",
            "policy_verify_formula": "",
            "show_time_formula": "3*T_E1 + 2k*T_E2 + T_P",
            "verify_time_formula": "(k+1)*T_E2 + T_ET + 3*T_P",
            "size_formula": "pk=k*G2; cred=2*G1; policy=(2*k*I+k+1)*G2+(k+2)*Zp; proof=2*G1+G2+k*Zp",
            "issuer_hiding_target": "single issuer hidden inside verifier policy set",
            "user_knows_issuer_set": "yes, policy-set model",
            "user_knows_issuer_count": "yes, policy size is visible",
            "multi_authority_aggregation": "no",
            "designated_verifier_deniability": "no",
            "notes": "该方案作为基于 PS 签名的签发方隐藏基线使用，而不是作为多签发方聚合签发方案使用。",
        }
    )
    return row


def bobolz_2021(dim):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    k = dim["k"]
    issuer_set_size = dim["issuer_set_size"]
    policy = (issuer_set_size + 1) * g1 + 3 * issuer_set_size * g2
    token = 3 * g1 + 4 * g2 + (k + 5) * zp
    row = base_row(
        "Bobolz et al. 2021 issuer-hiding ABC",
        k,
        issuer_set_size,
        0,
        "CANS 2021 Table 1/2 uses L=10 and policies of 10/100 issuers; token formula is parameterized by L=k.",
    )
    row.update(
        {
            "credential_bytes": 2 * g1 + g2,
            "issuer_public_key_bytes": g2,
            "verifier_policy_key_bytes": policy,
            "user_visible_public_material_bytes": policy,
            "presentation_transcript_bytes": token,
            "proof_bytes": token,
            "policy_setup_time_ms_est": "",
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": "",
            "verify_time_ms_est": "",
            "policy_setup_formula": "paper gives operation counts for PresPolicy; not converted to local ms",
            "policy_verify_formula": "paper gives operation counts for VfPolicy; not converted to local ms",
            "show_time_formula": "paper operation counts: Present has 3327 G1 ops, 1206 G2 ops, 4 GT ops, 7 pairings",
            "verify_time_formula": "paper operation counts: Verify has 2398 G1 ops, 901 GT ops, 12 pairings",
            "size_formula": "ipk=G2; cred=2*G1+G2; policy=(I+1)*G1+3I*G2; token=3*G1+4*G2+(k+5)*Zp",
            "issuer_hiding_target": "single issuer hidden inside verifier policy set",
            "user_knows_issuer_set": "yes, policy-set model",
            "user_knows_issuer_count": "yes, policy size is visible",
            "multi_authority_aggregation": "no",
            "designated_verifier_deniability": "no",
            "notes": "该项时间仅保留公式描述，因为原论文给出的是底层群运算计数，不能直接等同于本仓库的标量乘单位成本。",
        }
    )
    return row


def bosk_2022_hiac(dim, unit_costs):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    issuer_set_size = dim["issuer_set_size"]
    setup = 4 * issuer_set_size * cost(unit_costs, "T_E1")
    show_cached = 26 * cost(unit_costs, "T_E1") + 2 * cost(unit_costs, "T_E2")
    verify = 20 * cost(unit_costs, "T_E1") + 2 * cost(unit_costs, "T_E2") + 8 * cost(unit_costs, "T_P")
    integrity_message = 2 * issuer_set_size * zp + 4 * issuer_set_size * g1
    signature = zp + 4 * g1
    randomized_signature = 6 * g1 + 4 * g2
    row = base_row(
        "Bosk et al. 2022 HIAC",
        dim["k"],
        issuer_set_size,
        "N/A",
        "PoPETs 2022 Table 1 and Table 8 formulas. Randomized-signature size is used as the comparable presentation object; the full interactive upload in Table 10 is larger and not modeled as a single transcript.",
    )
    row.update(
        {
            "credential_bytes": signature,
            "issuer_public_key_bytes": 3 * g1 + 2 * g2,
            "verifier_policy_key_bytes": integrity_message,
            "user_visible_public_material_bytes": integrity_message,
            "presentation_transcript_bytes": randomized_signature,
            "proof_bytes": randomized_signature,
            "policy_setup_time_ms_est": round_ms(setup),
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": round_ms(show_cached),
            "verify_time_ms_est": round_ms(verify),
            "policy_setup_formula": "VerifierSetup=4I*T_E1",
            "policy_verify_formula": "IntegrityVerification=4I*T_E1, if first-time verifier interaction is included",
            "show_time_formula": "cached Randomize=26*T_E1+2*T_E2",
            "verify_time_formula": "VerifyRandomize=20*T_E1+2*T_E2+8*T_P",
            "size_formula": "ipk=3*G1+2*G2; signature=Zp+4*G1; verifier public key=2I*Zp+4I*G1; randomized signature=6*G1+4*G2; full Table 10 interaction is not modeled as one transcript",
            "issuer_hiding_target": "issuer hidden inside verifier trusted set",
            "user_knows_issuer_set": "yes, verifier trusted-set model",
            "user_knows_issuer_count": "yes, aggregator/verifier-set interaction is size-dependent",
            "multi_authority_aggregation": "aggregator for trusted issuer set, not multi-issuer credential aggregation",
            "designated_verifier_deniability": "no",
            "notes": "缓存展示时间不包含首次完整性验证；展示大小采用论文 Table 8 的 randomized signature，完整交互上传量应另按 Table 10 建模。",
        }
    )
    return row


def elkhiyaoui_2021(dim, unit_costs):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    issuer_set_size = dim["issuer_set_size"]
    log_i = ceil_log2(max(issuer_set_size, 2))
    proof = 37 * g1 + (27 + 4 * log_i) * g2 + (5 + 3 * log_i) * zp
    show = 68 * cost(unit_costs, "T_E1") + ((7 + 2 * issuer_set_size) * log_i + 40) * cost(unit_costs, "T_E2")
    verify = (2 * issuer_set_size + 12 * log_i + 2) * cost(unit_costs, "T_E2") + 69 * cost(unit_costs, "T_P")
    row = base_row(
        "Elkhiyaoui et al. 2021 one-out-of-many baseline",
        dim["k"],
        issuer_set_size,
        "N/A",
        "ePrint 2021 Table 1 formulas. The table explicitly excludes the extra Schnorr-signature cost; this row keeps the same convention.",
    )
    row.update(
        {
            "credential_bytes": "",
            "issuer_public_key_bytes": g2,
            "verifier_policy_key_bytes": issuer_set_size * g2,
            "user_visible_public_material_bytes": issuer_set_size * g2,
            "presentation_transcript_bytes": proof,
            "proof_bytes": proof,
            "policy_setup_time_ms_est": "",
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": round_ms(show),
            "verify_time_ms_est": round_ms(verify),
            "policy_setup_formula": "",
            "policy_verify_formula": "",
            "show_time_formula": "68*T_E1 + ((7+2I)*ceil(log2 I)+40)*T_E2; Schnorr signature cost excluded as in the paper",
            "verify_time_formula": "(2I+12*ceil(log2 I)+2)*T_E2 + 69*T_P; Schnorr signature cost excluded as in the paper",
            "size_formula": "proof=37*G1+(27+4*ceil(log2 I))*G2+(5+3*ceil(log2 I))*Zp; Schnorr signature size excluded as in the paper",
            "issuer_hiding_target": "issuer hidden via one-out-of-many proof",
            "user_knows_issuer_set": "yes, authorized issuer set is public",
            "user_knows_issuer_count": "yes, proof depends on set size",
            "multi_authority_aggregation": "no",
            "designated_verifier_deniability": "no",
            "notes": "该项采用论文 Table 1 的非紧凑型签发方隐藏证明开销；额外 Schnorr 签名成本按原论文说明未计入。",
        }
    )
    return row


def mir_2023_formula_only(dim):
    row = base_row(
        "Mir et al. 2023 IhMA",
        dim["k"],
        dim["issuer_set_size"],
        "scheme-dependent",
        "CCS 2023 Table 1 reports asymptotic costs; the local PDF does not give enough concrete element counts for a byte-level estimate.",
    )
    row.update(
        {
            "credential_bytes": "",
            "issuer_public_key_bytes": "",
            "verifier_policy_key_bytes": "",
            "user_visible_public_material_bytes": "",
            "presentation_transcript_bytes": "",
            "proof_bytes": "",
            "policy_setup_time_ms_est": "",
            "policy_verify_time_ms_est": "",
            "show_time_ms_est": "",
            "verify_time_ms_est": "",
            "policy_setup_formula": "policy contains signatures on accepted verification keys",
            "policy_verify_formula": "",
            "show_time_formula": "IhMAAtoSa Show(P)=O(K); IhMAATMS Show(P)=O(uK)",
            "verify_time_formula": "IhMAAtoSa Show(V)=O(k); IhMAATMS Show(V)=O(kK)",
            "size_formula": "|Cred| can be constant for fixed signatures; |Show|=O(K)",
            "issuer_hiding_target": "issuer-hiding multi-authority anonymous credentials",
            "user_knows_issuer_set": "policy-set model",
            "user_knows_issuer_count": "yes, K appears in show complexity",
            "multi_authority_aggregation": "yes",
            "designated_verifier_deniability": "no",
            "notes": "该项作为仅保留公式的核心功能基线；在缺少完整元素计数前，不虚构具体时间或字节数。",
        }
    )
    return row


def build_rows(unit_costs):
    rows = []
    for dim in dimensions():
        rows.append(katz_sefranek_2026(dim, unit_costs))
        rows.append(sanders_traore_2024_as_in_ks(dim, unit_costs))
        rows.append(bobolz_2021(dim))
        rows.append(bosk_2022_hiac(dim, unit_costs))
        rows.append(elkhiyaoui_2021(dim, unit_costs))
        rows.append(mir_2023_formula_only(dim))
    return rows


def write_csv(path, columns, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def sheet_rows(columns, rows):
    return [[row.get(column, "") for column in columns] for row in rows]


def write_outputs(args, rows, unit_costs):
    write_csv(args.output_csv, BASELINE_COLUMNS, rows)
    sheets = [
        ("IssuerHidingBaselines", BASELINE_COLUMNS, sheet_rows(BASELINE_COLUMNS, rows)),
        ("UnitCosts", ["unit_id", "mean_ms"], [[unit_id, unit_costs[unit_id]] for unit_id in sorted(unit_costs)]),
    ]
    if args.ours_summary_csv and Path(args.ours_summary_csv).exists():
        ours_rows = read_csv(args.ours_summary_csv)
        ours_columns = list(ours_rows[0].keys()) if ours_rows else []
        sheets.insert(0, ("OurMeasured", ours_columns, sheet_rows(ours_columns, ours_rows)))
    workbook.write_xlsx(args.output_xlsx, sheets)


def build_parser():
    parser = argparse.ArgumentParser(description="Estimate issuer-hiding baselines for Chapter 7.")
    parser.add_argument("--unit-costs-xlsx", default="results/issuer_hiding_20260610/unit_costs_30samples.xlsx")
    parser.add_argument("--ours-summary-csv", default="results/issuer_hiding_20260610/ours_summary_long.csv")
    parser.add_argument("--output-csv", default="results/issuer_hiding_20260610/issuer_hiding_baselines.csv")
    parser.add_argument("--output-xlsx", default="results/issuer_hiding_20260610/issuer_hiding_comparison_ready.xlsx")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    unit_costs = xlsx_reader.read_unit_costs(args.unit_costs_xlsx)
    rows = build_rows(unit_costs)
    write_outputs(args, rows, unit_costs)
    print(f"wrote {args.output_csv}")
    print(f"wrote {args.output_xlsx}")
    print(f"baseline rows={len(rows)}")


if __name__ == "__main__":
    main()
