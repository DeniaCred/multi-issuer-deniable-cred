import argparse
import csv
import math
import os
import random
import re
import statistics
import subprocess
import sys
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePath
from xml.sax.saxutils import escape as xml_escape


SCHEME_NAME = "OurScheme"
DEFAULT_MESSAGES = [2, 4, 6, 8, 10, 12]
DEFAULT_OTHER_ISSUERS = [3]
DEFAULT_RUNS = 30
DEFAULT_WARMUP = 5
DEFAULT_TRIM_PERCENT = 5.0
ROUND_TRIM_PERCENT = 0.0
BATCH_TRIM_PERCENT = 20.0
DEFAULT_OUTPUT_XLSX = "results/issuer_hiding_protocol_v2/performance_data.xlsx"

# Conservative uncompressed estimates for a pairing-friendly curve with
# 256-bit base-field elements. If the implementation switches to compressed
# encodings, update these constants and keep the workbook schema unchanged.
GROUP_BYTES = {
    "Zp": 32,
    "G1": 64,
    "G2": 128,
    "GT": 384,
}

COMPONENT_PHASES = {
    "aggregatePublicKeys": "Issue",
    "issueCredential": "CredentialIssue",
    "verifySignature": "CredentialVerify",
    "verifySignature_coordinator": "CredentialVerify",
    "verifySignature_user": "CredentialVerify",
    "CertVerify_original": "CredentialVerify",
    "CertVerify_demo": "PresentationVerify",
    "CertVerify_standalone": "PresentationVerifyStandalone",
    "CertVerify_real": "PresentationVerify",
    "CertVerify_simulated": "DeniabilityVerification",
    "deriveVkCoordinator": "CredentialVerify",
    "deriveVkUser": "CredentialVerify",
    "Certify": "Issue",
    "CertVerify": "PresentationVerify",
    "verifierAuthNIZKGen": "VerifierAuth",
    "verifierAuthNIZKVerify": "VerifierAuth",
    "randomizeCertificate": "PresentationGen",
    "blindCredential": "PresentationGen",
    "blindTotal": "PresentationGen",
    "verifyRandomizedCertificate": "PresentationVerify",
    "verifyRandomizedTACredential_standalone": "PresentationVerifyStandalone",
    "verifyRandomizedTACredential_real": "PresentationVerify",
    "verifyRandomizedTACredential_simulated": "DeniabilityVerification",
    "generatePresentationPayload": "PresentationGen",
    "presentProof": "PresentationGen",
    "presentTotal": "PresentationGen",
    "verifyORProof": "PresentationVerify",
    "verifyORProof_real": "PresentationVerify",
    "verifyORProof_simulated": "DeniabilityVerification",
    "verifyBlindedAggregateCredential_real": "PresentationVerify",
    "verifyBlindedAggregateCredential_simulated": "DeniabilityVerification",
    "verifyPresentationPayload_total_real": "PresentationVerify",
    "verifyPresentationPayload_total_simulated": "DeniabilityVerification",
    "simulatePresentationPayloadByVerifier": "DeniabilitySimulation",
}
COMPONENT_ORDER = [
    "aggregatePublicKeys",
    "issueCredential",
    "verifySignature",
    "verifySignature_coordinator",
    "verifySignature_user",
    "CertVerify",
    "CertVerify_original",
    "CertVerify_demo",
    "deriveVkCoordinator",
    "deriveVkUser",
    "Certify",
    "verifierAuthNIZKGen",
    "verifierAuthNIZKVerify",
    "randomizeCertificate",
    "blindCredential",
    "blindTotal",
    "CertVerify_standalone",
    "generatePresentationPayload",
    "presentProof",
    "presentTotal",
    "CertVerify_real",
    "verifyBlindedAggregateCredential_real",
    "verifyORProof",
    "verifyORProof_real",
    "verifyPresentationPayload_total_real",
    "simulatePresentationPayloadByVerifier",
    "CertVerify_simulated",
    "verifyBlindedAggregateCredential_simulated",
    "verifyORProof_simulated",
    "verifyPresentationPayload_total_simulated",
]
COMPONENT_LABELS = {
    "aggregatePublicKeys": "Internal aggregate public key",
    "issueCredential": "Issue credential",
    "verifySignature": "Aggregate credential verification",
    "verifySignature_coordinator": "Coordinator aggregate credential verification",
    "verifySignature_user": "User aggregate credential verification",
    "CertVerify_original": "Original certificate verification",
    "CertVerify_demo": "Demo certificate verification",
    "CertVerify_standalone": "Standalone certificate verification",
    "CertVerify_real": "Real presentation certificate verification",
    "CertVerify_simulated": "Simulated presentation certificate verification",
    "deriveVkCoordinator": "Coordinator vk_U derivation",
    "deriveVkUser": "User vk_U derivation",
    "Certify": "Credential binding certification",
    "CertVerify": "Certificate verification",
    "randomizeCertificate": "Certificate randomization",
    "blindCredential": "Aggregate credential blinding",
    "blindTotal": "Blind total (sampling + certificate randomization + credential blinding)",
    "verifyRandomizedCertificate": "Certificate verification",
    "verifyRandomizedCertificate_original": "Original certificate verification",
    "verifyRandomizedCertificate_demo": "Demo certificate verification",
    "verifyRandomizedCertificate_standalone": "Standalone certificate verification",
    "verifyRandomizedCertificate_real": "Real presentation certificate verification",
    "verifyRandomizedCertificate_simulated": "Simulated presentation certificate verification",
    "generatePresentationPayload": "Presentation generation",
    "presentProof": "Present (OR-proof generation only)",
    "presentTotal": "Historical mixed presentation timer",
    "verifyORProof": "OR proof verification",
    "verifyORProof_real": "Real presentation OR proof verification",
    "verifyORProof_simulated": "Simulated presentation OR proof verification",
    "verifyBlindedAggregateCredential_real": "Real presentation blinded credential verification",
    "verifyBlindedAggregateCredential_simulated": "Simulated presentation blinded credential verification",
    "verifyPresentationPayload_total_real": "Real full presentation verification",
    "verifyPresentationPayload_total_simulated": "Simulated full presentation verification",
    "simulatePresentationPayloadByVerifier": "Deniable simulation generation",
}

COMPONENT_LABELS.update(
    {
        "verifierAuthNIZKGen": "Verifier auth NIZK generation",
        "verifierAuthNIZKVerify": "Verifier auth NIZK verification",
    }
)

# Historical execution records used the pre-migration labels.  Normalize them
# only when reading legacy data; newly generated records must use the canonical
# coordinator/certificate labels above.
LEGACY_METRIC_ALIASES = {
    "computeUserApk": "deriveVkCoordinator",
    "TACert": "Certify",
    "randomizeTACredential": "randomizeCertificate",
    "verifyRandomizedTACredential": "CertVerify",
    "verifyRandomizedTACredential_standalone": "CertVerify_standalone",
    "verifyRandomizedTACredential_real": "CertVerify_real",
    "verifyRandomizedTACredential_simulated": "CertVerify_simulated",
    "verifyRandomizedCertificate": "CertVerify",
    "verifyRandomizedCertificate_original": "CertVerify_original",
    "verifyRandomizedCertificate_demo": "CertVerify_demo",
    "verifyRandomizedCertificate_standalone": "CertVerify_standalone",
    "verifyRandomizedCertificate_real": "CertVerify_real",
    "verifyRandomizedCertificate_simulated": "CertVerify_simulated",
}

def canonical_metric_name(name: str) -> str:
    return LEGACY_METRIC_ALIASES.get(name, name)

RAW_FIELDNAMES = [
    "scheme",
    "num_attrs",
    "num_issuers",
    "num_other_issuers",
    "num_disclosed",
    "phase",
    "component",
    "run_id",
    "batch_id",
    "batch_run_id",
    "time_ms",
    "credential_bytes",
    "proof_bytes",
    "public_key_bytes",
    "apk_user_visible_bytes",
    "internal_pk_directory_bytes",
    "ta_credential_bytes",
    "holder_binding_bytes",
    "signature_bytes",
    "transcript_bytes",
    "transcript_bytes_compact",
    "transcript_bytes_serialized",
    "verifier_auth_proof_bytes",
    "verifier_auth_message_bytes",
    "presentation_transcript_real_bytes",
    "presentation_transcript_simulated_bytes",
]

SUMMARY_FIELDNAMES = [
    "scheme",
    "num_attrs",
    "num_issuers",
    "num_other_issuers",
    "num_disclosed",
    "phase",
    "component",
    "runs",
    "batches",
    "trim_percent",
    "trim_removed_each_tail",
    "round_trim_percent",
    "round_trim_removed_each_tail",
    "mean_ms",
    "trimmed_mean_ms",
    "round_mean_ms",
    "round_mean_std_ms",
    "round_trimmed_mean_ms",
    "round_trimmed_mean_std_ms",
    "batch_trim_percent",
    "batch_trim_removed_each_tail",
    "batch_trimmed_mean_ms",
    "batch_median_ms",
    "batch_mad_ms",
    "median_ms",
    "std_ms",
    "p95_ms",
    "p99_ms",
    "min_ms",
    "max_ms",
    "credential_bytes",
    "proof_bytes",
    "public_key_bytes",
    "apk_user_visible_bytes",
    "internal_pk_directory_bytes",
    "ta_credential_bytes",
    "holder_binding_bytes",
    "signature_bytes",
    "transcript_bytes",
    "transcript_bytes_compact",
    "transcript_bytes_serialized",
    "verifier_auth_proof_bytes",
    "verifier_auth_message_bytes",
    "presentation_transcript_real_bytes",
    "presentation_transcript_simulated_bytes",
]

COMBINED_COLUMNS = [
    ("record_type", "record_type/record type"),
    ("experiment_id", "experiment_id/experiment id"),
    ("run_started_at", "run_started_at/run started at"),
    ("notes", "notes/notes"),
    ("scheme", "scheme/scheme"),
    ("num_attrs", "num_attrs/attribute count"),
    ("num_issuers", "num_issuers/issuer count"),
    ("num_other_issuers", "num_other_issuers/other issuer count"),
    ("num_disclosed", "num_disclosed/disclosed attribute count"),
    ("phase", "phase/phase"),
    ("component", "component/component"),
    ("run_id", "run_id/run id"),
    ("time_ms", "time_ms/elapsed milliseconds"),
    ("runs", "sample count"),
    ("mean_ms", "mean milliseconds"),
    ("median_ms", "median milliseconds"),
    ("std_ms", "stddev milliseconds"),
    ("min_ms", "min_ms/min milliseconds"),
    ("max_ms", "max_ms/max milliseconds"),
    ("credential_bytes", "credential_bytes/credential bytes"),
    ("proof_bytes", "proof_bytes/proof bytes"),
    ("public_key_bytes", "public_key_bytes/public key bytes"),
    ("signature_bytes", "signature_bytes/signature bytes"),
    ("transcript_bytes", "transcript_bytes/presentation transcript bytes"),
]
def insert_column_specs(columns, insertions):
    updated = []
    for key, label in columns:
        updated.append((key, label))
        updated.extend(insertions.get(key, []))
    return updated


COMBINED_COLUMNS = insert_column_specs(
    COMBINED_COLUMNS,
    {
        "run_id": [
            ("batch_id", "batch_id/batch id"),
            ("batch_run_id", "batch_run_id/run id within batch"),
        ],
        "runs": [
            ("batches", "batches/batch count"),
            ("trim_percent", "trim_percent/trim percent"),
            ("trim_removed_each_tail", "trim_removed_each_tail/removed samples per tail"),
        ],
        "mean_ms": [("trimmed_mean_ms", "trimmed_mean_ms/trimmed mean milliseconds")],
        "std_ms": [
            ("p95_ms", "p95_ms/95th percentile milliseconds"),
            ("p99_ms", "p99_ms/99th percentile milliseconds"),
        ],
    },
)
COMBINED_FIELDNAMES = [label for _, label in COMBINED_COLUMNS]

SUMMARY_WIDE_METADATA_COLUMNS = [
    ("experiment_id", "experiment_id/experiment id"),
    ("run_started_at", "run_started_at/run started at"),
    ("notes", "notes/notes"),
]
SUMMARY_WIDE_BASE_COLUMNS = [
    ("scheme", "scheme/scheme"),
    ("num_attrs", "num_attrs/attribute count"),
    ("num_issuers", "num_issuers/issuer count"),
    ("num_other_issuers", "num_other_issuers/other issuer count"),
    ("num_disclosed", "num_disclosed/disclosed attribute count"),
]
SUMMARY_WIDE_SIZE_COLUMNS = [
    ("credential_bytes", "credential_bytes/credential bytes"),
    ("proof_bytes", "proof_bytes/proof bytes"),
    ("public_key_bytes", "public_key_bytes/public key bytes"),
    ("apk_user_visible_bytes", "apk_user_visible_bytes/user-visible aggregate public key bytes"),
    ("internal_pk_directory_bytes", "internal_pk_directory_bytes/internal public-key directory bytes"),
    ("ta_credential_bytes", "ta_credential_bytes/certificate bytes"),
    ("holder_binding_bytes", "holder_binding_bytes/holder binding bytes"),
    ("signature_bytes", "signature_bytes/signature bytes"),
    ("transcript_bytes", "transcript_bytes/presentation transcript bytes"),
    ("transcript_bytes_compact", "transcript_bytes_compact/compact presentation transcript bytes"),
    ("transcript_bytes_serialized", "transcript_bytes_serialized/direct serialized presentation transcript bytes"),
]
SUMMARY_WIDE_SIZE_COLUMNS.extend(
    [
        ("verifier_auth_proof_bytes", "verifier_auth_proof_bytes/verifier authentication proof bytes"),
        ("verifier_auth_message_bytes", "verifier_auth_message_bytes/verifier authentication message bytes"),
        ("presentation_transcript_real_bytes", "presentation_transcript_real_bytes/real presentation transcript bytes"),
        ("presentation_transcript_simulated_bytes", "presentation_transcript_simulated_bytes/simulated presentation transcript bytes"),
    ]
)

SUMMARY_WIDE_METRICS = [
    ("runs", "sample count"),
    ("mean_ms", "mean milliseconds"),
    ("std_ms", "stddev milliseconds"),
]


SUMMARY_WIDE_METRICS = insert_column_specs(
    SUMMARY_WIDE_METRICS,
    {
        "mean_ms": [
            ("trimmed_mean_ms", "trimmed mean milliseconds"),
            ("median_ms", "median milliseconds"),
            ("batch_trimmed_mean_ms", "batch-trimmed mean milliseconds"),
            ("batch_median_ms", "batch median milliseconds"),
        ],
        "std_ms": [("p95_ms", "95th percentile milliseconds")],
    },
)


EXCEL_COLUMNS = [
    ("experiment_id", "experiment_id/experiment id"),
    ("run_started_at", "run_started_at/run started at"),
    ("notes", "notes/notes"),
    ("warmup_runs", "warmup_runs/warmup runs"),
    ("scheme", "scheme/scheme"),
    ("num_attrs", "num_attrs/attribute count"),
    ("num_issuers", "num_issuers/issuer count"),
    ("num_other_issuers", "num_other_issuers/other issuer count"),
    ("num_disclosed", "num_disclosed/disclosed attribute count"),
    ("signature_size_bytes", "signature_size_bytes/signature size bytes"),
    ("issue_total_time_ms", "issue_total_time_ms/multi-issuer issue time milliseconds"),
    ("issue_total_runs", "issue_total_runs/issue valid run count"),
    ("issue_total_std_ms", "issue_total_std_ms/issue stddev milliseconds"),
    ("issue_total_min_ms", "issue_total_min_ms/issue min milliseconds"),
    ("issue_total_max_ms", "issue_total_max_ms/issue max milliseconds"),
    ("raw_signature_verify_time_ms", "raw_signature_verify_time_ms/raw signature verification milliseconds"),
    ("raw_signature_verify_runs", "raw_signature_verify_runs/raw signature verification valid run count"),
    ("raw_signature_verify_std_ms", "raw_signature_verify_std_ms/raw signature verification stddev milliseconds"),
    ("raw_signature_verify_min_ms", "raw_signature_verify_min_ms/raw signature verification min milliseconds"),
    ("raw_signature_verify_max_ms", "raw_signature_verify_max_ms/raw signature verification max milliseconds"),
    ("proof_size_bytes", "proof_size_bytes/proof size bytes"),
    ("proof_generation_time_ms", "proof_generation_time_ms/proof generation milliseconds"),
    ("proof_generation_runs", "proof_generation_runs/proof generation valid run count"),
    ("proof_generation_std_ms", "proof_generation_std_ms/proof generation stddev milliseconds"),
    ("proof_generation_min_ms", "proof_generation_min_ms/proof generation min milliseconds"),
    ("proof_generation_max_ms", "proof_generation_max_ms/proof generation max milliseconds"),
    ("proof_verification_time_ms", "proof_verification_time_ms/proof verification milliseconds"),
    ("proof_verification_runs", "proof_verification_runs/proof verification valid run count"),
    ("proof_verification_std_ms", "proof_verification_std_ms/proof verification stddev milliseconds"),
    ("proof_verification_min_ms", "proof_verification_min_ms/proof verification min milliseconds"),
    ("proof_verification_max_ms", "proof_verification_max_ms/proof verification max milliseconds"),
]
EXCEL_COLUMNS = insert_column_specs(
    EXCEL_COLUMNS,
    {
        "issue_total_time_ms": [
            ("issue_total_trimmed_mean_ms", "issue_total_trimmed_mean_ms/issue 5% trimmed mean ms"),
            ("issue_total_median_ms", "issue_total_median_ms/issue median ms"),
            ("issue_total_p95_ms", "issue_total_p95_ms/issue p95 ms"),
        ],
        "raw_signature_verify_time_ms": [
            (
                "raw_signature_verify_trimmed_mean_ms",
                "raw_signature_verify_trimmed_mean_ms/signature verify 5% trimmed mean ms",
            ),
            ("raw_signature_verify_median_ms", "raw_signature_verify_median_ms/signature verify median ms"),
            ("raw_signature_verify_p95_ms", "raw_signature_verify_p95_ms/signature verify p95 ms"),
        ],
        "proof_generation_time_ms": [
            (
                "proof_generation_trimmed_mean_ms",
                "proof_generation_trimmed_mean_ms/presentation generation 5% trimmed mean ms",
            ),
            ("proof_generation_median_ms", "proof_generation_median_ms/presentation generation median ms"),
            ("proof_generation_p95_ms", "proof_generation_p95_ms/presentation generation p95 ms"),
        ],
        "proof_verification_time_ms": [
            (
                "proof_verification_trimmed_mean_ms",
                "proof_verification_trimmed_mean_ms/proof verification 5% trimmed mean ms",
            ),
            ("proof_verification_median_ms", "proof_verification_median_ms/proof verification median ms"),
            ("proof_verification_p95_ms", "proof_verification_p95_ms/proof verification p95 ms"),
        ],
    },
)


def parse_int_list(value):
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def parse_name_list(value):
    return [part.strip() for part in value.split(",") if part.strip()]


def build_experiment_configs(
    messages,
    other_issuers,
    plan="cartesian",
    attribute_axis_other_issuers=3,
    issuer_axis_messages=12,
):
    if plan == "cartesian":
        return [
            {"num_attrs": num_attrs, "num_other_issuers": num_other_issuer}
            for num_other_issuer in other_issuers
            for num_attrs in messages
        ]

    if plan != "paper-scaling":
        raise ValueError(f"Unknown experiment plan: {plan}")

    configs = []
    seen = set()

    def add_config(num_attrs, num_other_issuer):
        key = (num_attrs, num_other_issuer)
        if key in seen:
            return
        seen.add(key)
        configs.append({"num_attrs": num_attrs, "num_other_issuers": num_other_issuer})

    for num_attrs in messages:
        add_config(num_attrs, attribute_axis_other_issuers)

    for num_other_issuer in other_issuers:
        add_config(issuer_axis_messages, num_other_issuer)

    return configs


def default_experiment_id(started_at=None):
    dt = started_at or datetime.now().astimezone()
    return dt.strftime("%Y%m%d-%H%M%S")


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def parse_timing_records(output):
    records = []
    seen = set()
    clean_output = strip_ansi(output)
    pattern = re.compile(
        r"^\s*\[Time\]\s+([A-Za-z_][A-Za-z0-9_]*)\s+execution time:\s+(\S+)\s+ms\s*$"
    )
    for line in clean_output.splitlines():
        if "[Time]" not in line:
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError(f"Malformed timing record: {line!r}")
        raw_name, raw_value = match.groups()
        try:
            time_ms = float(raw_value)
        except ValueError as exc:
            raise ValueError(f"Invalid timing value for {raw_name}: {raw_value!r}") from exc
        if not math.isfinite(time_ms) or time_ms < 0:
            raise ValueError(f"Timing value for {raw_name} must be finite and non-negative")
        component = canonical_metric_name(raw_name)
        if component in seen:
            raise ValueError(f"Duplicate timing record for {component}")
        seen.add(component)
        records.append(
            {
                "component": component,
                "phase": COMPONENT_PHASES.get(component, "Other"),
                "time_ms": time_ms,
            }
        )
    return records


def resolve_executable(executable):
    base = executable if isinstance(executable, PurePath) else Path(executable)
    exe_candidate = base.__class__(f"{base}.exe") if base.suffix.lower() != ".exe" else base
    candidates = [base]
    if base.suffix.lower() != ".exe":
        candidates.append(exe_candidate)
    if os.name == "nt":
        candidates = [exe_candidate, base] if exe_candidate != base else [base]

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    searched = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"Benchmark executable not found. Searched: {searched}")


def estimate_size_fields(num_attrs, num_issuers):
    zp = GROUP_BYTES["Zp"]
    g1 = GROUP_BYTES["G1"]
    g2 = GROUP_BYTES["G2"]
    gt = GROUP_BYTES["GT"]

    signature_bytes = 2 * g1  # aggregate PS-style credential: (h, S_agg)
    credential_bytes = 2 * g1 + 5 * g2  # h', S'_agg, vk'_U, R'_c, S'_c, pk'_U, N_V
    proof_bytes = (4 * zp) + (3 * g2)  # c_left, z_left, c_right, z_right, A1, A2, T_right
    apk_user_visible_bytes = (num_attrs + 1) * g2
    internal_pk_directory_bytes = num_issuers * (num_attrs + 1) * g2
    ta_credential_bytes = 2 * g2
    holder_binding_bytes = 2 * g2
    verifier_auth_proof_bytes = g2 + zp
    verifier_auth_message_bytes = g2 + verifier_auth_proof_bytes
    transcript_bytes_compact = g2 + credential_bytes + proof_bytes
    # Direct field encoding repeats vk_U' and pk_U' in credential and certificate.
    transcript_bytes_serialized = transcript_bytes_compact + 2 * g2

    return {
        "credential_bytes": credential_bytes,
        "proof_bytes": proof_bytes,
        "public_key_bytes": apk_user_visible_bytes,
        "apk_user_visible_bytes": apk_user_visible_bytes,
        "internal_pk_directory_bytes": internal_pk_directory_bytes,
        "ta_credential_bytes": ta_credential_bytes,
        "holder_binding_bytes": holder_binding_bytes,
        "signature_bytes": signature_bytes,
        "transcript_bytes": transcript_bytes_compact,
        "transcript_bytes_compact": transcript_bytes_compact,
        "transcript_bytes_serialized": transcript_bytes_serialized,
        "verifier_auth_proof_bytes": verifier_auth_proof_bytes,
        "verifier_auth_message_bytes": verifier_auth_message_bytes,
        "presentation_transcript_real_bytes": transcript_bytes_compact,
        "presentation_transcript_simulated_bytes": transcript_bytes_compact,
    }


def run_protocol(executable, num_attrs, num_other_issuers, *, benchmark_mode=False, cwd=None):
    input_text = f"{num_attrs}\n{num_other_issuers}\n"
    environment = os.environ.copy()
    if benchmark_mode:
        environment["PROTOCOL_BENCHMARK_MODE"] = "1"
    result = subprocess.run(
        [str(resolve_executable(executable))],
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        cwd=cwd,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{executable} failed with exit code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return parse_timing_records(result.stdout)


def trim_count(sample_count, trim_percent=DEFAULT_TRIM_PERCENT):
    count = int(sample_count * (trim_percent / 100.0))
    if count * 2 >= sample_count:
        return 0
    return count


def trimmed_values(values, trim_percent=DEFAULT_TRIM_PERCENT):
    sorted_values = sorted(float(value) for value in values)
    count = trim_count(len(sorted_values), trim_percent)
    if count:
        sorted_values = sorted_values[count:-count]
    return sorted_values


def trimmed_mean(values, trim_percent=DEFAULT_TRIM_PERCENT):
    sorted_values = trimmed_values(values, trim_percent)
    return statistics.mean(sorted_values)


def percentile(values, percent):
    sorted_values = sorted(float(value) for value in values)
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * (percent / 100.0)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[int(position)]
    lower_value = sorted_values[lower]
    upper_value = sorted_values[upper]
    return lower_value + (upper_value - lower_value) * (position - lower)


def batch_count(rows):
    batches = {row.get("batch_id") for row in rows if row.get("batch_id") not in ("", None)}
    return len(batches) if batches else 1


def batch_time_groups(rows):
    groups = defaultdict(list)
    for row in rows:
        batch_id = row.get("batch_id")
        if batch_id in ("", None):
            batch_id = 1
        groups[batch_id].append(float(row["time_ms"]))

    def sort_key(value):
        try:
            return (0, int(value))
        except (TypeError, ValueError):
            return (1, str(value))

    return [groups[batch_id] for batch_id in sorted(groups, key=sort_key)]


def stdev_or_zero(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def median_absolute_deviation(values):
    if not values:
        return 0.0
    median = statistics.median(values)
    return statistics.median(abs(value - median) for value in values)


def build_rows(records, scheme, num_attrs, num_other_issuers, num_disclosed, run_id, batch_id=1, batch_run_id=None):
    num_issuers = 2 + num_other_issuers
    size_fields = estimate_size_fields(num_attrs, num_issuers)
    batch_run_id = run_id if batch_run_id is None else batch_run_id
    rows = []
    for record in records:
        rows.append(
            {
                "scheme": scheme,
                "num_attrs": num_attrs,
                "num_issuers": num_issuers,
                "num_other_issuers": num_other_issuers,
                "num_disclosed": num_disclosed,
                "phase": record["phase"],
                "component": record["component"],
                "run_id": run_id,
                "batch_id": batch_id,
                "batch_run_id": batch_run_id,
                "time_ms": record["time_ms"],
                **size_fields,
            }
        )
    return rows


def summarize_rows(rows):
    groups = defaultdict(list)
    for row in rows:
        key = (
            row["scheme"],
            row["num_attrs"],
            row["num_issuers"],
            row["num_other_issuers"],
            row["num_disclosed"],
            row["phase"],
            row["component"],
        )
        groups[key].append(row)

    summary = []
    for key in sorted(groups):
        group_rows = groups[key]
        times = [float(row["time_ms"]) for row in group_rows]
        first = group_rows[0]
        removed_each_tail = trim_count(len(times), DEFAULT_TRIM_PERCENT)
        round_groups = batch_time_groups(group_rows)
        round_means = [statistics.mean(group) for group in round_groups]
        round_trimmed_means = [trimmed_mean(group, DEFAULT_TRIM_PERCENT) for group in round_groups]
        round_trimmed_samples = trimmed_values(round_trimmed_means, ROUND_TRIM_PERCENT)
        batch_trimmed_samples = trimmed_values(round_trimmed_means, BATCH_TRIM_PERCENT)
        summary.append(
            {
                "scheme": key[0],
                "num_attrs": key[1],
                "num_issuers": key[2],
                "num_other_issuers": key[3],
                "num_disclosed": key[4],
                "phase": key[5],
                "component": key[6],
                "runs": len(times),
                "batches": batch_count(group_rows),
                "trim_percent": DEFAULT_TRIM_PERCENT,
                "trim_removed_each_tail": removed_each_tail,
                "round_trim_percent": ROUND_TRIM_PERCENT,
                "round_trim_removed_each_tail": trim_count(len(round_trimmed_means), ROUND_TRIM_PERCENT),
                "mean_ms": statistics.mean(times),
                "trimmed_mean_ms": trimmed_mean(times, DEFAULT_TRIM_PERCENT),
                "round_mean_ms": statistics.mean(round_means),
                "round_mean_std_ms": stdev_or_zero(round_means),
                "round_trimmed_mean_ms": statistics.mean(round_trimmed_samples),
                "round_trimmed_mean_std_ms": stdev_or_zero(round_trimmed_samples),
                "batch_trim_percent": BATCH_TRIM_PERCENT,
                "batch_trim_removed_each_tail": trim_count(len(round_trimmed_means), BATCH_TRIM_PERCENT),
                "batch_trimmed_mean_ms": statistics.mean(batch_trimmed_samples),
                "batch_median_ms": statistics.median(round_trimmed_means),
                "batch_mad_ms": median_absolute_deviation(round_trimmed_means),
                "median_ms": statistics.median(times),
                "std_ms": stdev_or_zero(times),
                "p95_ms": percentile(times, 95),
                "p99_ms": percentile(times, 99),
                "min_ms": min(times),
                "max_ms": max(times),
                "credential_bytes": first["credential_bytes"],
                "proof_bytes": first["proof_bytes"],
                "public_key_bytes": first["public_key_bytes"],
                "apk_user_visible_bytes": first.get("apk_user_visible_bytes", ""),
                "internal_pk_directory_bytes": first.get("internal_pk_directory_bytes", ""),
                "ta_credential_bytes": first.get("ta_credential_bytes", ""),
                "signature_bytes": first["signature_bytes"],
                "transcript_bytes": first["transcript_bytes"],
                "transcript_bytes_compact": first.get("transcript_bytes_compact", ""),
                "transcript_bytes_serialized": first.get("transcript_bytes_serialized", ""),
                "verifier_auth_proof_bytes": first.get("verifier_auth_proof_bytes", ""),
                "verifier_auth_message_bytes": first.get("verifier_auth_message_bytes", ""),
                "presentation_transcript_real_bytes": first.get("presentation_transcript_real_bytes", ""),
                "presentation_transcript_simulated_bytes": first.get("presentation_transcript_simulated_bytes", ""),
            }
        )
    return summary


def write_csv(path, fieldnames, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def to_combined_row(record_type, row):
    combined = {}
    for key, label in COMBINED_COLUMNS:
        if key == "record_type":
            combined[label] = record_type
        else:
            combined[label] = row.get(key, "")
    return combined


def write_combined_csv(path, raw_rows, summary_rows, experiment_id="", run_started_at="", notes=""):
    rows = [
        *(to_combined_row("raw", row) for row in raw_rows),
        *(to_combined_row("summary", row) for row in summary_rows),
    ]
    for row in rows:
        row["experiment_id/experiment id"] = experiment_id
        row["run_started_at/run started at"] = run_started_at
        row["notes/notes"] = notes
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMBINED_FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summary_wide_fieldnames(components=None):
    selected_components = components or COMPONENT_ORDER
    fieldnames = [label for _, label in [*SUMMARY_WIDE_METADATA_COLUMNS, *SUMMARY_WIDE_BASE_COLUMNS]]
    for component in selected_components:
        label = COMPONENT_LABELS.get(component, component)
        for metric, metric_label in SUMMARY_WIDE_METRICS:
            fieldnames.append(f"{component}_{metric}/{label} {metric_label}")
    fieldnames.extend(label for _, label in SUMMARY_WIDE_SIZE_COLUMNS)
    return fieldnames


def build_summary_wide_rows(summary_rows, components=None):
    selected_components = components or COMPONENT_ORDER
    groups = {}
    for row in summary_rows:
        key = tuple(row[column] for column, _ in SUMMARY_WIDE_BASE_COLUMNS)
        if key not in groups:
            groups[key] = {
                label: row.get(column, "")
                for column, label in [
                    *SUMMARY_WIDE_METADATA_COLUMNS,
                    *SUMMARY_WIDE_BASE_COLUMNS,
                    *SUMMARY_WIDE_SIZE_COLUMNS,
                ]
            }
        if row["component"] not in selected_components:
            continue
        component_label = COMPONENT_LABELS.get(row["component"], row["component"])
        for metric, metric_label in SUMMARY_WIDE_METRICS:
            groups[key][f"{row['component']}_{metric}/{component_label} {metric_label}"] = row[metric]

    fieldnames = summary_wide_fieldnames(selected_components)
    wide_rows = []
    for key in sorted(groups):
        wide_rows.append({field: groups[key].get(field, "") for field in fieldnames})
    return wide_rows


def write_summary_wide_csv(
    path,
    summary_rows,
    components=None,
    experiment_id="",
    run_started_at="",
    notes="",
):
    fieldnames = summary_wide_fieldnames(components)
    rows = build_summary_wide_rows(summary_rows, components)
    for row in rows:
        row["experiment_id/experiment id"] = experiment_id
        row["run_started_at/run started at"] = run_started_at
        row["notes/notes"] = notes
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def append_summary_wide_csv(
    path,
    summary_rows,
    components=None,
    experiment_id="",
    run_started_at="",
    notes="",
    overwrite=False,
):
    path = Path(path)
    fieldnames = summary_wide_fieldnames(components)
    rows = build_summary_wide_rows(summary_rows, components)
    for row in rows:
        row["experiment_id/experiment id"] = experiment_id
        row["run_started_at/run started at"] = run_started_at
        row["notes/notes"] = notes

    path.parent.mkdir(parents=True, exist_ok=True)
    existing_rows = []
    if path.exists() and not overwrite and path.stat().st_size > 0:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            existing_rows = [
                {field: row.get(field, "") for field in fieldnames}
                for row in reader
            ]

    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in [*existing_rows, *rows]:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def build_excel_summary_rows(summary_rows, experiment_id="", run_started_at="", notes="", warmup_runs=""):
    groups = {}
    for row in summary_rows:
        key = (
            row["scheme"],
            row["num_attrs"],
            row["num_issuers"],
            row["num_other_issuers"],
            row["num_disclosed"],
        )
        if key not in groups:
            groups[key] = {
                "experiment_id": experiment_id,
                "run_started_at": run_started_at,
                "notes": notes,
                "warmup_runs": warmup_runs,
                "scheme": row["scheme"],
                "num_attrs": row["num_attrs"],
                "num_issuers": row["num_issuers"],
                "num_other_issuers": row["num_other_issuers"],
                "num_disclosed": row["num_disclosed"],
                "signature_size_bytes": row["signature_bytes"],
                "proof_size_bytes": row["proof_bytes"],
                "issue_total_time_ms": "",
                "raw_signature_verify_time_ms": "",
                "proof_generation_time_ms": "",
                "proof_verification_time_ms": "",
            }

        if row["component"] == "verifySignature" and any(
            candidate["scheme"] == row["scheme"] and candidate["num_attrs"] == row["num_attrs"] and
            candidate["num_issuers"] == row["num_issuers"] and candidate["num_other_issuers"] == row["num_other_issuers"] and
            candidate["num_disclosed"] == row["num_disclosed"] and candidate["component"] == "verifySignature_user"
            for candidate in summary_rows
        ):
            continue

        metric_prefix = {
            "issueCredential": "issue_total",
            # User acceptance is the externally relevant raw verification metric.
            "verifySignature_user": "raw_signature_verify",
            "verifySignature": "raw_signature_verify",
            "presentProof": "proof_generation",
            "generatePresentationPayload": "proof_generation",
            "verifyORProof": "proof_verification",
            "verifyORProof_real": "proof_verification",
        }.get(row["component"])
        if metric_prefix:
            groups[key][f"{metric_prefix}_time_ms"] = row["mean_ms"]
            groups[key][f"{metric_prefix}_trimmed_mean_ms"] = row.get("trimmed_mean_ms", row["mean_ms"])
            groups[key][f"{metric_prefix}_median_ms"] = row.get("median_ms", row["mean_ms"])
            groups[key][f"{metric_prefix}_p95_ms"] = row.get("p95_ms", row["mean_ms"])
            groups[key][f"{metric_prefix}_runs"] = row["runs"]
            groups[key][f"{metric_prefix}_std_ms"] = row.get("std_ms", "")
            groups[key][f"{metric_prefix}_min_ms"] = row.get("min_ms", "")
            groups[key][f"{metric_prefix}_max_ms"] = row.get("max_ms", "")

    labeled_rows = []
    for key in sorted(groups):
        grouped_row = groups[key]
        labeled_rows.append(
            {label: grouped_row.get(column, "") for column, label in EXCEL_COLUMNS}
        )
    return labeled_rows


def excel_column_name(column_index):
    name = ""
    while column_index:
        column_index, remainder = divmod(column_index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def cell_reference(row_index, column_index):
    return f"{excel_column_name(column_index)}{row_index}"


def xlsx_cell_xml(row_index, column_index, value, style_id=0):
    ref = cell_reference(row_index, column_index)
    style = f' s="{style_id}"' if style_id else ""
    if value is None:
        value = ""
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{style}><v>{int(value)}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style}><v>{value}</v></c>'
    text = xml_escape(str(value))
    return f'<c r="{ref}" t="inlineStr"{style}><is><t>{text}</t></is></c>'


def build_xlsx_sheet_xml(headers, rows):
    table = [headers, *rows]
    last_column = excel_column_name(len(headers))
    last_row = max(len(table), 1)
    col_defs = []
    for index, header in enumerate(headers, start=1):
        width = min(max(len(header) + 2, 14), 42)
        col_defs.append(
            f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        )

    row_xml = []
    for row_index, values in enumerate(table, start=1):
        cells = [
            xlsx_cell_xml(row_index, column_index, value, 1 if row_index == 1 else 0)
            for column_index, value in enumerate(values, start=1)
        ]
        row_xml.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<dimension ref="A1:{last_column}{last_row}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        f'<cols>{"".join(col_defs)}</cols>'
        f'<sheetData>{"".join(row_xml)}</sheetData>'
        '</worksheet>'
    )


def write_performance_workbook(
    path,
    summary_rows,
    experiment_id="",
    run_started_at="",
    notes="",
    warmup_runs="",
):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = [label for _, label in EXCEL_COLUMNS]
    labeled_rows = build_excel_summary_rows(summary_rows, experiment_id, run_started_at, notes, warmup_runs)
    rows = [[row.get(header, "") for header in headers] for row in labeled_rows]
    sheet_xml = build_xlsx_sheet_xml(headers, rows)
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
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
            'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:creator>benchmark_and_plot.py</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>'
            '</cp:coreProperties>'
        ),
        "docProps/app.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
            'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
            '<Application>Python</Application>'
            '</Properties>'
        ),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Performance" sheetId="1" r:id="rId1"/></sheets>'
            '</workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
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
        "xl/worksheets/sheet1.xml": sheet_xml,
    }

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as workbook_zip:
        for filename, content in files.items():
            workbook_zip.writestr(filename, content)


def write_legacy_csv(path, summary_rows):
    components = [
        "verifySignature",
        "verifyRandomizedTACredential",
        "generatePresentationPayload",
        "verifyORProof",
        "simulatePresentationPayloadByVerifier",
    ]
    grouped = defaultdict(dict)
    for row in summary_rows:
        if row["component"] not in components:
            continue
        grouped[row["num_attrs"]][row["component"]] = row["mean_ms"]

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["num_messages", *components])
        writer.writeheader()
        for num_attrs in sorted(grouped):
            output_row = {"num_messages": num_attrs}
            for component in components:
                output_row[component] = grouped[num_attrs].get(component, "")
            writer.writerow(output_row)


def print_summary(rows):
    print("\n=== Benchmark summary (5% trimmed mean ms; raw mean shown for audit) ===")
    for row in rows:
        trimmed_value = row.get("round_trimmed_mean_ms", row["trimmed_mean_ms"])
        print(
            f"attrs={row['num_attrs']:<2} issuers={row['num_issuers']:<2} "
            f"{row['component']:<36} trimmed={trimmed_value:.4f} "
            f"mean={row['mean_ms']:.4f} p95={row['p95_ms']:.4f}"
        )


def collect_benchmarks(args):
    executable = Path(args.executable)
    raw_rows = []
    batches = int(getattr(args, "batches", 1))
    randomize_order = bool(getattr(args, "randomize_order", False))
    random_seed = getattr(args, "random_seed", None)
    cooldown_seconds = float(getattr(args, "cooldown_seconds", 0.0) or 0.0)

    if batches < 1:
        raise ValueError("--batches must be at least 1")
    if batches > args.runs:
        raise ValueError("--batches cannot exceed --runs")
    if cooldown_seconds < 0:
        raise ValueError("--cooldown-seconds must be non-negative")

    configs = build_experiment_configs(
        messages=args.messages,
        other_issuers=args.other_issuers,
        plan=args.experiment_plan,
        attribute_axis_other_issuers=args.attribute_axis_other_issuers,
        issuer_axis_messages=args.issuer_axis_messages,
    )

    def config_key(config):
        return (config["num_attrs"], config["num_other_issuers"])

    def run_one(config, run_id, batch_id=1, batch_run_id=None):
        num_attrs = config["num_attrs"]
        num_other_issuers = config["num_other_issuers"]
        records = run_protocol(executable, num_attrs, num_other_issuers)
        raw_rows.extend(
            build_rows(
                records=records,
                scheme=args.scheme,
                num_attrs=num_attrs,
                num_other_issuers=num_other_issuers,
                num_disclosed=args.num_disclosed,
                run_id=run_id,
                batch_id=batch_id,
                batch_run_id=batch_run_id,
            )
        )

    if batches == 1 and not randomize_order:
        for config in configs:
            num_attrs = config["num_attrs"]
            num_other_issuers = config["num_other_issuers"]
            print(
                f"\nRunning attrs={num_attrs}, total_issuers={2 + num_other_issuers} "
                f"({args.warmup} warm-up, {args.runs} measured runs)"
            )
            for warmup_id in range(1, args.warmup + 1):
                print(f"  warm-up {warmup_id}/{args.warmup}", end="\r")
                sys.stdout.flush()
                run_protocol(executable, num_attrs, num_other_issuers)
            if args.warmup:
                print(" " * 60, end="\r")

            for run_id in range(1, args.runs + 1):
                print(f"  measured {run_id}/{args.runs}", end="\r")
                sys.stdout.flush()
                run_one(config, run_id=run_id, batch_id=1, batch_run_id=run_id)
            print(" " * 60, end="\r")
            print(f"  completed attrs={num_attrs}, total_issuers={2 + num_other_issuers}")

        return raw_rows

    rng = random.Random(random_seed)
    warmup_configs = list(configs)
    if randomize_order:
        rng.shuffle(warmup_configs)

    print(
        f"\nRunning {len(configs)} parameter points in {batches} batches "
        f"({args.warmup} warm-up per point, {args.runs} measured runs per point)"
    )
    for index, config in enumerate(warmup_configs, start=1):
        num_attrs = config["num_attrs"]
        num_other_issuers = config["num_other_issuers"]
        for warmup_id in range(1, args.warmup + 1):
            print(
                f"  warm-up point {index}/{len(configs)} attrs={num_attrs}, "
                f"total_issuers={2 + num_other_issuers} {warmup_id}/{args.warmup}",
                end="\r",
            )
            sys.stdout.flush()
            run_protocol(executable, num_attrs, num_other_issuers)
    if args.warmup:
        print(" " * 100, end="\r")

    base_runs, remainder = divmod(args.runs, batches)
    batch_sizes = [base_runs + (1 if index < remainder else 0) for index in range(batches)]
    run_counters = {config_key(config): 0 for config in configs}

    for batch_id, batch_runs in enumerate(batch_sizes, start=1):
        batch_configs = list(configs)
        if randomize_order:
            rng.shuffle(batch_configs)
        print(f"\nBatch {batch_id}/{batches}: {batch_runs} measured runs per parameter point")
        for config_index, config in enumerate(batch_configs, start=1):
            num_attrs = config["num_attrs"]
            num_other_issuers = config["num_other_issuers"]
            key = config_key(config)
            for batch_run_id in range(1, batch_runs + 1):
                run_counters[key] += 1
                run_id = run_counters[key]
                print(
                    f"  point {config_index}/{len(configs)} attrs={num_attrs}, "
                    f"total_issuers={2 + num_other_issuers}, "
                    f"batch run {batch_run_id}/{batch_runs}, total run {run_id}/{args.runs}",
                    end="\r",
                )
                sys.stdout.flush()
                run_one(config, run_id=run_id, batch_id=batch_id, batch_run_id=batch_run_id)
            print(" " * 120, end="\r")
        print(f"  completed batch {batch_id}/{batches}")
        if cooldown_seconds and batch_id < batches:
            print(f"  cooling down for {cooldown_seconds:g} seconds before next batch")
            time.sleep(cooldown_seconds)

    return raw_rows


def collect_benchmarks_sequential_legacy(args):
    executable = Path(args.executable)
    raw_rows = []

    configs = build_experiment_configs(
        messages=args.messages,
        other_issuers=args.other_issuers,
        plan=args.experiment_plan,
        attribute_axis_other_issuers=args.attribute_axis_other_issuers,
        issuer_axis_messages=args.issuer_axis_messages,
    )

    for config in configs:
        num_attrs = config["num_attrs"]
        num_other_issuers = config["num_other_issuers"]
        print(
            f"\nRunning attrs={num_attrs}, total_issuers={2 + num_other_issuers} "
            f"({args.warmup} warm-up, {args.runs} measured runs)"
        )
        for warmup_id in range(1, args.warmup + 1):
            print(f"  warm-up {warmup_id}/{args.warmup}", end="\r")
            sys.stdout.flush()
            run_protocol(executable, num_attrs, num_other_issuers)
        if args.warmup:
            print(" " * 60, end="\r")

        for run_id in range(1, args.runs + 1):
            print(f"  measured {run_id}/{args.runs}", end="\r")
            sys.stdout.flush()
            records = run_protocol(executable, num_attrs, num_other_issuers)
            raw_rows.extend(
                build_rows(
                    records=records,
                    scheme=args.scheme,
                    num_attrs=num_attrs,
                    num_other_issuers=num_other_issuers,
                    num_disclosed=args.num_disclosed,
                    run_id=run_id,
                )
            )
        print(" " * 60, end="\r")
        print(f"  completed attrs={num_attrs}, total_issuers={2 + num_other_issuers}")

    return raw_rows


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Run multi-issuer credential benchmarks and write comparison-ready Excel workbooks."
    )
    parser.add_argument("--scheme", default=SCHEME_NAME)
    parser.add_argument("--messages", default=",".join(map(str, DEFAULT_MESSAGES)))
    parser.add_argument("--other-issuers", default=",".join(map(str, DEFAULT_OTHER_ISSUERS)))
    parser.add_argument("--experiment-plan", choices=["cartesian", "paper-scaling"], default="cartesian")
    parser.add_argument("--attribute-axis-other-issuers", type=int, default=3)
    parser.add_argument("--issuer-axis-messages", type=int, default=12)
    parser.add_argument("--num-disclosed", type=int, default=0)
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--batches", type=int, default=1)
    parser.add_argument("--cooldown-seconds", type=float, default=0.0)
    parser.add_argument("--random-seed", type=int)
    parser.add_argument("--randomize-order", action="store_true")
    parser.add_argument("--executable", default="./main_multi_issuer")
    parser.add_argument("--output-xlsx", default=DEFAULT_OUTPUT_XLSX)
    parser.add_argument("--components", default=",".join(COMPONENT_ORDER))
    parser.add_argument("--experiment-id")
    parser.add_argument("--notes", default="")
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    args.messages = parse_int_list(args.messages)
    args.other_issuers = parse_int_list(args.other_issuers)
    args.components = parse_name_list(args.components)

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
    if args.experiment_plan == "paper-scaling" and args.num_disclosed != 0:
        raise ValueError("paper-scaling keeps disclosure fixed at 0 because the current protocol does not implement selective disclosure")
    unknown_components = [component for component in args.components if component not in COMPONENT_ORDER]
    if unknown_components:
        raise ValueError(f"Unknown components: {', '.join(unknown_components)}")

    started_at = datetime.now().astimezone()
    run_started_at = started_at.isoformat(timespec="seconds")
    experiment_id = args.experiment_id or default_experiment_id(started_at)

    raw_rows = collect_benchmarks(args)
    raw_rows = [row for row in raw_rows if row["component"] in args.components]
    summary_rows = summarize_rows(raw_rows)

    write_performance_workbook(
        args.output_xlsx,
        summary_rows,
        experiment_id=experiment_id,
        run_started_at=run_started_at,
        notes=args.notes,
        warmup_runs=args.warmup,
    )

    print_summary(summary_rows)
    print(f"\nExcel workbook written to {args.output_xlsx}")
    print(f"Experiment id: {experiment_id}")


if __name__ == "__main__":
    main()
