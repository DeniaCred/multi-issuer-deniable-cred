import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
import pytest
import benchmark_and_plot as bench
import render_chapter7_issuer_hiding_figures as figures

def row(component, value):
    return {"scheme":"OurScheme","num_attrs":12,"num_issuers":11,"num_other_issuers":10,"num_disclosed":8,"component":component,"mean_ms":value,"trimmed_mean_ms":value,"median_ms":value,"p95_ms":value,"runs":1,"std_ms":0,"min_ms":value,"max_ms":value,"signature_bytes":128,"proof_bytes":512}

def test_estimate_size_fields_uses_direct_field_count():
    sizes = bench.estimate_size_fields(12, 10)
    assert sizes["transcript_bytes_compact"] == 1408
    assert sizes["transcript_bytes_serialized"] == 1664

def test_parse_timing_records_canonicalizes_context_labels_and_phases():
    output = "[Time] verifySignature_user execution time: 2 ms\n[Time] verifySignature_coordinator execution time: 7 ms\n[Time] verifyRandomizedCertificate_original execution time: 3 ms\n[Time] verifyRandomizedCertificate_real execution time: 4 ms\n[Time] blindTotal execution time: 5 ms\n"
    records = bench.parse_timing_records(output)
    assert [(r["component"], r["phase"]) for r in records] == [("verifySignature_user","CredentialVerify"),("verifySignature_coordinator","CredentialVerify"),("CertVerify_original","CredentialVerify"),("CertVerify_real","PresentationVerify"),("blindTotal","PresentationGen")]

def test_summary_uses_user_acceptance_regardless_of_input_order():
    for rows in ([row("verifySignature_user",2),row("verifySignature",9),row("verifySignature_coordinator",7)],[row("verifySignature",9),row("verifySignature_coordinator",7),row("verifySignature_user",2)]):
        assert bench.build_excel_summary_rows(rows)[0]["raw_signature_verify_time_ms/raw signature verification milliseconds"] == 2
    assert bench.build_excel_summary_rows([row("verifySignature",9)])[0]["raw_signature_verify_time_ms/raw signature verification milliseconds"] == 9

def test_plot_metric_requires_selected_column():
    only_old = pd.DataFrame({"presentTotal_trimmed_mean_ms":[9.0]})
    with pytest.raises(ValueError): figures.metric_column(only_old,"presentProof")
    assert figures.metric_column(only_old,"presentTotal") == "presentTotal_trimmed_mean_ms"
    assert figures.build_parser().parse_args([]).presentation_metric == "presentProof"
    assert figures.build_parser().parse_args(["--presentation-metric","presentTotal"]).presentation_metric == "presentTotal"
