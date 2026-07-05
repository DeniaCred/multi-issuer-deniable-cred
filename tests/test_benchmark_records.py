import unittest
import csv
import zipfile
from unittest import mock
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import benchmark_and_plot as bench
import run_issuer_hiding_measurements as issuer_hiding


class BenchmarkRecordTests(unittest.TestCase):
    def test_paper_scaling_plan_varies_attributes_and_issuers_without_disclosure_axis(self):
        configs = bench.build_experiment_configs(
            messages=[2, 4, 6],
            other_issuers=[0, 3, 8],
            plan="paper-scaling",
            attribute_axis_other_issuers=3,
            issuer_axis_messages=6,
        )

        self.assertEqual(
            configs,
            [
                {"num_attrs": 2, "num_other_issuers": 3},
                {"num_attrs": 4, "num_other_issuers": 3},
                {"num_attrs": 6, "num_other_issuers": 3},
                {"num_attrs": 6, "num_other_issuers": 0},
                {"num_attrs": 6, "num_other_issuers": 8},
            ],
        )

    def test_cartesian_plan_preserves_existing_message_issuer_product(self):
        configs = bench.build_experiment_configs(
            messages=[2, 4],
            other_issuers=[1, 3],
            plan="cartesian",
            attribute_axis_other_issuers=3,
            issuer_axis_messages=4,
        )

        self.assertEqual(
            configs,
            [
                {"num_attrs": 2, "num_other_issuers": 1},
                {"num_attrs": 4, "num_other_issuers": 1},
                {"num_attrs": 2, "num_other_issuers": 3},
                {"num_attrs": 4, "num_other_issuers": 3},
            ],
        )

    def test_comparison_section_distinguishes_theoretical_sizes_from_measured_serialization(self):
        section_path = Path(__file__).resolve().parents[1] / "results" / "comparison_section.md"
        if not section_path.exists():
            self.skipTest("comparison_section.md is not present in this checkout")
        text = section_path.read_text(encoding="utf-8")

        self.assertIn("theoretical communication cost", text)
        self.assertIn("real serialized bytes", text)
        self.assertIn("compact encoding", text)
        self.assertIn("direct serialization of current struct fields", text)
        self.assertIn("1376", text)
        self.assertIn("1504", text)
        self.assertIn("fig1_our_payload_encoding.svg", text)
        self.assertIn("fig2_bbs_proof_scaling.svg", text)
        self.assertNotIn("fig1_size_comparison.svg", text)
        self.assertNotIn("OurScheme values are conservative uncompressed estimates from the current code", text)

    def test_external_baseline_reported_csv_has_sources_and_comparison_metrics(self):
        baseline_path = Path(__file__).resolve().parents[1] / "results" / "baseline_reported.csv"
        if not baseline_path.exists():
            self.skipTest("baseline_reported.csv is not present in this checkout")

        self.assertTrue(baseline_path.exists())

        with baseline_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)

        self.assertGreater(len(rows), 0)
        self.assertTrue(all("/" in field for field in reader.fieldnames))

        english_fields = {field.split("/", 1)[0]: field for field in reader.fieldnames}
        for field in [
            "scheme",
            "source_type",
            "source_url",
            "operation",
            "reported_time_ms_min",
            "reported_time_ms_max",
            "reported_time_ms",
            "signature_formula",
            "credential_formula",
            "proof_formula",
            "public_material_bytes",
            "signature_bytes",
            "credential_bytes",
            "proof_bytes",
            "public_material_formula",
            "operation_count",
            "comparison_scope",
        ]:
            self.assertIn(field, english_fields)

        schemes = {row[english_fields["scheme"]] for row in rows}
        for expected in ["BBS v06", "BBS+", "PS", "SPS-EQ Scheme 2"]:
            self.assertIn(expected, schemes)

        for row in rows:
            self.assertNotIn(None, row)
            self.assertTrue(row[english_fields["source_url"]].startswith("https://"))
            self.assertTrue(
                row[english_fields["reported_time_ms"]]
                or row[english_fields["reported_time_ms_min"]]
                or row[english_fields["reported_time_ms_max"]]
                or row[english_fields["public_material_bytes"]]
                or row[english_fields["signature_bytes"]]
                or row[english_fields["credential_bytes"]]
                or row[english_fields["proof_bytes"]]
                or row[english_fields["public_material_formula"]]
                or row[english_fields["signature_formula"]]
                or row[english_fields["credential_formula"]]
                or row[english_fields["proof_formula"]]
                or row[english_fields["operation_count"]]
            )

    def test_bbs_reported_proof_sizes_are_recorded_as_proof_bytes(self):
        baseline_path = Path(__file__).resolve().parents[1] / "results" / "baseline_reported.csv"
        if not baseline_path.exists():
            self.skipTest("baseline_reported.csv is not present in this checkout")
        with baseline_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)

        english_fields = {field.split("/", 1)[0]: field for field in reader.fieldnames}
        proof_rows = [
            row
            for row in rows
            if row[english_fields["scheme"]] == "BBS v06"
            and "proof" in row[english_fields["operation"]]
            and row[english_fields["metric"]] == "bytes"
        ]

        self.assertGreater(len(proof_rows), 0)
        for row in proof_rows:
            self.assertEqual(row[english_fields["credential_bytes"]], "")
            self.assertTrue(row[english_fields["proof_bytes"]])

    def test_parse_timing_records_strips_ansi_codes(self):
        output = (
            "[Time] issueCredential execution time: 21.7500 ms\n"
            "\x1b[36m[Time] verifySignature execution time: 12.5000 ms\x1b[0m\n"
            "[Time] verifyORProof execution time: 14.2500 ms\n"
        )

        records = bench.parse_timing_records(output)

        self.assertEqual(
            records,
            [
                {"component": "issueCredential", "phase": "CredentialIssue", "time_ms": 21.75},
                {"component": "verifySignature", "phase": "CredentialVerify", "time_ms": 12.5},
                {"component": "verifyORProof", "phase": "PresentationVerify", "time_ms": 14.25},
            ],
        )

    def test_size_estimates_include_comparison_fields(self):
        small = bench.estimate_size_fields(num_attrs=2, num_issuers=5)
        large = bench.estimate_size_fields(num_attrs=12, num_issuers=5)

        for field in [
            "credential_bytes",
            "proof_bytes",
            "public_key_bytes",
            "signature_bytes",
            "transcript_bytes",
        ]:
            self.assertIn(field, small)
            self.assertGreater(small[field], 0)

        self.assertEqual(small["credential_bytes"], large["credential_bytes"])
        self.assertEqual(small["proof_bytes"], large["proof_bytes"])
        self.assertGreater(large["public_key_bytes"], small["public_key_bytes"])

    def test_size_estimates_match_holder_bound_or_proof_construction(self):
        sizes = bench.estimate_size_fields(num_attrs=12, num_issuers=10)

        self.assertEqual(sizes["credential_bytes"], 768)
        self.assertEqual(sizes["proof_bytes"], 512)
        self.assertEqual(sizes["ta_credential_bytes"], 256)
        self.assertEqual(sizes["holder_binding_bytes"], 256)
        self.assertEqual(sizes["transcript_bytes_compact"], 1408)
        self.assertEqual(sizes["verifier_auth_proof_bytes"], 160)
        self.assertEqual(sizes["verifier_auth_message_bytes"], 288)

    def test_summarize_rows_groups_by_experiment_dimensions(self):
        rows = [
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationVerify",
                "component": "verifyORProof",
                "run_id": 1,
                "time_ms": 10.0,
                "credential_bytes": 512,
                "proof_bytes": 640,
                "public_key_bytes": 1024,
                "signature_bytes": 128,
                "transcript_bytes": 1408,
            },
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationVerify",
                "component": "verifyORProof",
                "run_id": 2,
                "time_ms": 14.0,
                "credential_bytes": 512,
                "proof_bytes": 640,
                "public_key_bytes": 1024,
                "signature_bytes": 128,
                "transcript_bytes": 1408,
            },
        ]

        summary = bench.summarize_rows(rows)

        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["runs"], 2)
        self.assertEqual(summary[0]["mean_ms"], 12.0)
        self.assertEqual(summary[0]["median_ms"], 12.0)
        self.assertAlmostEqual(summary[0]["std_ms"], 2.828427, places=5)
        self.assertEqual(summary[0]["min_ms"], 10.0)
        self.assertEqual(summary[0]["max_ms"], 14.0)

    def test_summary_rows_include_round_averaged_statistics(self):
        rows = []
        for batch_id, values in [(1, [10.0, 20.0]), (2, [30.0, 40.0])]:
            for batch_run_id, value in enumerate(values, start=1):
                rows.append(
                    {
                        "scheme": "OurScheme",
                        "num_attrs": 2,
                        "num_issuers": 5,
                        "num_other_issuers": 3,
                        "num_disclosed": 0,
                        "phase": "PresentationVerify",
                        "component": "verifyORProof",
                        "run_id": (batch_id - 1) * 2 + batch_run_id,
                        "batch_id": batch_id,
                        "batch_run_id": batch_run_id,
                        "time_ms": value,
                        "credential_bytes": 512,
                        "proof_bytes": 640,
                        "public_key_bytes": 1024,
                        "signature_bytes": 128,
                        "transcript_bytes": 1408,
                    }
                )

        summary = bench.summarize_rows(rows)

        self.assertEqual(summary[0]["batches"], 2)
        self.assertEqual(summary[0]["round_mean_ms"], 25.0)
        self.assertAlmostEqual(summary[0]["round_mean_std_ms"], 14.1421356, places=5)
        self.assertEqual(summary[0]["round_trimmed_mean_ms"], 25.0)
        self.assertAlmostEqual(summary[0]["round_trimmed_mean_std_ms"], 14.1421356, places=5)

    def test_summary_rows_average_per_round_trimmed_values_without_cross_round_trimming(self):
        rows = []
        round_values = [10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 17.0, 18.0, 100.0]
        for batch_id, value in enumerate(round_values, start=1):
            rows.append(
                {
                    "scheme": "OurScheme",
                    "num_attrs": 2,
                    "num_issuers": 5,
                    "num_other_issuers": 3,
                    "num_disclosed": 0,
                    "phase": "PresentationVerify",
                    "component": "verifyORProof",
                    "run_id": batch_id,
                    "batch_id": batch_id,
                    "batch_run_id": 1,
                    "time_ms": value,
                    "credential_bytes": 512,
                    "proof_bytes": 640,
                    "public_key_bytes": 1024,
                    "signature_bytes": 128,
                    "transcript_bytes": 1408,
                }
            )

        summary = bench.summarize_rows(rows)

        self.assertEqual(summary[0]["round_mean_ms"], 22.6)
        self.assertEqual(summary[0]["round_trimmed_mean_ms"], 22.6)
        self.assertEqual(summary[0]["round_trim_removed_each_tail"], 0)

    def test_summary_rows_include_batch_trimmed_and_median_statistics(self):
        rows = []
        batch_values = [10.0, 11.0, 12.0, 13.0, 100.0]
        for batch_id, value in enumerate(batch_values, start=1):
            rows.append(
                {
                    "scheme": "OurScheme",
                    "num_attrs": 2,
                    "num_issuers": 5,
                    "num_other_issuers": 3,
                    "num_disclosed": 0,
                    "phase": "PresentationVerify",
                    "component": "verifyORProof",
                    "run_id": batch_id,
                    "batch_id": batch_id,
                    "batch_run_id": 1,
                    "time_ms": value,
                    "credential_bytes": 512,
                    "proof_bytes": 640,
                    "public_key_bytes": 1024,
                    "signature_bytes": 128,
                    "transcript_bytes": 1408,
                }
            )

        summary = bench.summarize_rows(rows)

        self.assertEqual(summary[0]["batch_trim_percent"], 20.0)
        self.assertEqual(summary[0]["batch_trim_removed_each_tail"], 1)
        self.assertEqual(summary[0]["batch_trimmed_mean_ms"], 12.0)
        self.assertEqual(summary[0]["batch_median_ms"], 12.0)
        self.assertEqual(summary[0]["batch_mad_ms"], 1.0)

    def test_measurement_points_reuse_shared_axis_parameter_point(self):
        args = SimpleNamespace(runs=500)

        points = issuer_hiding.build_measurement_points(args)

        unique_keys = {(point["num_attrs"], point["num_other_issuers"]) for point in points}
        self.assertEqual(len(points), len(unique_keys))
        self.assertEqual(len(points), 18)

        shared = next(
            point for point in points if point["num_attrs"] == 12 and point["num_other_issuers"] == 8
        )
        self.assertEqual(
            {label["experiment_id"] for label in shared["labels"]},
            {"issuer-hiding-k-axis-500runs", "issuer-hiding-q-axis-500runs"},
        )

    def test_sentinel_detection_excludes_whole_bad_batches(self):
        rows = []
        for batch_id, sentinel_time in [(1, 50.0), (2, 200.0), (3, 52.0)]:
            for num_attrs, num_other_issuers in [(12, 8), (30, 22)]:
                rows.append(
                    {
                        "scheme": "OurScheme",
                        "num_attrs": num_attrs,
                        "num_issuers": 2 + num_other_issuers,
                        "num_other_issuers": num_other_issuers,
                        "num_disclosed": 0,
                        "phase": "PresentationVerify",
                        "component": "verifyPresentationPayload_total_real",
                        "run_id": batch_id,
                        "batch_id": batch_id,
                        "batch_run_id": 1,
                        "time_ms": sentinel_time if num_attrs == 12 else 10.0,
                        "credential_bytes": 512,
                        "proof_bytes": 640,
                        "public_key_bytes": 1024,
                        "signature_bytes": 128,
                        "transcript_bytes": 1408,
                    }
                )

        report = issuer_hiding.build_sentinel_batch_report(
            rows,
            sentinel_k=12,
            sentinel_other_issuers=8,
            sentinel_component="verifyPresentationPayload_total_real",
            max_relative_deviation=0.25,
        )
        filtered = issuer_hiding.exclude_batches(rows, {item["batch_id"] for item in report if item["excluded"]})

        self.assertEqual([item["batch_id"] for item in report if item["excluded"]], [2])
        self.assertEqual({row["batch_id"] for row in filtered}, {1, 3})

    def test_exclude_rounds_removes_only_matching_experiment_parameter_and_batch(self):
        rows = [
            {"experiment_id": "issuer-hiding-q-axis-500runs", "k": "12", "q_internal": "10", "batch_id": "8"},
            {"experiment_id": "issuer-hiding-q-axis-500runs", "k": "12", "q_internal": "10", "batch_id": "9"},
            {"experiment_id": "issuer-hiding-q-axis-500runs", "k": "12", "q_internal": "12", "batch_id": "9"},
            {"experiment_id": "issuer-hiding-k-axis-500runs", "k": "12", "q_internal": "10", "batch_id": "9"},
        ]
        exclusions = [issuer_hiding.parse_round_exclusion("issuer-hiding-q-axis-500runs:12:10:9")]

        filtered = issuer_hiding.exclude_rounds(rows, exclusions)

        self.assertEqual(len(filtered), 3)
        self.assertNotIn(rows[1], filtered)
        self.assertIn(rows[0], filtered)
        self.assertIn(rows[2], filtered)
        self.assertIn(rows[3], filtered)

    def test_collect_benchmarks_cools_down_between_batches_only(self):
        args = SimpleNamespace(
            executable="dummy",
            scheme="OurScheme",
            messages=[2],
            other_issuers=[1],
            experiment_plan="cartesian",
            attribute_axis_other_issuers=1,
            issuer_axis_messages=2,
            num_disclosed=0,
            runs=2,
            warmup=0,
            batches=2,
            randomize_order=False,
            random_seed=None,
            cooldown_seconds=0.01,
        )
        record = {"phase": "PresentationVerify", "component": "verifyORProof", "time_ms": 1.0}

        with mock.patch.object(bench, "run_protocol", return_value=[record]), mock.patch(
            "benchmark_and_plot.time.sleep"
        ) as sleep:
            rows = bench.collect_benchmarks(args)

        self.assertEqual(len(rows), 2)
        sleep.assert_called_once_with(0.01)

    def test_resolve_executable_prefers_existing_relative_file(self):
        with TemporaryDirectory() as tmp_dir:
            executable = Path(tmp_dir) / "main_multi_issuer"
            executable.write_text("", encoding="utf-8")

            resolved = bench.resolve_executable(Path(tmp_dir) / "." / "main_multi_issuer")

            self.assertEqual(resolved, executable.resolve())

    def test_resolve_executable_prefers_exe_on_windows(self):
        with TemporaryDirectory() as tmp_dir:
            unix_binary = Path(tmp_dir) / "main_multi_issuer"
            windows_binary = Path(tmp_dir) / "main_multi_issuer.exe"
            unix_binary.write_text("", encoding="utf-8")
            windows_binary.write_text("", encoding="utf-8")

            with mock.patch.object(bench.os, "name", "nt"):
                resolved = bench.resolve_executable(unix_binary)

            self.assertEqual(resolved, windows_binary.resolve())

    def test_write_summary_wide_csv_uses_observation_friendly_bilingual_header(self):
        raw_rows = [
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationVerify",
                "component": "verifyORProof",
                "run_id": 1,
                "time_ms": 10.0,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            }
        ]
        summary_rows = bench.summarize_rows(raw_rows)

        with TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "performance_results.csv"
            bench.write_summary_wide_csv(output_path, summary_rows)

            with output_path.open(newline="", encoding="utf-8-sig") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)

        self.assertNotIn("record_type/record type", reader.fieldnames)
        self.assertIn("scheme/scheme", reader.fieldnames)
        self.assertIn("verifyORProof_mean_ms/OR proof verification mean milliseconds", reader.fieldnames)
        self.assertIn("verifyORProof_std_ms/OR proof verification stddev milliseconds", reader.fieldnames)
        self.assertTrue(all("/" in field for field in reader.fieldnames))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scheme/scheme"], "OurScheme")
        self.assertEqual(rows[0]["verifyORProof_runs/OR proof verification sample count"], "1")
        self.assertEqual(rows[0]["verifyORProof_mean_ms/OR proof verification mean milliseconds"], "10.0")

    def test_default_output_lives_under_results_directory(self):
        parser = bench.build_arg_parser()
        args = parser.parse_args([])

        self.assertEqual(args.output_xlsx, "results/performance_data.xlsx")
        self.assertFalse(hasattr(args, "output_csv"))
        self.assertFalse(hasattr(args, "runs_csv"))
        self.assertFalse(hasattr(args, "include_raw"))

    def test_append_summary_wide_csv_keeps_existing_batches(self):
        raw_rows = [
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationVerify",
                "component": "verifyORProof",
                "run_id": 1,
                "time_ms": 10.0,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            }
        ]
        summary_rows = bench.summarize_rows(raw_rows)

        with TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "performance_data.csv"
            bench.append_summary_wide_csv(
                output_path,
                summary_rows,
                experiment_id="exp-a",
                run_started_at="2026-05-20T10:00:00+08:00",
                notes="first batch",
            )
            bench.append_summary_wide_csv(
                output_path,
                summary_rows,
                experiment_id="exp-b",
                run_started_at="2026-05-20T11:00:00+08:00",
                notes="second batch",
            )

            with output_path.open(newline="", encoding="utf-8-sig") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["experiment_id/experiment id"], "exp-a")
        self.assertEqual(rows[1]["experiment_id/experiment id"], "exp-b")
        self.assertEqual(rows[1]["notes/notes"], "second batch")
        self.assertIn("verifyORProof_mean_ms/OR proof verification mean milliseconds", reader.fieldnames)

    def test_build_excel_summary_rows_exposes_paper_metrics(self):
        summary_rows = [
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "CredentialIssue",
                "component": "issueCredential",
                "runs": 3,
                "mean_ms": 20.0,
                "median_ms": 20.0,
                "std_ms": 1.0,
                "min_ms": 19.0,
                "max_ms": 21.0,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            },
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "CredentialVerify",
                "component": "verifySignature",
                "runs": 3,
                "mean_ms": 12.5,
                "median_ms": 12.5,
                "std_ms": 0.5,
                "min_ms": 12.0,
                "max_ms": 13.0,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            },
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationGen",
                "component": "generatePresentationPayload",
                "runs": 3,
                "mean_ms": 9.25,
                "median_ms": 9.25,
                "std_ms": 0.25,
                "min_ms": 9.0,
                "max_ms": 9.5,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            },
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "PresentationVerify",
                "component": "verifyORProof",
                "runs": 3,
                "mean_ms": 14.0,
                "median_ms": 14.0,
                "std_ms": 0.75,
                "min_ms": 13.5,
                "max_ms": 14.5,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            },
        ]

        rows = bench.build_excel_summary_rows(
            summary_rows,
            experiment_id="exp-1",
            run_started_at="2026-05-20T10:00:00+08:00",
            notes="xlsx only",
            warmup_runs=2,
        )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["signature_size_bytes/signature size bytes"], 128)
        self.assertEqual(row["issue_total_time_ms/multi-issuer issue time milliseconds"], 20.0)
        self.assertEqual(row["raw_signature_verify_time_ms/raw signature verification milliseconds"], 12.5)
        self.assertEqual(row["proof_size_bytes/proof size bytes"], 736)
        self.assertEqual(row["proof_generation_time_ms/proof generation milliseconds"], 9.25)
        self.assertEqual(row["proof_verification_time_ms/proof verification milliseconds"], 14.0)
        self.assertEqual(row["warmup_runs/warmup runs"], 2)
        self.assertEqual(row["issue_total_runs/issue valid run count"], 3)
        self.assertEqual(row["issue_total_std_ms/issue stddev milliseconds"], 1.0)
        self.assertEqual(row["issue_total_min_ms/issue min milliseconds"], 19.0)
        self.assertEqual(row["issue_total_max_ms/issue max milliseconds"], 21.0)
        self.assertEqual(row["proof_verification_runs/proof verification valid run count"], 3)
        self.assertEqual(row["proof_verification_std_ms/proof verification stddev milliseconds"], 0.75)

    def test_write_performance_workbook_creates_xlsx_with_paper_metrics(self):
        summary_rows = [
            {
                "scheme": "OurScheme",
                "num_attrs": 2,
                "num_issuers": 5,
                "num_other_issuers": 3,
                "num_disclosed": 0,
                "phase": "CredentialIssue",
                "component": "issueCredential",
                "runs": 1,
                "mean_ms": 20.0,
                "median_ms": 20.0,
                "std_ms": 0.0,
                "min_ms": 20.0,
                "max_ms": 20.0,
                "credential_bytes": 512,
                "proof_bytes": 736,
                "public_key_bytes": 2176,
                "signature_bytes": 128,
                "transcript_bytes": 1376,
            }
        ]

        with TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "performance_data.xlsx"
            bench.write_performance_workbook(
                output_path,
                summary_rows,
                experiment_id="exp-1",
                run_started_at="2026-05-20T10:00:00+08:00",
                notes="xlsx only",
                warmup_runs=2,
            )

            self.assertTrue(output_path.exists())
            with zipfile.ZipFile(output_path) as workbook_zip:
                sheet_xml = workbook_zip.read("xl/worksheets/sheet1.xml").decode("utf-8")

        self.assertIn("signature_size_bytes/signature size bytes", sheet_xml)
        self.assertIn("issue_total_time_ms/multi-issuer issue time milliseconds", sheet_xml)
        self.assertIn("issue_total_std_ms/issue stddev milliseconds", sheet_xml)
        self.assertIn("warmup_runs/warmup runs", sheet_xml)
        self.assertIn("proof_verification_time_ms/proof verification milliseconds", sheet_xml)


if __name__ == "__main__":
    unittest.main()
