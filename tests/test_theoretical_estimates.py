import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import apply_theoretical_formulas as theory
import run_unit_benchmark as unit_bench


class TheoreticalEstimateTests(unittest.TestCase):
    def test_estimates_include_required_paper_metrics(self):
        unit_costs = {
            "T_E1": 0.4,
            "T_E2": 1.0,
            "T_ET": 2.5,
            "T_P": 6.0,
            "T_MP2": 8.0,
            "T_MP6": 16.0,
            "T_MP8": 20.0,
            "T_H": 0.03,
            "T_RZ": 0.001,
            "T_R1": 0.08,
            "T_INVZ": 0.004,
            "T_ZMUL": 0.0004,
        }

        rows = theory.build_theoretical_rows(
            dimensions=[{"num_attrs": 2, "num_issuers": 5, "num_other_issuers": 3, "num_disclosed": 0}],
            unit_costs=unit_costs,
        )

        schemes = {row["scheme"] for row in rows}
        self.assertEqual(schemes, {"BBS", "BBS+", "PS", "SPS-EQ"})
        for row in rows:
            for field in [
                "signature_size_bytes",
                "issue_total_time_ms",
                "raw_signature_verify_time_ms",
                "proof_size_bytes",
                "proof_generation_time_ms",
                "proof_verification_time_ms",
            ]:
                self.assertIn(field, row)
                self.assertGreater(row[field], 0)

    def test_bbs_independent_issuer_estimate_scales_by_issuer_count(self):
        unit_costs = {
            "T_E1": 0.4,
            "T_E2": 1.0,
            "T_ET": 2.5,
            "T_P": 6.0,
            "T_MP2": 8.0,
            "T_MP6": 16.0,
            "T_MP8": 20.0,
            "T_H": 0.03,
            "T_RZ": 0.001,
            "T_R1": 0.08,
            "T_INVZ": 0.004,
            "T_ZMUL": 0.0004,
        }

        row = theory.estimate_scheme_metrics("BBS", n=2, q=5, d=0, unit_costs=unit_costs)

        single_signature_time = (2 + 2) * 0.4 + 0.004 + 0.03
        single_signature_size = 64 + 32
        single_proof_size = 3 * 64 + (2 + 4) * 32
        self.assertAlmostEqual(row["issue_total_time_ms"], 5 * single_signature_time)
        self.assertEqual(row["signature_size_bytes"], 5 * single_signature_size)
        self.assertEqual(row["proof_size_bytes"], 5 * single_proof_size)

    def test_reads_unit_costs_and_dimensions_from_workbooks(self):
        unit_rows = [
            {
                "unit_id": "T_E1：G1标量乘",
                "unit_name": "G1 scalar multiplication",
                "operation": "pfc.mult(G1, scalar)",
                "samples": 3,
                "iterations_per_sample": 10,
                "mean_ms": 0.4,
                "median_ms": 0.4,
                "std_ms": 0.0,
                "min_ms": 0.4,
                "max_ms": 0.4,
                "notes": "",
            }
        ]
        performance_headers = [
            "scheme/方案",
            "num_attrs/属性数量",
            "num_issuers/签发方总数",
            "num_other_issuers/其他签发方数量",
            "num_disclosed/披露属性数量",
        ]
        performance_rows = [["OurScheme", 2, 5, 3, 0]]

        with TemporaryDirectory() as tmp_dir:
            unit_path = Path(tmp_dir) / "unit_costs.xlsx"
            perf_path = Path(tmp_dir) / "performance_data.xlsx"
            unit_bench.write_xlsx(
                unit_path,
                [
                    ("UnitCosts", unit_bench.UNIT_HEADERS, [[row.get(h, "") for h in unit_bench.UNIT_HEADERS] for row in unit_rows]),
                ],
            )
            unit_bench.write_xlsx(
                perf_path,
                [("Performance", performance_headers, performance_rows)],
            )

            unit_costs = theory.read_unit_costs(unit_path)
            dimensions = theory.read_experiment_dimensions(perf_path)

        self.assertEqual(unit_costs["T_E1"], 0.4)
        self.assertEqual(dimensions, [{"num_attrs": 2, "num_issuers": 5, "num_other_issuers": 3, "num_disclosed": 0}])

    def test_theoretical_workbook_uses_chinese_headers_and_explanations(self):
        unit_costs = {
            "T_E1": 0.4,
            "T_E2": 1.0,
            "T_ET": 2.5,
            "T_P": 6.0,
            "T_MP2": 8.0,
            "T_MP6": 16.0,
            "T_MP8": 20.0,
            "T_H": 0.03,
            "T_RZ": 0.001,
            "T_R1": 0.08,
            "T_INVZ": 0.004,
            "T_ZMUL": 0.0004,
        }
        rows = theory.build_theoretical_rows(
            dimensions=[{"num_attrs": 2, "num_issuers": 5, "num_other_issuers": 3, "num_disclosed": 0}],
            unit_costs=unit_costs,
        )

        with TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "theory.xlsx"
            theory.write_theoretical_workbook(output_path, rows, unit_costs)
            with zipfile.ZipFile(output_path) as workbook_zip:
                workbook_xml = workbook_zip.read("xl/workbook.xml").decode("utf-8")
                comparison_xml = workbook_zip.read("xl/worksheets/sheet1.xml").decode("utf-8")
                formulas_xml = workbook_zip.read("xl/worksheets/sheet3.xml").decode("utf-8")

        self.assertIn("理论对比", workbook_xml)
        self.assertIn("使用的单位耗时", workbook_xml)
        self.assertIn("操作数公式", workbook_xml)
        self.assertIn("签名大小字节", comparison_xml)
        self.assertIn("签名时间_多签发方总耗时毫秒", comparison_xml)
        self.assertIn("独立签发方", comparison_xml)
        self.assertIn("说明", formulas_xml)
        self.assertIn("证明大小按", formulas_xml)
        self.assertNotIn("signature_size_bytes", comparison_xml)
        self.assertNotIn("independent issuers", comparison_xml)
        self.assertNotIn("Approximation", formulas_xml)


if __name__ == "__main__":
    unittest.main()
