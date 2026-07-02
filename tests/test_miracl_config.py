import re
import unittest
from pathlib import Path

import run_issuer_hiding_measurements as issuer_hiding


ROOT = Path(__file__).resolve().parents[1]
MIRACL_CONFIGS = [
    ROOT / "Algorithm" / "mirdef.hpp",
    ROOT / "Algorithm" / "mirdef.h",
    ROOT / "Algorithm" / "MIRACL" / "mirdef.hpp",
    ROOT / "Algorithm" / "MIRACL" / "mirdef.h",
]
REMOVED_WINDOWS_BUILD_FILES = [
    ROOT / "Algorithm" / "MIRACL" / "mingw.bat",
    ROOT / "Algorithm" / "MIRACL" / "mirdef.mgw",
]
LINUX_MIRACL_MAKEFILE = ROOT / "Algorithm" / "MIRACL" / "Makefile"


def macro_value(text: str, name: str) -> str | None:
    match = re.search(rf"^\s*#define\s+{re.escape(name)}(?:\s+(.+?))?\s*$", text, re.MULTILINE)
    if not match:
        return None
    value = match.group(1)
    return "" if value is None else value.strip()


class MiraclConfigTests(unittest.TestCase):
    def test_active_miracl_configs_use_one_linux_cpp_64bit_abi(self):
        reference = None
        for path in MIRACL_CONFIGS:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                macros = {
                    "MIRACL": macro_value(text, "MIRACL"),
                    "mr_utype": macro_value(text, "mr_utype"),
                    "mr_unsign64": macro_value(text, "mr_unsign64"),
                    "MR_LBITS": macro_value(text, "MR_LBITS"),
                    "MR_CPP": macro_value(text, "MR_CPP"),
                }
                self.assertEqual(macros["MIRACL"], "64")
                self.assertEqual(macros["mr_utype"], "long")
                self.assertEqual(macros["mr_unsign64"], "unsigned long")
                self.assertEqual(macros["MR_LBITS"], "64")
                self.assertEqual(macros["MR_CPP"], "")
                if reference is None:
                    reference = macros
                self.assertEqual(macros, reference)

    def test_linux_makefile_syncs_generated_config_to_parent_include_dir(self):
        text = LINUX_MIRACL_MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("cp mirdef.hpp mirdef.h", text)
        self.assertIn("cp mirdef.h ../mirdef.h", text)
        self.assertIn("cp mirdef.hpp ../mirdef.hpp", text)

    def test_windows_only_build_files_are_not_active(self):
        for path in REMOVED_WINDOWS_BUILD_FILES:
            with self.subTest(path=path):
                self.assertFalse(path.exists())
        self.assertFalse(any("mgw" in str(path).lower() for path in issuer_hiding.MIRACL_CONFIGS))

    def test_experiment_runner_validates_current_miracl_archive(self):
        issuer_hiding.validate_miracl_build()
