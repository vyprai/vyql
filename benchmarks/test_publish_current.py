#!/usr/bin/env python3
"""publish_current.py patches only the live scores on a schema-1 report."""
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import publish_current as pc


def sample_report():
    return {
        "schema": 1,
        "generated": "2026-08-13",
        "corpora": "~/workspace/vypr/benchmark-corpora",
        "baseline": {"ref": "93fe745eb", "label": "v0.2.0", "date": "2026-08-04"},
        "current": {"ref": "54bcd4dfb", "label": "current", "date": "2026-08-13"},
        "notes": {"summary": "frozen prose"},
        "competitors": [
            {"name": "semgrep", "kind": "static", "recall": 0.07, "source": "published"}
        ],
        "competitorCaveat": "indicative",
        "xbow": {
            "benchmarks": 39,
            "note": "frozen note",
            "scanners": [
                {
                    "name": "VyQL",
                    "technical": [30, 35],
                    "nonTechnical": [8, 8],
                    "findings": 233,
                    "measured": "2026-08-13",
                },
                {
                    "name": "semgrep",
                    "technical": [19, 35],
                    "nonTechnical": [1, 8],
                    "findings": 298,
                    "measured": "2024-11-13",
                },
            ],
        },
        "owasp": {
            "BenchmarkJava": {
                "cmdi": {"baseline": [126, 0, 0, 125], "current": [126, 0, 0, 125]},
            },
            "BenchmarkPython": {
                "sqli": {"baseline": [5, 0, 0, 11], "current": [5, 0, 0, 11]},
            },
        },
        "ports": {"owasp-js": {"baseline": 1.0, "current": 1.0}},
        "realvuln": {
            "realvuln-djangoat": {
                "baseline": [20, 84, 32, 6],
                "current": [20, 79, 32, 6],
            },
        },
    }


OWASP_JAVA = """
category            TP    FN    FP    TN     TPR    FPR   Youden
cmdi               127     0     0   124    1.00   0.00    +1.00
OVERALL (avg Youden)                                                  +1.00
"""

OWASP_PYTHON = """
category            TP    FN    FP    TN     TPR    FPR   Youden
sqli                 5     0     1    10    1.00   0.09    +0.91
OVERALL (avg Youden)                                                  +0.91
"""

REALVULN = (
    "realvuln-djangoat                          "
    "TP= 21 FP= 70 FN= 31 TN=  6 prec=0.231 rec=0.404 J=-0.500\n"
    "\nPOOLED (1 repos)  TP=21 FP=70 FN=31 TN=6\n"
)

XBOW = """
XBEN-001  vulns= 1 detected= 1 findings= 16

technical       31/35   detection rate  88.6%
non_technical    8/8    detection rate 100.0%
benchmarks scanned: 39   total findings: 240
"""


class ParseTests(unittest.TestCase):
    def test_parse_owasp_suite_reads_tp_fn_fp_tn_as_tp_fp_fn_tn(self):
        got = pc.parse_owasp_suite(OWASP_JAVA)
        self.assertEqual(got, {"cmdi": [127, 0, 0, 124]})

    def test_parse_realvuln_reads_per_repo_counts(self):
        got = pc.parse_realvuln(REALVULN)
        self.assertEqual(got, {"realvuln-djangoat": [21, 70, 31, 6]})

    def test_parse_realvuln_reads_seeded_vc_repos(self):
        text = (
            "vc-claude-code-seeded-v2-crm-saas-django "
            "TP=  1 FP=  2 FN=  3 TN=  4 prec=0.333 rec=0.250 J=-0.500\n"
        )
        got = pc.parse_realvuln(text)
        self.assertEqual(got, {"vc-claude-code-seeded-v2-crm-saas-django": [1, 2, 3, 4]})

    def test_parse_xbow_reads_vyql_row(self):
        got = pc.parse_xbow(XBOW)
        self.assertEqual(
            got,
            {"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
        )


class PatchTests(unittest.TestCase):
    def test_patch_writes_current_scores_and_leaves_frozen_fields(self):
        report = sample_report()
        out = pc.patch_report(
            report,
            owasp={"BenchmarkJava": {"cmdi": [127, 0, 0, 124]},
                   "BenchmarkPython": {"sqli": [5, 0, 1, 10]}},
            realvuln={"realvuln-djangoat": [21, 70, 31, 6]},
            xbow={"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
            ref="abc123def",
            date="2026-08-19",
        )

        self.assertEqual(out["generated"], "2026-08-19")
        self.assertEqual(out["current"], {"ref": "abc123def", "label": "current", "date": "2026-08-19"})
        self.assertEqual(out["owasp"]["BenchmarkJava"]["cmdi"]["current"], [127, 0, 0, 124])
        self.assertEqual(out["owasp"]["BenchmarkJava"]["cmdi"]["baseline"], [126, 0, 0, 125])
        self.assertEqual(out["realvuln"]["realvuln-djangoat"]["current"], [21, 70, 31, 6])
        self.assertEqual(out["realvuln"]["realvuln-djangoat"]["baseline"], [20, 84, 32, 6])
        self.assertEqual(out["xbow"]["scanners"][0]["technical"], [31, 35])
        self.assertEqual(out["xbow"]["scanners"][0]["findings"], 240)
        self.assertEqual(out["xbow"]["scanners"][0]["measured"], "2026-08-19")

        self.assertEqual(out["baseline"], report["baseline"])
        self.assertEqual(out["notes"], report["notes"])
        self.assertEqual(out["ports"], report["ports"])
        self.assertEqual(out["competitors"], report["competitors"])
        self.assertEqual(out["xbow"]["note"], "frozen note")
        self.assertEqual(out["xbow"]["scanners"][1], report["xbow"]["scanners"][1])

    def test_patch_does_not_mutate_input(self):
        report = sample_report()
        snapshot = copy.deepcopy(report)
        pc.patch_report(
            report,
            owasp={"BenchmarkJava": {"cmdi": [127, 0, 0, 124]},
                   "BenchmarkPython": {"sqli": [5, 0, 1, 10]}},
            realvuln={"realvuln-djangoat": [21, 70, 31, 6]},
            xbow={"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
            ref="abc123def",
            date="2026-08-19",
        )
        self.assertEqual(report, snapshot)

    def test_shape_mismatch_on_missing_owasp_category(self):
        with self.assertRaises(pc.ShapeMismatch):
            pc.patch_report(
                sample_report(),
                owasp={"BenchmarkJava": {}, "BenchmarkPython": {"sqli": [5, 0, 1, 10]}},
                realvuln={"realvuln-djangoat": [21, 70, 31, 6]},
                xbow={"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
                ref="abc123def",
                date="2026-08-19",
            )

    def test_shape_mismatch_on_extra_realvuln_repo(self):
        with self.assertRaises(pc.ShapeMismatch):
            pc.patch_report(
                sample_report(),
                owasp={"BenchmarkJava": {"cmdi": [127, 0, 0, 124]},
                       "BenchmarkPython": {"sqli": [5, 0, 1, 10]}},
                realvuln={
                    "realvuln-djangoat": [21, 70, 31, 6],
                    "realvuln-vampi": [1, 2, 3, 4],
                },
                xbow={"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
                ref="abc123def",
                date="2026-08-19",
            )

    def test_shape_mismatch_does_not_put_counts_in_the_message(self):
        with self.assertRaises(pc.ShapeMismatch) as ctx:
            pc.patch_report(
                sample_report(),
                owasp={"BenchmarkJava": {"cmdi": [127, 0, 0, 124]},
                       "BenchmarkPython": {"sqli": [5, 0, 1, 10]}},
                realvuln={
                    "realvuln-djangoat": [21, 70, 31, 6],
                    "realvuln-vampi": [1, 2, 3, 4],
                },
                xbow={"technical": [31, 35], "nonTechnical": [8, 8], "findings": 240, "benchmarks": 39},
                ref="abc123def",
                date="2026-08-19",
            )
        self.assertNotRegex(str(ctx.exception), r"\b\d+\b")


class CliTests(unittest.TestCase):
    def test_cli_writes_report_and_prints_no_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report_path = tmp / "latest.json"
            out_path = tmp / "out.json"
            java = tmp / "java.txt"
            python = tmp / "python.txt"
            rv = tmp / "rv.txt"
            xbow = tmp / "xbow.txt"
            report_path.write_text(json.dumps(sample_report()))
            java.write_text(OWASP_JAVA)
            python.write_text(OWASP_PYTHON)
            rv.write_text(REALVULN)
            xbow.write_text(XBOW)

            buf = io.StringIO()
            with patch("sys.stdout", buf), patch("sys.stderr", buf):
                pc.main([
                    "--report", str(report_path),
                    "--owasp", f"BenchmarkJava={java}",
                    "--owasp", f"BenchmarkPython={python}",
                    "--realvuln", str(rv),
                    "--xbow", str(xbow),
                    "--ref", "abc123def",
                    "--date", "2026-08-19",
                    "--out", str(out_path),
                ])
            printed = buf.getvalue()
            for n in ("127", "124", "21", "70", "240", "31"):
                self.assertNotIn(n, printed)

            out = json.loads(out_path.read_text())
            self.assertEqual(out["owasp"]["BenchmarkJava"]["cmdi"]["current"], [127, 0, 0, 124])
            self.assertEqual(out["xbow"]["scanners"][0]["findings"], 240)


if __name__ == "__main__":
    unittest.main()
