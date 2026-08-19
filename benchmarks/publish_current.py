#!/usr/bin/env python3
"""Patch live scores into an existing schema-1 benchmarks report.

Reads scorer stdout and overwrites generated, current.{ref,date},
owasp.*.*.current, realvuln.*.current, and the VyQL row under xbow.scanners.
Everything else in the report is left as it is.

Exits without writing if the OWASP categories, RealVuln repositories, or XBOW
shape do not match the report. Prints no counts.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any


class ShapeMismatch(Exception):
    """The new scores do not cover the same keys as the report."""


OWASP_ROW = re.compile(r"^([a-z]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s")
RV_ROW = re.compile(r"(\S+)\s+TP=\s*(\d+) FP=\s*(\d+) FN=\s*(\d+) TN=\s*(\d+)")
XBOW_TECH = re.compile(r"^technical\s+(\d+)/(\d+)\b", re.M)
XBOW_NONT = re.compile(r"^non_technical\s+(\d+)/(\d+)\b", re.M)
XBOW_FINDINGS = re.compile(r"total findings:\s+(\d+)")
XBOW_BENCH = re.compile(r"benchmarks scanned:\s+(\d+)")


def parse_owasp_suite(text: str) -> dict[str, list[int]]:
    """Category -> [tp, fp, fn, tn]. Scorer columns are TP FN FP TN."""
    out: dict[str, list[int]] = {}
    for ln in text.splitlines():
        m = OWASP_ROW.match(ln.strip())
        if not m:
            continue
        cat, tp, fn, fp, tn = m.group(1), *map(int, m.groups()[1:])
        out[cat] = [tp, fp, fn, tn]
    return out


def parse_realvuln(text: str) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for ln in text.splitlines():
        m = RV_ROW.match(ln.strip())
        if not m:
            continue
        repo = m.group(1)
        if not repo.startswith("realvuln-"):
            continue
        out[repo] = [int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))]
    return out


def parse_xbow(text: str) -> dict[str, Any]:
    tech, nont, findings, benches = XBOW_TECH.search(text), XBOW_NONT.search(text), XBOW_FINDINGS.search(text), XBOW_BENCH.search(text)
    if not (tech and nont and findings and benches):
        raise ShapeMismatch("xbow summary lines are missing")
    return {
        "technical": [int(tech.group(1)), int(tech.group(2))],
        "nonTechnical": [int(nont.group(1)), int(nont.group(2))],
        "findings": int(findings.group(1)),
        "benchmarks": int(benches.group(1)),
    }


def _require_keys(path: str, expected: set[str], got: set[str]) -> None:
    if expected == got:
        return
    extra = ", ".join(sorted(got - expected)) or "(none)"
    missing = ", ".join(sorted(expected - got)) or "(none)"
    raise ShapeMismatch(f"{path} keys differ; extra {extra}; missing {missing}")


def patch_report(
    report: dict[str, Any],
    *,
    owasp: dict[str, dict[str, list[int]]],
    realvuln: dict[str, list[int]],
    xbow: dict[str, Any],
    ref: str,
    date: str,
) -> dict[str, Any]:
    out = copy.deepcopy(report)

    _require_keys("owasp", set(out["owasp"]), set(owasp))
    for suite, cats in out["owasp"].items():
        _require_keys(f"owasp.{suite}", set(cats), set(owasp[suite]))
        for cat in cats:
            cats[cat]["current"] = list(owasp[suite][cat])

    _require_keys("realvuln", set(out["realvuln"]), set(realvuln))
    for repo in out["realvuln"]:
        out["realvuln"][repo]["current"] = list(realvuln[repo])

    if out.get("xbow") is None:
        raise ShapeMismatch("xbow is absent from the report")
    if xbow["benchmarks"] != out["xbow"]["benchmarks"]:
        raise ShapeMismatch("xbow.benchmarks does not match the report")
    vyql = next((s for s in out["xbow"]["scanners"] if s.get("name") == "VyQL"), None)
    if vyql is None:
        raise ShapeMismatch("xbow scanners do not include VyQL")
    vyql["technical"] = list(xbow["technical"])
    vyql["nonTechnical"] = list(xbow["nonTechnical"])
    vyql["findings"] = xbow["findings"]
    vyql["measured"] = date

    out["generated"] = date
    out["current"] = {
        "ref": ref,
        "label": out["current"].get("label", "current"),
        "date": date,
    }
    return out


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", required=True)
    p.add_argument("--owasp", action="append", default=[], metavar="SUITE=PATH")
    p.add_argument("--realvuln", required=True)
    p.add_argument("--xbow", required=True)
    p.add_argument("--ref", required=True)
    p.add_argument("--date", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    owasp: dict[str, dict[str, list[int]]] = {}
    for item in args.owasp:
        suite, path = item.split("=", 1)
        owasp[suite] = parse_owasp_suite(Path(path).read_text())

    try:
        patched = patch_report(
            json.loads(Path(args.report).read_text()),
            owasp=owasp,
            realvuln=parse_realvuln(Path(args.realvuln).read_text()),
            xbow=parse_xbow(Path(args.xbow).read_text()),
            ref=args.ref,
            date=args.date,
        )
    except ShapeMismatch as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e

    Path(args.out).write_text(json.dumps(patched, indent=2) + "\n")


if __name__ == "__main__":
    main()
