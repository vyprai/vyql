#!/usr/bin/env python3
"""Score VyQL against the XBOW validation benchmarks.

Follows the methodology in that repo's own `results/scanner_performance_summary_*.json`:
a known vulnerability counts as detected when a finding lands in the same file with a
line inside its recorded range, and the corpus splits into `technical` vulnerabilities
(the ones a static analyser can reach) and `non_technical` ones.

usage: score_xbow.py <validation-benchmarks> <vyql-binary> <VYQL_HOME> [line-tolerance]
"""
import glob
import json
import os
import re
import subprocess
import sys

V = sys.argv[1]
VYQL = sys.argv[2]
HOME = sys.argv[3]
TOL = int(sys.argv[4]) if len(sys.argv) > 4 else 10


def known_vulns():
    """benchmark id -> [(is_technical, [(relpath, start, end), ...]), ...]"""
    out = {}
    for p in sorted(glob.glob(os.path.join(V, "rules", "*_vulns.json"))):
        bid = re.match(r"(XBEN-\d+)", os.path.basename(p))
        if not bid:
            continue
        entries = []
        for v in json.load(open(p)).get("vulnerabilities", []):
            locs = [
                (loc["file_path"], loc.get("start_line"), loc.get("end_line"))
                for loc in v.get("valid_vulns", [])
                if loc.get("file_path")
            ]
            if locs:
                entries.append((bool(v.get("is_technical")), locs))
        if entries:
            out.setdefault(bid.group(1), []).extend(entries)
    return out


def scan(path):
    env = dict(os.environ, VYQL_HOME=HOME)
    try:
        p = subprocess.run([VYQL, "scan", "--format", "sarif", path],
                           capture_output=True, text=True, env=env, timeout=1800)
    except subprocess.TimeoutExpired:
        return []
    if not p.stdout.strip():
        return []
    try:
        sarif = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    found = []
    for run in sarif.get("runs", []):
        for res in run.get("results") or []:
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation", {})
                uri = (phys.get("artifactLocation") or {}).get("uri", "")
                line = (phys.get("region") or {}).get("startLine")
                if uri:
                    found.append((uri.replace("\\", "/").lstrip("./"), line))
    return found


def hit(locs, findings):
    """Did any finding land in one of this vulnerability's recorded ranges?"""
    for want_path, start, end in locs:
        tail = want_path.split("/", 2)[-1] if want_path.startswith("benchmarks/") else want_path
        for got_path, line in findings:
            # ground-truth paths are repo-relative; findings are scan-root-relative
            if not (got_path.endswith(tail) or tail.endswith(got_path)):
                continue
            if line is None or start is None:
                return True
            if start - TOL <= line <= (end or start) + TOL:
                return True
    return False


vulns = known_vulns()
tech = {"tp": 0, "total": 0}
nont = {"tp": 0, "total": 0}
scanned = 0
total_findings = 0

for bid, entries in sorted(vulns.items()):
    dirs = glob.glob(os.path.join(V, "benchmarks", bid + "-*"))
    if not dirs:
        continue
    findings = scan(dirs[0])
    scanned += 1
    total_findings += len(findings)
    btp = 0
    for is_tech, locs in entries:
        bucket = tech if is_tech else nont
        bucket["total"] += 1
        if hit(locs, findings):
            bucket["tp"] += 1
            btp += 1
    print(f"{bid}  vulns={len(entries):2d} detected={btp:2d} findings={len(findings):3d}")

print()
for name, b in (("technical", tech), ("non_technical", nont)):
    rate = 100.0 * b["tp"] / b["total"] if b["total"] else 0.0
    print(f"{name:14s} {b['tp']:3d}/{b['total']:<3d}  detection rate {rate:5.1f}%")
print(f"benchmarks scanned: {scanned}   total findings: {total_findings}")
