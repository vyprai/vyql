#!/usr/bin/env python3
"""Score VyQL against the RealVuln benchmark, reusing RealVuln's own matcher.

Emits one NormalisedFinding per (result, CWE) pair from VyQL's SARIF, then defers
entirely to scorer.matcher / scorer.metrics so the numbers are produced by the same
code that scores semgrep, snyk and the LLM agents.
"""
import glob
import json
import os
import re
import subprocess
import sys

RV = sys.argv[1]        # Real-Vuln-Benchmark checkout
VYQL = sys.argv[2]      # vyql binary
VYQL_HOME = sys.argv[3] # VYQL_HOME data dir
PACKS = sys.argv[4]     # vyql/packs dir

sys.path.insert(0, RV)
from parsers.base import NormalisedFinding, normalise_path  # noqa: E402
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402
from scorer.metrics import compute_scorecard  # noqa: E402


def rule_cwes():
    """rule id -> [CWE-nnn], read from the shipped rule packs."""
    out = {}
    for f in glob.glob(os.path.join(PACKS, "*.vyql")):
        for m in re.finditer(r"meta\s*\{([^}]*)\}", open(f).read()):
            body = m.group(1)
            rid = re.search(r'id:\s*"([^"]+)"', body)
            cwes = re.findall(r"CWE_(\d+)", body)
            if rid and cwes:
                out[rid.group(1)] = ["CWE-" + c for c in cwes]
    return out


CWES = rule_cwes()


def scan(repo_path):
    env = dict(os.environ, VYQL_HOME=VYQL_HOME)
    p = subprocess.run([VYQL, "scan", "--format", "sarif", repo_path],
                       capture_output=True, text=True, env=env, timeout=1800)
    if p.returncode not in (0, 1) or not p.stdout.strip():
        return None
    return json.loads(p.stdout)


def to_findings(sarif):
    """One finding per (SARIF result x CWE of its rule).

    A VyQL rule may map to several CWEs; the matcher tests membership in the ground
    truth's acceptable_cwes, so emitting each lets any of them match. Duplicates on
    the same (file, line) collapse in the matcher.
    """
    out = []
    if not sarif:
        return out
    for run in sarif.get("runs", []):
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("message") or {}).get("text") or ""
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = (phys.get("artifactLocation") or {}).get("uri", "")
            line = (phys.get("region") or {}).get("startLine")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(
                res.get("level", "warning"), "medium")
            for cwe in CWES.get(rid, []):
                out.append(NormalisedFinding(
                    file=normalise_path(uri), cwe=cwe, line=line, function=None,
                    severity=sev, rule_id=rid,
                    message=(res.get("message") or {}).get("text"), scanner="vyql"))
    return out


families = json.load(open(os.path.join(RV, "config", "cwe-families.json")))
rows, agg = [], {"tp": 0, "fp": 0, "fn": 0, "tn": 0}

for repo_dir in sorted(glob.glob(os.path.join(RV, "repos", "*"))):
    repo_id = os.path.basename(repo_dir)
    gt_path = os.path.join(RV, "ground-truth", repo_id, "ground-truth.json")
    if not os.path.exists(gt_path):
        continue
    gt = load_ground_truth(gt_path)
    findings = to_findings(scan(repo_dir))
    matches = match_findings(findings, gt)
    sc = compute_scorecard(repo_id, "vyql", "2026-08-03", matches, families)
    rows.append(sc)
    for k in agg:
        agg[k] += getattr(sc, k)
    print(f"{repo_id:42s} TP={sc.tp:3d} FP={sc.fp:3d} FN={sc.fn:3d} TN={sc.tn:3d} "
          f"prec={sc.precision:.3f} rec={sc.recall:.3f} J={sc.youden_j:+.3f}")

tp, fp, fn, tn = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
prec = tp / (tp + fp) if tp + fp else 0.0
rec = tp / (tp + fn) if tp + fn else 0.0
fpr = fp / (fp + tn) if fp + tn else 0.0
print(f"\nPOOLED ({len(rows)} repos)  TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"  precision={prec:.4f}  recall={rec:.4f}  FPR={fpr:.4f}  Youden={rec-fpr:+.4f}")
