#!/usr/bin/env python3
"""Score VyQL against the RealVuln benchmark, reusing RealVuln's own matcher.

Emits one NormalisedFinding per (result, CWE) pair from VyQL's SARIF, then defers
entirely to scorer.matcher / scorer.metrics so the numbers are produced by the same
code that scores semgrep, snyk and the LLM agents.

Usage:
    score_realvuln.py <realvuln-checkout> <vyql-binary> <VYQL_HOME> [--by-rule]

    --by-rule   rank rules by false-positive mass instead of printing per-repo
                scorecards. Same scan, same matcher, so the two views cannot
                disagree with each other.

The rule -> CWE mapping comes from the SARIF `tool.driver.rules` array VyQL
publishes. It used to be recovered by regex over vyql/packs/**, which coupled this
script to the knowledge layer's directory layout and `meta { }` syntax -- and broke
silently when v2 moved rules from flat files into nested directories, matching zero
of 728 rules and reporting a recall of zero that read like a measurement.
"""
import collections
import glob
import json
import os
import subprocess
import sys

argv = [a for a in sys.argv[1:] if not a.startswith("--")]
BY_RULE = "--by-rule" in sys.argv
if len(argv) < 3:
    sys.exit(__doc__)
RV, VYQL, VYQL_HOME = argv[0], argv[1], argv[2]

sys.path.insert(0, RV)
from parsers.base import NormalisedFinding, normalise_path  # noqa: E402
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402
from scorer.metrics import compute_scorecard  # noqa: E402

LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low"}


def scan(repo_path):
    env = dict(os.environ, VYQL_HOME=VYQL_HOME)
    # -fail-on none because this is a scorer, not a gate: every repo here is meant
    # to have findings, and the default threshold exits 3 on them. Without it the
    # exit code reports the corpus rather than whether vyql ran, and every repo is
    # discarded as a failed scan.
    p = subprocess.run([VYQL, "scan", "--format", "sarif", "-fail-on", "none", repo_path],
                       capture_output=True, text=True, env=env, timeout=1800)
    if p.returncode not in (0, 1) or not p.stdout.strip():
        return None
    return json.loads(p.stdout)


def rule_meta(run):
    """rule id -> (["CWE-nnn", ...], severity) from the run's own rule metadata."""
    out = {}
    for r in (run.get("tool") or {}).get("driver", {}).get("rules") or []:
        rid = r.get("id")
        if not rid:
            continue
        props = r.get("properties") or {}
        cwes = []
        for c in props.get("cwe") or []:
            n = str(c).strip().upper()
            for prefix in ("CWE_", "CWE-"):
                if n.startswith(prefix):
                    n = n[len(prefix):]
            if n:
                cwes.append("CWE-" + n)
        out[rid] = (cwes, props.get("severity", "?"))
    return out


def to_findings(sarif, sev_of):
    """One finding per (SARIF result x CWE of its rule).

    A VyQL rule may map to several CWEs; the matcher tests membership in the ground
    truth's acceptable_cwes, so emitting each lets any of them match.

    The fan-out is a matching device, not several claims: VyQL emits ONE result per
    (rule, sink). collapse_fanout() folds the verdicts back down so a single result
    contributes at most one TP or one FP.
    """
    out, has_meta = [], False
    if not sarif:
        return out, has_meta
    for run in sarif.get("runs", []):
        meta = rule_meta(run)
        for rid, (cwes, sev) in meta.items():
            sev_of[rid] = sev
            if cwes:
                has_meta = True
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("message") or {}).get("text") or ""
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = (phys.get("artifactLocation") or {}).get("uri", "")
            line = (phys.get("region") or {}).get("startLine")
            sev = LEVEL_SEV.get(res.get("level", "warning"), "medium")
            for cwe in meta.get(rid, ([], None))[0]:
                out.append(NormalisedFinding(
                    file=normalise_path(uri), cwe=cwe, line=line, function=None,
                    severity=sev, rule_id=rid,
                    message=(res.get("message") or {}).get("text"), scanner="vyql"))
    return out, has_meta


def collapse_fanout(matches):
    """Fold the (result x CWE) fan-out back to one verdict per emitted result.

    Without this, a rule carrying N CWEs books N false positives for a single
    reported finding, so a rule's measured precision falls purely with the length
    of its `cwe:` list. Measured: every one-CWE rule scored a 1.00 rows/distinct
    ratio, while three-CWE rules scored 2.6-2.9, and VYQL-AUTH-106 read as the
    corpus's second-worst offender (467 FPs) when it had emitted 181.

    A result that matched ground truth under ANY of its CWEs is one TP; otherwise
    it is one FP. FN/TN rows are per-ground-truth-entry, not per finding, so they
    pass through untouched.
    """
    out, seen = [], {}
    for m in matches:
        sf = m.scanner_finding
        if sf is None:                      # FN / TN: keyed on ground truth
            out.append(m)
            continue
        key = (sf.rule_id, sf.file, sf.line)
        prev = seen.get(key)
        if prev is None:
            seen[key] = m
            continue
        # a TP anywhere in the fan-out wins: some acceptable CWE did match
        if prev.classification != "TP" and m.classification == "TP":
            seen[key] = m
    return out + list(seen.values())


def main():
    families = json.load(open(os.path.join(RV, "config", "cwe-families.json")))
    rows, agg = [], {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    fp_by_rule, tp_by_rule, sev_of = collections.Counter(), collections.Counter(), {}
    saw_meta = False

    for repo_dir in sorted(glob.glob(os.path.join(RV, "repos", "*"))):
        repo_id = os.path.basename(repo_dir)
        gt_path = os.path.join(RV, "ground-truth", repo_id, "ground-truth.json")
        if not os.path.exists(gt_path):
            continue
        gt = load_ground_truth(gt_path)
        findings, has_meta = to_findings(scan(repo_dir), sev_of)
        saw_meta = saw_meta or has_meta
        matches = collapse_fanout(match_findings(findings, gt))
        sc = compute_scorecard(repo_id, "vyql", "2026-08-04", matches, families)
        rows.append(sc)
        for k in agg:
            agg[k] += getattr(sc, k)
        for m in matches:
            if m.scanner_finding is None:
                continue
            if m.classification == "TP":
                tp_by_rule[m.scanner_finding.rule_id] += 1
            elif m.classification == "FP":
                fp_by_rule[m.scanner_finding.rule_id] += 1
        if not BY_RULE:
            print(f"{repo_id:42s} TP={sc.tp:3d} FP={sc.fp:3d} FN={sc.fn:3d} "
                  f"TN={sc.tn:3d} prec={sc.precision:.3f} rec={sc.recall:.3f} "
                  f"J={sc.youden_j:+.3f}")

    if not rows:
        sys.exit(f"no repos under {RV}/repos -- run benchmarks/fetch-corpora.sh")
    if not saw_meta:
        sys.exit("VyQL's SARIF carried no rule CWE metadata, so every finding would "
                 "be dropped for want of a CWE and this run would report a recall of "
                 "zero. Rebuild the binary -- it predates the rule-metadata emission.")

    tp, fp, fn, tn = agg["tp"], agg["fp"], agg["fn"], agg["tn"]
    if BY_RULE:
        total = sum(fp_by_rule.values()) or 1
        print(f"repos scored: {len(rows)}   TP={tp}  FP={fp}")
        print(f"{'rule':<22}{'sev':<10}{'FP':>7}{'TP':>7}{'prec':>8}  {'cum%FP':>7}")
        cum = 0
        for rule, n in fp_by_rule.most_common(30):
            cum += n
            t = tp_by_rule[rule]
            print(f"{rule:<22}{sev_of.get(rule, '?'):<10}{n:>7}{t:>7}"
                  f"{t / (t + n):>8.3f}  {100 * cum / total:>6.1f}%")
        smell = [r for r in set(fp_by_rule) | set(tp_by_rule)
                 if r.startswith("VYQL-SMELL")]
        sfp = sum(fp_by_rule[r] for r in smell)
        print(f"\nVYQL-SMELL-* total: FP={sfp} ({100 * sfp / total:.1f}% of all FP)  "
              f"TP={sum(tp_by_rule[r] for r in smell)}")
    else:
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        print(f"\nPOOLED ({len(rows)} repos)  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"  precision={prec:.4f}  recall={rec:.4f}  FPR={fpr:.4f}  "
              f"Youden={rec - fpr:+.4f}")


if __name__ == "__main__":
    main()
