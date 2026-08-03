#!/usr/bin/env python3
"""Attribute RealVuln false positives to the rules that produced them.

Same matcher as score_realvuln.py, but keeps the rule id on each classified
finding so the FP mass can be ranked. Precision work needs to know which rules
cost what, not which rules feel noisy.
"""
import glob
import json
import os
import re
import subprocess
import sys
import collections

R, VYQL, HOME, PACKS = sys.argv[1:5]
sys.path.insert(0, R)
from parsers.base import NormalisedFinding, normalise_path  # noqa: E402
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402

cwes, sev = {}, {}
for f in glob.glob(os.path.join(PACKS, '**', '*.vyql'), recursive=True):
    body = open(f).read()
    for m in re.finditer(r'meta \{([^}]*)\}', body):
        b = m.group(1)
        rid = re.search(r'id: "([^"]+)"', b)
        cs = re.findall(r'CWE_(\d+)', b)
        sv = re.search(r'severity: (\w+)', b)
        if rid and cs:
            cwes[rid.group(1)] = ['CWE-' + x for x in cs]
            sev[rid.group(1)] = sv.group(1) if sv else '?'
if len(cwes) < 100:
    sys.exit(f"only {len(cwes)} rules resolved under {PACKS}")

tp = collections.Counter()
fp = collections.Counter()
repos = 0
for d in sorted(glob.glob(os.path.join(R, 'repos', '*'))):
    rid = os.path.basename(d)
    gtp = os.path.join(R, 'ground-truth', rid, 'ground-truth.json')
    if not os.path.exists(gtp):
        continue
    gt = load_ground_truth(gtp)
    try:
        p = subprocess.run([VYQL, 'scan', '--format', 'sarif', d], capture_output=True,
                           text=True, env=dict(os.environ, VYQL_HOME=HOME), timeout=1800)
        sar = json.loads(p.stdout)
    except Exception:
        continue
    repos += 1
    fs = []
    for run in sar.get('runs', []):
        for res in run.get('results') or []:
            r = res.get('ruleId') or ''
            L = res.get('locations') or []
            if not L:
                continue
            ph = L[0].get('physicalLocation', {})
            for cwe in cwes.get(r, []):
                fs.append(NormalisedFinding(
                    file=normalise_path((ph.get('artifactLocation') or {}).get('uri', '')),
                    cwe=cwe, line=(ph.get('region') or {}).get('startLine'), function=None,
                    severity='medium', rule_id=r, message=None, scanner='vyql'))
    for mr in match_findings(fs, gt):
        r = getattr(mr.scanner_finding, 'rule_id', None) or '?'
        if mr.classification == 'TP':
            tp[r] += 1
        elif mr.classification == 'FP':
            fp[r] += 1

print(f"repos scored: {repos}   TP={sum(tp.values())}  FP={sum(fp.values())}")
print(f"{'rule':<22}{'sev':<10}{'FP':>7}{'TP':>7}{'prec':>8}  {'cum%FP':>7}")
tot = sum(fp.values()) or 1
cum = 0
for r, n in fp.most_common(30):
    cum += n
    t = tp[r]
    print(f"{r:<22}{sev.get(r,'?'):<10}{n:>7}{t:>7}{(t/(t+n)):>8.3f}  {100*cum/tot:>6.1f}%")
print()
smell = [r for r in set(list(fp) + list(tp)) if r.startswith('VYQL-SMELL')]
sfp, stp = sum(fp[r] for r in smell), sum(tp[r] for r in smell)
print(f"VYQL-SMELL-* total: FP={sfp} ({100*sfp/tot:.1f}% of all FP)  TP={stp}")
info = [r for r in set(list(fp) + list(tp)) if sev.get(r) == 'info']
ifp, itp = sum(fp[r] for r in info), sum(tp[r] for r in info)
print(f"severity=info total: FP={ifp} ({100*ifp/tot:.1f}% of all FP)  TP={itp}")
