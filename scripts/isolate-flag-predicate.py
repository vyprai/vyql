#!/usr/bin/env python3
"""Isolate which predicate in a VyQL flag block prevents it from matching its spec.

Truncates the flag's predicate list to the first N predicates, runs the spec, and
reports the first N at which the rule stops firing. That predicate is the blocker.

usage: isolate-flag-predicate.py <adapter-file> <flag-start-line> <spec-run-pattern> <rule-id>
"""
import re
import subprocess
import sys

adapter, start_line, run_pat, rule_id = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

orig = open(adapter).read()
lines = orig.split("\n")

# The flag block runs from start_line (1-indexed) to its closing brace at the same indent.
i = start_line - 1
header = lines[i]
indent = len(header) - len(header.lstrip())
end = i + 1
while end < len(lines) and lines[end].strip() != "}":
    end += 1
preds = [l for l in lines[i + 1 : end] if l.strip()]

print(f"flag block: {adapter}:{start_line}  ({len(preds)} predicates)")
print(f"  {header.strip()}")


def run(n):
    """Rebuild the file with only the first n predicates; return True if the rule fires."""
    body = preds[:n]
    new = lines[:i] + [header] + body + [" " * indent + "}"] + lines[end + 1 :]
    open(adapter, "w").write("\n".join(new))
    r = subprocess.run(
        ["go", "test", "-count=1", "-run", run_pat, "./cmd/vyql/"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    return f"expected rule {rule_id}" not in r.stdout


try:
    blocker = None
    for n in range(1, len(preds) + 1):
        fires = run(n)
        mark = "FIRES  " if fires else "no fire"
        print(f"  {n:2d}  {mark}  +{preds[n-1].strip()}")
        if not fires and blocker is None:
            blocker = preds[n - 1].strip()
    print()
    print(f"BLOCKER: {blocker}" if blocker else "BLOCKER: none — fires with all predicates")
finally:
    open(adapter, "w").write(orig)
