#!/usr/bin/env python3
"""Serial VyQL scan benchmark harness.

Runs cache-off scans one target at a time, captures phase timings, optional
per-rule timings, CPU/heap profiles, finding counts, and canonical output hashes.
The output is intentionally plain files plus a JSON summary so results can be
checked into progress notes without depending on a benchmark service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


TIMING_RE = re.compile(
    r"^\[timing\]\s+(\S+)\s+([0-9.]+)ms\s+\(total\s+([0-9.]+)ms\)"
)
RULE_RE = re.compile(r"^\[rule\]\s+(.+?)\s+([0-9.]+)ms\s+([0-9]+)\s+finding")
RULE_NAME_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RULE_ID_RE = re.compile(r"\bid\s*:\s*\"([^\"]+)\"")
MODULE_RE = re.compile(r"^\s*module\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)
TAINT_RE = re.compile(
    r"\btaint\s+([A-Za-z0-9_.]+)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*->\s*"
    r"([A-Za-z0-9_.]+)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?"
)
ISSUE_RE = re.compile(r"\bissue\s+([A-Za-z0-9_.]+)")
MATCH_RE = re.compile(r"\bmatch\s+([A-Za-z0-9_.]+)")
ORDER_RE = re.compile(
    r"\border\s+([A-Za-z0-9_.]+)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s+before\s+"
    r"([A-Za-z0-9_.]+)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?"
)
COVERED_BY_RE = re.compile(
    r"\bunless\s+(?:(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z]+)\s+)?coveredBy\s+([A-Za-z0-9_.]+)"
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def sanitize_name(path: Path) -> str:
    s = path.name or "target"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("._") or "target"


def build_cli(go_dir: Path, binary: Path) -> None:
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/vyql"],
        cwd=go_dir,
        check=True,
    )


def parse_timings(stderr: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in stderr.splitlines():
        m = TIMING_RE.match(line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def parse_rule_timings(stderr: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in stderr.splitlines():
        m = RULE_RE.match(line)
        if not m:
            continue
        rows.append(
            {
                "rule": m.group(1).strip(),
                "ms": float(m.group(2)),
                "findings": int(m.group(3)),
            }
        )
    rows.sort(key=lambda r: (-r["ms"], r["rule"]))
    return rows


def load_rule_catalog(vyql_home: Path) -> dict[str, dict[str, Any]]:
    packs = vyql_home / "packs"
    catalog: dict[str, dict[str, Any]] = {}
    if not packs.exists():
        return catalog
    for path in sorted(packs.rglob("*.vyql")):
        text = path.read_text(errors="replace")
        name_match = RULE_NAME_RE.search(text)
        if not name_match:
            continue
        rule_name = name_match.group(1)
        module_match = MODULE_RE.search(text)
        qualified = rule_name
        if module_match:
            qualified = module_match.group(1) + "." + rule_name
        rule_id_match = RULE_ID_RE.search(text)
        rule_id = rule_id_match.group(1) if rule_id_match else qualified
        meta = {
            "id": rule_id,
            "name": qualified,
            "source_file": str(path),
            "verb": "unknown",
            "source_concept": "",
            "sink_concept": "",
            "coverage": [],
        }
        if m := TAINT_RE.search(text):
            meta["verb"] = "taint"
            meta["source_concept"] = m.group(1)
            meta["sink_concept"] = m.group(2)
        elif m := ISSUE_RE.search(text):
            meta["verb"] = "issue"
            meta["sink_concept"] = m.group(1)
        elif m := MATCH_RE.search(text):
            meta["verb"] = "match"
            meta["sink_concept"] = m.group(1)
        elif m := ORDER_RE.search(text):
            meta["verb"] = "order"
            meta["source_concept"] = m.group(1)
            meta["sink_concept"] = m.group(2)
        coverage = []
        for cov in COVERED_BY_RE.finditer(text):
            mode = cov.group(1) or "path"
            coverage.append({"mode": mode, "concept": cov.group(2)})
        coverage.sort(key=lambda x: (x["mode"], x["concept"]))
        meta["coverage"] = coverage
        catalog[rule_id] = meta
        catalog[qualified] = meta
    return catalog


def enrich_rule_timings(
    rows: list[dict[str, Any]], catalog: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        enriched = dict(row)
        meta = catalog.get(row["rule"], {})
        enriched.update(
            {
                "verb": meta.get("verb", "unknown"),
                "source_concept": meta.get("source_concept", ""),
                "sink_concept": meta.get("sink_concept", ""),
                "coverage": meta.get("coverage", []),
                "definition": meta.get("source_file", ""),
            }
        )
        out.append(enriched)
    return out


def group_rule_timings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        coverage_key = ",".join(
            f"{c.get('mode', '')}:{c.get('concept', '')}" for c in row.get("coverage", [])
        )
        key = (
            row.get("verb", "unknown"),
            row.get("source_concept", ""),
            row.get("sink_concept", ""),
            coverage_key,
        )
        g = groups.setdefault(
            key,
            {
                "verb": key[0],
                "source_concept": key[1],
                "sink_concept": key[2],
                "coverage_key": key[3],
                "rules": [],
                "total_ms": 0.0,
                "findings": 0,
            },
        )
        g["rules"].append(row["rule"])
        g["total_ms"] += row["ms"]
        g["findings"] += row["findings"]
    out = list(groups.values())
    for g in out:
        g["rules"] = sorted(g["rules"])
        g["rule_count"] = len(g["rules"])
        g["total_ms"] = round(g["total_ms"], 3)
    out.sort(key=lambda g: (-g["total_ms"], g["verb"], g["source_concept"], g["sink_concept"]))
    return out


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def finding_count(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("findings", "Findings"):
            val = payload.get(key)
            if isinstance(val, list):
                return len(val)
    return 0


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text()), None
    except Exception as exc:  # noqa: BLE001 - summary should record decode failures
        return None, str(exc)


def pprof_top(go_dir: Path, binary: Path, profile: Path, mode: str, out: Path) -> None:
    if not profile.exists() or profile.stat().st_size == 0:
        return
    cmd = ["go", "tool", "pprof", "-top"]
    if mode == "heap":
        cmd.append("-alloc_space")
    cmd.extend([str(binary), str(profile)])
    with out.open("w") as fh:
        subprocess.run(cmd, cwd=go_dir, stdout=fh, stderr=subprocess.STDOUT, check=False)


def run_scan(
    *,
    binary: Path,
    go_dir: Path,
    vyql_home: Path,
    target: Path,
    out_dir: Path,
    run_id: int,
    timeout: int,
    include_rule_timing: bool,
    profile: bool,
    rule_catalog: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    prefix = f"{sanitize_name(target)}-run{run_id}"
    json_out = out_dir / f"{prefix}.json"
    stderr_out = out_dir / f"{prefix}.err"
    cpu_profile = out_dir / f"{prefix}.cpu.prof"
    heap_profile = out_dir / f"{prefix}.heap.prof"

    env = os.environ.copy()
    env["VYQL_HOME"] = str(vyql_home)
    env["VYQL_TIMING"] = "1"
    if include_rule_timing:
        env["VYQL_RULE_TIMING"] = "1"
    else:
        env.pop("VYQL_RULE_TIMING", None)
    if profile:
        env["VYQL_CPUPROFILE"] = str(cpu_profile)
        env["VYQL_MEMPROFILE"] = str(heap_profile)
    else:
        env.pop("VYQL_CPUPROFILE", None)
        env.pop("VYQL_MEMPROFILE", None)

    cmd = [str(binary), "scan", "-cache", "off", "-format", "json", str(target)]
    started = time.monotonic()
    timed_out = False
    return_code = 0
    with json_out.open("w") as stdout_fh, stderr_out.open("w") as stderr_fh:
        try:
            proc = subprocess.run(
                cmd,
                cwd=go_dir,
                env=env,
                stdout=stdout_fh,
                stderr=stderr_fh,
                timeout=timeout,
                check=False,
            )
            return_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            return_code = 124
    elapsed_ms = (time.monotonic() - started) * 1000.0

    stderr = stderr_out.read_text(errors="replace") if stderr_out.exists() else ""
    payload, json_error = load_json(json_out)
    canon_hash = ""
    count = 0
    if payload is not None:
        canon = canonical_json(payload)
        canon_hash = hashlib.sha256(canon.encode()).hexdigest()
        count = finding_count(payload)

    rule_timings = enrich_rule_timings(parse_rule_timings(stderr), rule_catalog)
    rule_groups = group_rule_timings(rule_timings)
    if rule_timings:
        (out_dir / f"{prefix}.rules.json").write_text(
            json.dumps(rule_timings, indent=2, sort_keys=True) + "\n"
        )
        (out_dir / f"{prefix}.rule-groups.json").write_text(
            json.dumps(rule_groups, indent=2, sort_keys=True) + "\n"
        )

    if profile:
        pprof_top(go_dir, binary, cpu_profile, "cpu", out_dir / f"{prefix}.cpu.top.txt")
        pprof_top(go_dir, binary, heap_profile, "heap", out_dir / f"{prefix}.heap.top.txt")

    return {
        "target": str(target),
        "run_id": run_id,
        "command": cmd,
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed_ms": round(elapsed_ms, 3),
        "timings_ms": parse_timings(stderr),
        "finding_count": count,
        "canonical_sha256": canon_hash,
        "json_error": json_error,
        "stdout_json": str(json_out),
        "stderr": str(stderr_out),
        "cpu_profile": str(cpu_profile) if profile else "",
        "heap_profile": str(heap_profile) if profile else "",
        "rule_timing_top": rule_timings[:20],
        "rule_group_top": rule_groups[:20],
    }


def compare_runs(rows: list[dict[str, Any]]) -> dict[str, Any]:
    hashes = [r["canonical_sha256"] for r in rows if r.get("canonical_sha256")]
    counts = [r["finding_count"] for r in rows]
    return {
        "repeat_count": len(rows),
        "deterministic_hash": bool(hashes) and len(set(hashes)) == 1,
        "deterministic_count": len(set(counts)) <= 1,
        "hashes": hashes,
        "counts": counts,
    }


def main() -> int:
    root = repo_root()
    go_dir = root / "go"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="repo/file/dir targets to scan serially")
    parser.add_argument("--out", default="/tmp/vyql-bench", help="artifact directory")
    parser.add_argument("--binary", default="/tmp/vyql", help="vyql binary path")
    parser.add_argument("--vyql-home", default=str(root / "vyql"))
    parser.add_argument("--repeat", type=int, default=1, help="runs per target")
    parser.add_argument("--timeout", type=int, default=900, help="seconds per scan")
    parser.add_argument("--no-build", action="store_true", help="reuse existing binary")
    parser.add_argument("--no-profile", action="store_true", help="skip CPU/heap profiles")
    parser.add_argument("--rule-timing", action="store_true", help="enable VYQL_RULE_TIMING")
    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    binary = Path(args.binary).resolve()
    if not args.no_build:
        build_cli(go_dir, binary)
    rule_catalog = load_rule_catalog(Path(args.vyql_home).resolve())

    all_rows: list[dict[str, Any]] = []
    target_summaries: list[dict[str, Any]] = []
    for target_arg in args.targets:
        target = Path(target_arg).resolve()
        rows: list[dict[str, Any]] = []
        for run_id in range(1, args.repeat + 1):
            row = run_scan(
                binary=binary,
                go_dir=go_dir,
                vyql_home=Path(args.vyql_home).resolve(),
                target=target,
                out_dir=out_dir,
                run_id=run_id,
                timeout=args.timeout,
                include_rule_timing=args.rule_timing,
                profile=not args.no_profile,
                rule_catalog=rule_catalog,
            )
            rows.append(row)
            all_rows.append(row)
            print(
                f"{target} run {run_id}: rc={row['return_code']} "
                f"findings={row['finding_count']} hash={row['canonical_sha256'][:12]} "
                f"elapsed={row['elapsed_ms']:.1f}ms",
                flush=True,
            )
        target_summaries.append(
            {
                "target": str(target),
                "runs": rows,
                "determinism": compare_runs(rows),
            }
        )

    summary = {
        "repo": str(root),
        "binary": str(binary),
        "vyql_home": str(Path(args.vyql_home).resolve()),
        "cache_mode": "off",
        "profile_enabled": not args.no_profile,
        "rule_timing_enabled": args.rule_timing,
        "rule_catalog_entries": len({id(meta) for meta in rule_catalog.values()}),
        "targets": target_summaries,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    with (out_dir / "runs.jsonl").open("w") as fh:
        for row in all_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    failed = [r for r in all_rows if r["return_code"] != 0 or r["json_error"]]
    nondeterministic = [
        t for t in target_summaries if args.repeat > 1 and not t["determinism"]["deterministic_hash"]
    ]
    if failed or nondeterministic:
        print(f"summary: {out_dir / 'summary.json'}", file=sys.stderr)
        return 1
    print(f"summary: {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
