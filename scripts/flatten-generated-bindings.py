#!/usr/bin/env python3
"""Collapse the generated per-package binding corpus to one file per package.

    bindings/packages/generated/<lang>/<pkg>/<lang>/<seq>/<name>.vyql   (before)
    bindings/packages/generated/<lang>/<pkg>.vyql                       (after)

The flat form is what everything else already expects: the generator writes it
(`adapter_pipeline.py`), the loader documents it, and the top-1000 test uses it.
Only the shipped corpus diverged, into 24,835 files across ~43,000 directories
holding one entry each -- more directories than files.

Every file in a package group already declares the same module, so the group was
always one module that happened to be spread across a directory per binding.
Merging keeps the module declaration and concatenates the binding blocks.

Idempotent: a corpus already flat is left alone. Run with --check to verify
without writing, which is what CI wants.

    python3 scripts/flatten-generated-bindings.py [--check] [--root DIR]
"""
import argparse
import collections
import os
import re
import shutil
import sys

MODULE_RE = re.compile(r"\A\s*module\s+([A-Za-z0-9_.]+)\s*;\s*", re.S)
BINDING_RE = re.compile(r"^\s*binding\s+([A-Za-z0-9_]+)\s*\{", re.M)

DEFAULT_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "vyql", "bindings", "packages", "generated"
)


def collect(root):
    """Group nested files by (language, package). Returns groups and any files
    already flat, which are left untouched."""
    groups = collections.defaultdict(list)
    flat = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith(".vyql"):
                continue
            full = os.path.join(dirpath, fn)
            parts = os.path.relpath(full, root).split(os.sep)
            if len(parts) == 2:
                flat.append(full)
            elif len(parts) >= 3:
                groups[(parts[0], parts[1])].append(full)
    for paths in groups.values():
        paths.sort()  # deterministic output, so the result does not churn in git
    return groups, flat


def merge(paths):
    """One module declaration plus every binding block, in path order."""
    module = None
    bodies = []
    for p in paths:
        text = open(p, encoding="utf-8").read()
        m = MODULE_RE.match(text)
        if not m:
            raise SystemExit(f"{p}: no module declaration; refusing to guess")
        if module is None:
            module = m.group(1)
        elif m.group(1) != module:
            # The corpus has none of these. If one ever appears, merging would
            # silently reassign bindings to another module rather than fail.
            raise SystemExit(f"{p}: module {m.group(1)} != {module} in the same package")
        bodies.append(text[m.end():].strip())
    return f"module {module};\n\n" + "\n\n".join(b for b in bodies if b) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report without writing")
    ap.add_argument("--root", default=DEFAULT_ROOT)
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"no such directory: {root}")
        return 1

    groups, flat = collect(root)
    if not groups:
        print(f"already flat: {len(flat)} file(s), nothing nested")
        return 0

    # Collisions, checked before anything is written. Case-insensitively,
    # because macOS and Windows would silently merge two packages into one file.
    targets = collections.defaultdict(list)
    for lang, pkg in groups:
        targets[(lang.lower(), f"{pkg}.vyql".lower())].append(pkg)
    clashes = {k: v for k, v in targets.items() if len(v) > 1}
    for existing in flat:
        rel = os.path.relpath(existing, root).split(os.sep)
        key = (rel[0].lower(), rel[1].lower())
        if key in targets:
            clashes[key] = targets[key] + ["(existing flat file)"]
    if clashes:
        print("FAIL: target filename collisions")
        for k, v in sorted(clashes.items()):
            print(f"    {k[0]}/{k[1]}  <-  {v}")
        return 1

    total_in = sum(len(v) for v in groups.values())
    bindings_in = 0
    for paths in groups.values():
        for p in paths:
            bindings_in += len(BINDING_RE.findall(open(p, encoding="utf-8").read()))

    if args.check:
        print(f"would flatten {total_in} file(s) in {len(groups)} package(s) "
              f"carrying {bindings_in} binding(s); no collisions")
        return 1  # nested corpus present is itself the failure CI reports

    bindings_out = 0
    for (lang, pkg), paths in sorted(groups.items()):
        text = merge(paths)
        bindings_out += len(BINDING_RE.findall(text))
        out = os.path.join(root, lang, f"{pkg}.vyql")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        shutil.rmtree(os.path.join(root, lang, pkg))

    # The count is the whole safety property: a merge that drops a binding looks
    # exactly like a merge that worked.
    if bindings_out != bindings_in:
        print(f"FAIL: {bindings_in} bindings in, {bindings_out} out")
        return 1
    print(f"flattened {total_in} file(s) -> {len(groups)} file(s); "
          f"{bindings_out} binding(s) preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
