#!/usr/bin/env python3
"""Collapse the numeric shard directories in the binding tree.

    bindings/<lang>/<lang>/<seq>/<name>.vyql          (before)
    bindings/<lang>/<module>.vyql                     (after)

    bindings/packages/<lang>/<lang>/<seq>/<name>.vyql (before)
    bindings/packages/<lang>/<module>.vyql            (after)

Each shard directory holds exactly one file, so the tree carried roughly one
directory per binding. The language name also repeated -- `python/python/...` --
and the numeric level carried no meaning.

`bindings/<lang>/` stays a directory, because `vyql bindings -lang python` reads
it as one (`ReadVYQLDir("bindings/" + lang)`); only the doubled name and the
shard level go.

Files are grouped by module rather than by directory. Unlike the generated
package corpus, a language directory here holds several modules, and merging
them into one file would silently reassign bindings to a module they were not
written for.

Idempotent: a tree with no shard directories is left alone. --check reports
without writing.

    python3 scripts/flatten-binding-shards.py [--check] [--root DIR]
"""
import argparse
import collections
import os
import re
import shutil
import sys

SEQ_RE = re.compile(r"^\d+$")
MODULE_RE = re.compile(r"\A\s*module\s+([A-Za-z0-9_.]+)\s*;\s*", re.S)
BINDING_RE = re.compile(r"^\s*binding\s+([A-Za-z0-9_]+)\s*\{", re.M)

DEFAULT_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "vyql", "bindings"
)


def collect(root):
    """Map (destination directory, module) -> the shard files that belong to it."""
    groups = collections.defaultdict(list)
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith(".vyql"):
                continue
            full = os.path.join(dirpath, fn)
            parts = os.path.relpath(full, root).split(os.sep)
            # A shard is <...>/<seq>/<file>; anything else is already flat.
            if len(parts) < 3 or not SEQ_RE.match(parts[-2]):
                continue
            prefix = parts[:-2]
            # Every group ends <x>/<x>; the repeat carries nothing.
            if len(prefix) >= 2 and prefix[-1] == prefix[-2]:
                prefix = prefix[:-1]
            text = open(full, encoding="utf-8").read()
            m = MODULE_RE.match(text)
            if not m:
                raise SystemExit(f"{full}: no module declaration; refusing to guess")
            groups[(tuple(prefix), m.group(1))].append(full)
    for paths in groups.values():
        paths.sort()  # deterministic output, so the result does not churn in git
    return groups


def merge(paths):
    """One module declaration plus every binding block, in path order."""
    module = None
    bodies = []
    for p in paths:
        text = open(p, encoding="utf-8").read()
        m = MODULE_RE.match(text)
        if module is None:
            module = m.group(1)
        elif m.group(1) != module:
            raise SystemExit(f"{p}: module {m.group(1)} != {module}")
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

    groups = collect(root)
    if not groups:
        print("no shard directories; nothing to flatten")
        return 0

    # Destination names, checked before anything is written. Case-insensitively,
    # because macOS and Windows would merge two modules into one file.
    targets = collections.defaultdict(list)
    for (prefix, module) in groups:
        leaf = module.rsplit(".", 1)[-1]
        targets[(tuple(p.lower() for p in prefix), f"{leaf}.vyql".lower())].append(module)
    clashes = {k: v for k, v in targets.items() if len(v) > 1}
    if clashes:
        print("FAIL: destination filename collisions")
        for k, v in sorted(clashes.items()):
            print(f"    {'/'.join(k[0])}/{k[1]}  <-  {v}")
        return 1

    files_in = sum(len(v) for v in groups.values())
    bindings_in = sum(
        len(BINDING_RE.findall(open(p, encoding="utf-8").read()))
        for paths in groups.values()
        for p in paths
    )

    if args.check:
        print(f"would flatten {files_in} file(s) into {len(groups)} module file(s), "
              f"carrying {bindings_in} binding(s); no collisions")
        return 1  # a sharded tree is itself the failure CI should report

    shard_dirs = set()
    bindings_out = 0
    for (prefix, module), paths in sorted(groups.items()):
        for p in paths:
            shard_dirs.add(os.path.dirname(p))
        text = merge(paths)
        bindings_out += len(BINDING_RE.findall(text))
        dest_dir = os.path.join(root, *prefix)
        os.makedirs(dest_dir, exist_ok=True)
        with open(os.path.join(dest_dir, module.rsplit(".", 1)[-1] + ".vyql"), "w",
                  encoding="utf-8") as fh:
            fh.write(text)

    # Remove the shard directories, then any parent left empty by that.
    for d in sorted(shard_dirs, key=len, reverse=True):
        shutil.rmtree(d, ignore_errors=True)
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        if dirpath != root and not dirnames and not filenames:
            os.rmdir(dirpath)

    # A merge that drops a binding looks exactly like a merge that worked.
    if bindings_out != bindings_in:
        print(f"FAIL: {bindings_in} bindings in, {bindings_out} out")
        return 1
    print(f"flattened {files_in} file(s) -> {len(groups)} module file(s); "
          f"{bindings_out} binding(s) preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
