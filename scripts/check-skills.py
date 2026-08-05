#!/usr/bin/env python3
"""Validate every skill under skills/ against the Agent Skills specification.

The format is an open standard (https://agentskills.io/specification.md) read by
roughly 32 agent tools, so a malformed SKILL.md does not fail loudly in one
place -- it is silently ignored, differently, by each of them. That is the
failure this guards against.

Also checks that the skill does not tell an agent to run a command the CLI does
not have. A skill is instructions, and instructions that name a flag which was
renamed are worse than no instructions: the agent runs them and reports the
error as a finding about the user's code.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SKILLS = os.path.join(ROOT, "skills")

NAME_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*\Z")

failures = []


def fail(skill, msg):
    failures.append(f"{skill}: {msg}")


def frontmatter(text):
    """Parse the leading YAML block without a yaml dependency.

    Only the shapes the spec allows are handled: `key: value`, folded blocks
    introduced by `>-`, and a one-level `metadata:` mapping.
    """
    if not text.startswith("---\n"):
        return None, text
    raw, _, body = text[4:].partition("\n---\n")
    fields, key = {}, None
    for line in raw.split("\n"):
        m = re.match(r"^([a-z-]+):\s*(.*)$", line)
        if m:
            key, value = m.group(1), m.group(2).strip()
            fields[key] = "" if value in (">-", ">", "|") else value
        elif key and line.strip():
            fields[key] = (fields[key] + " " + line.strip()).strip()
    return fields, body


def cli_surface():
    """Subcommands and flags the built binary actually exposes."""
    binary = os.path.join(ROOT, "bin", "vyql")
    if not os.path.exists(binary):
        return None, None
    env = dict(os.environ, VYQL_HOME=os.path.join(ROOT, "vyql"))
    top = subprocess.run([binary], capture_output=True, text=True, env=env).stderr
    top += subprocess.run([binary], capture_output=True, text=True, env=env).stdout
    subs = set(re.findall(r"^  ([a-z-]+)\s", top, re.M))
    flags = {}
    for sub in subs:
        out = subprocess.run([binary, sub, "-h"], capture_output=True, text=True, env=env)
        flags[sub] = set(re.findall(r"^  -([a-z-]+)", out.stderr + out.stdout, re.M))
    return subs, flags


def check(skill_dir):
    name = os.path.basename(skill_dir)
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(path):
        fail(name, "no SKILL.md")
        return
    text = open(path, encoding="utf-8").read()
    fields, _ = frontmatter(text)
    if fields is None:
        fail(name, "no YAML frontmatter")
        return

    fm_name = fields.get("name", "")
    if not NAME_RE.match(fm_name):
        fail(name, f"name {fm_name!r} must be lowercase alphanumeric with single hyphens")
    if len(fm_name) > 64:
        fail(name, "name exceeds 64 characters")
    if fm_name != name:
        fail(name, f"name {fm_name!r} must match the directory name {name!r}")

    desc = fields.get("description", "")
    if not desc:
        fail(name, "description is required")
    if len(desc) > 1024:
        fail(name, f"description is {len(desc)} characters, max 1024")
    if desc and "use when" not in desc.lower():
        fail(name, "description must say WHEN to use the skill, not only what it does")

    if len(fields.get("compatibility", "")) > 500:
        fail(name, "compatibility exceeds 500 characters")

    lines = text.count("\n") + 1
    if lines > 500:
        fail(name, f"SKILL.md is {lines} lines; the spec recommends under 500")

    for ref in set(re.findall(r"references/([A-Za-z0-9_.-]+\.md)", text)):
        if not os.path.exists(os.path.join(skill_dir, "references", ref)):
            fail(name, f"references/{ref} does not exist")

    subs, flags = cli_surface()
    if subs is None:
        print("  (skipped command check: bin/vyql not built)")
        return
    body = text
    for ref in os.listdir(os.path.join(skill_dir, "references")):
        body += open(os.path.join(skill_dir, "references", ref), encoding="utf-8").read()
    # Anywhere, not only at the start of a line: most invocations in prose are
    # inline code spans, and those are exactly the ones that go stale unnoticed.
    # A word that is not a subcommand is prose ("is vyql installed?"), not a
    # mistake.
    for sub, tail in re.findall(r"vyql ([a-z-]+)([^\n`|]*)", body):
        if sub not in subs:
            continue
        for flag in re.findall(r"(?<![\w-])-([a-z][a-z-]*)", tail):
            if flag not in flags.get(sub, set()):
                fail(name, f"`vyql {sub}` has no -{flag}")


def main():
    if not os.path.isdir(SKILLS):
        print("no skills/ directory")
        return 0
    found = 0
    for entry in sorted(os.listdir(SKILLS)):
        d = os.path.join(SKILLS, entry)
        if os.path.isdir(d):
            found += 1
            check(d)
    if found == 0:
        print("FAIL: skills/ exists but contains no skill")
        return 1
    if failures:
        print("FAIL: skill validation")
        for f in sorted(set(failures)):
            print("    " + f)
        return 1
    print(f"skills OK ({found} validated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
