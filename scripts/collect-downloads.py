#!/usr/bin/env python3
"""Append a snapshot of release-asset download counts to data/downloads.json.

GitHub reports the total right now, not a history, so a graph over time only
exists if the totals are recorded over time. This runs daily and appends one
dated snapshot.

Per asset rather than per release, for two reasons. A new platform can appear
without breaking the series, and the checksum files carry their own signal:
`install.sh` fetches an archive and then its checksum, so a checksum running
ahead of its archive means checksum-only fetches or retried downloads.

Exits 0 and writes nothing when the counts are unchanged, so the caller can skip
an empty commit.
"""
import json
import os
import pathlib
import subprocess
import sys
from datetime import date

# Resolved from the environment so the script works wherever it is run from.
# It is copied next to the series on CI, where the repository layout it would
# otherwise assume does not exist.
DATA = pathlib.Path(
    os.environ.get("DOWNLOADS_JSON")
    or pathlib.Path(__file__).resolve().parent.parent / "data" / "downloads.json"
)
SCHEMA = 1


def fetch_releases():
    """Release assets and their counts, via the gh CLI so auth is the caller's."""
    out = subprocess.run(
        ["gh", "api", "--paginate", "/repos/vyprai/vyql/releases"],
        capture_output=True, text=True, check=True,
    ).stdout
    # --paginate concatenates JSON arrays; gh emits one array per page.
    releases = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(out):
        while idx < len(out) and out[idx].isspace():
            idx += 1
        if idx >= len(out):
            break
        page, idx = decoder.raw_decode(out, idx)
        releases.extend(page)
    return releases


def snapshot(releases):
    return {
        "date": os.environ.get("SNAPSHOT_DATE") or date.today().isoformat(),
        "releases": {
            r["tag_name"]: {a["name"]: a["download_count"] for a in r["assets"]}
            for r in releases
            if r["assets"]
        },
    }


def load():
    if not DATA.exists():
        return {"schema": SCHEMA, "snapshots": []}
    d = json.loads(DATA.read_text())
    if d.get("schema") != SCHEMA:
        sys.exit(f"downloads.json is schema {d.get('schema')}, this script writes {SCHEMA}")
    return d


def regressions(prev, cur):
    """Assets whose count fell.

    A count only goes down when an asset is deleted and re-uploaded, which resets
    it. Worth surfacing rather than smoothing: a chart that quietly draws a cliff
    is a chart that lies about a release.
    """
    out = []
    for tag, assets in cur["releases"].items():
        for name, count in assets.items():
            before = prev["releases"].get(tag, {}).get(name)
            if before is not None and count < before:
                out.append(f"{tag}/{name}: {before} -> {count}")
    return out


def main():
    data = load()
    cur = snapshot(fetch_releases())

    total = sum(c for a in cur["releases"].values() for c in a.values())
    print(f"total downloads across all releases: {total}")

    if data["snapshots"]:
        prev = data["snapshots"][-1]
        for line in regressions(prev, cur):
            print(f"::warning::asset count fell, an asset was probably replaced: {line}")
        if prev["releases"] == cur["releases"]:
            print("unchanged since the last snapshot; nothing written")
            return
        if prev["date"] == cur["date"]:
            data["snapshots"].pop()

    data["snapshots"].append(cur)
    DATA.parent.mkdir(parents=True, exist_ok=True)
    DATA.write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote snapshot for {cur['date']}, {len(data['snapshots'])} in the series")


if __name__ == "__main__":
    main()
