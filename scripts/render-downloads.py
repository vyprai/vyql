#!/usr/bin/env python3
"""Render the download series into the landing page, between its markers.

The series lives on the download-data branch and the page lives on main, so
this runs at deploy time with both checked out. The generated markup is plain
inline SVG: the page makes no third-party requests, and the deploy job fails if
one appears, so a charting library from a CDN is not an option.

The whole section is generated, markers included, so that a repository with no
recorded snapshots publishes no section at all rather than an empty box.

The headline number renders from one snapshot. The chart needs two, because a
single point drawn as a line is a claim about a trend that has not been
observed yet.
"""
import json
import os
import pathlib
import sys

SERIES = pathlib.Path(os.environ.get("DOWNLOADS_JSON") or "data/downloads.json")
PAGE = pathlib.Path(os.environ.get("SITE_HTML") or "site/index.html")

START = "<!-- downloads:start -->"
END = "<!-- downloads:end -->"

# Plot geometry, in viewBox units. The SVG scales to the column width, so these
# are proportions rather than pixels. PAD insets the first and last points so
# the dot marking the latest value is not sliced in half by the viewBox edge.
W, TOP, FLOOR, LABELS, PAD = 720, 16, 140, 162, 5


def totals(data):
    """(date, total) per snapshot, oldest first.

    Led by a zero at the first release's publication date when the collector
    recorded one, so the chart has two points from the first day rather than a
    lone dot. That zero is observed, not padding: the assets did not exist
    before they were published.
    """
    points = [
        (s["date"], sum(c for assets in s["releases"].values() for c in assets.values()))
        for s in data["snapshots"]
    ]
    anchor = data.get("origin")
    if anchor and (not points or anchor < points[0][0]):
        points.insert(0, (anchor, 0))
    return points


def ceiling(n):
    """A round number at or above n, for the top gridline.

    The axis starts at zero rather than at the minimum. Cropping the baseline
    turns a modest rise into a cliff, which is the flattering-by-omission this
    page spends its length arguing against.
    """
    if n <= 0:
        return 10
    step = 10 ** (len(str(int(n))) - 1)
    # Fine enough that a peak just over a power of ten does not double the axis
    # and squash the line into the bottom half.
    for mult in (1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        if n <= step * mult:
            return int(step * mult)
    return int(step * 10)


def chart(series):
    top = ceiling(max(t for _, t in series))
    n = len(series)
    xs = [round(PAD + i * (W - 2 * PAD) / (n - 1), 1) for i in range(n)]
    ys = [round(FLOOR - (t / top) * (FLOOR - TOP), 1) for _, t in series]
    pts = " ".join(f"{x},{y}" for x, y in zip(xs, ys))
    area = f"M {xs[0]},{FLOOR} L " + " L ".join(f"{x},{y}" for x, y in zip(xs, ys)) + f" L {xs[-1]},{FLOOR} Z"

    first, last = series[0], series[-1]
    label = (
        f"Release downloads from {first[0]} to {last[0]}, "
        f"rising from {first[1]:,} to {last[1]:,}."
    )
    # The default preserveAspectRatio, so the SVG scales uniformly. Stretching
    # it to a fixed height distorts the tick text and flattens the end dot into
    # an ellipse.
    return f"""<svg class="dl-chart" viewBox="0 0 {W} {LABELS + 6}" role="img"
       aria-label="{label}">
    <line class="dl-grid" x1="0" y1="{TOP}" x2="{W}" y2="{TOP}"/>
    <line class="dl-grid" x1="0" y1="{FLOOR}" x2="{W}" y2="{FLOOR}"/>
    <path class="dl-area" d="{area}"/>
    <polyline class="dl-line" points="{pts}"/>
    <circle class="dl-dot" cx="{xs[-1]}" cy="{ys[-1]}" r="3.5"/>
    <text class="dl-tick" x="0" y="{LABELS}">{first[0]}</text>
    <text class="dl-tick" x="{W}" y="{LABELS}" text-anchor="end">{last[0]}</text>
    <text class="dl-tick" x="0" y="{TOP - 5}">{top:,}</text>
  </svg>"""


def section(series):
    total = series[-1][1]
    since = series[0][0]

    body = [
        f'<p class="dl-total"><strong>{total:,}</strong> release downloads</p>',
    ]
    if len(series) > 1:
        body.append(chart(series))
    body.append(
        f'<p class="dl-note">Counted from GitHub release assets since {since}. '
        f'Continuous integration and mirrors are included. '
        f'<code>go install</code> and container pulls are not counted at all.</p>'
    )
    inner = "\n    ".join(body)
    return f"""{START}
  <section>
    <h2>Downloads</h2>
    {inner}
  </section>
  {END}"""


def main():
    if not SERIES.exists():
        sys.exit(f"no series at {SERIES}")
    series = totals(json.loads(SERIES.read_text()))

    page = PAGE.read_text()
    if START not in page or END not in page:
        sys.exit(f"{PAGE} has no {START} / {END} markers")
    head, rest = page.split(START, 1)
    _, tail = rest.split(END, 1)

    if not series:
        print("no snapshots; the section is left out")
        PAGE.write_text(head + START + "\n  " + END + tail)
        return

    PAGE.write_text(head + section(series) + tail)
    what = "headline only" if len(series) == 1 else f"headline and a {len(series)}-point chart"
    print(f"rendered {what}: {series[-1][1]:,} downloads")


if __name__ == "__main__":
    main()
