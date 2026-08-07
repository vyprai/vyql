# download-data

Release-asset download counts, one dated snapshot per day, written by
`.github/workflows/downloads.yml` on `main`.

This is an orphan branch and shares no history with `main`. It exists because
`main` requires seven status checks before a push lands, and a daily counter
tick has no business running a build to record itself.

GitHub reports the total now, not a history, so the series only exists because it
is written down here. It starts the day the collector shipped.

Read it, do not edit it.
