---
name: Missed finding (false negative)
about: VyQL did not report something it should have
labels: false-negative
---

**Language / framework**

**Minimal reproducer** — the smallest file that shows it:

```
paste code here
```

**What should have been reported** (rule id if you know it, otherwise the
vulnerability class):

**Diagnostics.** These three answer most of the question before anyone else has
to guess, so please include their output:

```sh
vyql match ./repro      # was the source or sink labelled at all?
vyql resolve ./repro    # did the call resolve?
vyql explain ./repro    # which unless-clause suppressed it?
```

A missed finding is usually one of: the source/sink was never labelled, the call
did not resolve, or a rule's `unless` clause was satisfied by something that
should not count.

**Version** — `vyql version`, or the commit you built.
