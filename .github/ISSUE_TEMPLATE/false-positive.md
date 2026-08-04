---
name: False positive
about: VyQL reported something that is actually safe
labels: false-positive
---

**Rule id** (e.g. `VYQL-INJ-001`) and the finding as printed:

```
paste the finding here
```

**Minimal reproducer**:

```
paste code here
```

**Why it is safe.** This is the important part — what neutralises the flow?
A sanitizer, a validation, an unreachable branch, a framework guarantee?

**`vyql explain ./repro` output**, which shows the controls the engine looked for
and did not find:

```
paste here
```

If the safe form uses a sanitizer VyQL does not know about, that is usually a
missing `check` binding rather than a rule bug.

**Version** — `vyql version`, or the commit you built.
