---
name: vyql-security-scan
description: >-
  Scan a codebase for security vulnerabilities with VyQL and triage what it
  finds, following tainted data from source to sink and naming the neutralizing
  controls that are missing. Use when asked to find vulnerabilities, run a
  security scan or audit, check for injection, XSS, SSRF, path traversal or
  hardcoded secrets, review code for security issues, or judge whether a
  specific scanner finding is real or a false positive. Covers Java, Python,
  JavaScript/TypeScript, Go, C#, PHP, Ruby and 15 more languages.
license: Apache-2.0
compatibility: >-
  Requires the vyql CLI (v0.2.0+). Offers to download a release archive on first
  use if absent, with the user's confirmation. Network access is needed only for
  that install.
metadata:
  author: vyprai
  repository: https://github.com/vyprai/vyql
---

# VyQL security scan

VyQL follows tainted data from where it enters a program to where it does
something dangerous, and reports **the neutralizing controls it looked for and
did not find**. That last part is what makes triage possible: a finding is not
"this looks risky", it is "this value reaches this sink and none of these
specific controls is on the path."

## Before anything: is vyql installed?

```sh
vyql version
```

If that fails, read `references/install.md` and **ask before installing
anything**. Never download and run a binary on someone's machine unannounced.

## Pick the mode from the request

| The user wants | Mode |
|---|---|
| "audit this codebase", "find vulnerabilities", "is this secure" | **Audit** |
| "is this finding real?", a finding from any scanner, "why did X fire" | **Adjudicate** |

## Audit

```sh
vyql scan -fail-on none -all .
```

`-fail-on none` matters: by default `scan` exits 1 when it finds anything HIGH
or CRITICAL, which is right for CI and wrong here — a non-zero exit reads as
"the scan failed" and derails the run. `-all` adds attention and review flags
that a plain scan omits.

A plain scan already reports every severity; the gate only changes the exit
code. There is no flag to "show more findings".

### Report coverage before findings. Always.

The output ends with what was read, and warns about what was not:

```
scanned python:1 textpattern:1 — 9 finding(s)
warning: 15 file(s) matched no frontend and were not analysed (.zig 12, .cob 3)
```

**Never suppress that warning, and never summarise findings without it.** A
clean report over a tree that was mostly skipped looks exactly like a clean
report over a tree that was fully read. Run `vyql scan -coverage .` for the full
account when anything looks off.

Three things to state plainly, before any finding:

1. **What was actually parsed**, from the `scanned` line, against what is in the
   repository. If it says `python:1` and the project is forty Java files, that
   is the headline — not the findings.
2. **Depth.** Java, Python and JavaScript are the reference frontends. Other
   languages range down to call-and-concat coverage, so "no findings" in Elixir
   means materially less than in Java.
3. **Never say "no vulnerabilities".** Say "no findings in what was analysed",
   and say what that was.

One gap the tool admits and you should repeat when it matters: a file whose
parse partially failed still counts as parsed, because tree-sitter recovers from
syntax errors.

### Then triage

Group by severity and rule family. Triage the significant ones using the section
below — do not just reformat the scanner's output, which the user could have read
themselves.

## Adjudicate

```sh
vyql explain .
```

`explain` gives each finding's full proof tree and its negation evidence. It is
the fastest answer to "why did this fire", and it works just as well for
adjudicating a finding another scanner reported: point VyQL at the same code and
ask whether a path really exists.

If the question is "why did this **not** fire", read `references/debugging.md`.

## Reading a finding

```
[P2] [CRITICAL] VYQL-INJ-002  (conf=high, fp=cfb54bfb4024aa90)
    source: code.HttpInput @ server.js:4
    sink: code.CommandExecution @ server.js:5
    taint path: server.jsAttr#77 -> server.jsFormat#78 -> server.jsArg#80
    unless path coveredBy core.ShellEscape: not satisfied
    unless endpoint coveredBy core.CommandArgumentValidation: not satisfied
```

The `unless` lines are the fix list. Each names the control whose absence made
the finding fire, so the fix is "introduce this control", written in the
language's idiom.

`conf=` is the engine's own confidence. Low confidence is a hint to look harder,
not permission to dismiss.

## Is it real?

Three questions, in this order.

**1. Is the source genuinely attacker-controlled?**

```sh
vyql query -concept HttpInput .
```

Lists every node that got the label, with its location. If the "source" is
actually a constant, a test fixture or an internal caller, the finding is a
false positive — say so and show this output as the reason.

**2. Does the path really carry the value?**

```sh
vyql trace -from HttpInput -to SqlExecution .
```

Read the hops in `taint path:`. A path through a function that discards or
replaces the value is a false positive.

**3. Is there a control VyQL did not model?**

If the code neutralizes the value by a route the ontology does not know, you
have found two things: the finding is a false positive, **and** there is a
binding gap. Report both. The second is how coverage improves, and it is more
valuable than the first.

Before concluding this, check one known modelling limitation: an inline control
call inside a concatenation sometimes fails to neutralize where assign-then-use
works.

```python
sink("... " + escape(p))     # may not register as covered
clean = escape(p)            # does
sink("... " + clean)
```

If that is the shape, the code is fine and the finding is a modelling gap, not a
vulnerability.

Per-family judgment — what makes an injection, path traversal, SSRF, crypto or
secret finding real — is in `references/triage.md`.

## Record the verdict, or it is lost

Triage that lives only in the conversation is gone the moment it ends, and the
next scan reports all of it again. Offer to write the verdicts down:

```sh
vyql scan -baseline .vyql-baseline.json .     # report only what is new
```

Entries are keyed on the finding fingerprint, which is anchored to rule and
location rather than line number, so a verdict survives edits elsewhere in the
file.

```json
{ "fp": "cfb54bfb4024aa90", "verdict": "false-positive",
  "reason": "source is a build-time constant, not request data" }
```

`false-positive` and `accepted` are different claims — one says the finding is
wrong, the other says it is right and being lived with. Record which, and always
write the reason: an entry with no reason is a suppression nobody can review.

For a codebase with an existing backlog, `-baseline-write .vyql-baseline.json`
records everything as `accepted` so the gate fires only on new findings. Say
plainly that this accepts the backlog rather than fixing it.

**If the scan warns that baseline entries match nothing, surface it.** The code
they excused has changed, and a suppression that outlives its reason is worse
than no suppression.

## Proposing a fix

Name the control from the `unless` clause, give the idiom for the language, say
where it goes. **Do not edit the code.** The user applies it.

If they do apply a fix, re-scanning is a reasonable check — but say what it
proves. A green re-scan means the pattern stopped matching. It does not mean the
code is safe, and reporting it as proof would be the same overclaim this tool
exists to avoid.

## Honesty rules

These are the difference between a useful security report and a dangerous one.

- Coverage before findings, every time.
- "No findings in what was analysed", never "no vulnerabilities".
- A false positive is a finding about VyQL, not a nuisance. Report the binding
  gap.
- Do not raise confidence beyond what the evidence supports. `conf=medium` with
  an unverified source is a lead, not a vulnerability.
- If a scan took an implausibly short time or read implausibly few files, say so
  before anything else.

## Command reference

| Command | Answers |
|---|---|
| `vyql scan -fail-on none -all .` | what is wrong, everything reported |
| `vyql scan -coverage .` | what was read, skipped, and left unanalysed |
| `vyql explain .` | why each finding fired, with negation evidence |
| `vyql query -concept X .` | every node labelled with a concept |
| `vyql trace -from X -to Y .` | the path, or where it stops |
| `vyql match .` | what got labelled at all |
| `vyql resolve .` | which calls did not resolve |
| `vyql diff before.json after.json` | what a change introduced or removed |
| `vyql definitions -kind concepts` | the concept vocabulary |

`-from`, `-to` and `-concept` are substring filters over concept names. A filter
matching no known concept is an error with a suggestion, not an empty result —
so if you get one, fix the name rather than concluding there is nothing there.

Paths work as they do for `scan`; with no path, the working directory is used.
