# Security policy

## Reporting a vulnerability in VyQL itself

Please report privately, not as a public issue.

Use GitHub's [private vulnerability
reporting](https://github.com/vyprai/vyql/security/advisories/new), or email
**security@vyprsec.ai**.

Tell us what the issue is, how to trigger it, and what an attacker gets out of
it. A small reproducer is worth more than a long description.

We will reply within 3 working days and tell you what we plan to do. If we
disagree that it is a vulnerability we will say so and explain why, rather than
leaving you without an answer.

## What is in scope

VyQL parses whatever source tree you point it at, so it reads untrusted input
by design. Anything that lets a **scanned repository** affect the machine running
the scan is in scope:

- code execution, or any write outside the output paths, triggered by scanned content
- path traversal out of the scan root
- a crafted source file that hangs the scanner or exhausts memory
- a crafted `.vyql` data file that escapes its intended effect

## What is not

- **A missed vulnerability is a bug, not a security issue.** Open a normal issue
  with a reproducer; see [CONTRIBUTING.md](CONTRIBUTING.md).
- **A false positive is likewise a bug.** Same route.
- Findings that VyQL reports *about your own code* are yours to fix. This policy
  covers the scanner, not what it scans.
- Resource use on a genuinely enormous repository is a performance issue unless a
  small input triggers it.

## Disclosure

We aim to ship a fix and publish an advisory within 90 days of a confirmed
report, sooner where the fix is small. We will credit you unless you ask us not
to.
