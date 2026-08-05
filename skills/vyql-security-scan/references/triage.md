# Judging a finding by family

What makes a finding real differs by vulnerability class. The general procedure
is in `SKILL.md`; this is what to check per family, and the fix each one wants.

Rule IDs are prefixed by family: `VYQL-INJ-*`, `VYQL-PATH-*`, `VYQL-CRY-*`,
`VYQL-SEC-*`, `VYQL-SMELL-*`.

## Injection — `VYQL-INJ-*`

SQL, command, code, LDAP, XPath, NoSQL, template.

**Real when:** an attacker-controlled value reaches an interpreter as *syntax*
rather than as *data*, and nothing on the path escapes or parameterizes it.

**Check:**
- Is the source actually request data? `vyql query -concept HttpInput .` — a
  "source" that is a config constant or an internal caller is a false positive.
- Does the value land in the query string, or in a bound parameter? A value
  passed as a parameter is data and cannot change the statement's shape.
- Is there escaping VyQL did not see? Check the inline-concatenation shape in
  `references/debugging.md` before concluding the code is wrong.

**Fix:** parameterized statements — `core.SqlParameterization`. For commands,
pass an argument vector rather than a shell string, and avoid `shell=True` and
its equivalents. Escaping is the weaker fallback and it must be the right
escaper for the interpreter: `core.XpathEscape` for XPath, not
`core.HtmlEscape`.

**Watch for:** an ORM that interpolates raw SQL under a safe-looking method.
`.raw()`, `.execute()` and query-builder escape hatches take strings and do not
parameterize them.

## Path traversal — `VYQL-PATH-*`

**Real when:** request data reaches a filesystem call and nothing canonicalizes
the path or constrains it to a directory.

**Check:**
- A `..` filter alone is not a control. It misses encoding, symlinks, and
  absolute paths.
- A prefix check *after* canonicalization is a control; *before* it is not,
  because the value can still traverse out afterwards.

**Fix:** canonicalize, then verify the result is inside the intended root —
`core.PathCanonicalization` plus `core.PathAccessCheck`. Better still, do not
accept a path at all: take an identifier and look up the filename yourself.

## Crypto — `VYQL-CRY-*`

Weak algorithms, weak randomness, bad modes.

**These need no taint path.** They are properties of the call, so the usual
source-to-sink reasoning does not apply and "there is no attacker input" is not
a refutation.

**Check:**
- Is it security-relevant? MD5 for a cache key or an ETag is not a
  vulnerability. MD5 for a password or a signature is.
- Is the randomness used for anything unguessable — a token, a session ID, a
  salt, a nonce? A non-cryptographic RNG for jitter or sampling is fine.

**Fix:** SHA-256 or better for integrity; a password hash (argon2, scrypt,
bcrypt) for passwords, never a bare digest; the platform's CSPRNG for anything
security-bearing.

**The most common false positive in this family** is a weak digest used
somewhere it does not matter. Say what it is used *for* before calling it real.

## Secrets — `VYQL-SEC-*`

**Real when:** a credential is committed and usable.

**Check:**
- Is it a live credential, a placeholder, a documentation example, or a test
  fixture? Vendor documentation values appear constantly and are not secrets.
- Is the file actually committed, or is it ignored or generated?

**Fix:** rotate first, then remove. **Say this explicitly.** Deleting a
committed secret without rotating leaves it valid and still in git history —
removing it from the working tree only makes it harder to find, not harmless.

## Smells — `VYQL-SMELL-*`

Broader design observations — over-broad responses, missing narrowing.

Lower confidence by design. Treat them as questions to ask the author, not
findings to assert. They earn their place in an audit summary as "worth a look",
not in a list of vulnerabilities.

## Review conditions

Some findings carry a `review condition:` instead of a proven path. VyQL is
saying it saw a dangerous *shape* — a dynamically built query, say — without
proving attacker control reaches it.

Those are leads. Confirm the source yourself before reporting one as a
vulnerability, and label it as needing review if you cannot.

## Confidence

`conf=high` means the path and the labels are well grounded, not that the
finding is certainly exploitable. `conf=medium` or `low` means look harder — it
is not permission to dismiss.

Never report a finding at higher confidence than the evidence supports, and
never lower one just because the fix looks inconvenient.
