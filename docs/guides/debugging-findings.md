# Why did this fire, or not?

VyQL is built so you can interrogate the analysis instead of guessing at it. When
something is wrong, four commands answer almost every question, and they answer
it faster than reading rules.

Work on the smallest file that reproduces the problem.

## It found nothing, and it should have

Ask the three questions in order — the answer is almost always the first one that
comes back empty.

### 1. Was anything labelled?

```sh
vyql match ./repro
```

`match` lists every node a binding attached a concept to. If your source or sink
is not there, no rule can fire, because rules match concepts and nothing gave
your code one.

That means a **missing binding**. Your framework's request object, or your
database wrapper's execute, is not modelled yet. See
[writing a binding](writing-a-binding.md) — this is the most common gap and the
easiest to fix.

### 2. Did the call resolve?

```sh
vyql resolve ./repro
```

Taint crosses function boundaries only when the call resolved to a body. A call
listed as unresolved is a wall: taint reaching it stops there.

Resolution is import- and type-aware, so it fails when the import cannot be
followed — dynamic dispatch, a receiver whose type is unknown, an interface with
several implementations. The fix is usually a type hint, not a rule.

### 3. Was it suppressed?

```sh
vyql trace -from HttpInput -to SqlExecution ./repro
```

`trace` shows the path from source to sink, or where the taint stops. If the path
exists but no finding appeared, a rule's `unless` clause was satisfied — the
engine believes something neutralised it.

```sh
vyql explain ./repro
```

`explain` prints each finding's full proof tree **and its negation evidence** —
every `unless` the rule carries and whether it was satisfied. A control that
should not count as neutralising will be named there.

## It found something, and it should not have

```sh
vyql explain ./repro
```

Read the `unless` lines. A false positive is one of:

- **The guard is not modelled.** Your validation is real, but no `check` binding
  claims it, so the engine cannot see it. Add one — this is the same work as
  adding a source or sink.
- **The guard is modelled but not positioned.** `coveredBy path` needs the
  control to dominate the flow; a check inside a branch that does not dominate
  the sink does not suppress it. `explain` says *"no neutralizing control
  dominates the path"* rather than *"none found"*.
- **The source is not really attacker-controlled.** The binding is too broad.
  Narrow its query rather than deleting the rule.

Inline control calls inside a concatenation sometimes fail to neutralise. If
`sink("..." + esc(p))` still fires, try `clean = esc(p); sink("..." + clean)` —
if that fixes it, the binding's `covers` is the thing to fix.

## Looking at the graph

```sh
vyql graph ./repro                    # every node: id, type, loc, concepts
vyql graph -taint ./repro             # taint reachability
vyql query -call execute ./repro      # nodes by predicate
vyql query -concept code.SqlExecution ./repro
```

`graph` is verbose but definitive. When `match` and `resolve` both look right and
a rule still will not fire, the answer is in here.

## Which rules and bindings exist

```sh
vyql definitions -kind all                        # what loaded
vyql definitions explain code.SqlExecution        # where a concept comes from
vyql bindings -lang python                        # a language's vocabulary
```

`definitions explain` traces a label back to the binding that produced it — the
quickest way to find out *which* binding is being too eager.

## Filing it

If you cannot resolve it, open an issue with the reproducer and the output of
`match`, `resolve` and `explain`. Those three narrow it to one of the causes
above before anyone else has to reproduce anything. See
[CONTRIBUTING.md](../../CONTRIBUTING.md).
