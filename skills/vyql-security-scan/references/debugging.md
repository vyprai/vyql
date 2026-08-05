# When a finding did not fire

You expected a vulnerability to be reported and it was not. Work down the
layers, because each one rules out everything below it. Stopping at the first
"no" saves the rest.

## 1. Was the concept attached at all?

```sh
vyql match .
```

Lists every node a binding labelled. **If the source or the sink is not in this
list, no rule can fire**, because rules match concepts and there is no concept
here to match.

This is the most common answer by a wide margin. It means the framework or
library is not modelled — a binding gap, not an engine bug.

Confirm what the vocabulary contains:

```sh
vyql bindings -lang python           # this language's sources, sinks, checks
vyql definitions -kind concepts      # the whole concept vocabulary
```

If the sink genuinely is not modelled, that is the finding: report it as missing
coverage and describe the shape that should be bound.

## 2. Did the call resolve?

```sh
vyql resolve .
```

Taint stops at an unresolved call. If the flow passes through a function VyQL
could not resolve to a body, the path ends there and no rule sees the far side.

Dynamic dispatch, reflection, and calls into dependencies that were not scanned
all show up here.

## 3. Is there a path?

```sh
vyql trace -from HttpInput -to SqlExecution .
```

Shows each source, whether it reaches a sink, and where it dead-ends. Both
filters are substrings of concept names.

A filter matching no known concept is an error with a suggestion, not an empty
result — so if you see one, the name is wrong, not the code.

## 4. Was an `unless` clause satisfied?

```sh
vyql explain .
```

The rule may have fired and then been neutralized. `explain` prints each
`unless` clause and whether it was satisfied. A satisfied clause means VyQL
believes a control covers the path — which is the correct outcome if the control
is real, and a false negative if the control does not actually neutralize
anything.

## The shape that catches people out

An inline control call inside a concatenation sometimes fails to register as
covering the path, where assigning first works:

```python
sink("... " + escape(p))     # may not register as covered
clean = escape(p)            # does
sink("... " + clean)
```

If a finding did not fire and the code uses the second shape, the control was
probably credited. That is the intended behaviour. If it fired and the code uses
the first shape, suspect the modelling rather than the code.

## Narrowing the rules

```sh
vyql explain -rules vyql/packs/injection .
```

Restricts to one pack or file, which is faster and much easier to read when you
already know the family you care about.

## The graph itself

```sh
vyql graph .
vyql graph -taint .
```

Verbose and definitive. Reach for it when `match`, `resolve` and `trace` all
look right and the finding still does not appear — at that point the question is
about the graph's structure rather than its labels.
