<!-- One logical change per PR. CI must pass: build, vet, gofmt, acceptance suite. -->

## What

<!-- What does this PR change? One or two sentences. -->

## Why

<!-- The problem: a missed finding, a false positive, an install bug, a doc gap. Link the issue if there is one. -->

## How it was verified

<!-- Acceptance suite? A local vulnserver session? Paste the relevant output. -->

```
<output>
```

## Checklist

- [ ] `go vet ./...` and `gofmt -l .` are clean
- [ ] `python3 tests/acceptance.py` passes
- [ ] New findings come with verifiable evidence (no passive pattern matches)
- [ ] No destructive exploit routines added
- [ ] Docs (README/CHANGELOG) updated if behavior changed
