# Contributing to VEXOR

Thank you for considering a contribution. VEXOR grows through high-quality probe modules, sharper chain rules, and cleaner engineering.

## Ground Rules

1. **No Persian or other non-English text in code.** All identifiers, comments, strings, and commit messages are in English.
2. **Evidence-based findings only.** A new probe module must verify its finding with concrete response evidence — never report on a single passive pattern match.
3. **No destructive exploitation.** Exploit routines may read data, echo markers, and measure timing. They must never write, delete, or deny service.
4. **Standard library only.** Do not introduce third-party dependencies without prior discussion.
5. **Respect the pipeline contract.** New modules implement `detect.Module` (Name, Level, Scan) and return `[]detect.Finding` with a deterministic ID, severity, evidence, and PoC.

## Development Workflow

```bash
# Clone and build
git clone https://github.com/0xamirdev/vexor.git
cd vexor
go build ./...

# Quality gates (all must pass before opening a PR)
go vet ./...
gofmt -l .                        # must output nothing
go test ./...
python3 tests/acceptance.py       # black-box reporting contract
```

## Adding a Probe Module

1. Create `internal/detect/<module>.go` implementing the `Module` interface.
2. Register it in `detect.All()` inside `internal/detect/types.go`.
3. Build payloads as package-level tables — keep them data-driven, not inline strings.
4. Test against a local vulnerable server before submitting.

## Adding a Chain Rule

1. Create a method on `chain.Engine` following the existing naming pattern (`chain<Name>`).
2. Compose from existing findings only — chains verify combinations, they do not probe.
3. Register the rule in `chain.Engine.Run`.

## Commit Style

Short, imperative, and descriptive:

```
add time-based cmdi detection for windows shells
fix crawler dropping links with encoded query strings
```

## Pull Requests

- One logical change per PR.
- Describe what the change detects (or fixes) and how it was verified.
- CI must pass: build, vet, format, and tests across Go 1.24.
