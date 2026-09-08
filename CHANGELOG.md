# Changelog

All notable changes to VEXOR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com) and versions follow
[SemVer](https://semver.org).

## [1.1.1] - 2026-09-08

### Fixed — VEXOR is now a proper system CLI

- Renamed the Go module to `github.com/0xamirdev/vexor`, which makes the
  standard installation path work:
  `go install github.com/0xamirdev/vexor/cmd/vexor@latest`.
- The binary now runs identically from any working directory — no repo,
  no relative resources, no `./vexor` requirement. `cd /tmp && vexor
  --version` is the contract.
- Added `Makefile` (`make install`) and a cross-platform installer
  (`scripts/install.sh`) that detects Linux / Termux / Debian, installs Go
  when missing, fixes the user's PATH, and verifies the result.
- Added a non-blocking release check: at startup VEXOR queries the latest
  GitHub release with a 3-second budget and prints a warning when a newer
  version exists. Offline or rate-limited networks fail silently — scans
  are never delayed or interrupted.

### Added

- `internal/update` package: buffered-channel check wired into the CLI
  flow; the notice prints after a run (or an aborted run) completes.
- Acceptance coverage: the suite now verifies `--version` from a foreign
  cwd and a real `go install` into an isolated `GOBIN`, executed from
  `/tmp`.

## [1.1.0] - 2026-09-08

### Fixed — severity is earned by verified impact, not pattern matches

- Secret and token detection no longer rates client-side values as HIGH.
  Values emitted under public-by-design names (SDK `websiteToken`,
  publishable keys, site keys, client IDs) are reported as **info** with an
  explicit "public client-side configuration" label — or not at all.
- Unverified credential patterns are capped at **medium**, titled
  "Potential ... (unverified)", and carry **no fabricated exploit PoC**.
- Verified secrets (the scanner replayed the token and the server accepted
  it) keep full severity and ship a replay PoC.
- robots.txt and other public static files are exempt from misconfiguration
  findings: no more "missing security headers" on `Disallow: /`.
- Missing-security-header findings across multiple endpoints are aggregated
  into a single site-wide finding listing the affected URLs.
- Fixed a severity comparison bug where lexical string ordering could leave
  unverified findings at critical.

### Changed

- A finding PoC must demonstrate impact. Plain "the page exists" curls are
  no longer presented as exploit proofs for unverified secrets; the exploit
  stage skips every finding labeled Potential/unverified.
- Evidence for file exposures redacts credential values while keeping key
  names readable.

### Added

- `internal/version` package: the release version lives in one place.
- `--version` / `-version` CLI flag printing the tool version.
- `tool_version` field in the JSON report.
- Acceptance suite (`tests/acceptance.py` + `tests/vulnserver`): a
  black-box regression harness that reproduces real-world false-positive
  reports (chat-widget websiteToken on a public login page) and blocks them
  in CI. Python is used deliberately here: the contract under test is the
  compiled binary's behavior, not Go internals.
- Redesigned CLI banner with the version from the central package.

## [1.0.0] - 2026-09-08

### Added

- Initial public release: crawl (zero-assumption surface mining), nine probe
  modules (SQLi, XSS, CMDi, SSTI, LFI, SSRF, redirect, misconfiguration,
  exposure), vulnerability fusion engine with seven chain rules, safe PoC
  generation, console/JSON/PoC-script reporting, CI pipeline.
