<div align="center">

# ⚡ VEXOR

**V**ulnerability **EX**ploit & **OR**chestration

*Autonomous web vulnerability discovery and exploit-chain analysis — written in Go.*

VEXOR crawls a target with zero path assumptions, detects injection flaws and misconfigurations, verifies impact before rating severity, and fuses confirmed findings into attack chains that a triager can act on immediately. Every report ships with a reproducible proof-of-concept.

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/0xamirdev/vexor?style=for-the-badge&color=blue)](https://github.com/0xamirdev/vexor/releases)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/0xamirdev/vexor/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/0xamirdev/vexor?style=for-the-badge&color=yellow)](https://github.com/0xamirdev/vexor/stargazers)

[Report a Bug](https://github.com/0xamirdev/vexor/issues) · [Feature Request](https://github.com/0xamirdev/vexor/issues) · [Security Policy](SECURITY.md) · [Releases](https://github.com/0xamirdev/vexor/releases) · [Contact](mailto:oxamirdev@gmail.com)

</div>

---

> ⚠️ **Authorized Use Only.** VEXOR is built for penetration testers, security researchers, and bug bounty hunters operating within explicit written permission. Testing systems without authorization is illegal in nearly every jurisdiction. The authors accept no liability for misuse.

---

## Key Capabilities

- **Autonomous reconnaissance** — maps the attack surface by mining links, forms, query parameters, JSON API keys, and script sources from live responses. No wordlists, no hardcoded paths.
- **Nine detection modules** — SQL injection, XSS, command injection, SSTI, LFI, SSRF, open redirect, security misconfiguration, and secret exposure.
- **Evidence-based severity** — a finding is rated only when VEXOR can demonstrate impact; everything else is labeled *Potential (unverified)* and capped.
- **Exploit-chain fusion** — combines independent findings into account-takeover, auth-bypass, and credential-theft chains.
- **Reproducible evidence** — exact payloads, `curl` PoCs, a JSON report, and an executable PoC replay script. Nonzero exit code on findings makes it CI/CD friendly.

## Why VEXOR Exists

Traditional scanners report *matches*, not *impact*. A reflected parameter means nothing on its own — a scanner that stops there wastes your triage time.

VEXOR takes the approach real red teamers use. It explores a target with zero path assumptions, identifies every injectable surface, verifies each vulnerability with live evidence rather than passive pattern matching, and then — this is the part that matters — fuses individual findings into composite attack chains.

A reflected XSS plus a session cookie without HttpOnly is not two low findings. It is an account takeover. VEXOR understands this.

## Installation

**One line:**

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/0xamirdev/vexor/main/scripts/install.sh)"
```

The installer detects your OS and architecture, downloads a **prebuilt binary** from [Releases](https://github.com/0xamirdev/vexor/releases) (no Go required), places it in the first writable bin directory on your PATH, wires your shell profile, and verifies the result end to end.

**Supported environments:**

| Environment | Status |
|---|---|
| Linux (Debian / Ubuntu / generic, amd64 & arm64) | Prebuilt binaries + source install, CI-tested |
| macOS (Intel & Apple Silicon) | Prebuilt binaries |
| Termux (Android) | Via the same installer — installs `golang` through `pkg` when needed and targets the Termux `usr/bin` |
| Windows | Compiles from source; not yet covered by the test suite |

If Go is already installed, the standard toolchain path works too:

```bash
go install github.com/0xamirdev/vexor/cmd/vexor@latest
export PATH="$PATH:$(go env GOPATH)/bin"   # persist in ~/.profile
```

Prefer doing it manually? Grab the matching binary from [Releases](https://github.com/0xamirdev/vexor/releases):

```bash
curl -fLo vexor https://github.com/0xamirdev/vexor/releases/latest/download/vexor-linux-amd64
chmod +x vexor && sudo mv vexor /usr/local/bin/
```

**Developers** (inside a clone):

```bash
git clone https://github.com/0xamirdev/vexor.git
cd vexor
go build -o vexor ./cmd/vexor   # local binary: ./vexor
make install                    # or install it system-wide
```

The install contract is enforced in CI by `tests/install_clean_env.py`, which simulates a brand-new user (synthetic HOME, minimal PATH, empty shell profiles) and verifies the full flow.

## Quick Start

```bash
# Full pipeline scan
vexor -u https://target.example.com

# Authenticated scan with more workers and a custom out-of-band domain
vexor -u https://target.example.com -t 16 -H "Cookie: session=your_cookie" -marker oob.yourdomain.com
```

Verify the install from any directory:

```bash
cd /tmp
vexor --version                 # VEXOR 1.1.2
```

### Command-Line Reference

| Flag | Description | Default |
|---|---|---|
| `-u` | Target URL — the only required flag | — |
| `-t` | Concurrent worker threads | `8` |
| `-timeout` | Per-request timeout in seconds | `15` |
| `-p` | Maximum pages to crawl | `40` |
| `-marker` | Marker domain used in redirect and CORS probes. Point this at a host you control | `vexor.probe.invalid` |
| `-o` | Output directory for reports | `vexor-out` |
| `-H` | Extra request headers, comma-separated `Name: value` pairs — use for authenticated scans | — |
| `--version` | Print the VEXOR version and exit | — |

### Example Output

A real scan against a deliberately vulnerable test app:

```
 critical  XSS + Weak Cookie Flags -> Account Takeover
   ID       : VXR-7497962C
   Endpoint : GET http://10.0.0.5:8081/greet
   Param    : name
   Payload  : <svg onload=alert('VEXOR')>
   Evidence : 1 session cookie(s) issued without HttpOnly+Secure
   PoC      : curl -sk 'http://10.0.0.5:8081/greet?name=%3Csvg+onload%3Dalert%28%27VEXOR%27%29%3E'

 critical  SQL Injection (Error-Based) - MySQL
   ID       : VXR-C44BD072
   Endpoint : GET http://10.0.0.5:8081/item
   Param    : id
   Payload  : '
   Evidence : You have an error in your SQL syntax ... near ''' at line 1
```

Findings are color-coded by severity in the terminal. Exit code is `1` when findings exist and `0` when the target is clean, so VEXOR drops straight into CI/CD pipelines.

## Detection Coverage

| Module | Techniques | Level |
|---|---|---|
| **SQLi** | Error-based fingerprints across five database engines, boolean-based differential analysis using response similarity scoring, UNION column-count discovery | Parameter |
| **XSS** | Unique-canary reflection detection, HTML context classification (attribute / script-string / body), context-matched event-handler escalation | Parameter |
| **CMDi** | Echo-based arithmetic markers and time-based blind detection across eight shell syntaxes | Parameter |
| **SSTI** | Arithmetic fingerprints for Jinja2, Twig, Freemarker, Velocity, Pebble, and Smarty | Parameter |
| **LFI** | Traversal variants, filter-evasion encodings, PHP wrapper abuse, Windows targets | Parameter |
| **SSRF** | Loopback and cloud-metadata fetches with reflection-versus-fetch discrimination to eliminate false positives | Parameter |
| **Redirect** | Location-header and client-side redirect primitives tested against ten bypass vectors | Parameter |
| **Misconfig** | CORS origin reflection, missing security headers, exposed directory listings | Endpoint |
| **Exposure** | Credential patterns (AWS, GitHub, Stripe, JWT, private keys), sensitive file exposure, verbose debug output — every secret finding passes an impact-verification tier | Endpoint / Host |

### Exploit-Chain Fusion

The chain engine looks for *combinations* of confirmed findings and verifies them:

| Chain | Result |
|---|---|
| XSS + session cookies without HttpOnly/Secure | **Account Takeover** |
| SQLi on an authentication parameter | **Authentication Bypass** |
| SSRF + exposed configuration endpoints | **Cloud Credential Theft** |
| LFI reaching log or session files | **Pre-Auth RCE Path** (verified live) |
| CORS reflection + same-origin XSS | **Cross-Origin Data Exfiltration** |
| Open redirect on an OAuth flow | **Authorization Code Theft** |
| Confirmed SSTI | **Remote Code Execution Path** |

## Reporting & Evidence

Every finding ships with the exact payload, a `curl` command that reproduces it, and where applicable a live verification: extracted database version, read host files, echoed shell markers. The PoC replay script generated at the end of each run re-executes every finding automatically — ready to attach to a bug bounty report.

Severity is never assigned on pattern matching alone. A finding either demonstrates impact, or it is explicitly labeled **Potential (unverified)** and capped below high. Client-side SDK tokens (chat-widget `websiteToken`s, publishable keys, site keys) are public by design and reported as informational, never as HIGH secrets.

| Verification tier | Meaning | Severity |
|---|---|---|
| **Verified** | VEXOR replayed the token and the server accepted it, or extracted live data | Full severity, replay PoC included |
| **Potential (unverified)** | Sensitive-looking pattern, impact unproven | Capped at medium, no exploit PoC |
| **Public by design** | Client-side SDK configuration sent to every visitor | Informational |

### Output Artifacts

| File | Purpose |
|---|---|
| `vexor_<target>_<timestamp>.json` | Machine-readable report with every finding, PoC URL, and exploit proof |
| `vexor_poc_<target>_<timestamp>.sh` | Executable script that replays every PoC end to end |
| Console | Color-coded findings ranked by severity with evidence and reproduction commands |

## How It Works

<p align="center">
  <img src="docs/assets/how-it-works.png" alt="VEXOR pipeline: crawl, probe, chain, prove, report" width="100%">
</p>

The crawler never touches a static wordlist. It mines links, forms (GET and POST), query parameters, JSON API keys, and script sources from live responses, then quietly probes well-known sensitive locations. Every URL it touches becomes raw material for the probe stage.

### Project Structure

```
vexor/
├── cmd/vexor/          CLI entry point
├── internal/
│   ├── banner/         UI rendering
│   ├── httpc/          HTTP client — redirect control, cookie persistence, timing
│   ├── crawler/        attack-surface discovery, zero path assumptions
│   ├── detect/         nine probe modules and evidence types
│   ├── chain/          vulnerability fusion engine
│   ├── exploit/        safe proof-of-concept generation
│   ├── engine/         pipeline orchestration and worker pool
│   ├── version/        central release version
│   └── report/         console, JSON, and PoC-script reports
├── tests/              acceptance suite (Python) + vulnerable test server
├── CHANGELOG.md
└── LICENSE
```

### Design Principles

- **Evidence over matches.** Nothing is reported without a concrete, reproducible artifact.
- **Zero dependencies.** Pure standard library. The entire toolchain builds with `go build` alone.
- **Safe by default.** Exploit routines are read-only and non-destructive — data reads, echo markers, fingerprint checks. Nothing is written, deleted, or denied.
- **Concurrency-first.** A bounded worker pool drives every probe stage, with race-safe result aggregation.
- **Deterministic IDs.** Findings are hash-addressed (`VXR-XXXXXXXX`), which makes deduplication and cross-run diffing trivial.

## Project Status

VEXOR is under active development and already used in real bug bounty triage. The core detection and chaining pipeline is stable; module coverage expands release by release. See the [CHANGELOG](CHANGELOG.md) for the precise history and [Releases](https://github.com/0xamirdev/vexor/releases) for binaries.

## Roadmap

- [ ] Out-of-band DNS callback integration for blind SSRF and XXE
- [ ] Stored XSS detection through crawler state persistence
- [ ] GraphQL schema introspection module
- [ ] HTTP/2 and request smuggling probes
- [ ] SARIF output format for GitHub Code Scanning integration

## Contributing

Contributions are welcome — new probe modules, chain rules, and performance work are all valuable. Read [CONTRIBUTING.md](CONTRIBUTING.md) to get started, and please follow the security policy for responsible disclosure.

## Support the Project

VEXOR is free and open source, built in spare time between engagements. If it helped you land a bounty or secure a system, consider supporting continued development.

<p align="center">
  <a href="https://0xamirdev.github.io/vexor/donate.html">
    <img src="https://img.shields.io/badge/%E2%9D%A4_Donate-Support_VEXOR-8A2BE2?style=for-the-badge&logo=ethereum&logoColor=white&labelColor=0b1020" alt="Donate to VEXOR">
  </a>
</p>

**EVM / Ethereum wallet:**

```
0x75a727b8eb0e08e5cf184e102aa7f28497127e1b
```

The donate button opens an interactive donation page with a scannable wallet QR and one-click address copy — available on every EVM network: Ethereum, BSC, Polygon, Arbitrum, Base, Optimism.

## Contact

Questions, collaboration ideas, or a bounty you want a second opinion on? Reach out:

**Email:** [oxamirdev@gmail.com](mailto:oxamirdev@gmail.com)

For vulnerability reports in VEXOR itself, please follow the [Security Policy](SECURITY.md) instead of emailing publicly.

## License

Released under the [MIT License](LICENSE).
