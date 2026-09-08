# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a Vulnerability

VEXOR is a security tool — vulnerabilities in it deserve careful, responsible handling.

1. Do **not** open a public issue for security reports.
2. Use GitHub's [private vulnerability reporting](https://github.com/0xamirdev/vexor/security/advisories/new), or email **oxamirdev@gmail.com** with `[SECURITY]` in the subject line.
3. Include reproduction steps, affected versions, and impact assessment.

Expect an initial response within 72 hours. Credit is given to reporters in the advisory unless anonymity is requested.

## Scope

- The VEXOR codebase itself (injection into probe payloads, report tampering, SSRF pivoting via the tool, dependency issues)
- Documentation that encourages unsafe defaults

## Out of Scope

- Vulnerabilities discovered *by* VEXOR in third-party targets
- Denial-of-service through scan volume (rate limiting is operator-controlled by design)
