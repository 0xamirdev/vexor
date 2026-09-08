---
name: Detection improvement
about: Propose a sharper technique for an existing module or chain rule
title: '[detection] '
labels: enhancement, detection
assignees: ''
---

For new modules or chain rules, use the "New probe module or chain rule" template. Use this one to sharpen what already exists.

**Module affected**

[sqli | xss | cmdi | ssti | lfi | ssrf | redirect | misconfig | exposure | chain]

**Current behavior**

What the module does today that misses findings, generates noise, or rates severity wrong.

**Proposed improvement**

The concrete technique change: payload additions, a new evidence check, a smarter differential. VEXOR's contract: findings need verifiable evidence, not more pattern matches.

**Evidence it works**

Show the payloads against a vulnerable setup, or the verification logic that separates real from benign. A reproducible test case is ideal — the vulnserver in `tests/` is a good starting point.
