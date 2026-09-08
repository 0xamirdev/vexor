---
name: False positive report
about: Report a finding that turned out to be a non-issue
title: '[false-positive] '
labels: false-positive, bug
assignees: ''
---

VEXOR's severity model exists to protect triage time. If a finding wasted yours, report it here — it directly improves the verification logic.

**Finding**

```
<ID, title, severity, endpoint, param — paste the console block or JSON entry>
```

**Why it is a false positive**

What you verified manually, and what the actual behavior was. E.g. "the reflected canary sits inside a JSON string in a JS bundle, not HTML", "the cookie is not a session cookie", "the token is a public site key by design".

**Suggested fix** (optional)

If you can see how the verification should have caught this — a checkable condition, a context test, a severity rule — describe it.

**Environment**

- VEXOR version / commit: [`vexor --version` or `git rev-parse --short HEAD`]
- Target technology: [framework / server / CDN, if known]
