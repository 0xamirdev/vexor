---
name: New probe module or chain rule
about: Propose a new vulnerability probe or vulnerability-fusion rule
title: '[module] '
labels: enhancement
assignees: ''
---

**Module / rule name**
e.g. `xxe`, ` smuggling`, `chain-graphql-batching`

**Vulnerability class**
What does it detect, and at what level (host / endpoint / parameter)?

**Detection technique**
Describe the payload strategy and, critically, the **evidence** that confirms the finding. VEXOR does not accept passive pattern matches.

**Proposed payloads / fingerprints**

```
<payload table or list>
```

**False-positive controls**
How will the module distinguish real issues from reflection, caching, or soft-404 responses?

**Verification**
Describe the local test setup you validated against.
