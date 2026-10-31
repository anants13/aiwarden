# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems in aiwarden itself, such as a detector bypass with real-world impact, a crash triggered by crafted traffic, or a way to make aiwarden leak data.

Report privately via GitHub's **"Report a vulnerability"** button (Security → Advisories) on this repository. We aim to acknowledge reports within 3 days and to ship a fix or mitigation within 30 days.

## Scope

In scope: the aiwarden code in this repository.
Out of scope: vulnerabilities in model runtimes (Ollama, vLLM, …) or models themselves. Please report those upstream. We're happy to add detection for them afterwards.

## Detection gaps

Detector false negatives that are *not* exploitable bypasses (e.g. "this injection phrasing isn't caught") are welcome as normal issues or PRs.
