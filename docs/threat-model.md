# Threat model

## What we protect
1. **Your data:** files, credentials, prompts, and conversation history.
2. **Data residency:** where your data physically goes.
3. **Your machine:** keeping it free of code execution and persistence.

## Where the risk actually lives

Model weights are inert numbers: a `.safetensors` or `.gguf` file cannot open a socket. The risk is in everything around the weights.

| # | Vector | Example | aiwarden v0.1 coverage |
|---|---|---|---|
| T1 | Malicious model files | Pickle `__reduce__` → `os.system`. `trust_remote_code` repos. Jinja chat-template sandbox escapes. | `scan` (static) |
| T2 | Runtime phones home | Inference server or dependency sends telemetry, update checks, or a compromised package beacons out | `watch`: silent-server rule, cross-border rule |
| T3 | Agent exfiltration | The model emits a tool call that uploads files or reads `~/.ssh` | gateway tool-call detectors, `watch` child-process + egress rules |
| T4 | Indirect prompt injection | A web page or document the agent reads tells the model to exfiltrate data | gateway injection detectors on tool results |
| T5 | Exfiltration through rendered output | Markdown image with data in the URL, auto-fetched by a chat UI | gateway exfil-URL detector |
| T6 | Cross-border processing | A hosted open-model API processes your prompts in another jurisdiction | gateway upstream-country check, `watch` |
| T7 | Accidental exposure | Ollama bound to `0.0.0.0`, reachable from your network | `watch` public-listen rule |
| T8 | Sensitive data in prompts | Pasting secrets or PII into prompts sent to remote APIs | gateway secrets/PII detectors |

## Non-goals (for now)
- **Blocking.** v0.1 alerts only. Enforcement is planned.
- **Defending against an attacker who already has root**, or one who targets aiwarden itself.
- **Detecting backdoored weights** (trigger phrases baked into the model). That is an open research problem. aiwarden catches the *actions* a backdoor would need to take, such as network or tool use, not the backdoor itself.
- **Inspecting TLS content of traffic that bypasses the gateway.**

## Known evasions in v0.1
- Connections shorter than the poll interval. Fixed by the planned sandbox and eBPF backends.
- Exfiltration to allowlisted or domestic services, e.g. a GitHub gist. Mitigation: tool-call detectors, and in future, volume anomaly detection.
- Exfiltration over DNS (data encoded in query names). Planned DNS sensor.
- Prompt injection phrased in ways the regexes don't cover. Heuristics will always miss some.
- Processes outside the watched process tree, e.g. an agent that asks a separate daemon to do the work.

## Design principles
- **Local-first:** no telemetry, and nothing leaves the machine unless you configure a webhook.
- **Redact by default:** stored matches are redacted, and raw prompts are never written to disk.
- **Few dependencies:** four runtime dependencies. Every dependency is attack surface.
- **Transparent rules:** detectors are readable regexes with tests, so anyone can audit them.
- **Fail open, loudly:** in alert-only mode, aiwarden never breaks your workflow. Errors are logged, not raised.
