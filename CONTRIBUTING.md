# Contributing to aiwarden

Thanks for helping! aiwarden is a security tool, so we care about **clarity, low false-positive rates, and a small dependency footprint** above all.

## Dev setup

```bash
git clone https://github.com/OWNER/aiwarden && cd aiwarden
python -m venv .venv && . .venv/bin/activate     # or: uv venv && uv pip install -e '.[dev]'
pip install -e '.[dev]'
pytest
ruff check .
```

## Good first contributions

- **Detection rules.** Add a pattern to `src/aiwarden/detectors/*.py` with at least one test that it fires and one realistic benign example that it doesn't fire on.
- **API formats.** Teach `gateway/parse.py` a new wire format (with a recorded sample in a test).
- **Process names.** Add default entries for other model runtimes in `config.py`.
- **Scanner.** Add more model formats (Keras Lambda layers, ONNX external data, etc.).

## Rules for rules

1. Every detector change needs tests, both positive and negative.
2. Prefer checksums and structure over loose regexes (see the Luhn and IBAN checks in `pii.py`).
3. Never put raw secrets or prompts in event details. Use `redact()` / `snippet()`.
4. New runtime dependencies need a strong justification in the PR.
5. Keep the gateway pass-through. Inspection must never alter, slow down, or break traffic in alert mode.

## Commit and PR

- Small, focused PRs. Describe the threat the change addresses (link to `docs/threat-model.md` IDs like T3).
- By contributing you agree your work is licensed under Apache-2.0.
