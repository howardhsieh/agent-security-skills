## Summary

<!-- What does this change and why? Link the issue it closes, if any. -->

## Type of change

- [ ] New skill
- [ ] New or changed check in an audit script
- [ ] New or changed detection rule
- [ ] Skill instructions or references
- [ ] Repository tooling, CI or docs

## Checklist

- [ ] `python tools/validate_skills.py` passes with no errors (paste the summary line below).
- [ ] `python -m pytest -q` passes.
- [ ] Every new check or rule has a positive fixture (must match) and a negative fixture (similar benign input that must not match) under `tests/fixtures/`.
- [ ] Fixtures are inert: `example.invalid` / `example.com` domains, tokens marked `FAKE`, no working payloads.
- [ ] Defensive only: no offensive tooling, working exploits or payload collections.
- [ ] Scripts stay read-only, make no network calls, use only the Python 3.9+ standard library, and redact secret values in all output.
- [ ] Claims cite sources, and framework IDs carry their edition (e.g. `ASI04 (Agentic Top 10 2026)`, `LLM01:2025`, `AML.T0051 (ATLAS v2026.09)`).
- [ ] The skill's limits section says what it cannot detect or do.
- [ ] `evals/<skill>.json` is updated if triggers or expected behavior changed.
- [ ] `CHANGELOG.md` has an entry under Unreleased.
- [ ] If `audit-baseline.json` changed, each newly accepted finding is explained below.

## Validator output

```text

```

## Notes for reviewers

<!-- Anything reviewers should look at closely: new detection patterns, baseline changes, vendor docs you relied on. -->
