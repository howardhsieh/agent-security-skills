# Contributing

Thanks for helping make AI agents safer to run. This repo holds **defensive**
skills only: things that help people audit, harden, detect, and respond. We do
not accept offensive tooling, working exploits, or payload collections.

## Ground rules for every skill

1. **Read-only by default.** Scripts inspect and report. Anything that changes
   a system (deleting files, rotating keys, editing configs) is written as a
   step the user performs or explicitly approves, never done silently.
2. **Never print secrets.** Scripts redact values that look like credentials.
   Findings show *where* a secret is, not *what* it is.
3. **Standard library only.** Scripts run on Python 3.9+ on macOS, Linux, and
   Windows with no `pip install`. Optional extras (e.g. `tomllib` on 3.11+)
   must degrade gracefully.
4. **No network access from scripts.** Skills may tell the agent to consult a
   URL; bundled scripts never call out.
5. **Cite sources for claims.** Framework IDs (OWASP, MITRE ATLAS, MCP spec)
   carry the edition/version they come from, e.g. `ASI01 (Agentic Top 10 2026)`.
6. **Say what the skill cannot do.** Static checks are evadable; every audit
   skill states its limits and what to use alongside it.

## SKILL.md conventions

We follow the [Agent Skills specification](https://agentskills.io/specification)
so skills work in Claude Code, claude.ai, Codex, Cursor, Copilot, Gemini CLI,
and OpenCode.

- Frontmatter uses **only** the six spec fields: `name`, `description`,
  `license`, `compatibility`, `metadata`, `allowed-tools`. Anything else breaks
  claude.ai uploads.
- `name` matches the directory, lowercase `a-z0-9-`, max 64 chars, and does not
  contain `claude` or `anthropic`.
- `description` is third person, says **what** the skill does and **when** to
  use it, includes trigger keywords, stays under 500 characters, and contains
  no `<` or `>`.
- Body under 300 lines. Put detail in `references/` (one level deep; files over
  100 lines start with a table of contents).
- Structure: purpose → when to use / not use → safety rules → workflow
  checklist → output format → references.

Run the validator before opening a PR:

```bash
python tools/validate_skills.py
python -m pytest -q
```

## Adding a detection rule

Rules live in `skills/agent-trace-detection/assets/`. Every rule needs:

- a positive fixture (events that must match) and a negative fixture (similar
  benign events that must not) under `tests/fixtures/`,
- a `falsepositives` note,
- framework tags where they apply (`attack.*`, ATLAS, OWASP ASI).

## Adding a check to an audit script

Each check has a stable ID (`CC001`, `SKL012`, …), a severity, a one-line
title, and a fix. Add a fixture that triggers it and one that does not.

## Reporting a vulnerability in this repo

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities.
