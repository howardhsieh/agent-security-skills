# GitHub Action: audit your skills and plugins in CI

If you publish Agent Skills, a Claude Code plugin or a marketplace, run the
`skill-supply-chain-audit` checks on every pull request. Findings appear in the
job summary and, optionally, in the repository's Security tab.

## Minimal workflow

```yaml
name: Skill audit
on: [push, pull_request]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: howardhsieh/agent-security-skills@v0.2.2
        with:
          path: skills          # the folder that holds your skills or plugin
          fail-on: high         # critical | high | medium | low | none
```

## Inputs and outputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Folder to audit, relative to the repository root |
| `fail-on` | `high` | Fail when any finding is at or above this severity; `none` never fails |
| `baseline` | | JSON file of accepted findings (see below) |
| `sarif` | `agentsec-kit.sarif` | Where the SARIF report is written |
| `upload-sarif` | `false` | Upload to GitHub code scanning |

Outputs: `findings-total`, `critical`, `high`, `sarif-file`.

## Show results in the Security tab

Code scanning must be enabled for the repository (free for public repositories).

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: howardhsieh/agent-security-skills@v0.2.2
        with:
          path: skills
          upload-sarif: "true"
```

## Accepting findings with a baseline

Some findings are expected, for example a script that legitimately calls an
API. Record them once, write a reason for each, and commit the file:

```bash
python3 skills/skill-supply-chain-audit/scripts/audit_skill.py scan skills --write-baseline .agentsec-baseline.json
```

Then pass `baseline: .agentsec-baseline.json`. Any new finding, or any change
to an accepted line, is reported again.

## Badge

If the action runs on your default branch and passes, you can show:

```markdown
[![Audited by agentsec-kit](https://img.shields.io/badge/audited%20by-agentsec--kit-2ea44f?logo=github)](https://github.com/howardhsieh/agent-security-skills)
```

[![Audited by agentsec-kit](https://img.shields.io/badge/audited%20by-agentsec--kit-2ea44f?logo=github)](https://github.com/howardhsieh/agent-security-skills)

Only use the badge while the audit runs in your CI. To show the live result
instead, use your workflow's own status badge:
`https://github.com/OWNER/REPO/actions/workflows/skill-audit.yml/badge.svg`.

## What the audit can and cannot tell users

A passing audit means the package has no findings at or above your threshold
in a static, pattern-based review (plus the ones you accepted in a baseline).
It does not prove the package is safe: obfuscated or runtime-downloaded logic
can evade static checks. Pin versions and keep hooks and scripts readable.

The action is read-only, makes no network calls of its own (except the
optional SARIF upload through GitHub's official action), and uses only the
Python that ships on GitHub-hosted runners.
