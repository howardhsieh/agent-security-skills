# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** (or open
   <https://github.com/howardhsieh/agent-security-skills/security/advisories/new>).
3. Describe the issue, the affected skill, script or file, the version or commit,
   and steps to reproduce with inert inputs.

Do not open a public issue, pull request or discussion for a vulnerability.
Do not include real credentials, customer data or working exploit payloads in
the report; a minimal description of the data flow is enough.

You can expect an acknowledgement within 7 days and an assessment within 14
days. Fixes are released as a new tagged version and credited in the release
notes and advisory unless you ask to stay anonymous. This is a personal
open-source project with no bug bounty.

## Supported versions

Only the latest release receives fixes. Pin a release tag (see
[docs/install.md](docs/install.md)) and update when a new one ships.

## Scope

In scope: everything in this repository.

- **Scripts** under `skills/*/scripts/` and `tools/`, for example: a script
  that executes, imports or evaluates content from the target it inspects;
  writes outside an explicit output path; makes a network call; prints a
  secret value that should have been redacted; or can be driven by crafted
  input into path traversal, symlink following outside its scope, or unbounded
  resource use.
- **Skill instructions** (`SKILL.md`, `references/`, `assets/`), for example:
  instructions that would lead an agent to run untrusted code, weaken a user's
  configuration without asking, leak secrets into its output, or follow
  instructions embedded in the material it is auditing.
- **Detection rules and baselines**: a rule or accepted baseline entry that
  hides a real attack class the skill claims to cover.
- **Packaging and CI**: the marketplace manifest, release zips and workflows.

Out of scope:

- Detection gaps that the relevant skill already lists under its limits. Static
  checks can be evaded; a new evasion technique is welcome as a proposal issue,
  not a vulnerability report, unless it defeats a control the skill says it
  enforces.
- Vulnerabilities in the agents, MCP servers, plugins or skills these tools
  audit. Report those to their maintainers.
- Vulnerabilities in third-party dependencies of CI (GitHub Actions, PyPI
  packages). Report those upstream; Dependabot tracks action updates here.

## Design principles

Every script in this repository follows these rules, and a violation is a
security bug:

- **Read-only.** Scripts inspect and report. They never modify, delete or
  execute what they inspect. Changes to a system are written as steps for the
  user to perform or approve.
- **No network.** Bundled scripts make no network connections. A skill may tell
  the agent to consult a URL, but scripts never call out.
- **Standard library only.** Scripts run on Python 3.9+ with no `pip install`,
  so there is no third-party dependency chain to compromise at run time.
- **Secrets are redacted.** Findings show where a credential is and what kind
  it is, never its value, in text and JSON output alike.
- **Defensive only.** No offensive tooling, working exploits or payload
  collections. Test fixtures are inert: `example.invalid` domains and tokens
  marked `FAKE`.

## Why security scanners may flag this repository

This repository contains detection logic, and detection logic looks like the
thing it detects. Audit scripts carry regular expressions for credential
formats, download-and-execute commands, prompt-injection phrasing and hidden
Unicode. Fixtures contain fake tokens and deliberately suspicious hooks and
skill files so the checks can be tested. Secret scanners, malware scanners and
skill scanners (including this repository's own) may report these strings.

To keep that from hiding real problems, CI audits the repository with its own
supply-chain scanner:

```bash
python skills/skill-supply-chain-audit/scripts/audit_skill.py scan skills --baseline audit-baseline.json --fail-on high
```

`audit-baseline.json` at the repository root lists findings that maintainers
reviewed and accepted as intentional, such as a detection pattern in a script
or a fixture that is supposed to trigger a check. The self-audit job fails on
any high or critical finding that is not in the baseline. Changes to the
baseline are reviewed like code: each new entry must be explained in the pull
request.

If a scanner flags something here that is not a detection pattern, a test
fixture or documentation of an attack class, treat it as suspicious and report
it privately as described above.

## Verifying releases

Release assets are built by `.github/workflows/release.yml` from the tagged
commit with `tools/package_skills.py`, which produces deterministic zips.
Each release includes `SHA256SUMS.txt`. To check a download, compare its hash,
or rebuild from the tag (set `SOURCE_DATE_EPOCH` to the tagged commit's
timestamp) and compare.
