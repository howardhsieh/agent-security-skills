# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-09-30

### Added

- SKL044: documents inside a package (Office, OpenDocument, EPUB, RTF, PDF).
  Zipped documents are opened with size limits and their text gets the
  Markdown checks (override phrases, hidden comments, credential paths,
  download-and-execute); Markdown that tells the agent to follow a document
  the package ships is high severity. Zip data disguised under another name is
  reported as an archive, PDF data under another name as a document.
- Regression tests for the four scanner bypasses Trail of Bits published in
  June 2026: blank-line padding, `.pyc` bytecode, instructions in a `.docx`,
  and text aimed at an LLM-based scanner.
- README: how agentsec-kit compares with Cloudflare's security-audit skill,
  code-review skills, skill scanners, AgentShield and runtime hook projects.

## [0.2.1] - 2026-09-30

### Fixed

- The checkup no longer lowers the grade when `agentsec-guard` is installed.
  The guard's own detection patterns (credential paths, download-and-run
  commands) were reported as risks: the checkup now applies the guard's
  reviewed baseline, and `agent-config-audit` recognizes the released
  `guard.py` by SHA-256 (any modified copy is still analyzed). With both
  plugins installed on a clean setup the grade stays A.
- The `agentsec-guard` baseline test passes on Windows (`USERPROFILE`).

### Added

- `CODE_OF_CONDUCT.md`.

## [0.2.0] - 2026-09-30

### Added

- `agent-security-checkup` skill: one command grades the whole agent setup
  (Claude Code, Codex and Cursor configuration, every installed skill and
  plugin, MCP servers) from A to F, lists top risks and quick wins, and writes
  a self-contained, shareable HTML report. `--json`, `--md` and
  `--fail-below` for scripts.
- `agentsec-guard`, an optional second plugin in the marketplace: PreToolUse,
  PostToolUse and SessionStart hooks that deny download-and-execute commands,
  ask before credential-store reads, agent-config edits and sandbox bypass,
  ask before push or publish shortly after the session read web or MCP
  content, and warn when installed packages change. Never returns "allow";
  fails open; no network.
- GitHub Action (`action.yml`): audits skills, plugins and marketplaces in CI
  with a severity gate, baseline support, a job summary and optional SARIF
  upload to code scanning. Badge and usage in `docs/github-action.md`.
- `audit_skill.py scan|diff --sarif FILE` writes SARIF 2.1.0 with
  security-severity and stable fingerprints.
- Social preview and checkup screenshots under `docs/assets/`.

### Changed

- The plugin is now named `agentsec-kit` (install with
  `/plugin install agentsec-kit@agent-security-skills`); the repository and
  marketplace names are unchanged.
- README: quick start, the three ways to use the pack, and how it fits with
  agent-policy-gateway and TraceSig.

### Fixed

- README and docs now state the correct check count for
  `skill-supply-chain-audit` (32, including SKL039 for symlinks and special
  files) and the correct number of skills.

## [0.1.1] - 2026-09-29

### Fixed

- `tools/validate_skills.py` now detects a misnamed `skill.md` on
  case-insensitive filesystems (macOS, Windows), where it previously passed as
  `SKILL.md`. This made the macOS and Windows CI jobs fail on 0.1.0. The six
  skills themselves are unchanged.

### Changed

- CI uses `actions/checkout` v7 and `actions/setup-python` v7.
- The release workflow also attaches the skill zips to releases published from
  the GitHub web UI.

## [0.1.0] - 2026-09-29

Initial release: six defensive Agent Skills for teams that build and run AI
agents, packaged as the `agent-security` plugin in the `agent-security-skills`
Claude Code marketplace and as per-skill zips for claude.ai.

### Added

- `skill-supply-chain-audit`: audits skills, plugins and marketplaces before
  install or update, including hooks, scripts, MCP server definitions and
  instructions aimed at the agent.
- `agent-config-audit`: audits local agent configuration (Claude Code, Codex,
  Cursor) for risky permissions, hooks, MCP servers and exposed credentials.
- `agent-threat-model`: threat-models LLM and agent systems, checks each agent
  context for the lethal trifecta, and maps threats to OWASP Agentic Top 10
  2026, OWASP LLM Top 10 and MITRE ATLAS.
- `mcp-server-security-review`: source-code security review of MCP servers
  against the MCP 2026-07-28 specification.
- `agent-trace-detection`: normalizer for Claude Code session transcripts and
  OpenTelemetry exports, 12 Sigma rules for Claude Code telemetry, 7 TraceSig
  provenance rules (secret read then egress, untrusted content then publish,
  and more), and a Sigma validator and test evaluator.
- `agent-incident-response`: incident response for compromised skills, plugins,
  MCP servers and agent sessions, with a read-only artifact locator.
- Repository tooling: `tools/validate_skills.py` (Agent Skills spec and repo
  rules), `tools/package_skills.py` (deterministic upload zips), CI on Linux,
  macOS and Windows with Python 3.9 and 3.12, a self-audit job with
  `audit-baseline.json`, and a tag-triggered release workflow.
- Evals for each skill under `evals/`, install guide in `docs/install.md`, and
  a security policy.

[Unreleased]: https://github.com/howardhsieh/agent-security-skills/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/howardhsieh/agent-security-skills/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/howardhsieh/agent-security-skills/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/howardhsieh/agent-security-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/howardhsieh/agent-security-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/howardhsieh/agent-security-skills/releases/tag/v0.1.0
