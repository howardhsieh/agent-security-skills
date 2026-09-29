# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/howardhsieh/agent-security-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/howardhsieh/agent-security-skills/releases/tag/v0.1.0
