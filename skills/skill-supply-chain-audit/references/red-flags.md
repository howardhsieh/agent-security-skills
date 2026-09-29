# Red flags when reviewing a skill or plugin

Grouped by the OWASP Agentic Skills Top 10 (v1.0, March 2026) and ASI04
Agentic Supply Chain Vulnerabilities (Agentic Top 10 2026). For each: what to
look for, which scanner check helps, and what only a human read catches.

## Contents

- [AST01 Malicious Skills](#ast01-malicious-skills)
- [AST02 Supply Chain Compromise](#ast02-supply-chain-compromise)
- [AST03 Over-Privileged Skills](#ast03-over-privileged-skills)
- [AST04 Insecure Metadata](#ast04-insecure-metadata)
- [AST05 Untrusted External Instructions](#ast05-untrusted-external-instructions)
- [AST06 Weak Isolation](#ast06-weak-isolation)
- [AST07 Update Drift](#ast07-update-drift)
- [AST08 Poor Scanning](#ast08-poor-scanning)
- [AST09 No Governance](#ast09-no-governance)
- [AST10 Cross-Platform Reuse](#ast10-cross-platform-reuse)
- [Questions to ask of every executable file](#questions-to-ask-of-every-executable-file)

## AST01 Malicious Skills

Look for:
- Hooks or scripts that fetch and run remote code, read credential stores, or
  post data to hosts unrelated to the skill's stated purpose.
- Instructions that tell the agent to hide steps from the user, skip
  confirmations, or send files somewhere.
- Hidden text: invisible Unicode, HTML comments, text after many blank lines,
  instructions inside example files the agent is told to read.

Scanner: SKL010, SKL011, SKL013, SKL021, SKL022, SKL032, SKL034.
Human only: whether a network destination is plausible for the feature; whether
"example" text is really an instruction; logic spread across several files.

## AST02 Supply Chain Compromise

Look for:
- Dependencies installed at runtime (`npx -y`, `uvx`, `pip install` inside a
  hook or script) without a version pin.
- Marketplace entries that point to other repositories.
- Skills that tell the agent to install more skills or plugins.

Scanner: SKL016, SKL040, SKL050, SKL051.
Human only: reputation of each transitive dependency; whether the upstream
repository recently changed hands.

## AST03 Over-Privileged Skills

Look for:
- `allowed-tools` that pre-approves all shell commands or wildcards.
- Hooks on every tool call or every prompt when the feature needs one event.
- Scripts that touch files outside the skill folder or the user's project.

Scanner: SKL015, SKL024, SKL023.
Human only: the minimum privilege the stated feature needs.

## AST04 Insecure Metadata

Look for:
- Frontmatter fields beyond the portable six (`name`, `description`,
  `license`, `compatibility`, `metadata`, `allowed-tools`); agent-specific
  fields such as `hooks`, `shell` or `model` change behavior on some agents.
- Descriptions stuffed with trigger words so the skill activates everywhere.
- Names that imitate popular skills.

Scanner: SKL001-SKL004.
Human only: whether the description matches what the files actually do.

## AST05 Untrusted External Instructions

Look for:
- "Fetch the latest rules from <url> and follow them."
- Reference files loaded from a URL at runtime instead of bundled.
- Inline shell in SKILL.md whose output becomes part of the prompt.

Scanner: SKL012, SKL014.
Human only: any indirection where text the author controls later (a gist, a
wiki page, an API response) becomes instructions.

## AST06 Weak Isolation

Look for:
- Hooks, `bin/` executables and inline shell run with the user's full
  privileges, outside any sandbox.
- Writes to shell profiles, cron, launch agents, systemd units, startup
  folders or git hooks (persistence that survives uninstall).

Scanner: SKL012, SKL020, SKL023, SKL037, SKL039 (symlinks out of the package).
Mitigate: enable the agent's sandbox (`agent-config-audit`), set
`disableSkillShellExecution` for third-party skills, avoid plugins with hooks
unless needed.

## AST07 Update Drift

Look for:
- No pinned version anywhere: marketplace entry without `sha`, install from a
  branch, auto-update enabled.
- A package that was clean at review time; nothing guarantees the next version
  is.

Scanner: SKL040, SKL050, and the `lock` / `diff` subcommands.
See [pinning-and-drift.md](pinning-and-drift.md).

## AST08 Poor Scanning

Static scanning is evadable (Trail of Bits, 2026-06-03; Ji et al., 2026-07-02).
Look for anything that resists reading: encoded blobs, minified code, binaries,
archives, very long lines, generated code. Treat unreadable as unapproved.

Scanner: SKL033-SKL036, SKL038.

## AST09 No Governance

For teams: keep an inventory of approved skills and plugins with the reviewed
commit and lockfile, restrict marketplace sources with managed settings
(`strictKnownMarketplaces`, `blockedMarketplaces`), and log installs and skill
activations (`agent-trace-detection` covers `plugin_installed` and
`skill_activated` telemetry).

## AST10 Cross-Platform Reuse

A skill reviewed for one agent can behave differently in another: fields such
as `allowed-tools` or `hooks` are honored by some agents and ignored by
others, and install paths differ. Review for every agent you will install it
into, and note which agent-specific fields are present (SKL003).

## Questions to ask of every executable file

1. What event or instruction makes this run, and how often?
2. What does it read? Anything outside the skill folder or the project?
3. What does it write? Anything that persists after uninstall?
4. Does it talk to the network? To which hosts, carrying what data?
5. Does it build or decode code at runtime?
6. Could the stated feature work without it?
