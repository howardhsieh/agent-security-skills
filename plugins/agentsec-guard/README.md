# agentsec-guard

Optional runtime guardrails for Claude Code, from
[agent-security-skills](https://github.com/howardhsieh/agent-security-skills).
Install it next to the `agentsec-kit` skills when you want protection while
the agent works, not only audits before and after.

## What it does

| Rule | Action | Fires on |
|---|---|---|
| G001 | deny | a download piped straight into a shell or interpreter (`curl ... \| sh`) |
| G002 | ask | reading or printing credential stores: `.env`, SSH private keys, `~/.aws/credentials`, GitHub CLI tokens, `.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`, Docker and kube config, the macOS keychain CLI |
| G003 | ask | `git push`, force-push, publish, release, `rm -rf`, `git reset --hard`, infrastructure teardown or `curl` uploads within 10 minutes after the session read web or MCP content |
| G004 | ask | edits to Claude Code settings, `.mcp.json`, hooks, agents, commands, skills, `CLAUDE.md`/`AGENTS.md`, Codex/Cursor/Gemini config, or shell profiles |
| G005 | ask | a Bash call that sets `dangerouslyDisableSandbox` |
| S001 | warn | installed plugins or skills changed since you approved them |

"Ask" shows Claude Code's normal permission prompt with the reason; you decide.
The guard never answers "allow", so it can only add prompts, never skip them.

## Exactly what runs, and what it touches

- **PreToolUse** (Bash, PowerShell, Read, Grep, Glob, Edit, Write, MultiEdit,
  NotebookEdit): `scripts/guard.py pre` reads the tool call JSON from stdin and
  checks it with regular expressions. Reads nothing else except its own state
  file for G003.
- **PostToolUse** (WebFetch, WebSearch, `mcp__*`): `scripts/guard.py post`
  writes one small JSON file per session (time and tool name only, never
  content) to the plugin data folder (`${CLAUDE_PLUGIN_DATA}`). Old session
  files are pruned after 7 days or beyond 200 sessions.
- **SessionStart** (startup, resume): `scripts/guard.py session` lists folders
  under `~/.claude/plugins/cache`, `~/.claude/skills` and `~/.agents/skills`
  and records file names, sizes and modification times (not contents) in
  `baseline.json` in the plugin data folder, then compares on later starts.

It makes **no network calls**, sends nothing anywhere, starts no background
process, and uses only the Python standard library. Each hook typically takes
tens of milliseconds; SessionStart takes longer with many installed plugins.
If the script fails for any reason it lets the call through and prints the
error to stderr (fail open), so it cannot break a session.

Requirement: Python 3.9+ on `PATH` as `python3` or `python`.

## Configure or turn off

- `AGENTSEC_GUARD_MODE=warn` (messages only) or `off`
- `AGENTSEC_GUARD_DISABLE=G002,G004` to turn off rules
- `AGENTSEC_GUARD_WINDOW=600` seconds for G003
- Uninstall: `/plugin uninstall agentsec-guard@agent-security-skills`

Ask Claude about any message, or run `/agentsec-guard:guard` for status,
dry-runs and approving packages after a review.

## Limits

Pattern matching on command text and paths is a seatbelt, not a sandbox: an
attacker can write a command the patterns miss. Keep the Claude Code sandbox
on, review plugins before installing them, and use `agent-trace-detection`
from agentsec-kit to look for what got through.

License: Apache-2.0.
