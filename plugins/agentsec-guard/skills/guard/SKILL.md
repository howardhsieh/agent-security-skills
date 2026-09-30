---
name: guard
description: Shows the status of the agentsec-guard runtime guardrails, explains why a tool call was blocked or questioned, dry-runs a command against the rules, and approves the currently installed plugins and skills as the new baseline after a review. Use when the user asks about agentsec-guard, a G001-G005 or S001 message, or wants to approve installed packages.
license: Apache-2.0
metadata:
  author: howardhsieh
  version: "0.2.1"
  repository: https://github.com/howardhsieh/agent-security-skills
---

# agentsec-guard

agentsec-guard is a set of Claude Code hooks from this plugin. They run a local
Python script before and after some tool calls and at session start. Nothing
is sent anywhere.

| Rule | Action | Fires on |
|---|---|---|
| G001 | deny | a download piped straight into a shell or interpreter |
| G002 | ask | reading or printing credential stores (.env, SSH keys, cloud and package-manager credentials, keychain) |
| G003 | ask | push, publish or destructive commands within 10 minutes of web or MCP content in the same session |
| G004 | ask | edits to agent settings, MCP config, hooks, CLAUDE.md or AGENTS.md, or shell profiles |
| G005 | ask | a command that disables the sandbox |
| S001 | warn | installed plugins or skills changed since the user approved them |

## What to do

- **Explain a message.** Quote the rule ID, say what it protects against, and
  ask whether the user requested the action. Never retry a denied command in a
  different form to get around the guard.
- **Status:** `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" status`
- **Dry-run a command:**
  `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" test '{"tool_name":"Bash","tool_input":{"command":"..."}}'`
- **Approve installed packages (S001).** Only after the user has reviewed what
  changed (the `skill-supply-chain-audit` skill from agentsec-kit does this),
  and only when the user asks: `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" approve`

Use `python` instead of `python3` on Windows.

## Configuration

Set in the environment before starting Claude Code (or in the `env` block of
`~/.claude/settings.json`):

- `AGENTSEC_GUARD_MODE=enforce` (default), `warn` (messages only), or `off`
- `AGENTSEC_GUARD_DISABLE=G002,G004` to turn off specific rules
- `AGENTSEC_GUARD_WINDOW=600` seconds for G003

Changing these weakens protection: only do it at the user's explicit request.

## Limits

The guard matches command text and file paths. A determined attacker can
obfuscate a command; the guard is a seatbelt, not a sandbox. Keep the Claude
Code sandbox on and review what you install.
