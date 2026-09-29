# Claude Code hardening baseline

Verified against the Claude Code docs on 2026-09-29. Settings change often;
re-check the linked pages before rolling out to a team.

## Contents

- [How settings combine](#how-settings-combine)
- [Individual baseline](#individual-baseline)
- [Working in repositories you did not write](#working-in-repositories-you-did-not-write)
- [MCP servers](#mcp-servers)
- [Hooks](#hooks)
- [Team baseline (managed settings)](#team-baseline-managed-settings)
- [Sources](#sources)

## How settings combine

- Precedence, highest first: managed settings, `--settings` on the CLI,
  `.claude/settings.local.json`, `.claude/settings.json`, `~/.claude/settings.json`.
- Arrays such as `permissions.allow` and `permissions.deny` merge across files.
  A repository can add allow rules; you cannot "outvote" them from user
  settings, only deny.
- Rule evaluation is deny, then ask, then allow. The first match wins,
  regardless of how specific a rule is.
- Bash rules match the literal command text. `Bash(curl *)` in deny does not
  stop `/usr/bin/curl` or `sh -c "curl ..."`. Containment comes from the
  sandbox, not from deny lists.
- From a shared project file, allow rules, `additionalDirectories` and project
  MCP approvals apply only after the folder is trusted; deny and ask rules
  apply immediately. `claude -p` and SDK sessions treat the folder as trusted.

## Individual baseline

A starting point for `~/.claude/settings.json`. Merge with what you have; do
not paste over it.

```json
{
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable",
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.config/gh/**)"
    ],
    "ask": [
      "Bash(git push *)",
      "Bash(npm publish *)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "network": {
      "allowedDomains": ["github.com", "*.npmjs.org", "pypi.org", "files.pythonhosted.org"]
    }
  }
}
```

Why each part matters:

| Setting | Effect |
|---|---|
| `defaultMode: "default"` | Every new session asks before side effects |
| `disableBypassPermissionsMode: "disable"` | `--dangerously-skip-permissions` stops working |
| `deny: Read(...)` | File tools cannot read secrets; with the sandbox on, Read deny rules also feed `sandbox.filesystem.denyRead` |
| `ask` on push/publish | Irreversible, externally visible actions always prompt |
| `sandbox.enabled` | Bash runs with filesystem and network isolation (macOS, Linux, WSL2; Linux needs bubblewrap and socat) |
| `network.allowedDomains` | Egress limited to the hosts your work needs; never `*` |

Allow rules: prefer exact commands (`Bash(npm run test *)`,
`Bash(git diff *)`) over interpreters (`Bash(python *)`, `Bash(node *)`),
which are equivalent to allowing anything.

## Working in repositories you did not write

A repository can ship `.claude/settings.json` (hooks, env, permissions),
`.mcp.json` (servers) and skills. Before trusting the folder:

1. Read `.claude/settings.json`, `.claude/settings.local.json` if tracked, and
   `.mcp.json`. Run `scripts/audit_agent_config.py --project <repo>`.
2. Open it in `claude --safe-mode` first: no CLAUDE.md, skills, plugins,
   hooks or MCP servers load. For non-interactive runs, exclude project
   settings and project MCP servers:
   `claude -p --setting-sources user --strict-mcp-config "..."`.
3. Never set `enableAllProjectMcpServers: true` in user settings. Approve
   reviewed servers by name with `enabledMcpjsonServers` and block others with
   `disabledMcpjsonServers`.

## MCP servers

- Pin package versions in launch commands (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`).
  Unpinned launches install whatever is newest at every start.
- Remote servers over `https://` only; plain `http://` is acceptable for
  `localhost` alone.
- Put tokens in the environment and reference them (`${VAR}`); never commit a
  literal token in `.mcp.json`.
- Review the server source or provenance first (`mcp-server-security-review`).

## Hooks

- Hooks run shell commands with your privileges on agent events
  (SessionStart, PreToolUse, PostToolUse, Stop and more). Treat every hook as
  code you are about to run.
- HTTP hooks send event data to a URL. Pin destinations with
  `allowedHttpHookUrls` and limit forwarded variables with
  `httpHookAllowedEnvVars`.
- Plugins can ship hooks in `hooks/hooks.json`; the install screen does not
  show what they run. Audit plugins before install (`skill-supply-chain-audit`).

## Team baseline (managed settings)

Managed settings live in `managed-settings.json` (plus `managed-settings.d/`)
under `/Library/Application Support/ClaudeCode/` (macOS), `/etc/claude-code/`
(Linux/WSL) or `C:\Program Files\ClaudeCode\` (Windows), or arrive through
MDM or server-managed settings. Keys that only work there:

| Key | Use |
|---|---|
| `allowManagedHooksOnly` | Only organization-deployed hooks run |
| `allowManagedPermissionRulesOnly` | Only managed allow/ask/deny rules apply |
| `allowManagedMcpServersOnly` | Only the managed MCP allowlist applies |
| `strictKnownMarketplaces` | Allowlist of plugin marketplace sources |
| `blockedMarketplaces` | Blocklist of marketplace sources |
| `sandbox.network.allowManagedDomainsOnly` | Only managed egress domains apply |

`disableSkillShellExecution` stops skills and custom commands from running
inline shell when they load; it works in any settings file, and a managed
`true` cannot be overridden. Recommended for teams that install third-party
skills.

## Sources

- https://code.claude.com/docs/en/settings
- https://code.claude.com/docs/en/permissions
- https://code.claude.com/docs/en/sandboxing
- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/mcp
- https://code.claude.com/docs/en/managed-settings
