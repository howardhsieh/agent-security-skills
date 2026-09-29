# Persistence locations for agent incidents

Places where a malicious skill, plugin, MCP server or hijacked agent can leave something that runs
again or keeps its access, and how to inspect each one read-only. `recent-changes` in
`scripts/locate_agent_artifacts.py` checks the file-based ones by mtime (the `recent-changes`
column below). The rest need the manual command shown. Paths were checked against vendor docs on
2026-09-29. ATT&CK IDs are Enterprise v19.

## Contents

1. [How to inspect safely](#how-to-inspect-safely)
2. [Agent configuration: hooks, MCP entries, command settings](#agent-configuration)
3. [Skills, plugins and extensions](#skills-plugins-and-extensions)
4. [Instruction and memory files](#instruction-and-memory-files)
5. [Shell startup files](#shell-startup-files)
6. [Git hooks and git config](#git-hooks-and-git-config)
7. [macOS: launchd and login items](#macos)
8. [Linux: systemd user units, XDG autostart, cron](#linux)
9. [Windows: Startup folder, Run keys, scheduled tasks](#windows)
10. [SSH access](#ssh-access)
11. [IDE tasks and extensions](#ide-tasks-and-extensions)
12. [What mtime cannot tell you](#what-mtime-cannot-tell-you)

## How to inspect safely

- Read with `cat`, `less`, `plutil -p`, `systemctl --user cat` or a text editor. Never `source`,
  `bash`, `launchctl load` or double-click a suspect file to see what it does.
- Copy to the evidence folder with `cp -p` before editing or deleting anything.
- Diff against a known-good source: a dotfiles repo, a backup, a teammate's machine, or the
  vendor default.
- Look for: commands that download and run (`curl ... | sh`, `iwr ... | iex`), base64 or hex
  blobs, `eval`, outbound hosts, new `PATH` entries in front of system dirs, aliases that shadow
  `git`, `ssh`, `sudo` or `claude`, and references to files in temp or hidden dirs.

## Agent configuration

Hooks and helper commands run automatically with the user's privileges, and MCP entries start
processes or connect to remote servers. These are the first place to look.

| Agent | Files | What can persist | recent-changes |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json`, `~/.claude/settings.local.json`, project `.claude/settings.json` and `.claude/settings.local.json` | `hooks`, `statusLine`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `fileSuggestion` commands; `env`; permission allow rules; `enabledPlugins`; `extraKnownMarketplaces` | yes |
| Claude Code | `~/.claude.json`, project `.mcp.json` | MCP servers (`mcpServers`) and per-project state. `~/.claude.json` is rewritten often, so diff it rather than trusting mtime | yes |
| Claude Code (managed) | `/etc/claude-code/`, `/Library/Application Support/ClaudeCode/`, `C:\Program Files\ClaudeCode\`: `managed-settings.json`, `managed-settings.d/`, `managed-mcp.json`, `CLAUDE.md`, `.claude/skills/` | Everything above, for all users; needs admin rights to write | `--include-system` |
| Claude Code plugins | `hooks/hooks.json`, `.mcp.json` and `.lsp.json` inside each plugin; hooks in skill or agent frontmatter | Hooks and servers that run while the plugin or skill is enabled | via plugin dirs |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, `%APPDATA%\Claude\claude_desktop_config.json` | Local MCP servers started with the app | yes |
| Codex | `~/.codex/config.toml`, `~/.codex/hooks.json`, project `.codex/config.toml` and `.codex/hooks.json` (`CODEX_HOME` moves `~/.codex`) | `[mcp_servers.*]`, `[hooks]`, `notify` command, `[[skills.config]]`, plugin choices | yes |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json`, `~/.cursor/hooks.json`, `.cursor/hooks.json`; enterprise `/etc/cursor/hooks.json`, `/Library/Application Support/Cursor/hooks.json`, `C:\ProgramData\Cursor\hooks.json` | MCP servers and hooks | yes (enterprise with `--include-system`) |
| Gemini CLI | `~/.gemini/settings.json`, `.gemini/settings.json`; system `settings.json` and `system-defaults.json` under `/etc/gemini-cli/`, `/Library/Application Support/GeminiCli/`, `C:\ProgramData\gemini-cli\` | `mcpServers`, `hooks` | yes (system with `--include-system`) |
| OpenCode | `~/.config/opencode/opencode.json`, project `opencode.json` | `mcp`, `plugin` entries | yes |
| VS Code (Copilot) | `.vscode/mcp.json`, `.mcp.json`, user-profile `mcp.json` | MCP servers | yes (user path assumed next to `settings.json`) |

Inspect: `claude mcp list`, `claude plugin list`, `/hooks` inside a session, and
`python3 -m json.tool FILE` to read the JSON. Harden afterwards with `agent-config-audit`.

## Skills, plugins and extensions

| Location | Notes | recent-changes |
|---|---|---|
| `~/.claude/skills/`, `.claude/skills/`, nested `<dir>/.claude/skills/` | Personal and project skills; a folder with `.claude-plugin/plugin.json` loads as a `@skills-dir` plugin | yes |
| `~/.claude/skills/synced/` | Downloaded from claude.ai about every 10 minutes; removal happens on claude.ai | yes (noisy) |
| `~/.claude/commands/`, `~/.claude/agents/`, project equivalents | Legacy commands and subagents; can carry hooks and tool grants | yes |
| `~/.claude/plugins/` (`cache/`, `marketplaces/`, `data/`, `synced/`, `.trash/`, `installed_plugins.json`, `known_marketplaces.json`) | Plugin root, moved by `CLAUDE_CODE_PLUGIN_CACHE_DIR`; `data/` survives updates | yes |
| `~/.agents/skills/`, `.agents/skills/`, `~/.config/agents/skills/` | Shared by Codex, Gemini CLI, Copilot, Cursor, OpenCode and `npx skills` (canonical copy; other agents often symlink to it) | yes |
| `~/.agents/.skill-lock.json` (or `$XDG_STATE_HOME/skills/.skill-lock.json`), project `skills-lock.json` | `npx skills` install records | yes |
| `~/.codex/skills/`, `~/.codex/plugins/cache/`, `/etc/codex/skills/` | Codex and `npx skills` global installs for Codex; admin skills | yes (`/etc` with `--include-system`) |
| `~/.cursor/skills/`, `.cursor/skills/` | Cursor also loads `.claude/skills`, `.codex/skills` and their home equivalents | yes |
| `~/.gemini/skills/`, `.gemini/skills/`, `~/.gemini/extensions/` | Gemini CLI skills and extensions (extensions can bundle skills, MCP servers and hooks) | yes |
| `~/.config/opencode/skills/`, `.opencode/skills/`, `~/.config/opencode/plugins/`, `.opencode/plugins/` | OpenCode skills and JS plugins | yes |
| `~/.copilot/skills/`, `.github/skills/` | GitHub Copilot | yes |

Use `find-skill` to find every copy of one suspect by name, frontmatter or manifest name, or file
hash. Other agents supported by `npx skills` use their own folders (listed in its README); add
them with `--extra-root`.

## Instruction and memory files

Injected instructions here persist across sessions and steer every future run (ASI06 Memory &
Context Poisoning, Agentic Top 10 2026).

| Files | recent-changes |
|---|---|
| `~/.claude/CLAUDE.md`, `~/.claude/rules/`, project `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/` | yes |
| `~/.claude/projects/<project>/memory/` (auto memory, `MEMORY.md` loaded every session) | yes |
| `~/.codex/AGENTS.md`, `~/.codex/AGENTS.override.md`, project `AGENTS.md` and `AGENTS.override.md` | yes |
| `~/.gemini/GEMINI.md`, project `GEMINI.md` | yes |
| `.cursor/rules/`, `.cursorrules`, `.github/copilot-instructions.md` | yes (project root only) |

Nested instruction files in subdirectories are not scanned. Search for them with
`find . -name CLAUDE.md -o -name AGENTS.md -o -name GEMINI.md`.

## Shell startup files

ATT&CK T1546.004 Unix Shell Configuration Modification and T1546.013 PowerShell Profile.

| Shell | Files | recent-changes |
|---|---|---|
| bash | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile` | yes |
| zsh | `~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.zlogin` | yes |
| fish | `~/.config/fish/config.fish`, `~/.config/fish/conf.d/` | yes |
| PowerShell 7 | `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` and `Profile.ps1`; `~/.config/powershell/` on Linux and macOS | yes |
| Windows PowerShell 5.1 | `$HOME\Documents\WindowsPowerShell\` profiles | yes |
| System-wide | `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/zshrc`, `$PSHOME\Profile.ps1` | manual |

Inspect: `grep -nE 'curl|wget|iwr|eval|base64|alias (git|ssh|sudo|claude)|PATH=' ~/.bashrc ~/.zshrc`,
or `$PROFILE | Format-List -Force` in PowerShell, then read each file.

## Git hooks and git config

- Hooks in `.git/hooks/` run on commit, checkout, merge and push. Files ending in `.sample` never
  run, and hooks without the executable bit are ignored. `recent-changes` skips `.sample` files.
  In a worktree, the script follows the `.git` file to the common directory.
- `core.hooksPath` redirects hooks to any directory, and `core.fsmonitor` can name a hook command
  git runs on status and diff. Both can be set in `.git/config`, `~/.gitconfig`,
  `~/.config/git/config` or system config. Inspect:
  `git config --show-origin --get-regexp '^core[.](hookspath|fsmonitor)$'`.
- Also check `includeIf` and `include.path` entries that pull in other config files, and
  `credential.helper` entries pointing to unknown scripts.

## macOS

| Location | Notes | recent-changes |
|---|---|---|
| `~/Library/LaunchAgents/` | Per-user agents (T1543.001) | yes |
| `/Library/LaunchAgents/`, `/Library/LaunchDaemons/` | All users, and system daemons (T1543.004); admin rights to write | `--include-system` |
| Login and background items | System Settings > General > Login Items | manual |

Inspect: `plutil -p FILE.plist` (look at `ProgramArguments`, `RunAtLoad`, `KeepAlive`),
`launchctl print gui/$(id -u) | grep -i LABEL`. Unload with `launchctl bootout gui/$(id -u) FILE`
only after the evidence copy and approval.

## Linux

| Location | Notes | recent-changes |
|---|---|---|
| `~/.config/systemd/user/`, `~/.local/share/systemd/user/` | User units and timers (T1543.002, T1053.006) | yes |
| `/etc/systemd/user/`, `/etc/xdg/autostart/` | System-wide user units and autostart | `--include-system` |
| `~/.config/autostart/*.desktop` | XDG autostart for desktop sessions (T1547.013) | yes |
| User crontab | Spool under `/var/spool/cron/` is root-only; use `crontab -l` (T1053.003) | manual |
| `/etc/crontab`, `/etc/cron.d/` | System cron | `--include-system` |

Inspect: `systemctl --user list-unit-files --state=enabled`, `systemctl --user list-timers --all`,
`systemctl --user cat UNIT`, `crontab -l`. Disable with `systemctl --user disable --now UNIT`
after approval.

## Windows

| Location | Notes | recent-changes |
|---|---|---|
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Per-user Startup folder (T1547.001) | yes |
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` | All users | `--include-system` |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` (and HKLM equivalents) | Registry autostart | manual: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Scheduled tasks | Task Scheduler service (T1053.005) | manual: `schtasks /query /fo LIST /v` |
| Services | T1543.003; admin rights to write | manual: `Get-CimInstance Win32_Service` |

## SSH access

| File | Why | recent-changes |
|---|---|---|
| `~/.ssh/authorized_keys` | An added public key gives the attacker login access (T1098.004) | yes |
| `~/.ssh/config` | `ProxyCommand`, `LocalCommand` with `PermitLocalCommand`, `Match exec` run commands on connect | yes |

Also check `authorized_keys` on every host the agent could reach over SSH, and remove private keys
the agent could read from the machine once they are rotated
([credential-rotation.md](credential-rotation.md)).

## IDE tasks and extensions

| Location | Why | recent-changes |
|---|---|---|
| `.vscode/tasks.json` | A task with `"runOptions": {"runOn": "folderOpen"}` runs when the folder opens in a trusted workspace, if `task.allowAutomaticTasks` allows it | yes |
| `.vscode/settings.json`, user `settings.json` (`~/.config/Code/User/`, `~/Library/Application Support/Code/User/`, `%APPDATA%\Code\User\`) | Settings that point at executables, terminal profiles, MCP | yes |
| `~/.vscode/extensions/` | New or updated extensions (T1176.002); folder names include publisher and version | yes (top level) |

Inspect: `code --list-extensions --show-versions`; remove with `code --uninstall-extension ID`
after approval. VS Code forks (Cursor, Windsurf) keep extensions in their own folders; add them
with `--extra-root` or check them by hand.

## What mtime cannot tell you

- mtime is set by whoever writes the file, and `touch -d` or `os.utime` can backdate it. On POSIX,
  `--use-ctime` also flags inode change time, which user tools cannot set directly, and marks
  entries where ctime falls inside the window but mtime does not.
- Deleted files leave no mtime. Payloads that removed themselves show up only in transcripts,
  shell history, EDR telemetry or backups.
- Agents rewrite some files constantly (`~/.claude.json`, synced skills, plugin auto-updates), so
  a change there is expected. Diff the content against a known-good copy.
- Registry values, scheduled tasks, login items, crontab and remote state (connector grants,
  repository webhooks, CI secrets, cloud IAM) have no file here. Check them with their own tools
  and audit logs.
