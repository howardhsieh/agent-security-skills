# Installing agent-security-skills

The repository holds seven Agent Skills under `skills/` and an optional
runtime guard plugin under `plugins/`. You can install the skills as
one Claude Code plugin, as individual skills on claude.ai, or as plain skill
folders for any agent that supports the
[Agent Skills specification](https://agentskills.io/specification).

| Skill | What it does |
| --- | --- |
| `agent-security-checkup` | One-command checkup of your whole agent setup, graded A to F, with an HTML report |
| `skill-supply-chain-audit` | Audits skills, plugins and marketplaces before install or update |
| `agent-config-audit` | Audits Claude Code, Codex and Cursor configuration for risky settings |
| `agent-threat-model` | Threat-models LLM and agent systems |
| `mcp-server-security-review` | Reviews MCP server source code |
| `agent-trace-detection` | Sigma-style detections for agent tool-call traces |
| `agent-incident-response` | Responds to a compromised skill, plugin, MCP server or agent session |

**Requirements.** The bundled scripts need Python 3.9 or later and no network.
They use only the standard library, except `sigma_check.py`
(agent-trace-detection), which needs PyYAML; running the TraceSig rules needs
[TraceSig](https://github.com/howardhsieh/tracesig). On Windows the skills tell the agent to run
`python` instead of `python3`.

**Review before you install.** A skill runs with your agent's permissions.
Read what you install, pin a release tag, and update deliberately. This applies
to this repository too.

Each section below says how its commands were checked. **Tested** means the
command was run against this repository before release. **Docs** means it was
checked against the vendor's documentation but not run here. See
[Verification status](#verification-status).

## Contents

- [Claude Code (plugin marketplace)](#claude-code-plugin-marketplace)
- [claude.ai and the Claude desktop app](#claudeai-and-the-claude-desktop-app)
- [npx skills (many agents)](#npx-skills-many-agents)
- [GitHub CLI: gh skill](#github-cli-gh-skill)
- [Manual install for other agents](#manual-install-for-other-agents)
- [Pin a version](#pin-a-version)
- [Update and uninstall](#update-and-uninstall)
- [Troubleshooting](#troubleshooting)
- [Verification status](#verification-status)

## Claude Code (plugin marketplace)

The repository is a Claude Code plugin marketplace named `agent-security-skills`
with two plugins:

- `agentsec-kit`: all seven skills.
- `agentsec-guard` (optional): runtime guardrail hooks. See
  [plugins/agentsec-guard](../plugins/agentsec-guard/README.md) for exactly
  what runs.

In a Claude Code session:

```text
/plugin marketplace add howardhsieh/agent-security-skills
/plugin install agentsec-kit@agent-security-skills
/plugin install agentsec-guard@agent-security-skills   # optional
```

`/plugin install` opens the plugin's details in the `/plugin` panel, where you
pick a scope and confirm.

From your shell:

```bash
claude plugin marketplace add howardhsieh/agent-security-skills
claude plugin install agentsec-kit@agent-security-skills
claude plugin install agentsec-guard@agent-security-skills   # optional
```

`claude plugin install` installs at user scope by default. Add
`--scope project` to enable it for everyone working in the current repository
(each collaborator still runs the install once).

On Claude Code v2.1.275 or later you can add the marketplace and install in one
step from a session:

```text
/plugin install agentsec-kit --marketplace howardhsieh/agent-security-skills
```

Check that it loaded:

```bash
claude plugin list
claude plugin details agentsec-kit
```

`details` lists the skills under `Component inventory`. Plugin skills are
namespaced, so you can also run one directly, for example
`/agentsec-kit:agent-config-audit`. Normally Claude picks the skill from your
request.

To try the skills without the plugin, copy folders into your personal skills
directory, `~/.claude/skills/<skill-name>/SKILL.md`, or a project's
`.claude/skills/`.

**Team setup.** To offer the marketplace to everyone who opens a repository,
add it to that repository's `.claude/settings.json`. Claude Code honors these
keys only after the user accepts the workspace trust dialog.

```json
{
  "extraKnownMarketplaces": {
    "agent-security-skills": {
      "source": {
        "source": "github",
        "repo": "howardhsieh/agent-security-skills",
        "ref": "v0.2.0"
      }
    }
  },
  "enabledPlugins": {
    "agentsec-kit@agent-security-skills": true
  }
}
```

Status: **Tested** from a local checkout (`claude plugin validate` passes,
`claude plugin marketplace add <path>` and `claude plugin install` succeed, and
`claude plugin details` lists the skills). The GitHub shorthand form and the
settings snippet are **Docs**.

## claude.ai and the Claude desktop app

### Upload individual skills

Each [GitHub release](https://github.com/howardhsieh/agent-security-skills/releases)
has one zip per skill, such as `agent-config-audit.zip`, with the skill folder at
the top level of the archive, which is the layout claude.ai expects.

1. Download the zip for the skill you want from the latest release.
2. In claude.ai or the desktop app, go to **Customize > Skills**.
3. Click **+**, then **+ Create skill**, then **Upload a skill**, and choose the zip.
4. Turn the skill on in the list.

Skills need **Code execution and file creation** turned on. On Team and
Enterprise plans an Owner may have to enable skills for the organization first.
Uploaded skills are private to you until you share them.

To build the same zips from a checkout: `python3 tools/package_skills.py`
(output in `dist/`).

Status: zip layout **Tested** (built and inspected with `zipfile`, one
top-level `<skill-name>/` folder); the upload flow is **Docs**.

### Add the marketplace (plugins)

claude.ai can also add a GitHub repository as a plugin marketplace: go to
**Customize > Plugins**, choose **Add > Add marketplace**, and enter
`howardhsieh/agent-security-skills`. Plugins you add this way sync to Claude
Code as well.

Status: **Docs, not tested with this repository.** This marketplace's plugin
entry has no `plugin.json` (the entry itself is the manifest, with
`"strict": false`). Claude Code accepts that layout; whether claude.ai lists
such a plugin has not been confirmed. If it does not appear, upload the
per-skill zips instead.

The repository has no top-level `bin/` directory, which would stop claude.ai
and Cowork from installing the plugin. `tools/validate_skills.py` fails if one
is added.

## npx skills (many agents)

The [`skills` CLI](https://github.com/vercel-labs/skills) installs skills into
the right folder for many agents, including Claude Code, Codex, Cursor, Gemini
CLI, GitHub Copilot and OpenCode. It needs Node.js.

```bash
# See what the repository offers
npx skills add howardhsieh/agent-security-skills --list

# Pick skills and agents interactively
npx skills add howardhsieh/agent-security-skills

# Install specific skills for specific agents
npx skills add howardhsieh/agent-security-skills --skill agent-config-audit --skill skill-supply-chain-audit -a claude-code -a codex

# Install everything for Claude Code in your home directory, without prompts
npx skills add howardhsieh/agent-security-skills --skill '*' -a claude-code -g -y
```

Useful flags: `-g` installs to your home directory instead of the current
project, `--copy` copies files instead of symlinking, and `-y` skips prompts.
To pin a release, point at the tag's tree URL, for example
`npx skills add https://github.com/howardhsieh/agent-security-skills/tree/v0.2.0/skills/agent-config-audit`.

Status: **Tested** from a local checkout (`--list` finds the skills;
`--skill agent-threat-model -a claude-code -a codex -y --copy` installs to
`.claude/skills/` and `.agents/skills/`). The GitHub shorthand and tree-URL
pinning are **Docs**.

## GitHub CLI: gh skill

`gh skill` is in public preview and needs GitHub CLI 2.90.0 or later. Preview a
skill before installing it; this renders its `SKILL.md` and file tree without
installing anything:

```bash
gh skill preview howardhsieh/agent-security-skills agent-config-audit
```

Install one skill, all skills, or a pinned version:

```bash
gh skill install howardhsieh/agent-security-skills agent-config-audit
gh skill install howardhsieh/agent-security-skills --all
gh skill install howardhsieh/agent-security-skills agent-config-audit@v0.2.0
gh skill install howardhsieh/agent-security-skills agent-config-audit --pin v0.2.0
```

By default `gh skill` installs for GitHub Copilot at project scope. Use
`--agent` and `--scope` for another agent, for example
`--agent claude-code --scope user`. `@VERSION` and `--pin` are mutually
exclusive; pinned skills are skipped by `gh skill update`.

Status: **Docs** (GitHub CLI manual and GitHub Docs; not run against this
repository).

## Manual install for other agents

Every skill is a self-contained folder. Copy `skills/<skill-name>/` into the
agent's skills directory, keeping the folder name. Get the files from a release
(the `agent-security-skills-<version>.zip` bundle) or a pinned clone:

```bash
git clone --depth 1 --branch v0.2.0 https://github.com/howardhsieh/agent-security-skills.git
mkdir -p ~/.agents/skills
cp -R agent-security-skills/skills/* ~/.agents/skills/
```

PowerShell:

```powershell
git clone --depth 1 --branch v0.2.0 https://github.com/howardhsieh/agent-security-skills.git
New-Item -ItemType Directory -Force "$HOME\.agents\skills" | Out-Null
Copy-Item -Recurse agent-security-skills\skills\* "$HOME\.agents\skills\"
```

Skill directories by agent:

| Agent | Project | Personal | Source |
| --- | --- | --- | --- |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` | Claude Code docs |
| OpenAI Codex | `.agents/skills/` (from the working directory up to the repo root) | `$HOME/.agents/skills/` | Codex docs |
| Cursor | `.agents/skills/` or `.cursor/skills/` | `~/.agents/skills/` or `~/.cursor/skills/` | Cursor docs |
| Gemini CLI | `.agents/skills/` or `.gemini/skills/` | `~/.agents/skills/` or `~/.gemini/skills/` | Gemini CLI docs |
| OpenCode | `.agents/skills/`, `.opencode/skills/` or `.claude/skills/` | `~/.agents/skills/`, `~/.config/opencode/skills/` or `~/.claude/skills/` | OpenCode docs |
| GitHub Copilot | `.agents/skills/`, `.github/skills/` or `.claude/skills/` | `~/.agents/skills/` or `~/.copilot/skills/` | GitHub Docs |

`.agents/skills/` works for Codex, Cursor, Gemini CLI, OpenCode and Copilot, so
one copy there covers all five. Cursor and OpenCode also read Claude Code's
`.claude/skills/` folders.

Gemini CLI can also install from Git directly:

```bash
gemini skills install https://github.com/howardhsieh/agent-security-skills.git --path skills/agent-config-audit
```

Restart the agent or reload its skills after copying. Codex, for example, picks
up new skills automatically but may need a restart; Gemini CLI has
`/skills reload`.

Status: paths and the `gemini skills install` command are **Docs** (vendor
documentation checked 2026-09-29), not tested with each agent.

## Pin a version

Pin to a release tag so an update to this repository never reaches your
agents unreviewed.

| Method | Pinned form |
| --- | --- |
| Claude Code | `/plugin marketplace add howardhsieh/agent-security-skills#v0.2.0` (also `claude plugin marketplace add ...#v0.2.0`), or `"ref": "v0.2.0"` in `extraKnownMarketplaces` |
| claude.ai | Upload zips from a specific release |
| npx skills | A tree URL at the tag, such as `https://github.com/howardhsieh/agent-security-skills/tree/v0.2.0/skills/<skill>` |
| gh skill | `<skill>@v0.2.0` or `--pin v0.2.0` |
| Manual | `git clone --branch v0.2.0`, or the release bundle zip |

Each release lists SHA-256 hashes in `SHA256SUMS.txt`, and the zips are built
deterministically from the tagged commit.

## Update and uninstall

Claude Code:

```bash
claude plugin marketplace update agent-security-skills
claude plugin update agentsec-kit@agent-security-skills
claude plugin uninstall agentsec-kit@agent-security-skills
claude plugin uninstall agentsec-guard@agent-security-skills
claude plugin marketplace remove agent-security-skills
```

The plugin declares a `version`, so installed copies change only when a
release bumps it. Removing the marketplace also uninstalls its plugins. To move
a pinned marketplace to a newer tag, remove it, add it again with the new
`#ref`, and reinstall (not tested; the Claude Code docs do not describe
changing the ref of a registered marketplace).

Other methods: `npx skills update` / `npx skills remove`, `gh skill update`,
or replace or delete the copied folders. On claude.ai, delete the old skill in
**Customize > Skills** and upload the new zip.

## Troubleshooting

- **Plugin installs but a skill is missing.** Run `claude plugin details agentsec-kit`.
  Each skill folder must contain `SKILL.md`; run
  `python3 tools/validate_skills.py` in a checkout to see what is wrong.
- **`Plugin "..." not found in marketplace`.** Install by the entry name,
  `agentsec-kit@agent-security-skills`.
- **Skill does not trigger.** Ask for the task in plain words ("audit my Claude
  Code settings"), or invoke the skill by name. The `evals/` folder lists
  prompts each skill should and should not respond to.
- **claude.ai rejects an upload.** Upload a per-skill zip, not the bundle or a
  zip of the whole repository. The archive must contain `<skill-name>/SKILL.md`
  at its top level. An older help-center article gives a 200-character limit for
  uploaded skill descriptions, while current docs follow the specification's
  1,024. These descriptions are under 500 characters. If a limit error appears,
  please open an issue.
- **Scripts fail on Windows.** Use `python`, not `python3`, and check
  `python --version` reports 3.9 or later.

## Verification status

Checked on 2026-09-29.

| Item | Status |
| --- | --- |
| `.claude-plugin/marketplace.json` passes `claude plugin validate --strict` (Claude Code 2.1.284 and 2.1.285) | Tested |
| Claude Code install from a local checkout: marketplace add, plugin install, plugin details | Tested |
| Claude Code install from `howardhsieh/agent-security-skills` (GitHub) and `#v0.2.0` pinning | Docs |
| Every skill folder passes `agentskills validate` (skills-ref 0.1.1) | Tested (all seven); run in CI |
| Per-skill zip layout for claude.ai upload | Tested (layout), Docs (upload) |
| claude.ai **Add marketplace** with this repository (no `plugin.json`) | Not tested |
| `npx skills add` discovery and install from a local checkout | Tested |
| `npx skills add` from GitHub and tree-URL pinning | Docs |
| `gh skill preview` / `install` / `--pin` | Docs |
| `gemini skills install --path` | Docs |
| Manual skill directories for Codex, Cursor, Gemini CLI, OpenCode, Copilot | Docs |
