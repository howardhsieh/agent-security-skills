# Codex and Cursor hardening baseline

Verified against vendor docs on 2026-09-29. OpenAI moved the Codex config
reference to learn.chatgpt.com; older links redirect.

## Contents

- [Codex: how configuration loads](#codex-how-configuration-loads)
- [Codex: individual baseline](#codex-individual-baseline)
- [Codex: MCP servers](#codex-mcp-servers)
- [Codex: admin requirements](#codex-admin-requirements)
- [Cursor](#cursor)
- [Sources](#sources)

## Codex: how configuration loads

- User config: `~/.codex/config.toml` (or `$CODEX_HOME`). Profiles:
  `$CODEX_HOME/<name>.config.toml`, selected with `--profile`.
- Project config: `.codex/config.toml`, loaded only for trusted projects.
  Trust is recorded per path: `[projects."<path>"] trust_level = "trusted"`.
- Admin requirements: `/etc/codex/requirements.toml` or
  `%ProgramData%\OpenAI\Codex\requirements.toml`; values that conflict with
  requirements fall back to a compatible value.

## Codex: individual baseline

```toml
sandbox_mode    = "workspace-write"
approval_policy = "on-request"

[sandbox_workspace_write]
network_access = false

[shell_environment_policy]
ignore_default_excludes = false
```

| Setting | Effect |
|---|---|
| `sandbox_mode = "workspace-write"` | Commands can write only inside the workspace; `.git`, `.agents` and `.codex` stay read-only |
| `approval_policy = "on-request"` | The agent asks before stepping outside the sandbox |
| `network_access = false` | Sandboxed commands cannot reach the network |
| `ignore_default_excludes = false` | Secret-named environment variables (KEY, SECRET, TOKEN) are not passed to commands |

Avoid:

- `sandbox_mode = "danger-full-access"` outside a disposable container or VM.
- `approval_policy = "never"` with anything other than a read-only sandbox.
- `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`) on your own
  machine.
- `approval_policy = "untrusted"`: retired and unsupported. For stricter
  approvals, set `trust_level = "untrusted"` on the project entry instead
  (this also disables project-local config).
- `approval_policy = "on-failure"`: deprecated.

Codex 0.138.0 and later also support permission profiles
(`default_permissions = ":workspace"` and friends); prefer them when your
version supports them.

## Codex: MCP servers

```toml
[mcp_servers.issues]
url = "https://mcp.example.com/issues"
bearer_token_env_var = "ISSUES_MCP_TOKEN"
default_tools_approval_mode = "prompt"
```

- Reference tokens by environment variable (`bearer_token_env_var`, `env`
  pointing at variables), never as literals in `config.toml`.
- Pin package versions in stdio launch commands.
- Use `enabled_tools` / `disabled_tools` to expose only what the task needs,
  and `default_tools_approval_mode = "prompt"` (or `writes`) for servers that
  can change things.

## Codex: admin requirements

```toml
# requirements.toml
allowed_approval_policies = ["on-request"]
allowed_sandbox_modes     = ["read-only", "workspace-write"]
allow_managed_hooks_only  = true
```

- `allowed_sandbox_modes` / `allowed_approval_policies` block
  `danger-full-access` and `never` fleet-wide. On Codex 0.138.0+ prefer
  `allowed_permission_profiles` with a managed `default_permissions`.
- `allow_managed_hooks_only` skips user, project, session and plugin hooks
  (it only works in `requirements.toml`).
- An `mcp_servers` allowlist with identities enables only approved servers.

## Cursor

Local files:

- MCP servers: `~/.cursor/mcp.json` (user) and `.cursor/mcp.json` (project,
  often committed). Same rules as above: pinned versions, HTTPS, tokens from
  the environment, review before enabling repository-supplied servers.
- Sandbox: `~/.cursor/sandbox.json` / `.cursor/sandbox.json`. Keep the sandbox
  on and default-deny the network:

```json
{
  "networkPolicy": {
    "default": "deny",
    "allow": ["registry.npmjs.org"]
  }
}
```

App settings (not in files, check by hand): Run Mode (auto-run of commands),
sandbox network mode, and Browser / File-Deletion / External-File protection
under Settings > Agents > Approvals & Execution. Team dashboard policies (MCP
allowlist, Run Modes, sandbox networking) override local files.

## Sources

- https://learn.chatgpt.com/docs/config-file/config-reference
- https://learn.chatgpt.com/docs/agent-approvals-security
- https://cursor.com/docs
