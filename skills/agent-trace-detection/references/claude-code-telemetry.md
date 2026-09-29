# Claude Code telemetry reference

Event and attribute names from the Claude Code monitoring docs
(https://code.claude.com/docs/en/monitoring-usage), verified 2026-09-29. Attributes
marked * appear only with `OTEL_LOG_TOOL_DETAILS=1` (or the prompt/response
flags). Check the docs for your version before relying on a field.

## Contents

- [Enabling log export](#enabling-log-export)
- [Attributes on every event](#attributes-on-every-event)
- [Security-relevant events](#security-relevant-events)
- [tool_parameters contents](#tool_parameters-contents)
- [Session transcripts](#session-transcripts)
- [Privacy notes](#privacy-notes)

## Enabling log export

| Variable | Purpose |
|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY=1` | Required to emit anything |
| `OTEL_LOGS_EXPORTER` | `console`, `otlp` or `none` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc`, `http/json` or `http/protobuf` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector endpoint |
| `OTEL_LOG_TOOL_DETAILS=1` | Adds `tool_parameters`, commands, MCP server/tool names, skill and plugin names |
| `OTEL_LOG_USER_PROMPTS=1` | Adds prompt text (sensitive) |
| `OTEL_LOG_ASSISTANT_RESPONSES=1` | Adds response text (sensitive) |
| `OTEL_LOGS_EXPORT_INTERVAL` | Export interval in ms (default 5000) |

Organizations can set these in managed settings so every developer machine
reports to the same collector.

## Attributes on every event

`event.name` (without the `claude_code.` prefix, e.g. `tool_result`),
`event.timestamp`, `event.sequence`, `session.id`, `prompt.id`, `app.version`,
`terminal.type`, `user.id`, `user.email`, `user.account_uuid`,
`organization.id`, plus any `OTEL_RESOURCE_ATTRIBUTES` keys and repository
attributes (`vcs.repository.url.full` and similar).

## Security-relevant events

| event.name | Key attributes | Detection use |
|---|---|---|
| `tool_result` | `tool_name`, `tool_use_id`, `success`, `duration_ms`, `decision_source` (config, hook, user_permanent, user_temporary), `mcp_server_scope`, `tool_parameters`* | What actually ran |
| `tool_decision` | `tool_name`, `decision` (accept, reject), `tool_source` (builtin, mcp, sdk_host_builtin_mcp), `source` (config, hook, user_permanent, user_temporary, user_abort, user_reject), `tool_parameters`* | What was attempted and who allowed or blocked it |
| `permission_mode_changed` | `from_mode`, `to_mode` (default, plan, acceptEdits, auto, bypassPermissions), `trigger` | Guardrails turned off |
| `mcp_server_connection` | `status` (connected, failed, disconnected), `transport_type`, `server_scope` (user, project, local), `is_plugin`, `server_name`* | Repository or plugin MCP servers coming online |
| `plugin_installed` | `marketplace.is_official`, `install.trigger`, `plugin.name`*, `marketplace.name`* | Supply-chain changes |
| `plugin_loaded` | `plugin.scope` (official, community, org, user-local, default-bundle), `enabled_via`, `has_hooks`, `has_mcp`, `plugin_id_hash` | Inventory; community plugins with hooks |
| `skill_activated` | `skill.name`*, `invocation_trigger` (user-slash, claude-proactive, nested-skill), `skill.source` (bundled, userSettings, projectSettings, plugin) | Which skills influence the agent |
| `hook_registered` | `hook_event`, `hook_type`, `hook_source` (userSettings, projectSettings, localSettings, flagSettings, policySettings, pluginHook), `hook_matcher`* | Code that runs on agent events |
| `hook_execution_start` / `_complete` | `hook_event`, `hook_name`, `num_hooks`, `hook_source` | Hook activity |
| `auth` | `action` (login, logout), `success`, `auth_method` | Account changes |
| `user_prompt` | `prompt_length`, `prompt`* | Context (sensitive) |

## tool_parameters contents

A JSON string. Keys by tool:

- Bash: `bash_command`, `full_command`, `timeout`, `description`,
  `dangerouslyDisableSandbox`; `git_commit_id`, `git_branch` on commits.
- MCP tools: `mcp_server_name`, `mcp_tool_name`.
- Skill: `skill_name`.
- Agent / Task: `subagent_type`.

Other tools (Read, WebFetch, Edit) do not report their paths or URLs in OTel.
Use transcripts when you need them.

## Session transcripts

`~/.claude/projects/<encoded-project-path>/<session-id>.jsonl`, one record per
line. Subagent transcripts live under `<session-id>/subagents/`. Relevant
records:

- `type: "assistant"` with `message.content[]` blocks of `type: "tool_use"`
  (`id`, `name`, `input`).
- `type: "user"` with blocks of `type: "tool_result"` (`tool_use_id`,
  `content`, `is_error`).
- Every record carries `sessionId`, `timestamp`, `cwd`, `isSidechain`.

The format is internal to Claude Code and may change; `normalize.py` ignores
record types it does not know.

## Privacy notes

- Transcripts contain full tool inputs and outputs, including file contents
  the agent read. Treat them like source code plus secrets.
- `user.email` and `user.id` are on every OTel event. Aggregate or pseudonymize
  where your policies require it.
- Prefer detections that work without prompt text.
