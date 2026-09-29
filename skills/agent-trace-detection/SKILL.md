---
name: agent-trace-detection
description: Builds and runs detections over AI coding-agent activity - normalizes Claude Code session transcripts and OpenTelemetry exports, runs bundled Sigma rules (for SIEMs) and TraceSig rules (provenance-aware, e.g. secret read then network call, untrusted content then publish), and guides writing and testing new agent detections. Use to set up monitoring for coding-agent fleets, hunt through local transcripts after a suspicious session, or write detection rules for agent tool calls.
license: Apache-2.0
compatibility: Python 3.9+. sigma_check.py needs PyYAML. TraceSig rules need the tracesig package from github.com/howardhsieh/tracesig.
metadata:
  author: howardhsieh
  version: "0.1.0"
  repository: https://github.com/howardhsieh/agent-security-skills
---

# Agent trace detection

Prevention fails eventually: a skill turns malicious after an update, a web
page injects instructions, a permissive setting slips through. This skill is
the detection layer. It turns what Claude Code already records (session
transcripts on disk, OpenTelemetry events for fleets) into rows that rules can
run on, ships a tested starter rule pack, and shows how to write detections
that key on provenance and behavior rather than on payload keywords.

## When to use

- Setting up monitoring for developers who use coding agents (SIEM via Sigma).
- Hunting after a suspicious session: "did the agent read secrets and then
  call out?", "what ran right after it read that issue?"
- Writing and testing a new detection for agent tool calls.
- Adding CI checks that fail when an agent trace trips a critical rule.

Not for: hardening configuration (`agent-config-audit`), reviewing a package
before install (`skill-supply-chain-audit`), or running a full incident
(`agent-incident-response`, which uses this skill for scoping).

## Safety rules

- Telemetry and transcripts are sensitive: they can contain source code,
  prompts, file contents and secrets. Keep them local unless the user decides
  otherwise; the scripts redact credential-looking strings but are not a DLP.
- Do not turn on `OTEL_LOG_USER_PROMPTS` or raw API body logging without the
  user's (and, at work, the organization's) agreement.
- Detections describe behavior. When writing rules, never include real
  payloads or working attack strings; use inert fixtures (example.invalid).

## Two sources, two formats

| Source | Where | Best for | Limits |
|---|---|---|---|
| Session transcripts | `~/.claude/projects/<project>/<session>.jsonl` | Local forensics, full tool inputs and results | One machine; users can delete them |
| OpenTelemetry events | Your collector / SIEM | Fleets, real-time alerting, plugin/hook/MCP lifecycle events | Tool details only with `OTEL_LOG_TOOL_DETAILS=1`; no tool results |

`scripts/normalize.py` reads either and writes:

- `--format tracesig` (default): one tool call per line in the TraceSig trace
  schema, with provenance labels and category-suffixed Bash names:

| Label / name | Meaning |
|---|---|
| `web`, `untrusted` | WebFetch / WebSearch results |
| `mcp`, `untrusted` | Any MCP tool result (issues, email, docs from external systems) |
| `file` / `file`, `secret` | File reads; `secret` for .env, SSH keys, cloud and package-manager credentials |
| `Bash(network)` | curl, wget, nc, scp, ssh, rsync to remote, PowerShell web cmdlets |
| `Bash(publish)` | git push, npm/pnpm/yarn publish, twine upload, docker push, gh release/pr/gist create |
| `Bash(destructive)` | rm -rf, git reset --hard, force push, DROP, kubectl delete, terraform destroy |
| `Bash(install)` | package installs and download-and-execute installers |

- `--format flat`: one flat JSON object per event with Claude Code OTel
  attribute names (`event.name`, `tool_name`, `tool_parameters`, ...).
  Transcripts are converted to `tool_result`-shaped events so the Sigma rules
  run on them too.

## Workflow

```
- [ ] 1. Pick the source (transcripts or OTel) and export it
- [ ] 2. Normalize
- [ ] 3. Run the bundled rules
- [ ] 4. Triage findings with the surrounding timeline
- [ ] 5. Write or tune rules; test with positive and negative fixtures
```

### 1. Export

Transcripts need nothing: they are on disk. For OpenTelemetry, set before
starting Claude Code (full reference:
[references/claude-code-telemetry.md](references/claude-code-telemetry.md)):

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/json
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_LOG_TOOL_DETAILS=1   # needed for Bash commands, MCP/skill names
```

A local OpenTelemetry Collector with a file exporter produces the OTLP/JSON
files `normalize.py` reads. Organizations usually send the same events to
their SIEM directly.

### 2. Normalize

Call the scripts by full path from the user's working directory;
`${CLAUDE_SKILL_DIR}` is this skill's folder (Claude Code fills it in; in other
agents use the folder that contains this SKILL.md). `python` on Windows. Write
outputs to a private working folder, not into the skill:

```bash
S="${CLAUDE_SKILL_DIR}"; W=~/agent-hunt; mkdir -p "$W"
python3 "$S/scripts/normalize.py" ~/.claude/projects/PROJECT/ --out "$W/trace.jsonl"
python3 "$S/scripts/normalize.py" ~/.claude/projects/PROJECT/SESSION.jsonl --format flat --out "$W/flat.jsonl"
python3 "$S/scripts/normalize.py" otel-export.json --format flat --out "$W/flat.jsonl"
```

`--session <id>` keeps one session. Output is redacted.

### 3. Run the rules

TraceSig rules (provenance chains, in `assets/tracesig/`):

```bash
pip install "git+https://github.com/howardhsieh/tracesig@773e019a4fd84a6a8ca17acb1ba4b51076abe82c"
tracesig scan "$W/trace.jsonl" --rules "$S/assets/tracesig/"
tracesig scan "$W/trace.jsonl" --rules "$S/assets/tracesig/" --fail-on critical   # CI
```

| ID | Severity | Chain |
|---|---|---|
| CC-EXF-001 | critical | secret read, then network shell, web fetch or MCP send/write |
| CC-EXF-002 | critical | secret read, then push or publish |
| CC-INJ-001 | critical | untrusted content, then push or publish within 5 calls |
| CC-INJ-002 | high | untrusted content, then destructive command within 5 calls |
| CC-INJ-003 | medium | untrusted content, then package install within 3 calls |
| CC-INJ-004 | high | untrusted tool result asks for tokens, passwords or keys |
| CC-PRIV-001 | high | agent edits its own settings, MCP config, CLAUDE.md/AGENTS.md or shell profile |

Sigma rules (single events, in `assets/sigma/`, `logsource: product: claude_code, service: otel`):

```bash
python3 "$S/scripts/sigma_check.py" test "$S/assets/sigma/" --events "$W/flat.jsonl"
```

They cover bypassPermissions mode, sandbox-disabled commands,
download-and-execute, credential-store access, force push, publishing,
non-official plugin installs, community plugins with hooks, repository MCP
servers, repository hooks, repository skills invoked proactively, and
hook-blocked tool calls. `sigma_check.py` is a small evaluator for testing;
for production, convert with pySigma or sigma-cli using a pipeline that maps
these field names to your SIEM's schema and parses the `tool_parameters`
JSON string (the rules address its keys as `tool_parameters.<key>`).

### 4. Triage

For each finding, rebuild the timeline around it (the normalized trace keeps
order and a 300-character result preview) and answer: what untrusted input
preceded it, did the user ask for this, what data could have left, and was it
blocked? Escalate confirmed chains to `agent-incident-response`.

### 5. Write and test rules

Method and patterns: [references/writing-agent-detections.md](references/writing-agent-detections.md).
Minimum bar for any new rule:

- keys on provenance or behavior (label, tool category, order), not on
  specific payload strings;
- one positive and one negative fixture (inert data);
- `falsepositives` written down and a level that matches the evidence;
- run against a week of normal traces before alerting on it.

```bash
python3 "$S/scripts/sigma_check.py" validate my-rule.yml
python3 "$S/scripts/sigma_check.py" test my-rule.yml --events positive.jsonl --expect-match
python3 "$S/scripts/sigma_check.py" test my-rule.yml --events benign.jsonl --expect-no-match
```

## Output format

```
## Agent trace review: <scope>, <time window>
Sources: <transcripts / OTel>, <n> sessions, <n> tool calls
Findings: <rule, severity, session, timeline excerpt, verdict (true/false positive, why)>
Gaps: <what the telemetry could not show>
Rule changes: <new or tuned rules, with fixtures>
```

## Limits

- Detection sees only what is logged. OTel omits tool results and, without
  `OTEL_LOG_TOOL_DETAILS`, commands and names; transcripts cover one machine.
- An attacker who controls the agent can choose tools you do not watch (for
  example a script file executed later). Detection complements hardened
  configuration (`agent-config-audit`), it does not replace it.
- Bash categories are regex-based; unusual commands land in plain `Bash`.
- Rules are `experimental`: tune thresholds and allowlists to your environment.

## Related skills

`agent-config-audit`, `skill-supply-chain-audit`, `agent-threat-model` (which
residual risks need a detection), `agent-incident-response`.
