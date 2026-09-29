# Incident report: TITLE

<!-- Keep this report private. Never paste secrets: name credentials by type and last 4 characters.
     Defang every indicator (hxxps://host[.]example, 203.0.113[.]7). Times in UTC. -->

| Field | Value |
|---|---|
| Incident ID | IR-YYYY-NNN |
| Status | Open / Contained / Eradicated / Closed |
| Severity | SEV1 / SEV2 / SEV3 / SEV4 (criteria in SKILL.md, Triage) |
| Incident type | Malicious or hijacked skill / plugin / MCP server; prompt-injected agent action; credential leak via agent |
| Agents affected | e.g. Claude Code 2.x on macOS, Codex CLI, Cursor |
| Detected (UTC) | |
| Contained (UTC) | |
| Closed (UTC) | |
| Incident lead | |
| Report author | |
| Escalated to | Security team / legal / vendor / registry (with times) |

## 1. Summary

Three to five sentences: what happened, how it was found, what was exposed, and where things stand
now. Write it for someone who reads nothing else.

## 2. Timeline

All times UTC. Mark each entry's source: transcript (session ID), file mtime, audit log, git,
registry, person.

| Time (UTC) | Source | Event | Evidence ref |
|---|---|---|---|
| | marketplace / repo | Suspect component published or changed | E-01 |
| | `find-skill` / install record | Installed on this machine (which agents, which paths) | E-02 |
| | `search-sessions` | First session that loaded or invoked it | E-03 |
| | transcript / OTel | First harmful action (tool, target) | E-04 |
| | person / alert | Detected | |
| | | Contained (each containment step, see section 6) | |
| | | Eradicated | |
| | | Recovered | |

## 3. Impact

- **Data exposed**: what, how much, classification, whether it left the machine (evidence).
- **Actions taken by the agent**: commits, pushes, publishes, messages, config changes, deletions.
- **Credentials exposed**: list in section 7.
- **Systems and people affected**: repos, packages, cloud accounts, workspaces, users, customers.
- **Unknowns**: what could not be ruled out, and why (retention expired, logging off).

## 4. Root cause

- **Entry point**: how the malicious instructions or code got in (marketplace install, `npx skills`,
  update or sync that changed a clean skill, injected issue, web page, tool output).
- **Why it could act**: which lethal-trifecta legs were present in the context (private data,
  untrusted content, exfiltration channel) and which controls were missing or bypassed.
- **Why it was not caught earlier**: missing review, pinning, detection or approval.
- **Framework mapping**: e.g. AST01, AST07 (OWASP Agentic Skills Top 10 v1.0); ASI01, ASI04
  (Agentic Top 10 2026); AML.T0010.005, AML.T0086 (MITRE ATLAS v2026.09).

## 5. Indicators of compromise

Defang network indicators. Hashes are SHA-256 from the evidence folder's `SHA256SUMS`.

| Type | Value (defanged) | Context | First seen (UTC) |
|---|---|---|---|
| Skill / plugin name | `name@marketplace` | Frontmatter or manifest name, and renamed copies | |
| Path | `~/.agents/skills/NAME/` | Each installed copy found by `find-skill` | |
| File hash | `sha256:...` | `scripts/FILE` in the suspect | |
| Tree hash | `sha256:...` | `tree_sha256` from `find-skill --json` | |
| Domain / URL | `hxxps://collector[.]example[.]invalid/upload` | Exfiltration endpoint in tool call | |
| IP | `203.0.113[.]7` | | |
| MCP server | name, command or URL (defanged) | | |
| Persistence | path, unit or task name | From `recent-changes` or manual checks | |
| Package / version | registry, name, version | Malicious publish, if any | |

## 6. Actions taken

| Time (UTC) | Action | Command or UI path | Approved by | Performed by | Verified how |
|---|---|---|---|---|---|
| | Evidence preserved | evidence folder path, `SHA256SUMS` | | | hashes recorded |
| | Plugin disabled and uninstalled | `claude plugin uninstall NAME@MKT --scope user` | | | `claude plugin list` |
| | Skill copies moved out of agent dirs | list of paths | | | `find-skill` shows only AIR007 |
| | MCP server removed; OAuth cleared | `claude mcp remove`, `claude mcp logout` | | | `claude mcp list` |
| | Persistence removed | file or unit | | | `recent-changes` re-run |

## 7. Credentials rotated

| Credential (type, last 4) | Location | Reachable by | Action | Done (UTC) | Old one verified dead | Audit log reviewed |
|---|---|---|---|---|---|---|
| | | | | | | |

## 8. Detections added

For each gap, what now detects it, where it runs, and how it was tested.

| Gap | Detection (rule ID, name) | Data source | Tested with | Owner |
|---|---|---|---|---|
| Skill changed after install went unnoticed | e.g. alert on new `tree_sha256` for installed skills | scheduled `find-skill --json` diff | fixture | |
| Agent sent data to an unknown host | e.g. agent-trace-detection rule on tool-call egress | OTel `claude_code.tool_result` | positive and negative fixtures | |

## 9. Lessons and follow-ups

Blameless. Record what worked, what did not, and the system change that prevents a repeat.

- **Went well**:
- **Went poorly**:
- **Lucky**:

| Follow-up | Type (prevent / detect / respond) | Owner | Due | Tracking link |
|---|---|---|---|---|
| Pin third-party skills and turn off marketplace auto-update | prevent | | | |
| Deny agent reads of secret files; restrict egress | prevent | | | |
| | | | | |

## 10. Evidence index

| Ref | Item | Location (private) | SHA-256 | Collected (UTC) | By |
|---|---|---|---|---|---|
| E-01 | | | | | |
