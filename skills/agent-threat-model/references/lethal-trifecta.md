# The lethal trifecta in agent systems

## Contents

- [Definition](#definition)
- [Why filters and prompt hardening do not close it](#why-filters-and-prompt-hardening-do-not-close-it)
- [Identifying each leg](#identifying-each-leg)
- [Scoping the analysis: the agent context](#scoping-the-analysis-the-agent-context)
- [Leg-breaking patterns and trade-offs](#leg-breaking-patterns-and-trade-offs)
- [Worked example: coding agent on GitHub issues](#worked-example-coding-agent-on-github-issues)

## Definition

Simon Willison, "The lethal trifecta for AI agents: private data, untrusted content, and external
communication" (2025-06-16), https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/. An agent
that combines access to private data, exposure to untrusted content, and the ability to communicate
externally can be tricked into sending that data to an attacker.

OWASP LLM01:2026 Prompt Injection cites it as a pre-deployment check: an agent with all three has
the conditions for high-impact exploitation, and removing any one leg removes them. The same entry
cites Meta's "Agents Rule of Two" (2025). The Rule of Two counts untrusted input, sensitive data,
and state change or external communication, and requires per-action human approval when all
three are present. Use the trifecta for confidentiality. Use the state-change variant for
integrity: untrusted input plus an irreversible tool can do damage with no private data at all.

Framework tags for a trifecta finding (see framework-crosswalk.md for provenance): ASI01 (entry),
ASI02 (tool used to exfiltrate), LLM01:2026 / LLM01:2025, LLM02:2026 / LLM02:2025, AML.T0051.001,
AML.T0086 (tool-based exfiltration) or AML.T0077 (exfiltration by rendering).

## Why filters and prompt hardening do not close it

- ASI01 (Agentic Top 10 2026): agents and the underlying model cannot reliably distinguish
  instructions from related content.
- LLM01:2026: no reliable prevention mechanism exists today, so defense must be architectural. It
  cites Nasr et al. (2025): near-zero static attack success, but over 90% adaptive attack success
  against most of 12 recent defenses. It calls system-prompt constraints and provenance marking
  partial controls that an attacker who infers the prompt or knows the scheme can bypass.
- Structural reasons. System-prompt rules and injected text share one channel. Classifiers are
  probabilistic and evadable by rephrasing, encoding, or another modality. The attacker can retry
  indefinitely and needs one success. Exfiltration can be low-bandwidth and look benign (one URL
  parameter, one DNS lookup, one comment).

Record detection and filtering as likelihood reducers. The finding closes only when a
deterministic control outside the model removes or gates a leg.

## Identifying each leg

A leg is present if any tool, input, or side effect in the context provides it, **including indirect
paths**. List the concrete capability, not the tool name alone.

### Leg 1: private data

Data that the author of any untrusted input must not obtain.

| System type | Examples |
|---|---|
| Coding agent | Private repo files; `.env` and local config; environment variables and CI secrets; cloud or package-registry credentials on the machine; SSH keys; git history; other repos reachable with the same token |
| Support or ops agent | Customer records, tickets from other customers, order and payment data, internal runbooks |
| RAG app | Retrieved internal documents; other tenants' chunks if namespaces are loose |
| Any agent | Long-term memory, conversation history, hidden context such as system prompts with embedded details (LLM08:2026), tool results from authenticated APIs |

### Leg 2: untrusted content

Anything whose text a party outside the trust boundary can author or influence, at any turn.

| Source | Notes |
|---|---|
| Issues, PR descriptions and comments, discussions, commit messages | On public repos, anyone can write these; on private repos, any collaborator or integration |
| Repository files | READMEs, docs, code comments, config and rule files, test fixtures, vendored or dependency code |
| Web fetch and search results | The whole page, including text a human reader never sees |
| Email, calendar invites, chat messages, tickets, uploaded files | Arrive from outside with no action by the user |
| MCP tool results and tool descriptions | Third-party servers, or first-party servers that relay third-party data |
| Skill and plugin files | Instructions from their authors (see `skill-supply-chain-audit`) |
| Peer-agent messages and shared memory | Untrusted if any upstream context was exposed (ASI07, ASI06) |
| Package metadata, logs, error messages | Attacker-influenced text often read during debugging |

### Leg 3: exfiltration channel

Any action whose effect can carry bytes to a place the attacker can read.

| Channel | Examples |
|---|---|
| Direct network | Web fetch or browse to an arbitrary URL (path or query parameters carry data), `curl` or `wget` in a shell tool, webhooks, generic HTTP tools |
| Messaging | Email send, chat post, SMS, ticket reply to an external customer |
| Code hosting | Comment on a public issue or PR, open a PR to a public repo, push a branch, create a gist, change repo visibility |
| Publishing | Package publish, container image push, docs site deploy, uploads to object storage |
| Rendering | Model output rendered as Markdown images or link previews, auto-fetched by the client (AML.T0077; LLM10:2026) |
| Side channels | DNS lookups (ping, nslookup, any hostname resolution), error reports sent to third-party services, telemetry |
| Indirect | Writing to a store that an external party can read later: a shared doc, a public wiki, memory synced to another tenant |

A fetch tool whose destination the model chooses is an exfiltration channel even when it is
described as "read-only".

## Scoping the analysis: the agent context

Evaluate per **context**: every token that shares one context window over its lifetime.

- Untrusted content read early is still present when a write tool is called later.
- A sub-agent that reads untrusted content and returns free text to the parent carries the untrusted
  leg into the parent. A sub-agent that returns only schema-validated, constrained values (an enum,
  an ID, a boolean) does not, provided validation happens in code.
- Shared memory or scratch files connect contexts across time. If context A writes and context B
  reads, B inherits A's untrusted leg.
- One agent that serves several users with one credential gives every user's input access to data
  within the credential's reach.

## Leg-breaking patterns and trade-offs

| Pattern | Breaks | Enforced at | Trade-off |
|---|---|---|---|
| Split contexts: a quarantined reader handles untrusted content with no private data and no egress, and returns constrained output to a privileged actor that never sees raw content | Untrusted in the privileged context | Orchestrator code and schema validation | More engineering; constrained output limits tasks; free-text hand-off reintroduces the leg |
| Egress deny-by-default with an allowlist of hosts and paths | Exfiltration | Network policy, proxy, sandbox | Breaks tasks that need open web access; allowlisted hosts that accept user content (code hosts, paste sites, storage buckets) remain channels, so allowlist by path and method |
| Remove egress tools from the context | Exfiltration | Tool configuration | Lower capability; check for indirect channels (DNS, rendering, public comments) |
| Disable auto-rendering of images and link previews, or proxy them and strip query data | Rendering channel | Client or UI | Minor UX loss |
| Scope credentials to the task: one repo, read-only, short-lived; no secrets in the agent's environment | Private data | IAM, token issuance, CI config | Token management overhead; tasks that need broad access need a separate, gated path |
| Trusted-author filter on inputs (for example only issues from org members) | Untrusted | Trigger condition in code | Loses external-input use cases; insiders and compromised accounts remain |
| Human approval of each egress action, showing the exact payload and destination | Exfiltration (gated) | Harness or UI, outside the model | Approval fatigue at volume (T10); reviewers must see raw payloads, since hidden characters or long URLs defeat summaries |
| Provenance labels or spotlighting of untrusted content | None; lowers likelihood | Prompt construction | Useful defense in depth; bypassable by adaptive attackers |

Prefer, in order: remove the leg; enforce it at the network or identity layer; split contexts; gate
with a human. Record which leg each mitigation breaks.

## Worked example: coding agent on GitHub issues

**System.** A CI workflow runs a coding agent when an issue is labeled. The agent reads the issue
and its comments through a GitHub MCP server, clones the repository, can fetch URLs to read
documentation, runs build and test commands in the runner, and opens a PR with its fix. The runner
environment holds a GitHub token with org-wide repository access and a package-registry publish token.

**Inventory and classes.**

| Tool or input | Class |
|---|---|
| GitHub MCP: read issues and comments | RU (anyone can comment on public issues) |
| GitHub MCP: read any repo in the org | RP |
| Repository checkout | RP and RU (contributor-authored files) |
| Environment variables (org token, registry token) | RP |
| Web fetch, any URL | RU + WE |
| Shell (build, test) with network | WE, IRR (can run a publish command with the registry token) |
| Open PR, comment on issue | WE (public) |

**Trifecta.** One context holds all three: private (org repos, secrets), untrusted (issue text,
fetched pages), and exfiltration (fetch URL, public comment, PR contents, shell network). Rating:
likelihood High (anyone can comment), impact High (credential and private-code exfiltration,
unauthorized package publish). Result: **Critical**. The integrity variant is also present: untrusted
input plus the IRR publish path.

**Threat path, conceptually.** An outside party writes an issue or comment containing instructions.
The agent reads them as part of the task, gathers private data it can reach, and moves the data out
through a URL it fetches, a public comment, or content in the PR. Tags: ASI01, ASI02, ASI03 (org-wide
token beyond task scope), LLM01:2026, LLM02:2026, LLM03:2026, AML.T0051.001, AML.T0086. This matches
the trusted-backend injection pattern described in LLM01:2026 Scenario #9.

**Mitigation of record: break legs, in this order.**

1. Private data: replace the org token with a token for this repository only, with contents and
   pull-request write scope, issued per run. Remove the registry token from this job, and publish
   from a separate, human-triggered workflow. The agent can no longer reach other repos or secrets.
2. Exfiltration: run the job in a sandbox with egress denied except the package mirror and the
   GitHub API paths for this repository. Replace open web fetch with a documentation allowlist.
   Turn off DNS resolution for other hosts.
3. Untrusted: run only on issues from org members, or split the flow. A quarantined triage context
   reads the issue and emits a structured task (file paths, failing test name, category from an
   enum), and the fixing agent never sees raw issue text.
4. Human gate: the PR is a draft and needs review before CI with secrets runs on it. Comments the
   agent posts are limited to a fixed template.

**Residual risk.** The PR body and code diff remain an outbound channel to anyone who can read the
repository, and repo files remain untrusted. Keep the data reachable through the scoped token to
this repository only. Log every tool call with its arguments and destination, and alert on egress
denials, on reads of `.env` or credential paths, and on PRs that touch CI or workflow files (hand
these to `agent-trace-detection`). Review the workflow config itself with `agent-config-audit`.
