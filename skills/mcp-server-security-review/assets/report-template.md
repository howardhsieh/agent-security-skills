# MCP Server Security Review: {server name}

| Field | Value |
| --- | --- |
| Repository | {URL or path} |
| Version / commit | {tag} / {full commit SHA} |
| Review date | {YYYY-MM-DD} |
| Reviewer | {name or agent} |
| Review type | {pre-release / pull request / third-party adoption} |
| Protocol versions supported | {2026-07-28, 2025-11-25, ...} |
| Transports | {stdio / Streamable HTTP / HTTP+SSE (deprecated)} |
| Deployment model | {local single-user / remote single-tenant / remote multi-tenant / proxy to third-party API} |
| Method | Static source review; runtime observation {none / sandboxed with dummy credentials} |

## Contents

1. [Scope](#1-scope) · 2. [Summary](#2-summary) · 3. [Findings](#3-findings) ·
4. [Tool surface map](#4-tool-surface-map) · 5. [Spec conformance](#5-spec-conformance) ·
6. [Positive observations](#6-positive-observations) · 7. [Residual risks](#7-residual-risks) ·
8. [Recommended detections](#8-recommended-detections)

## 1. Scope

- **In scope:** {directories, packages, entrypoints}
- **Out of scope:** {upstream APIs, authorization server, client, infrastructure}
- **Not traced:** {areas where dynamic dispatch, generated code or missing source
  prevented a full trace}
- **Assumptions:** {for example: authorization server issues audience-restricted JWTs}

## 2. Summary

{Two to four sentences: overall posture, the most important risk, and the single change
that most reduces it.}

**Adoption decision (third-party reviews):** {adopt / adopt with conditions / do not adopt}
{If conditions: pin version, restrict scopes or roots, sandbox, disable tools X and Y.}

| ID | Title | Severity | Status | Location |
| --- | --- | --- | --- | --- |
| MCP-001 | {title} | {Critical/High/Medium/Low/Info} | {Confirmed/Candidate} | `{path}:{line}` |

Counts: Critical {n}, High {n}, Medium {n}, Low {n}, Info {n}.

## 3. Findings

Order by severity. Copy this block per finding. Show secrets only as
`<redacted: credential type>`. No exploit payloads.

### MCP-001: {short title}

- **Severity:** {Critical/High/Medium/Low/Info}, rationale: {impact + who can reach it}
- **Status:** {Confirmed / Candidate: unresolved hop is ...}
- **Category:** {model-facing text / auth / state / transport / command injection /
  path traversal / SSRF / injection / deserialization / eval / access control /
  secrets exposure / unbounded consumption / supply chain}
- **Location:** `{path}:{line}` (commit `{short SHA}`)
- **Affected tool / resource / endpoint:** `{name}`

**Evidence (data flow):**

1. Entry: `{tool name}` registered at `{path}:{line}`
2. Source: `{argument or input}`, controllable by {model context / authenticated user /
   unauthenticated caller / upstream API}
3. Path: `{function}` (`{path}:{line}`) → `{function}` (`{path}:{line}`)
4. Guards: {none / present but incomplete because ...}
5. Sink: `{call}` at `{path}:{line}`

```{language}
{minimal excerpt of the vulnerable code, secrets redacted}
```

**Impact:** {what an attacker or injected content could cause, in concrete terms for
this deployment}

**Fix:**

```{language}
{code-level change or diff}
```

{Plus configuration or deployment changes, and a negative test that asserts rejection.}

**References:** {MCP spec section URL}; {framework IDs with edition, for example
ASI05 (Agentic Top 10 2026), LLM05:2025, AML.T0110.000 (ATLAS v2026.09)}

## 4. Tool surface map

| Name | Kind | Side effect | Inputs reaching sinks | Returns third-party content | Authz check |
| --- | --- | --- | --- | --- | --- |
| `{name}` | {tool/resource/prompt} | {read/write/external/irreversible} | {shell/fs/net/DB/eval/none} | {yes: source / no} | {scope or check, `path:line`} |

Trifecta combinations (private data + untrusted content + external communication):
{list tools that together complete it, or "none"}

## 5. Spec conformance

Summarize results from `references/mcp-spec-checklist.md`. List only failed, partial or
not-applicable-with-reason rows.

| Requirement | Level | Result | Evidence |
| --- | --- | --- | --- |
| {e.g. Token audience validated (RFC 8707)} | MUST | {Pass/Fail/Partial/N/A} | `{path}:{line}` or reason |

## 6. Positive observations

- {Controls that work and should be kept, with location. For example: central path-jail
  helper used by all file tools; secrets redacted in the logger.}

## 7. Residual risks

Risks that remain after the fixes, or that this review could not assess.

- {Indirect prompt injection via tool X output: reduced by labeling, not removed}
- {Remote server can change tool definitions after approval: requires pinning and
  runtime monitoring}
- {Upstream API or authorization server behavior assumed, not verified}

## 8. Recommended detections

Runtime signals to monitor for this server (see `agent-trace-detection`).

| Signal | Why | Source |
| --- | --- | --- |
| `tools/list` result hash changes between approvals | Definition change after approval (rug-pull) | Client or gateway logs |
| Tool arguments containing parent-directory segments, private or link-local hosts, or shell metacharacters | Traversal, SSRF or injection attempts | Server request logs |
| Calls to {sensitive tool} following a read of third-party content | Possible indirect injection chain | Agent trace |
| Rate of 401/403 by principal, or tokens with an unexpected audience | Token misuse or passthrough attempts | Auth middleware logs |
| Unusual volume or cost per principal on {costly tool} | Unbounded consumption | Metrics |

## Appendix: method and tools

- Commands and patterns used: {rg patterns, linters, dependency scanners}
- Files reviewed: {count or list}
- Areas reviewed at reduced depth: {list}
