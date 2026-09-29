# OWASP Top 10 for Agentic Applications 2026: reviewer guide

Source: OWASP Top 10 for Agentic Applications, Version 2026 (December 2025),
https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (CC BY-SA 4.0).
Definitions are paraphrased, and the mitigations are condensed from each entry's "Prevention and
Mitigation Guidelines". Reviewer questions are this repo's. T-IDs refer to OWASP Agentic AI - Threats
and Mitigations v1.1 (December 2025), OWASP GenAI Security Project, https://genai.owasp.org/.

Mapping provenance: **T-IDs** official (entry text; "Appendix A adds" marks extra IDs from ASI
Appendix A). **LLM:2025** official (ASI Appendix A). **LLM:2026** official (LLM Top 10 2026 ASI
crosswalk, inverted). **ATLAS** (data v2026.09) author's judgment, listed only where the fit is clear.

## Contents

- [Summary table](#summary-table)
- [ASI01 Agent Goal Hijack](#asi01-agent-goal-hijack)
- [ASI02 Tool Misuse and Exploitation](#asi02-tool-misuse-and-exploitation)
- [ASI03 Identity and Privilege Abuse](#asi03-identity-and-privilege-abuse)
- [ASI04 Agentic Supply Chain Vulnerabilities](#asi04-agentic-supply-chain-vulnerabilities)
- [ASI05 Unexpected Code Execution (RCE)](#asi05-unexpected-code-execution-rce)
- [ASI06 Memory & Context Poisoning](#asi06-memory--context-poisoning)
- [ASI07 Insecure Inter-Agent Communication](#asi07-insecure-inter-agent-communication)
- [ASI08 Cascading Failures](#asi08-cascading-failures)
- [ASI09 Human-Agent Trust Exploitation](#asi09-human-agent-trust-exploitation)
- [ASI10 Rogue Agents](#asi10-rogue-agents)

## Summary table

| ASI | Definition | T (v1.1) | LLM:2025 | LLM:2026 | ATLAS (judgment) |
|---|---|---|---|---|---|
| ASI01 Agent Goal Hijack | Attacker content redirects goals, planning, multi-step behavior | T6, T7 | LLM01:2025, LLM06:2025 | LLM01:2026, LLM03:2026 | AML.T0051 (.000/.001/.002) |
| ASI02 Tool Misuse and Exploitation | Legitimate tools used unsafely within granted privileges | T2 | LLM06:2025 | LLM01:2026, LLM03:2026, LLM06:2026, LLM10:2026 | AML.T0053, AML.T0086, AML.T0101 |
| ASI03 Identity and Privilege Abuse | Delegation, inherited or cached credentials, agent trust used to escalate | T3 | LLM01:2025, LLM02:2025, LLM06:2025 | LLM01:2026, LLM03:2026 | AML.T0083, AML.T0098 |
| ASI04 Agentic Supply Chain Vulnerabilities | Malicious or compromised third-party components loaded at runtime | T17 | LLM03:2025 | LLM04:2026, LLM05:2026, LLM09:2026 | AML.T0010.005, AML.T0011.002, AML.T0110, AML.T0081 |
| ASI05 Unexpected Code Execution (RCE) | Generated or injected code compromises host or container | T11 | LLM01:2025, LLM05:2025 | LLM01:2026, LLM03:2026, LLM10:2026 | AML.T0112.000 |
| ASI06 Memory & Context Poisoning | Persistent corruption of memory, RAG, summaries | T1 | LLM01:2025, LLM04:2025, LLM08:2025 | LLM01:2026, LLM02:2026, LLM05:2026, LLM08:2026, LLM09:2026 | AML.T0080 (.000/.001), AML.T0099 |
| ASI07 Insecure Inter-Agent Communication | Agent messages lack authentication, integrity, semantic validation | T12, T16 | LLM02:2025, LLM06:2025 | LLM03:2026, LLM08:2026 | AML.T0051.001 for injected content |
| ASI08 Cascading Failures | One fault propagates across agents and workflows | T5 | LLM01:2025, LLM04:2025, LLM06:2025 | LLM01:2026, LLM03:2026, LLM05:2026, LLM06:2026, LLM07:2026 | none; tag the origin |
| ASI09 Human-Agent Trust Exploitation | Over-trust used to get humans to approve harmful actions | T7, T8, T10 | LLM01:2025, LLM05:2025, LLM06:2025, LLM09:2025 | LLM01:2026, LLM03:2026, LLM07:2026, LLM10:2026 | none; tag the origin |
| ASI10 Rogue Agents | Agents deviate from scope even when single actions look legitimate | T13 | LLM02:2025, LLM09:2025 | LLM07:2026 | none; tag observed behavior |

## ASI01 Agent Goal Hijack

Attacker-controlled content (prompts, tool outputs, documents, email, calendar entries, peer-agent
messages) redirects the agent's objectives, task selection, or multi-step plan. Agents cannot
reliably tell instructions from data. Distinct from ASI06 (persistent corruption) and ASI10 (drift
without active attacker control).

Reviewer questions:
1. Which inputs to each context can someone outside the trust boundary author?
2. If the agent followed those inputs instead of the user, what is the most damaging tool call available?
3. Are goal-changing or high-impact actions gated outside the model (policy engine, human approval)?
4. Are system prompts and goal definitions version-controlled and changed only through review?
5. Would an unexpected goal shift (new tool sequence, new destination) be logged and alerted on?

Mitigations: treat all natural-language input as untrusted; least privilege plus human approval
for high-impact actions; lock system prompts under configuration management; validate intent at
run time and pause on deviation; sanitize connected sources as defense in depth; log goal state
and tool patterns against a baseline; red-team goal override.

Also: T6, T7 · LLM01:2025, LLM06:2025 · LLM01:2026, LLM03:2026 · AML.T0051.000 Direct, .001 Indirect, .002 Triggered.

## ASI02 Tool Misuse and Exploitation

The agent uses a legitimate tool unsafely within its granted privileges: deleting data, looping
on costly APIs, exfiltrating. This covers runtime manipulation of an otherwise legitimate tool's
interface (descriptors, schemas). Privilege escalation belongs in ASI03, code execution in ASI05,
and a tool compromised at the source in ASI04.

Reviewer questions:
1. For each tool, which operations and objects does the task need, and what does the credential actually allow?
2. Can model output reach a shell, query, or API without argument and schema validation outside the model?
3. Which tools auto-run without approval, and could any of them (fetch, ping, DNS) carry data out?
4. Are there rate, cost, and loop ceilings per tool and per session?
5. Can a tool be resolved by an ambiguous or look-alike name?

Mitigations: per-tool least-privilege profiles (scopes, rate, egress allowlist) expressed as authz
policy; action-level authentication and human confirmation with a dry-run or diff for destructive
actions; sandboxes with outbound allowlists; a policy enforcement point that validates intent and
arguments; cost and rate budgets; just-in-time ephemeral credentials; fully qualified tool names
and version pins; immutable tool-call logs with detection of chains such as read-private followed
by external transfer.

Also: T2 (Appendix A adds T4, T16) · LLM06:2025 · LLM01:2026, LLM03:2026, LLM06:2026, LLM10:2026 ·
AML.T0053, AML.T0086, AML.T0101, AML.T0110.000 and .002 for interface poisoning.

## ASI03 Identity and Privilege Abuse

Delegation chains, role inheritance, cached credentials, or agent-to-agent trust are exploited to
escalate access. The root cause is that agents often lack a distinct, governed identity, so least
privilege cannot be enforced or attributed.

Reviewer questions:
1. Which identity does each agent act as (its own, the invoking user's, a shared service account), and are its actions attributable?
2. Which credentials pass to sub-agents and tools on delegation, and are they narrowed?
3. Are credentials or retrieved secrets cached in memory or context across tasks or users?
4. Are permissions re-checked per action at execution time, or only at workflow start (TOCTOU)?
5. Does a high-privilege agent act on requests from a lower-privilege agent without re-validating the original user's intent?

Mitigations: task-scoped, time-bound credentials per agent identity; isolated identities and
contexts with state wiped between tasks; per-action authorization through a central policy engine;
human approval for privilege escalation; tokens bound to subject, audience, purpose, and duration;
detection of transitive permission gain. For MCP: no token passthrough, audience validation, and
scope minimization (MCP Security Best Practices, protocol 2026-07-28).

Also: T3 · LLM01:2025, LLM02:2025, LLM06:2025 · LLM01:2026, LLM03:2026 · AML.T0083, AML.T0098, AML.T0053.

## ASI04 Agentic Supply Chain Vulnerabilities

Third-party models, tools, plugins, skills, MCP or A2A components, registries, prompt templates, or
update channels are malicious or compromised. Agentic systems compose these at run time, so the
supply chain is live, not only a build-time manifest.

Reviewer questions:
1. Which models, MCP servers, skills, plugins, templates, and agent descriptors load, from where, and who can change them?
2. Are they pinned by version or content hash and provenance-checked before activation? Do updates auto-apply?
3. Are tool descriptions and skill instructions reviewed for embedded instructions, and re-reviewed on change?
4. Can agents discover and connect to new tools or agents at run time (open registration, look-alike names)?
5. Is there a kill switch to revoke one component across all deployments?

Mitigations: signed manifests, prompts, and tool definitions; SBOM/AIBOM inventory; allowlist and
pin; typosquat scanning; sandboxed containers; prompts and orchestration under version control with
review; mutual authentication for agents; runtime re-verification of hashes; staged rollout with
auto-rollback; supply-chain kill switch; design assuming a component is compromised. See
`skill-supply-chain-audit`.

Also: T17 (Appendix A adds T2, T11, T12, T13, T16) · LLM03:2025 · LLM04:2026, LLM05:2026, LLM09:2026 ·
AML.T0010.005, AML.T0011.002, AML.T0110.000/.001, AML.T0081.

## ASI05 Unexpected Code Execution (RCE)

Generated or injected code (shell commands, scripts, package installs, deserialization, template
engines, eval) runs and compromises the host or container, persists, or escapes a sandbox.

Reviewer questions:
1. Where does the agent run code: shell tool, interpreter, package install, build or test scripts, eval inside memory or template layers?
2. What does that environment reach: credentials, network, host filesystem, production?
3. Does the agent install dependencies from unpinned specs or regenerate lockfiles?
4. Which commands auto-execute, and is that allowlist under version control?
5. Is generation separated from execution by a validation gate?

Mitigations: output handling controls on generated code; no direct agent-to-production path; ban
eval in production agents; never run as root; sandboxed containers with network limits and a
dedicated working directory; human approval for elevated runs; static scans before execution;
runtime monitoring and audit of every run.

Also: T11 · LLM01:2025, LLM05:2025 · LLM01:2026, LLM03:2026, LLM10:2026 · AML.T0112.000, AML.T0053.

## ASI06 Memory & Context Poisoning

Memory, RAG stores, summaries, or shared context are seeded or corrupted so that future reasoning or
tool use becomes biased or unsafe, across sessions or users. The ASI text places one-shot prompt
input under LLM01:2025, not ASI06.

Reviewer questions:
1. What persists beyond one session (memory, summaries, vector stores, shared scratchpads), and who or what can write it?
2. Is memory segmented per user, tenant, and task? Can retrieval cross a tenant boundary?
3. Can the agent's own outputs, or content it read, flow back into trusted memory automatically?
4. Do entries carry provenance, and can suspect entries be found, quarantined, and rolled back?
5. Do memory writes that contain instructions need approval?

Mitigations: validate memory writes before commit; segment by user, tenant, and domain;
authenticated, curated sources only; provenance and anomaly detection; no automatic re-ingestion
of the agent's own output; snapshots and rollback; per-tenant namespaces; expire unverified
entries; weight retrieval by trust.

Also: T1 (Appendix A adds T4, T6, T12) · LLM01:2025, LLM04:2025, LLM08:2025 ·
LLM01:2026, LLM02:2026, LLM05:2026, LLM08:2026, LLM09:2026 · AML.T0080.000 Memory, AML.T0080.001 Thread, AML.T0099.

## ASI07 Insecure Inter-Agent Communication

Messages between agents lack authentication, integrity, or semantic validation, so they can be
intercepted, spoofed, replayed, downgraded, or misrouted through discovery.

Reviewer questions:
1. How do agents find each other (static config, registry, agent cards), and can a new agent register itself?
2. Are messages authenticated per agent, integrity-protected end to end, and replay-protected?
3. Does the receiver treat a peer's message as data, or as instructions carrying the peer's authority?
4. Are protocol versions pinned and downgrades rejected?
5. Are messages typed and schema-validated, with explicit audiences?

Mitigations: per-agent credentials with mutual authentication; signed messages; nonces and
timestamps against replay; weak or legacy modes disabled; attested registries and signed agent
cards; versioned, typed schemas.

Also: T12, T16 · LLM02:2025, LLM06:2025 · LLM03:2026, LLM08:2026 · AML.T0051.001 when a peer
message carries injected instructions; channel-level spoofing and replay have no technique in the
ATLAS set this repo cites.

## ASI08 Cascading Failures

A single fault (hallucination, injection, poisoned memory, bad tool) propagates and amplifies across
agents and workflows. Record the origin under its own entry (for example ASI04, ASI06, ASI07) and use
ASI08 for the fan-out.

Reviewer questions:
1. Which downstream agents or systems act automatically on this agent's output without validation?
2. Is planning separated from execution by an independent policy check?
3. Are there quotas, fan-out limits, and circuit breakers between agents?
4. Could two agents form a feedback loop?
5. Can an action be traced back through the chain and rolled back?

Mitigations: design assuming component failure; isolation and segmentation; short-lived, task-scoped
credentials and policy-as-code on high-impact calls; an external policy engine between planner and
executor; checkpoints and human gates; rate limits and blast-radius caps; drift detection; replay
tests before policy expansion; tamper-evident logs with lineage.

Also: T5 (Appendix A adds T8) · LLM01:2025, LLM04:2025, LLM06:2025 ·
LLM01:2026, LLM03:2026, LLM05:2026, LLM06:2026, LLM07:2026 · ATLAS: tag the originating technique.

## ASI09 Human-Agent Trust Exploitation

Fluency, perceived authority, and automation bias lead humans to approve harmful actions or disclose
secrets. The agent's role can be invisible because a human performs the final, audited action.

Reviewer questions:
1. Which actions need human approval? Does the approver see the exact action and payload, or a model-written summary?
2. How many approvals does a reviewer handle per day? Is rubber-stamping likely?
3. Can a "preview" or "read-only" view trigger side effects?
4. Does the UI separate unverified model rationale from verified facts and sources?
5. Can users flag suspicious agent behavior, and does a flag trigger review or lockdown?

Mitigations: explicit multi-step confirmation for sensitive actions; immutable logs; a plain-language
risk summary rather than model rationale; previews that are separate from effects; visual risk
cues and provenance metadata; plan-divergence detection; training for human reviewers.

Also: T7, T8, T10 · LLM01:2025, LLM05:2025, LLM06:2025, LLM09:2025 ·
LLM01:2026, LLM03:2026, LLM07:2026, LLM10:2026 · ATLAS: tag the upstream technique.

## ASI10 Rogue Agents

An agent deviates from its intended function or scope, whether through compromise, misalignment,
or reward gaming. Individual actions can look legitimate. The focus is loss of behavioral integrity
after drift begins, not the initial intrusion.

Reviewer questions:
1. Is each agent's expected set of tools, destinations, and goals declared and enforced outside the agent?
2. Would you detect out-of-scope behavior: new tools, new destinations, self-spawning, unusual volume?
3. Can you stop one agent and revoke its credentials quickly across all instances?
4. Can agents spawn agents or provision infrastructure?
5. Can the success metric be gamed destructively, for example cost reduction by deleting backups?

Mitigations: signed, immutable audit logs; trust zones and sandboxes; behavioral monitoring or
watchdog agents; kill switches, credential revocation, and quarantine; per-agent identity
attestation and signed behavioral manifests; signing keys mediated by the orchestrator, never held
by agents; fresh attestation before reintegration.

Also: T13 (Appendix A adds T14, T15) · LLM02:2025, LLM09:2025 · LLM07:2026 · ATLAS: tag the observed
behavior, for example AML.T0086 or AML.T0101.
