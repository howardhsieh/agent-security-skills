# Framework crosswalk

## Contents

- [Provenance legend](#provenance-legend)
- [Editions and sources](#editions-and-sources)
- [LLM Top 10: 2025 to 2026](#llm-top-10-2025-to-2026)
- [ASI to LLM, ATLAS and AST](#asi-to-llm-atlas-and-ast)
- [ATLAS techniques used in this skill](#atlas-techniques-used-in-this-skill)
- [STRIDE to agentic threats](#stride-to-agentic-threats)

## Provenance legend

| Mark | Meaning |
|---|---|
| **[O]** | Official: stated in the named OWASP document |
| **[J]** | Author's judgment for this repo: a reasoned mapping, not endorsed by any framework owner |

When a threat register cites a [J] mapping, keep it: it is useful for search and triage. Do not
present it as an OWASP or MITRE position.

## Editions and sources

| Framework | Edition used | Source |
|---|---|---|
| OWASP Top 10 for Agentic Applications (ASI) | 2026, released 2025-12-09 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| OWASP Agentic AI - Threats and Mitigations (T1-T17) | v1.1, Dec 2025 | https://genai.owasp.org/ |
| OWASP Top 10 for LLM Applications | 2025 | https://genai.owasp.org/llm-top-10/ |
| OWASP Top 10 for LLM Applications | 2026 v1.0, released 2026-08 | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| OWASP Agentic Skills Top 10 (AST) | v1.0, Mar 2026 | https://owasp.github.io/www-project-agentic-skills-top-10/ |
| MITRE ATLAS | data v2026.09 | https://atlas.mitre.org/ |

Always write the LLM edition suffix: `LLM06:2025` and `LLM03:2026` are the same risk (Excessive
Agency) under different numbers.

## LLM Top 10: 2025 to 2026

Rows are matched by title, and the titles are unchanged except for one row. The replacement of
System Prompt Leakage by Hidden Context Exposure is stated in the 2026 document **[O]**.

| 2025 | 2026 | Change |
|---|---|---|
| LLM01:2025 Prompt Injection | LLM01:2026 Prompt Injection | Same rank |
| LLM02:2025 Sensitive Information Disclosure | LLM02:2026 Sensitive Information Disclosure | Same rank |
| LLM03:2025 Supply Chain | LLM04:2026 Supply Chain | Renumbered |
| LLM04:2025 Data and Model Poisoning | LLM05:2026 Data and Model Poisoning | Renumbered |
| LLM05:2025 Improper Output Handling | LLM10:2026 Improper Output Handling | Renumbered |
| LLM06:2025 Excessive Agency | LLM03:2026 Excessive Agency | Renumbered |
| LLM07:2025 System Prompt Leakage | LLM08:2026 Hidden Context Exposure | New entry in 2026; replaces System Prompt Leakage |
| LLM08:2025 Vector and Embedding Weaknesses | LLM09:2026 Vector and Embedding Weaknesses | Renumbered |
| LLM09:2025 Misinformation | LLM07:2026 Misinformation | Renumbered |
| LLM10:2025 Unbounded Consumption | LLM06:2026 Unbounded Consumption | Renumbered |

Scope boundary stated in the 2026 document **[O]**: the LLM list covers the model as a component.
Once the model acts, with tools, memory across sessions, and downstream consequences, pair it with
the Agentic Top 10. Threat models of agents should lead with ASI and use LLM IDs for the
model-level root cause.

## ASI to LLM, ATLAS and AST

- LLM:2025 column: **[O]** from ASI 2026 Appendix A.
- LLM:2026 column: **[O]** from the LLM 2026 ASI crosswalk appendix, inverted to read ASI to LLM.
- ATLAS and AST columns: **[J]**. AST mappings rest on AST titles only. Read the AST entries
  before relying on them.

| ASI (2026) | LLM:2025 [O] | LLM:2026 [O] | ATLAS v2026.09 [J] | AST v1.0 [J] |
|---|---|---|---|---|
| ASI01 Agent Goal Hijack | LLM01:2025, LLM06:2025 | LLM01:2026, LLM03:2026 | AML.T0051 (.000, .001, .002) | AST05 Untrusted External Instructions |
| ASI02 Tool Misuse and Exploitation | LLM06:2025 | LLM01:2026, LLM03:2026, LLM06:2026, LLM10:2026 | AML.T0053, AML.T0086, AML.T0101, AML.T0110.000, AML.T0110.002 | AST03 Over-Privileged Skills |
| ASI03 Identity and Privilege Abuse | LLM01:2025, LLM02:2025, LLM06:2025 | LLM01:2026, LLM03:2026 | AML.T0083, AML.T0098 | AST03 Over-Privileged Skills |
| ASI04 Agentic Supply Chain Vulnerabilities | LLM03:2025 | LLM04:2026, LLM05:2026, LLM09:2026 | AML.T0010.005, AML.T0011.002, AML.T0110 (.000, .001), AML.T0081 | AST01 Malicious Skills, AST02 Supply Chain Compromise, AST04 Insecure Metadata, AST07 Update Drift, AST08 Poor Scanning |
| ASI05 Unexpected Code Execution (RCE) | LLM01:2025, LLM05:2025 | LLM01:2026, LLM03:2026, LLM10:2026 | AML.T0112.000 | AST06 Weak Isolation |
| ASI06 Memory & Context Poisoning | LLM01:2025, LLM04:2025, LLM08:2025 | LLM01:2026, LLM02:2026, LLM05:2026, LLM08:2026, LLM09:2026 | AML.T0080 (.000, .001), AML.T0099 | none clear |
| ASI07 Insecure Inter-Agent Communication | LLM02:2025, LLM06:2025 | LLM03:2026, LLM08:2026 | AML.T0051.001 (content only) | none clear |
| ASI08 Cascading Failures | LLM01:2025, LLM04:2025, LLM06:2025 | LLM01:2026, LLM03:2026, LLM05:2026, LLM06:2026, LLM07:2026 | tag the originating technique | none clear |
| ASI09 Human-Agent Trust Exploitation | LLM01:2025, LLM05:2025, LLM06:2025, LLM09:2025 | LLM01:2026, LLM03:2026, LLM07:2026, LLM10:2026 | tag the upstream technique | none clear |
| ASI10 Rogue Agents | LLM02:2025, LLM09:2025 | LLM07:2026 | tag observed behavior (for example AML.T0086, AML.T0101) | AST09 No Governance (weak) |

Not mapped: AST10 Cross-Platform Reuse (no clear single ASI counterpart).

ASI to T-IDs (Threats and Mitigations v1.1) **[O]**, from the ASI entries: ASI01 to T6, T7; ASI02
to T2; ASI03 to T3; ASI04 to T17; ASI05 to T11; ASI06 to T1; ASI07 to T12, T16; ASI08 to T5; ASI09
to T7, T8, T10; ASI10 to T13. Appendix A of the ASI document adds contributing IDs, listed in
owasp-agentic-2026.md.

Notes on the official LLM:2026 mappings:

- LLM08:2026 Hidden Context Exposure maps to ASI06 and ASI07 only as a pointer for agentic
  amplification. The 2026 document says these are not equivalent risks.
- LLM10:2026 Improper Output Handling to ASI09 is described in the 2026 document as a loose
  content match.

## ATLAS techniques used in this skill

All names are from ATLAS data v2026.09. The "typical ASI" column is **[J]**.

| Technique | Name | Typical ASI |
|---|---|---|
| AML.T0051.000 / .001 / .002 | LLM Prompt Injection: Direct / Indirect / Triggered | ASI01 |
| AML.T0053 | AI Agent Tool Invocation | ASI02, ASI03 |
| AML.T0054 | LLM Jailbreak | ASI01 (model-level) |
| AML.T0056 | Extract LLM System Prompt | LLM08:2026 finding; ASI when chained |
| AML.T0057 | LLM Data Leakage | LLM02:2026; ASI02 when a tool is involved |
| AML.T0077 | LLM Response Rendering | ASI02 (rendering as exfiltration); LLM10:2026 |
| AML.T0080.000 / .001 | AI Agent Context Poisoning: Memory / Thread | ASI06 |
| AML.T0081 | Modify AI Agent Configuration | ASI04, ASI06 |
| AML.T0083 | Credentials from AI Agent Configuration | ASI03 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | ASI02 |
| AML.T0098 | AI Agent Tool Credential Harvesting | ASI03 |
| AML.T0099 | AI Agent Tool Data Poisoning | ASI06, ASI01 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | ASI02, ASI10 |
| AML.T0110.000 / .001 / .002 | AI Agent Tool Poisoning: Definition and Instructions / Implementation / Runtime Response | ASI04 (source), ASI02 (runtime interface) |
| AML.T0010.005 | AI Supply Chain Compromise: AI Agent Tool | ASI04 |
| AML.T0011.002 | Poisoned AI Agent Tool | ASI04 |
| AML.T0112.000 | Machine Compromise: Local AI Agent | ASI05 |

AML.T0053 was formerly named "LLM Plugin Compromise". Older reports may use that name.

## STRIDE to agentic threats

All **[J]**. Run STRIDE per boundary-crossing data flow, then cover the rows marked "not in STRIDE"
separately. OWASP Threats and Mitigations v1.1 notes that STRIDE and PASTA must be extended for
agentic AI and points to MAESTRO as one such extension **[O]**.

| STRIDE | Agentic form | ASI / LLM:2026 / T |
|---|---|---|
| Spoofing | Forged agent identity or agent card; look-alike tool or MCP server; confused deputy on delegation | ASI03, ASI07, ASI04; T9 |
| Tampering | Poisoned memory or RAG; modified agent config, prompts, tool definitions; altered inter-agent messages | ASI06, ASI04, ASI07; LLM05:2026; T1, T12 |
| Repudiation | Agent actions not attributable to an identity or user; missing tool-call logs | ASI09, ASI10; T8 |
| Information disclosure | Exfiltration through tools or rendering; hidden context exposure; cross-tenant retrieval | ASI02, ASI03, ASI06; LLM02:2026, LLM08:2026, LLM09:2026 |
| Denial of service | Tool loops, fan-out, cost exhaustion; cascades | ASI02, ASI08; LLM06:2026; T4 |
| Elevation of privilege | Inherited or cached credentials; generated code running with host rights | ASI03, ASI05; LLM03:2026; T3, T11 |
| Not in STRIDE | Goal hijack; human over-trust; rogue or misaligned behavior | ASI01, ASI09, ASI10; T6, T7, T10, T13 |

Adjacent reference for MCP-specific threats (token passthrough, confused deputy, SSRF, local server
compromise, scope minimization): MCP Security Best Practices, protocol 2026-07-28,
https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
