# Writing agent detections

How to write detections for AI agent tool calls that survive paraphrase,
new payloads and model changes.

## Contents

- [Principles](#principles)
- [Detection patterns](#detection-patterns)
- [Choosing Sigma or TraceSig](#choosing-sigma-or-tracesig)
- [Framework tags](#framework-tags)
- [Testing workflow](#testing-workflow)
- [Tuning and false positives](#tuning-and-false-positives)

## Principles

1. **Provenance over content.** Injected instructions can be phrased in
   endless ways; the sequence "read untrusted content, then act on the outside
   world" cannot. Label where data came from (`web`, `mcp`, `secret`) and
   detect the chain.
2. **Behavior over tool names.** `Bash` is every command. Classify what the
   command does (network, publish, destructive, install) and detect on that.
3. **Short windows.** A hijacked agent usually acts within a few tool calls of
   reading the injection. Windows of 3-5 calls keep false positives down.
4. **Irreversible sinks first.** Publish, push, send, delete, and anything
   that changes the agent's own configuration deserve the highest severity.
5. **Guardrail events are signal.** A hook or user rejecting a tool call is
   evidence someone (or something) tried. Count them per session.

## Detection patterns

| Pattern | Example rule | Primitive |
|---|---|---|
| Lethal trifecta completion: secret or private data read, then egress | CC-EXF-001 | TraceSig `taint` |
| Injection to action: untrusted content, then irreversible action | CC-INJ-001, CC-INJ-002 | TraceSig `sequence` with `within_events` |
| Injected dependency: untrusted content, then install | CC-INJ-003 | `sequence` |
| Credential solicitation in tool output | CC-INJ-004 | `selection` on `result_preview` |
| Self-modification / persistence | CC-PRIV-001 | `selection` on tool + args |
| Guardrails lowered | cc_permission_mode_bypass | Sigma single event |
| Supply-chain change | cc_third_party_plugin_installed, cc_project_hook_registered | Sigma single event |
| Human-in-the-loop gap | destructive action with no preceding approval event | TraceSig `not_preceded_by` (needs an approval event in your trace) |

## Choosing Sigma or TraceSig

- **Sigma** when the signal is one event and you want it in a SIEM next to
  other telemetry. Most SIEMs can also correlate (Sigma correlation rules or
  native), but sequence logic is backend-specific.
- **TraceSig** when the signal is a chain inside one session (taint, ordered
  sequence, missing guard), or when you want to run detections in CI or on a
  laptop without a SIEM.

Many detections should exist in both: a Sigma rule for the single strongest
event and a TraceSig rule for the full chain.

## Framework tags

Sigma tags must match `^[a-z0-9_-]+\.[a-z0-9._-]+$`. This repository uses:

- MITRE ATT&CK techniques: `attack.t1059.004`, `attack.t1552.001`, ...
- MITRE ATLAS (data v2026.09): `atlas.aml-t0053` (AI Agent Tool Invocation),
  `atlas.aml-t0086` (Exfiltration via AI Agent Tool Invocation),
  `atlas.aml-t0098` (AI Agent Tool Credential Harvesting),
  `atlas.aml-t0081` (Modify AI Agent Configuration),
  `atlas.aml-t0101` (Data Destruction via AI Agent Tool Invocation),
  `atlas.aml-t0010.005` (AI Supply Chain Compromise: AI Agent Tool),
  `atlas.aml-t0051.001` (Indirect LLM Prompt Injection).
- OWASP Top 10 for Agentic Applications 2026: `owasp.asi01` ... `owasp.asi10`.

TraceSig tags are free-form; use the same identifiers with hyphens
(`owasp-asi02`, `atlas-aml-t0086`).

## Testing workflow

1. Write the smallest trace that should match (positive) and a realistic
   benign trace that looks similar but should not (negative). Use inert data:
   `example.invalid` domains, tokens marked FAKE.
2. For Sigma: flat JSONL events, then
   `sigma_check.py test rule.yml --events pos.jsonl --expect-match` and
   `--expect-no-match` on the negative.
3. For TraceSig: write a synthetic transcript, `normalize.py` it, and
   `tracesig scan` with the rule directory.
4. Run the rule against at least a week of real, benign traces from your
   environment and count matches. More than a few per developer per week
   means it needs a tighter window, an allowlist, or a lower level.
5. Add the fixtures to the repository so regressions show up in CI.

## Tuning and false positives

- Allowlist by stable identifiers (`plugin_id_hash`, `server_name`, repository
  URL), not by free text.
- Split rules by environment: publishing from a release workflow is expected;
  publishing from a laptop session right after a web fetch is not.
- Keep `level` honest. `high` and `critical` should page someone; `low` and
  `informational` feed dashboards and hunting.
- Record every tuning decision in the rule's `falsepositives` so the next
  reader knows what was accepted and why.
