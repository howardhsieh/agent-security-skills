# Skill evals

One file per skill, `evals/<skill-name>.json`, describing when the skill should
load and what a good run looks like. They are small on purpose: enough to catch
a description that stops triggering, a skill that fires on the wrong request,
or instructions a model skips.

```json
{
  "skill": "agent-config-audit",
  "should_trigger": ["3 realistic user prompts that should load the skill"],
  "should_not_trigger": ["2 near-miss prompts that should not load it"],
  "expected_behaviors": ["4-6 checkable statements about a good run"]
}
```

- **should_trigger**: phrased the way a user would type the request, without
  naming the skill.
- **should_not_trigger**: near misses. They share keywords with the skill but
  belong to a different task, often a sibling skill in this repo or ordinary
  non-agent security work.
- **expected_behaviors**: things a grader can check from the transcript: a
  script ran before conclusions, a secret was not printed, a finding has an ID
  and a fix. Keep them true to the skill's purpose rather than to one exact
  wording of `SKILL.md`, so they survive edits.

`tools/validate_skills.py` warns when a skill has no eval file or an eval file
is missing a field, and `tests/test_repo_tooling.py` checks the shape.

## Running them by hand

1. Install the skills (see [docs/install.md](../docs/install.md)) in a clean
   profile with no other skills that overlap.
2. For each `should_trigger` prompt, start a fresh session, send the prompt, and
   confirm the skill loaded. In Claude Code the transcript shows a `Skill` tool
   call; in claude.ai, open Claude's thinking or the tool activity.
3. For each `should_not_trigger` prompt, confirm the skill did not load.
4. For the trigger prompts, score each `expected_behaviors` line pass or fail.
   Use an inert target: the fixtures under `tests/fixtures/<skill-name>/`, or a
   throwaway directory with fake credentials marked `FAKE`.
5. Record the model, client and version with the results.

Run each prompt more than once. Skill selection is not deterministic, and one
pass says little.

## Test with more than one model

Anthropic's skill authoring guidance says to test a skill with every model you
plan to use it with: what works for Opus may need more detail for Haiku, and
what Haiku needs may be over-explained for Opus. Run the same prompts on at
least a small model (Haiku), a mid-size model (Sonnet) and a large model
(Opus), and compare trigger rate and behavior pass rate per model. If the small
model misses steps, tighten the workflow checklist in `SKILL.md`. If the large
model ignores the skill, check that the description names the task in the
user's words.

## Using an eval harness

These files are a neutral source format. Harnesses expect their own layout, so
convert rather than point a harness at this directory.

- **skill-creator** (Anthropic's skill for writing and testing skills) keeps
  cases in `evals/evals.json` inside a skill folder, with `prompt`,
  `expected_output` and `expectations` per case. Map each `should_trigger`
  prompt to a case, and `expected_behaviors` to `expectations`. It runs each
  case with and without the skill and reports pass rates. Do not commit its
  workspace output into `skills/`, because it would ship in the upload zips.
- **`claude plugin eval`** (Claude Code) reads case directories, each with a
  `prompt.md` and `graders/*.md`. For a trigger prompt, add a `tool_used`
  grader with `tool: Skill` and an `input_match` on the skill name. For a
  near miss, use the same grader with `min: 0`, `max: 0` and `arm: both`. Write
  behaviors as `llm` graders with concrete PASS and FAIL conditions, or `regex`
  graders where the check is mechanical, such as a redaction marker. The command
  expects a plugin with a `plugin.json`; this repo's marketplace entry uses
  `strict: false` with no `plugin.json`, so run it against the installed plugin
  (`agentsec-kit@agent-security-skills`) and keep generated cases in a
  subdirectory such as `evals/cases/`. This path has not been tried against this
  repo yet.
- **Any other harness**: each file is plain JSON, so a short script can turn it
  into that harness's case format.

Judge models grade long outputs inconsistently. Prefer checks that read the
transcript (tool calls, script names, redaction markers) over rubric grading of
long reports, and keep rubric checks short.
