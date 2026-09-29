# Pinning and update drift

A review is only worth something if what runs later is what you reviewed.
Pin at the install layer and keep a lockfile of the reviewed files.

## Contents

- [The lockfile](#the-lockfile)
- [Claude Code marketplaces](#claude-code-marketplaces)
- [gh skill](#gh-skill)
- [npx skills](#npx-skills)
- [Vendoring](#vendoring)
- [Re-review routine](#re-review-routine)

## The lockfile

`scripts/audit_skill.py lock PATH --out FILE` writes (keep FILE outside the package):

```json
{
  "version": 1,
  "tool": "audit_skill",
  "generated_at": "2026-09-29T20:00:00Z",
  "root": "REPO",
  "git_commit": "<40-hex commit if PATH is a git checkout>",
  "tree_sha256": "<hash over all files>",
  "skills": {"skills/pdf-tools": "<tree hash of that skill folder>"},
  "files": {"skills/pdf-tools/SKILL.md": "<sha256>", "...": "..."}
}
```

- `files` is every file (forward slashes, sorted) with its SHA-256.
- `skills` has a tree hash per folder that contains a SKILL.md, so you can
  compare one skill across machines or agents.
- `diff PATH --lock skills.lock.json` lists added, modified and removed files
  and scans only added and modified ones.

## Claude Code marketplaces

- Add a marketplace at a fixed ref: `/plugin marketplace add OWNER/REPO#v1.2.0`.
- In a marketplace you maintain, pin every external plugin source with a full
  commit:

```json
{
  "name": "some-plugin",
  "source": {
    "source": "github",
    "repo": "owner/some-plugin",
    "ref": "v1.2.0",
    "sha": "0123456789abcdef0123456789abcdef01234567"
  }
}
```

- `git-subdir` and `url` sources accept `sha` the same way. The scanner flags
  entries without one (SKL050).
- Organizations can restrict which marketplaces users add with managed
  `strictKnownMarketplaces` and `blockedMarketplaces`.

## gh skill

`gh skill install OWNER/REPO SKILL@v1.2.0` installs a version;
`--pin v1.2.0` (or a commit SHA) keeps it from changing during updates. This
is a preview feature of GitHub CLI; check `gh skill --help` on your version.

## npx skills

`npx skills add OWNER/REPO` installs the current default branch and
`npx skills update` moves to the latest. To hold a reviewed version:

- review, then install from a local checkout at the reviewed commit
  (`npx skills add ./path/to/checkout --copy`), or
- vendor the skill (below) and skip `update` for it.

## Vendoring

The most robust pin: copy the reviewed skill folder into your dotfiles or
project repository, commit it with the lockfile, and review upstream changes
as a normal pull request:

```bash
python3 scripts/audit_skill.py diff ./vendor/upstream-new --lock ./vendor/skills.lock.json
```

## Re-review routine

1. Fetch the new version into a scratch folder (never over the installed copy).
2. `diff` against the lockfile. No changes: done.
3. Read every changed hook, script, MCP config and instruction file.
4. Any new network destination, credential access, persistence or hook event
   is a full re-review, not a diff review.
5. Approve, re-lock, update the install pin, and record who reviewed what.
6. If you reject an update, stay on the pinned version and note why.
