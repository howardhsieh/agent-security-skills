"""Tests for skills/agent-incident-response/scripts/locate_agent_artifacts.py.

Every test works on a temporary copy of tests/fixtures/agent-incident-response so
mtimes can be set freely. The fixture keeps the project's git dir as `dot-git/`
(git refuses to track `.git` paths); the copy renames it to `.git/`.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "skills" / "agent-incident-response" / "scripts" / "locate_agent_artifacts.py"
FIXTURES = REPO / "tests" / "fixtures" / "agent-incident-response"

FAKE_GH = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
FAKE_AKIA = "AKIAFAKEFAKEFAKEFAKE"
FAKE_AWS_SECRET = "FAKEfakeFAKEfakeFAKEfakeFAKEfake12345678"
SECRETS = (FAKE_GH, FAKE_AKIA, FAKE_AWS_SECRET, "FAKEFAKEFAKEFAKE")

S1 = "11111111-1111-4111-8111-111111111111"
S2 = "22222222-2222-4222-8222-222222222222"
S3 = "33333333-3333-4333-8333-333333333333"
FINDING_KEYS = {"id", "severity", "title", "location", "evidence", "fix", "refs"}


def _load():
    spec = importlib.util.spec_from_file_location("locate_agent_artifacts", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


laa = _load()

OLD = time.time() - 30 * 86400
RECENT = time.time() - 3600


@pytest.fixture()
def env(tmp_path):
    root = tmp_path / "air"
    shutil.copytree(FIXTURES, root, symlinks=True)
    (root / "project" / "dot-git").rename(root / "project" / ".git")
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames + dirnames:
            os.utime(os.path.join(dirpath, name), (OLD, OLD))
        os.utime(dirpath, (OLD, OLD))
    return {"root": root, "home": root / "fakehome", "project": root / "project",
            "ref": root / "reference" / "pdf-helper-pro"}


def run(capsys, *argv):
    code = laa.main([str(a) for a in argv])
    out = capsys.readouterr().out
    return code, out


def run_json(capsys, *argv):
    code, out = run(capsys, *argv, "--json")
    return code, json.loads(out), out


def touch(path: Path, when: float = RECENT) -> None:
    os.utime(path, (when, when))


def snapshot(root: Path):
    state = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            p = Path(dirpath) / name
            st = os.lstat(p)
            state[str(p)] = (st.st_size, st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
        for name in sorted(dirnames):
            p = Path(dirpath) / name
            state[str(p)] = ("dir", os.lstat(p).st_mtime_ns)
    return state


def assert_no_secrets(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"secret leaked: {secret[:8]}..."


def assert_report_schema(rep, tool_target=None):
    assert rep["tool"] == "locate_agent_artifacts"
    assert rep["version"] == "0.2.2"
    assert isinstance(rep["target"], str)
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", rep["generated_at"])
    assert set(rep["summary"]) == {"critical", "high", "medium", "low", "info"}
    counts = {k: 0 for k in rep["summary"]}
    for f in rep["findings"]:
        assert set(f) == FINDING_KEYS
        assert f["id"] in laa.CHECKS
        assert f["severity"] == laa.CHECKS[f["id"]]["severity"]
        assert f["title"] == laa.CHECKS[f["id"]]["title"]
        assert len(f["evidence"]) <= 160
        assert f["refs"] and all(isinstance(r, str) for r in f["refs"])
        counts[f["severity"]] += 1
    assert counts == rep["summary"]
    ranks = [laa._SEV_RANK[f["severity"]] for f in rep["findings"]]
    assert ranks == sorted(ranks)


def by_display(rep):
    return {r["display"].replace("\\", "/"): r for r in rep["records"]}


# ----------------------------------------------------------------------------- find-skill
def test_find_skill_by_name_finds_every_copy(env, capsys):
    code, rep, _ = run_json(capsys, "find-skill", "pdf-helper-pro", "--home", env["home"],
                            "--project", env["project"])
    assert code == 0
    assert_report_schema(rep)
    recs = by_display(rep)
    expected = {
        "~/.claude/skills/pdf-helper-pro", "~/.claude/skills/synced/pdf-helper-pro",
        "~/.agents/skills/pdf-helper-pro", "~/.codex/skills/doc-tools",
        "~/.claude/plugins/cache/example-market/pdf-tools/1.0.0/skills/pdf-helper-pro",
        "~/.claude/commands/pdf-helper-pro.md",
    }
    assert expected <= set(recs)
    project_copy = [r for r in rep["records"] if r["scope"] == "project"]
    assert len(project_copy) == 1 and project_copy[0]["path"].endswith("pdf-helper-pro")
    assert not any("benign-notes" in d or "pdfhelper" in d for d in recs)
    skill = recs["~/.claude/skills/pdf-helper-pro"]
    assert skill["file_count"] == 3
    assert "dir-name" in skill["matched_by"] and "frontmatter-name" in skill["matched_by"]
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", skill["newest_mtime"])
    ids = [f["id"] for f in rep["findings"]]
    assert ids.count("AIR001") == 5 and "AIR002" in ids and "AIR005" in ids
    assert "AIR006" in ids  # plugin copy differs from the others (changed after install)
    synced = recs["~/.claude/skills/synced/pdf-helper-pro"]
    assert "claude.ai" in synced["removal_hint"]


def test_find_skill_by_frontmatter_name_catches_renamed_dir(env, capsys):
    _, rep, _ = run_json(capsys, "find-skill", "pdf-helper-pro", "--home", env["home"], "--no-project")
    renamed = by_display(rep)["~/.codex/skills/doc-tools"]
    assert renamed["matched_by"] == ["frontmatter-name"]
    assert renamed["frontmatter_name"] == "pdf-helper-pro"
    finding = [f for f in rep["findings"] if f["location"].endswith("doc-tools")]
    assert finding and finding[0]["id"] == "AIR002"


def test_find_skill_by_hash_of_reference_copy(env, capsys):
    _, rep, _ = run_json(capsys, "find-skill", env["ref"], "--home", env["home"], "--no-project")
    assert_report_schema(rep)
    recs = by_display(rep)
    for disp in ("~/.claude/skills/pdf-helper-pro", "~/.claude/skills/synced/pdf-helper-pro",
                 "~/.agents/skills/pdf-helper-pro", "~/.codex/skills/doc-tools"):
        assert recs[disp]["identical_to_reference"] is True
        assert "hash-identical" in recs[disp]["matched_by"]
    variant = recs["~/.claude/plugins/cache/example-market/pdf-tools/1.0.0/skills/pdf-helper-pro"]
    assert variant["identical_to_reference"] is False
    assert variant["shared_files_with_reference"] == 1
    reused = recs["~/.gemini/skills/pdfhelper"]
    assert reused["matched_by"] == ["hash-partial"]
    by_loc = {f["location"].replace("\\", "/"): f["id"] for f in rep["findings"]}
    assert by_loc["~/.gemini/skills/pdfhelper"] == "AIR004"
    assert by_loc["~/.codex/skills/doc-tools"] == "AIR003"
    assert rep["reference"]["file_count"] == 3
    assert not any("benign-notes" in d for d in recs)


def test_find_skill_by_plugin_id_and_config_references(env, capsys):
    _, rep, _ = run_json(capsys, "find-skill", "pdf-tools@example-market", "--home", env["home"],
                         "--no-project")
    plugin = [r for r in rep["records"] if r.get("manifest_name") == "pdf-tools"]
    assert plugin and "manifest-name" in plugin[0]["matched_by"]
    assert "claude plugin uninstall pdf-tools@example-market" in plugin[0]["removal_hint"]
    refs = {Path(h["path"]).name for h in rep["config_references"]}
    assert {"settings.json", "installed_plugins.json"} <= refs
    assert "AIR008" in [f["id"] for f in rep["findings"]]


def test_find_skill_follows_no_symlink_but_reports_it(env, capsys):
    link = env["home"] / ".cursor" / "skills" / "pdf-link"
    try:
        os.symlink(env["home"] / ".agents" / "skills" / "pdf-helper-pro", link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    _, rep, _ = run_json(capsys, "find-skill", "pdf-helper-pro", "--home", env["home"], "--no-project")
    rec = by_display(rep)["~/.cursor/skills/pdf-link"]
    assert rec["matched_by"] == ["frontmatter-name"]
    assert rec["symlink_target"].endswith("pdf-helper-pro")


def test_find_skill_dir_name_ignores_subfolders_inside_skills(env, capsys):
    _, rep, _ = run_json(capsys, "find-skill", "scripts", "--home", env["home"], "--project", env["project"])
    assert rep["records"] == []
    assert [f["id"] for f in rep["findings"]] == ["AIR007"]


def test_find_skill_no_match_is_info_only(env, capsys):
    code, rep, _ = run_json(capsys, "find-skill", "no-such-skill", "--home", env["home"], "--no-project",
                            "--fail-on", "low")
    assert code == 0
    assert [f["id"] for f in rep["findings"]] == ["AIR007"]
    assert rep["records"] == []


# ------------------------------------------------------------------------- recent-changes
def test_recent_changes_honors_since(env, capsys):
    home, proj = env["home"], env["project"]
    changed = [home / ".claude" / "settings.json", home / ".bashrc",
               home / ".config" / "systemd" / "user" / "agent-sync.service",
               home / "Library" / "LaunchAgents" / "com.example.agent-sync.plist",
               home / ".codex" / "skills" / "doc-tools" / "SKILL.md",
               home / ".claude" / "CLAUDE.md", proj / ".mcp.json",
               proj / ".git" / "hooks" / "pre-commit", proj / ".git" / "hooks" / "pre-commit.sample"]
    (home / ".claude" / "CLAUDE.md").write_text("# fixture memory\n", encoding="utf-8")
    for p in changed:
        touch(p)
    code, rep, _ = run_json(capsys, "recent-changes", "--since", "24h", "--home", home, "--project", proj)
    assert code == 0
    assert_report_schema(rep)
    paths = {Path(r["path"]) for r in rep["records"]}
    for p in changed[:-1]:
        assert p in paths, p
    assert proj / ".git" / "hooks" / "pre-commit.sample" not in paths
    for untouched in (home / ".zshrc", home / ".codex" / "config.toml", home / ".claude.json",
                      home / ".claude" / "skills" / "pdf-helper-pro" / "SKILL.md"):
        assert untouched not in paths
    ids = {f["id"] for f in rep["findings"]}
    assert {"AIR010", "AIR011", "AIR012", "AIR013", "AIR014", "AIR015", "AIR019"} <= ids
    rec = next(r for r in rep["records"] if Path(r["path"]) == home / ".bashrc")
    assert rec["size"] == (home / ".bashrc").stat().st_size
    assert rec["mtime"] == dt.datetime.fromtimestamp(RECENT, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Same tree, a 30-minute window starts after the changes (made 1 hour ago): nothing listed.
    _, rep_none, _ = run_json(capsys, "recent-changes", "--since", "30m", "--home", home, "--project", proj)
    assert rep_none["records"] == []
    assert [f["id"] for f in rep_none["findings"]] == ["AIR019"] * len(laa.MANUAL_CHECKS)


def test_recent_changes_iso_since_and_text_columns(env, capsys):
    home = env["home"]
    stamp = dt.datetime(2026, 9, 20, 12, 0, tzinfo=dt.timezone.utc).timestamp()
    touch(home / ".zshrc", stamp)
    touch(home / ".bashrc", stamp - 7 * 86400)
    _, rep, _ = run_json(capsys, "recent-changes", "--since", "2026-09-19T00:00:00Z", "--home", home,
                         "--no-project")
    paths = {Path(r["path"]) for r in rep["records"]}
    assert home / ".zshrc" in paths and home / ".bashrc" not in paths
    assert rep["since"] == "2026-09-19T00:00:00Z"
    _, out = run(capsys, "recent-changes", "--since", "2026-09-19", "--home", home, "--no-project")
    table = out.split("(mtime UTC, size, path):", 1)[1]
    line = next(l for l in table.splitlines() if l.strip().endswith(".zshrc"))
    assert re.match(r"^\s+2026-09-20T12:00:00Z\s+\d+\s+~[/\\]\.zshrc$", line)
    _, rep_future, _ = run_json(capsys, "recent-changes", "--since", "2999-01-01", "--home", home,
                                "--no-project")
    assert rep_future["records"] == [] and any("future" in n for n in rep_future["notes"])


def test_recent_changes_new_extension_folder_is_reported(env, capsys):
    new_ext = env["home"] / ".vscode" / "extensions" / "example.fixture-ext-0.0.1"
    new_ext.mkdir(parents=True)
    (new_ext / "package.json").write_text("{}", encoding="utf-8")
    _, rep, _ = run_json(capsys, "recent-changes", "--since", "2h", "--home", env["home"], "--no-project")
    assert new_ext in {Path(r["path"]) for r in rep["records"]}
    assert "AIR018" in {f["id"] for f in rep["findings"]}


def test_parse_since_formats():
    now = dt.datetime(2026, 9, 29, 12, 0, tzinfo=dt.timezone.utc)
    assert laa.parse_since("24", now) == now - dt.timedelta(hours=24)
    assert laa.parse_since("24h", now) == now - dt.timedelta(hours=24)
    assert laa.parse_since("7d", now) == now - dt.timedelta(days=7)
    assert laa.parse_since("90m", now) == now - dt.timedelta(minutes=90)
    assert laa.parse_since("2026-09-28T10:00:00+02:00", now) == dt.datetime(2026, 9, 28, 8, 0,
                                                                              tzinfo=dt.timezone.utc)
    assert laa.parse_since("2026-09-28", now) == dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc)
    with pytest.raises(laa.UsageError):
        laa.parse_since("yesterday", now)


# ------------------------------------------------------------------------ search-sessions
def test_search_sessions_finds_sessions_and_tool_names(env, capsys):
    _, rep, raw = run_json(capsys, "search-sessions", "pdf-helper-pro", "--home", env["home"])
    assert_report_schema(rep)
    sessions = {r["session_id"]: r for r in rep["records"]}
    assert set(sessions) == {S1, S3}
    s1 = sessions[S1]
    assert s1["project_dir"] == "-home-user-work-demo"
    assert s1["first_timestamp"] == "2026-09-20T09:58:00Z"
    assert s1["last_timestamp"] == "2026-09-20T10:02:00Z"
    # attachment listing, assistant text + Skill tool_use, Skill tool_result
    assert s1["matching_lines"] == 3
    assert s1["tool_names"] == {"Skill": 2}
    assert s1["match_in"]["attachment"] == 1
    assert sessions[S3]["tool_names"] == {}
    by_session = {r["session_id"]: r for r in rep["records"]}
    ids = {f["location"].replace("\\", "/"): f["id"] for f in rep["findings"]}
    assert any(v == "AIR030" and S1 in k for k, v in ids.items())
    assert any(v == "AIR031" and S3 in k for k, v in ids.items())
    assert S2 not in raw and by_session


def test_search_sessions_maps_tool_results_subagents_and_spills(env, capsys):
    _, rep, _ = run_json(capsys, "search-sessions", "collector.example.invalid", "--home", env["home"])
    kinds = {(r["kind"], r["is_subagent"]): r for r in rep["records"]}
    main_rec = kinds[("transcript", False)]
    assert main_rec["tool_names"] == {"Bash": 2}
    assert set(main_rec["match_in"]) == {"tool_use", "tool_result"}
    sub = kinds[("transcript", True)]
    assert sub["tool_names"] == {"WebFetch": 1} and sub["agent_id"] == "afixture01"
    spill = kinds[("spilled-tool-output", False)]
    assert spill["tool_names"] == {"Bash": 1} and spill["session_id"] == S1


def test_search_sessions_matches_decoded_json_strings(env, capsys):
    _, rep, _ = run_json(capsys, "search-sessions", '"ok":true', "--home", env["home"])
    assert [r["session_id"] for r in rep["records"]] == [S1]


def test_search_sessions_since_filters_old_sessions(env, capsys):
    _, rep, _ = run_json(capsys, "search-sessions", "pdf-helper-pro", "--since", "2026-09-01",
                         "--home", env["home"])
    assert {r["session_id"] for r in rep["records"]} == {S1}


@pytest.mark.parametrize("pattern,extra", [
    ("ghp_", []), ("collector.example.invalid", []), (FAKE_GH, []), ("AKIA[A-Z]{4}", ["--regex"]),
    ("aws_secret", ["-i"]), ("token", ["-i"]), ("Authorization", []),
])
def test_search_sessions_never_leaks_fake_secrets(env, capsys, pattern, extra):
    _, out = run(capsys, "search-sessions", pattern, "--home", env["home"], "--max-excerpts", "10", *extra)
    assert_no_secrets(out)
    _, rep, raw = run_json(capsys, "search-sessions", pattern, "--home", env["home"], "--max-excerpts",
                           "10", *extra)
    assert_no_secrets(raw)
    assert rep["records"], "pattern should match the synthetic transcript"
    for rec in rep["records"]:
        for ex in rec["excerpts"]:
            assert len(ex) <= 120


def test_search_sessions_excerpt_redacts_even_when_pattern_is_the_secret(env, capsys):
    _, rep, raw = run_json(capsys, "search-sessions", FAKE_GH, "--home", env["home"])
    assert "<redacted:40 chars>" in raw
    assert_no_secrets(raw)
    assert "redacted" in rep["target"]


# ------------------------------------------------------------------ cross-cutting behavior
def test_scripts_are_read_only(env, capsys):
    before = snapshot(env["root"])
    run(capsys, "find-skill", env["ref"], "--home", env["home"], "--project", env["project"])
    run(capsys, "find-skill", "pdf-helper-pro", "--home", env["home"], "--project", env["project"], "--json")
    run(capsys, "recent-changes", "--since", "365d", "--home", env["home"], "--project", env["project"],
        "--use-ctime")
    run(capsys, "search-sessions", "pdf", "--home", env["home"], "--json")
    assert snapshot(env["root"]) == before


def test_exit_codes(env, capsys):
    code, _ = run(capsys, "find-skill", "pdf-helper-pro", "--home", env["home"], "--no-project",
                  "--fail-on", "high", "--quiet")
    assert code == 2
    code, _ = run(capsys, "find-skill", "no-such-skill", "--home", env["home"], "--no-project",
                  "--fail-on", "high")
    assert code == 0
    code, _ = run(capsys, "recent-changes", "--since", "nonsense", "--home", env["home"])
    assert code == 1
    code, _ = run(capsys, "search-sessions", "x", "--home", env["root"] / "missing")
    assert code == 1
    code, _ = run(capsys, "search-sessions", "(", "--regex", "--home", env["home"])
    assert code == 1
    with pytest.raises(SystemExit) as exc:
        laa.main(["find-skill"])
    assert exc.value.code == 1
    capsys.readouterr()


def test_checks_table_is_complete():
    for cid, check in laa.CHECKS.items():
        assert re.match(r"^AIR\d{3}$", cid)
        assert check["severity"] in laa.SEVERITIES
        assert check["title"] and check["fix"] and check["refs"]
    for category, cid in laa.CATEGORY_CHECK.items():
        assert cid in laa.CHECKS, category


@pytest.mark.parametrize("raw", [
    FAKE_GH, "github_pat_FAKEFAKEFAKEFAKEFAKE_FAKEFAKE", "sk-ant-api03-FAKEFAKEFAKEFAKEFAKE",
    "xoxb-FAKE-FAKE-FAKEFAKEFAKE", FAKE_AKIA, "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12",
    "glpat-FAKEFAKEFAKEFAKEFAKE", "npm_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
])
def test_redact_known_prefixes(raw):
    out = laa.redact(f"value {raw} end")
    assert raw not in out and "<redacted:" in out


def test_redact_key_value_url_and_header():
    assert FAKE_AWS_SECRET not in laa.redact(f"AWS_SECRET_ACCESS_KEY={FAKE_AWS_SECRET}")
    assert "p4ssw0rdFAKE" not in laa.redact("postgres://app:p4ssw0rdFAKE@db.example.invalid/app")
    assert "FAKEopaque0123456789" not in laa.redact("Authorization: Bearer FAKEopaque0123456789")
    assert laa.redact("description = a plain sentence") == "description = a plain sentence"


def test_env_overrides_apply_without_home_flag(tmp_path):
    alt = tmp_path / "alt-claude"
    ctx = laa.Ctx(tmp_path, None, False, {"CLAUDE_CONFIG_DIR": str(alt)})
    locs = {loc.lid: loc.path for loc in laa.build_catalog(ctx)}
    assert locs["cc-skills"] == alt / "skills"
    assert locs["cc-plugins"] == alt / "plugins"
    ctx2 = laa.Ctx(tmp_path, None, False, {})
    assert {loc.lid: loc.path for loc in laa.build_catalog(ctx2)}["cc-skills"] == tmp_path / ".claude" / "skills"
