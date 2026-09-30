"""Tests for skills/agent-security-checkup/scripts/checkup.py."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "agent-security-checkup"
SCRIPT = SKILL / "scripts" / "checkup.py"
CFG = ROOT / "tests" / "fixtures" / "agent-config-audit"
PKG = ROOT / "tests" / "fixtures" / "skill-supply-chain-audit"
FAKE_MARK = "FAKE"


def run(*args: str, script: Path = SCRIPT) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), "--no-system", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def checkup(home: Path, project: Path, *extra: str) -> dict:
    proc = run("--home", str(home), "--project", str(project), "--json", *extra)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def risky_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(CFG / "risky-home", home)
    plugin = home / ".claude" / "plugins" / "cache" / "fixture-market" / "pdf-helper-pro" / "1.0.0"
    shutil.copytree(PKG / "risky-plugin", plugin)
    skill = home / ".agents" / "skills" / "evil-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: evil-skill\ndescription: <script>alert(1)</script> helper.\n---\n\nRun it.\n",
                                    encoding="utf-8")
    return home


def test_hardened_setup_scores_well():
    rep = checkup(CFG / "hardened-home", CFG / "hardened-project")
    assert rep["grade"] in ("A", "B"), rep["score"]
    assert rep["capped_by_critical"] is False


def test_risky_setup_scores_badly_and_finds_packages(tmp_path):
    rep = checkup(risky_home(tmp_path), CFG / "risky-project")
    assert rep["grade"] in ("D", "F")
    assert rep["capped_by_critical"] is True or rep["score"] < 60
    names = {p["name"] for p in rep["packages"]}
    assert "pdf-helper-pro@fixture-market" in names and "evil-skill" in names
    pdf = next(p for p in rep["packages"] if p["name"] == "pdf-helper-pro@fixture-market")
    assert pdf["worst"] == "critical" and pdf["hooks"] >= 3
    assert rep["categories"]["packages"]["score"] < 100
    assert rep["top_risks"] and rep["quick_wins"]
    for key in ("tool", "version", "generated_at", "grade", "score", "categories", "summary", "scoring"):
        assert key in rep


def test_score_is_deterministic(tmp_path):
    home = risky_home(tmp_path)
    a = checkup(home, CFG / "risky-project")
    b = checkup(home, CFG / "risky-project")
    assert (a["score"], a["grade"], a["summary"]) == (b["score"], b["grade"], b["summary"])


def test_html_report_is_escaped_and_secret_free(tmp_path):
    out = tmp_path / "report.html"
    proc = run("--home", str(risky_home(tmp_path)), "--project", str(CFG / "risky-project"), "--html", str(out))
    assert proc.returncode == 0, proc.stderr
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and "Agent security checkup" in page
    assert "<script>" not in page
    assert FAKE_MARK not in page
    for tag in ("<link", "<script", "<img", "<iframe", "url("):
        assert tag not in page  # self-contained: no scripts or remote resources


def test_outputs_never_contain_fake_tokens(tmp_path):
    home = risky_home(tmp_path)
    for fmt in ([], ["--json"], ["--md"]):
        proc = run("--home", str(home), "--project", str(CFG / "risky-project"), *fmt)
        assert FAKE_MARK not in proc.stdout


def test_fail_below_exit_code(tmp_path):
    proc = run("--home", str(risky_home(tmp_path)), "--project", str(CFG / "risky-project"), "--fail-below", "C")
    assert proc.returncode == 2
    proc = run("--home", str(CFG / "hardened-home"), "--project", str(CFG / "hardened-project"), "--fail-below", "C")
    assert proc.returncode == 0


def test_missing_siblings_degrade_gracefully(tmp_path):
    lonely = tmp_path / "skills" / "agent-security-checkup"
    shutil.copytree(SKILL, lonely)
    proc = run("--home", str(CFG / "risky-home"), "--project", str(CFG / "risky-project"), "--json",
               script=lonely / "scripts" / "checkup.py")
    assert proc.returncode == 0, proc.stderr
    rep = json.loads(proc.stdout)
    assert all(not c["available"] for c in rep["categories"].values())
    assert "install the full agentsec-kit pack" in rep["categories"]["packages"]["note"]


def test_own_pack_is_not_penalized(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    cache = home / ".claude" / "plugins" / "cache" / "agent-security-skills" / "agentsec-kit" / "0.2.0"
    shutil.copytree(ROOT / "skills", cache)
    rep = checkup(home, tmp_path)
    own = next(p for p in rep["packages"] if p["name"] == "agentsec-kit@agent-security-skills")
    assert own["self_package"] is True
    assert own["counts"]["critical"] == 0 and own["counts"]["high"] == 0 and own["counts"]["medium"] == 0


def test_self_baseline_matches_repo_baseline():
    shipped = json.loads((SKILL / "assets" / "self-baseline.json").read_text(encoding="utf-8"))
    repo = json.loads((ROOT / "audit-baseline.json").read_text(encoding="utf-8"))
    assert shipped["accepted"] == repo["accepted"], "copy audit-baseline.json to the checkup assets after regenerating it"
