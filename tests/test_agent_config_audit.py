"""Tests for skills/agent-config-audit/scripts/audit_agent_config.py."""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-config-audit" / "scripts" / "audit_agent_config.py"
FIX = ROOT / "tests" / "fixtures" / "agent-config-audit"
FAKE_RE = re.compile(r"[A-Za-z0-9_-]*FAKE[A-Za-z0-9_-]{6,}")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def audit_json(home: str, project: str, *extra: str) -> dict:
    proc = run("--no-system", "--home", str(FIX / home), "--project", str(FIX / project), "--json", *extra)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def ids(report: dict) -> set:
    return {f["id"] for f in report["findings"]}


@pytest.fixture(scope="module")
def risky() -> dict:
    return audit_json("risky-home", "risky-project")


def test_report_schema(risky):
    for key in ("tool", "version", "target", "generated_at", "findings", "summary"):
        assert key in risky
    for f in risky["findings"]:
        assert f["severity"] in {"critical", "high", "medium", "low", "info"}
        assert {"id", "title", "location", "evidence", "fix", "refs"} <= set(f)
    total = sum(risky["summary"].values())
    assert total == len(risky["findings"])


@pytest.mark.parametrize("check", [
    "CC001",   # bypassPermissions default mode
    "CC005",   # unrestricted Bash allow
    "CC008",   # no deny rules for secret files
    "CC010",   # sandbox disabled
    "CC014",   # enableAllProjectMcpServers
    "CC015",   # repository hooks
    "CC016",   # hook downloads / exfiltrates
    "CC018",   # literal secret in settings
    "CX001",   # codex danger-full-access
    "CX004",   # codex network access
    "CX006",   # literal credential in codex config
    "CU001",   # cursor sandbox disabled
    "MCP001",  # unpinned package launch
    "MCP002",  # plaintext remote MCP
    "MCP003",  # literal secret in MCP config
])
def test_risky_fixture_triggers(risky, check):
    assert check in ids(risky)


def test_critical_findings_present(risky):
    crit = {f["id"] for f in risky["findings"] if f["severity"] == "critical"}
    assert {"CC001", "CX001"} <= crit


def test_hardened_fixture_has_no_high_or_critical():
    rep = audit_json("hardened-home", "hardened-project")
    bad = [f for f in rep["findings"] if f["severity"] in ("critical", "high")]
    assert bad == [], bad
    for check in ("CC001", "CC005", "CC014", "CC018", "CX001", "MCP003"):
        assert check not in ids(rep)


def test_secrets_never_printed():
    fakes = set()
    for p in FIX.rglob("*"):
        if p.is_file():
            fakes.update(FAKE_RE.findall(p.read_text(encoding="utf-8", errors="replace")))
    assert fakes, "fixtures should contain FAKE tokens"
    for fmt in ([], ["--json"]):
        proc = run("--no-system", "--home", str(FIX / "risky-home"), "--project", str(FIX / "risky-project"), *fmt)
        for token in fakes:
            assert token not in proc.stdout, token


def test_unparseable_config_is_a_finding_not_a_crash():
    rep = audit_json("broken-home", "broken-project")
    assert "GEN001" in ids(rep)


def test_fail_on_exit_codes():
    risky = run("--no-system", "--home", str(FIX / "risky-home"), "--project", str(FIX / "risky-project"),
                "--fail-on", "critical")
    assert risky.returncode == 2
    hardened = run("--no-system", "--home", str(FIX / "hardened-home"), "--project", str(FIX / "hardened-project"),
                   "--fail-on", "high")
    assert hardened.returncode == 0


def test_missing_directory_is_usage_error(tmp_path):
    proc = run("--no-system", "--home", str(tmp_path / "nope"), "--project", str(tmp_path))
    assert proc.returncode == 1


def test_managed_and_codex_system_dirs():
    proc = run("--home", str(FIX / "empty-home"), "--project", str(FIX / "empty-project"),
               "--managed-dir", str(FIX / "managed"), "--codex-system-dir", str(FIX / "codex-system"), "--json")
    assert proc.returncode == 0, proc.stderr
    rep = json.loads(proc.stdout)
    assert "CC001" in ids(rep)          # managed settings are audited too
    assert not FAKE_RE.search(proc.stdout)


def test_agent_filter_limits_sources():
    rep = audit_json("risky-home", "risky-project", "--agent", "codex")
    assert ids(rep)
    assert all(not i.startswith(("CC", "CU")) for i in ids(rep))


def test_tomllib_fallback_parser():
    spec = importlib.util.spec_from_file_location("audit_agent_config_fb", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.tomllib = None
    text = (FIX / "risky-home" / ".codex" / "config.toml").read_text(encoding="utf-8")
    data, used_fallback = mod.parse_toml(text)
    assert used_fallback is True
    assert data.get("sandbox_mode") == "danger-full-access"


def test_hardening_plan_in_json(risky):
    assert risky.get("hardening_plan"), "risky config should produce a hardening plan"
