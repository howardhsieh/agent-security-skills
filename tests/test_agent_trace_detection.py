"""Tests for skills/agent-trace-detection (normalize.py, sigma_check.py, bundled rules)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "agent-trace-detection"
NORMALIZE = SKILL / "scripts" / "normalize.py"
SIGMA = SKILL / "scripts" / "sigma_check.py"
SIGMA_RULES = sorted((SKILL / "assets" / "sigma").glob("*.yml"))
TRACESIG_RULES = SKILL / "assets" / "tracesig"
FIX = ROOT / "tests" / "fixtures" / "agent-trace-detection"
FAKE = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

yaml = pytest.importorskip("yaml")


def run(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def normalize(path: Path, fmt: str = "tracesig") -> list:
    proc = run(NORMALIZE, str(path), "--format", fmt)
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


# ---------------------------------------------------------------- normalize.py

def test_transcript_to_tracesig_labels_and_categories():
    rows = normalize(FIX / "transcripts" / "secret_exfil.jsonl")
    assert [r["seq"] for r in rows] == [0, 1, 2]
    assert rows[0]["tool"] == "Read" and set(rows[0]["labels"]) == {"file", "secret"}
    assert rows[1]["tool"] == "Bash"
    assert rows[2]["tool"] == "Bash(network)"
    assert all(r["session_id"] == "aaaa1111-0000-4000-8000-000000000001" for r in rows)


@pytest.mark.parametrize("fixture,expected", [
    ("web_then_publish.jsonl", "Bash(publish)"),
    ("web_then_destructive.jsonl", "Bash(destructive)"),
    ("web_then_install.jsonl", "Bash(install)"),
])
def test_bash_categories(fixture, expected):
    rows = normalize(FIX / "transcripts" / fixture)
    assert rows[-1]["tool"] == expected
    assert "untrusted" in rows[0]["labels"]


def test_mcp_results_are_untrusted_and_previewed():
    rows = normalize(FIX / "transcripts" / "mcp_asks_credentials.jsonl")
    assert rows[0]["labels"] == ["mcp", "untrusted"]
    assert "paste your API key" in rows[0]["result_preview"]


def test_secrets_redacted_everywhere():
    for fmt in ("tracesig", "flat"):
        for path in list((FIX / "transcripts").glob("*.jsonl")) + [FIX / "otel" / "otlp-export.json"]:
            proc = run(NORMALIZE, str(path), "--format", fmt)
            assert FAKE not in proc.stdout


def test_otlp_json_flattening():
    rows = normalize(FIX / "otel" / "otlp-export.json", "flat")
    names = [r["event.name"] for r in rows]
    assert names == ["tool_result", "permission_mode_changed", "plugin_installed"]
    assert rows[0]["service.name"] == "claude-code"
    assert rows[2]["marketplace.is_official"] is False
    assert isinstance(rows[0]["tool_parameters"], str)


def test_otlp_to_tracesig_uses_tool_results_only():
    rows = normalize(FIX / "otel" / "otlp-export.json")
    assert len(rows) == 1 and rows[0]["tool"] == "Bash(install)"


def test_directory_input_and_session_filter(tmp_path):
    proc = run(NORMALIZE, str(FIX / "transcripts"), "--session", "aaaa1111-0000-4000-8000-000000000002",
               "--out", str(tmp_path / "out.jsonl"))
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(l) for l in (tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3 and {r["session_id"] for r in rows} == {"aaaa1111-0000-4000-8000-000000000002"}


def test_missing_input_is_usage_error(tmp_path):
    assert run(NORMALIZE, str(tmp_path / "nope.jsonl")).returncode == 1


# ---------------------------------------------------------------- sigma_check.py

def test_all_bundled_sigma_rules_validate():
    proc = run(SIGMA, "validate", str(SKILL / "assets" / "sigma"))
    assert proc.returncode == 0, proc.stdout
    assert len(SIGMA_RULES) >= 10


@pytest.mark.parametrize("rule", SIGMA_RULES, ids=lambda p: p.stem)
def test_sigma_rule_positive_and_negative_fixtures(rule):
    pos = FIX / "sigma" / (rule.stem + ".pos.jsonl")
    neg = FIX / "sigma" / (rule.stem + ".neg.jsonl")
    assert pos.is_file() and neg.is_file(), "every rule needs .pos.jsonl and .neg.jsonl fixtures"
    assert run(SIGMA, "test", str(rule), "--events", str(pos), "--expect-match").returncode == 0
    assert run(SIGMA, "test", str(rule), "--events", str(neg), "--expect-no-match").returncode == 0


def test_sigma_rules_have_metadata():
    for rule in SIGMA_RULES:
        doc = yaml.safe_load(rule.read_text(encoding="utf-8"))
        assert doc["logsource"] == {"product": "claude_code", "service": "otel"}
        assert doc["falsepositives"] and doc["tags"] and doc["level"]


def test_sigma_ids_unique():
    ids = [yaml.safe_load(r.read_text(encoding="utf-8"))["id"] for r in SIGMA_RULES]
    assert len(ids) == len(set(ids))


def test_sigma_rules_on_transcript_derived_events(tmp_path):
    flat = tmp_path / "flat.jsonl"
    rows = normalize(FIX / "transcripts" / "web_then_publish.jsonl", "flat")
    flat.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    rule = SKILL / "assets" / "sigma" / "cc_package_or_release_publish.yml"
    assert run(SIGMA, "test", str(rule), "--events", str(flat), "--expect-match").returncode == 0


def write_rule(tmp_path: Path, detection: dict, **extra) -> Path:
    doc = {"title": "t", "id": "5f0c6b8a-1d2e-4f3a-9b4c-7d8e9f0a1b2c", "status": "test", "level": "low",
           "logsource": {"product": "claude_code"}, "detection": detection, "falsepositives": ["none"]}
    doc.update(extra)
    p = tmp_path / "rule.yml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def test_validator_rejects_bad_rules(tmp_path):
    bad_id = write_rule(tmp_path, {"sel": {"a": 1}, "condition": "sel"}, id="not-a-uuid")
    assert run(SIGMA, "validate", str(bad_id)).returncode == 1
    unknown = write_rule(tmp_path, {"sel": {"a": 1}, "condition": "sel and missing"})
    assert "unknown search identifier" in run(SIGMA, "validate", str(unknown)).stdout
    bad_tag = write_rule(tmp_path, {"sel": {"a": 1}, "condition": "sel"}, tags=["Bad Tag"])
    assert run(SIGMA, "validate", str(bad_tag)).returncode == 1
    bad_mod = write_rule(tmp_path, {"sel": {"a|nosuchmod": 1}, "condition": "sel"})
    assert run(SIGMA, "validate", str(bad_mod)).returncode == 1


@pytest.mark.parametrize("detection,event,expected", [
    ({"s": {"a": "x*"}, "condition": "s"}, {"a": "XYZ"}, True),
    ({"s": {"a|contains|all": ["b", "c"]}, "condition": "s"}, {"a": "abc"}, True),
    ({"s": {"a|contains|all": ["b", "z"]}, "condition": "s"}, {"a": "abc"}, False),
    ({"s": {"a|startswith": "ab"}, "f": {"b": 1}, "condition": "s and not f"}, {"a": "abc", "b": 2}, True),
    ({"s": {"a|endswith": "bc"}, "f": {"b": 1}, "condition": "s and not f"}, {"a": "abc", "b": 1}, False),
    ({"s1": {"a": 1}, "s2": {"b": 2}, "condition": "1 of s*"}, {"b": 2}, True),
    ({"s1": {"a": 1}, "s2": {"b": 2}, "condition": "all of s*"}, {"b": 2}, False),
    ({"s": {"a": None}, "condition": "s"}, {"b": 1}, True),
    ({"s": {"a|exists": False}, "condition": "s"}, {"a": 1}, False),
    ({"s": [{"a": 1}, {"b": 2}], "condition": "s"}, {"b": 2}, True),
    ({"s": {"a|re|i": "^AB+C$"}, "condition": "s"}, {"a": "abbc"}, True),
    ({"s": {"a|cased": "ABC"}, "condition": "s"}, {"a": "abc"}, False),
    ({"s": {"tool_parameters.k": "v"}, "condition": "s"}, {"tool_parameters": "{\"k\": \"v\"}"}, True),
    ({"s": {"flag": "true"}, "condition": "s"}, {"flag": True}, True),
    ({"a1": {"x": 1}, "b1": {"y": 1}, "condition": "(a1 or b1) and not a1"}, {"y": 1}, True),
])
def test_evaluator_semantics(tmp_path, detection, event, expected):
    rule = write_rule(tmp_path, detection)
    events = tmp_path / "e.jsonl"
    events.write_text(json.dumps(event) + "\n", encoding="utf-8")
    flag = "--expect-match" if expected else "--expect-no-match"
    proc = run(SIGMA, "test", str(rule), "--events", str(events), flag)
    assert proc.returncode == 0, proc.stdout


# ---------------------------------------------------------------- TraceSig rules

def _tracesig():
    # Use an installed tracesig, or point TRACESIG_PATH at a checkout of
    # https://github.com/howardhsieh/tracesig
    checkout = os.environ.get("TRACESIG_PATH", "")
    if checkout and Path(checkout, "tracesig", "engine.py").is_file() and checkout not in sys.path:
        sys.path.insert(0, checkout)
    try:
        from tracesig.engine import load_rules, scan  # type: ignore
        from tracesig.schema import load_jsonl  # type: ignore
    except ImportError:
        pytest.skip("tracesig not installed (pip install tracesig)")
    return load_rules, scan, load_jsonl


@pytest.mark.parametrize("fixture,rule_id", [
    ("secret_exfil.jsonl", "CC-EXF-001"),
    ("web_then_publish.jsonl", "CC-INJ-001"),
    ("web_then_destructive.jsonl", "CC-INJ-002"),
    ("web_then_install.jsonl", "CC-INJ-003"),
    ("mcp_asks_credentials.jsonl", "CC-INJ-004"),
    ("edits_agent_config.jsonl", "CC-PRIV-001"),
])
def test_tracesig_rules_fire_on_attack_traces(tmp_path, fixture, rule_id):
    load_rules, scan, load_jsonl = _tracesig()
    trace = tmp_path / "trace.jsonl"
    trace.write_text("".join(json.dumps(r) + "\n" for r in normalize(FIX / "transcripts" / fixture)), encoding="utf-8")
    findings = scan(load_jsonl(str(trace)), load_rules(str(TRACESIG_RULES)))
    assert [f.rule_id for f in findings] == [rule_id]


def test_tracesig_rules_quiet_on_benign_trace(tmp_path):
    load_rules, scan, load_jsonl = _tracesig()
    trace = tmp_path / "trace.jsonl"
    trace.write_text("".join(json.dumps(r) + "\n" for r in normalize(FIX / "transcripts" / "benign.jsonl")), encoding="utf-8")
    assert scan(load_jsonl(str(trace)), load_rules(str(TRACESIG_RULES))) == []


def test_tracesig_rules_follow_rule_spec():
    for path in TRACESIG_RULES.glob("*.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert doc["id"].startswith("CC-")
        assert doc["severity"] in {"critical", "high", "medium", "low", "informational"}
        assert doc["category"] in {"injection", "exfiltration", "privilege", "anomaly"}
        assert len([k for k in ("selection", "sequence", "taint", "frequency", "not_preceded_by") if k in doc["detection"]]) == 1
