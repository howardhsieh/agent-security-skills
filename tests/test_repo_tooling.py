"""Tests for tools/validate_skills.py and tools/package_skills.py.

Every test builds its own temporary repository tree, so these tests do not
depend on the real skills under skills/ being finished.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EXPECTED_SKILLS = [
    "agent-security-checkup",
    "skill-supply-chain-audit",
    "agent-config-audit",
    "agent-threat-model",
    "mcp-server-security-review",
    "agent-trace-detection",
    "agent-incident-response",
]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, str(REPO / rel))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vs = _load("repo_tooling_validate_skills", "tools/validate_skills.py")
ps = _load("repo_tooling_package_skills", "tools/package_skills.py")

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except Exception:  # pragma: no cover
    HAVE_YAML = False

PARSER_MODES = [pytest.param(False, id="builtin")]
if HAVE_YAML:
    PARSER_MODES.append(pytest.param(True, id="pyyaml"))


# --------------------------------------------------------------------------- helpers


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))  # keep LF endings on every OS
    return path


def frontmatter(name: str, description: str = None, extra: str = "", license_line: str = "license: Apache-2.0\n",
                metadata: str = 'metadata:\n  author: howardhsieh\n  version: "0.1.0"\n') -> str:
    if description is None:
        description = "Audits example things for problems. Use when the user asks to audit an example."
    return "---\nname: %s\ndescription: %s\n%s%s%s---\n" % (name, description, license_line, metadata, extra)


GOOD_BODY = (
    "# Example skill\n\n"
    "Read [the checklist](references/checklist.md) before you start.\n\n"
    "Run the scanner:\n\n"
    "```bash\npython3 scripts/scan.py --json .\n```\n"
)


def make_skill(root: Path, name: str, fm: str = None, body: str = GOOD_BODY, with_support: bool = True) -> Path:
    skill = root / "skills" / name
    write(skill / "SKILL.md", (fm if fm is not None else frontmatter(name)) + "\n" + body)
    if with_support:
        write(skill / "references" / "checklist.md", "# Checklist\n\n- item\n")
        write(skill / "scripts" / "scan.py", "#!/usr/bin/env python3\nprint('ok')\n")
    return skill


def make_marketplace(root: Path, skills, name: str = "test-marketplace", version: str = "0.1.0") -> Path:
    data = {
        "name": name,
        "owner": {"name": "Test Owner"},
        "description": "Test marketplace",
        "metadata": {"version": version},
        "plugins": [
            {
                "name": "test-plugin",
                "source": "./",
                "strict": False,
                "description": "Test plugin",
                "version": version,
                "skills": ["./skills/%s" % s for s in skills],
            }
        ],
    }
    return write(root / ".claude-plugin" / "marketplace.json", json.dumps(data, indent=2))


def make_evals(root: Path, skills) -> None:
    for s in skills:
        write(root / "evals" / ("%s.json" % s), json.dumps({
            "skill": s,
            "should_trigger": ["a", "b", "c"],
            "should_not_trigger": ["d", "e"],
            "expected_behaviors": ["f", "g", "h", "i"],
        }))


def make_repo(tmp_path: Path, names=("alpha-audit", "beta-review")) -> Path:
    root = tmp_path / "repo"
    for n in names:
        make_skill(root, n)
    make_marketplace(root, names)
    make_evals(root, names)
    write(root / "LICENSE", "Apache License\nVersion 2.0\n")
    return root


def run(root: Path, use_pyyaml: bool = True):
    return vs.validate_repo(root, use_pyyaml=use_pyyaml)


def error_codes(report):
    return report.codes("error")


def warning_codes(report):
    return report.codes("warning")


def set_skill_md(root: Path, name: str, fm: str, body: str = GOOD_BODY) -> None:
    write(root / "skills" / name / "SKILL.md", fm + "\n" + body)


# --------------------------------------------------------------------------- validator: good tree


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
def test_good_repo_is_clean(tmp_path, use_pyyaml):
    root = make_repo(tmp_path)
    report = run(root, use_pyyaml)
    assert report.errors == [], report.findings
    assert report.warnings == [], report.findings
    assert report.skills == ["alpha-audit", "beta-review"]


def test_cli_exit_codes_and_strict(tmp_path):
    root = make_repo(tmp_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert vs.main(["--root", str(root)]) == 0
    assert "0 error(s), 0 warning(s)" in buf.getvalue()

    # A warning only: exit 0 normally, 1 under --strict.
    desc = "Audits example things. Use when asked. " + "x" * 480
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", desc))
    with redirect_stdout(io.StringIO()):
        assert vs.main(["--root", str(root)]) == 0
        assert vs.main(["--root", str(root), "--strict"]) == 1

    # An error: exit 1.
    set_skill_md(root, "alpha-audit", frontmatter("wrong-name"))
    with redirect_stdout(io.StringIO()):
        assert vs.main(["--root", str(root)]) == 1


def test_cli_json_output(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", extra="version: 1\n"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = vs.main(["--root", str(root), "--json"])
    out = json.loads(buf.getvalue())
    assert rc == 1
    assert out["ok"] is False
    assert out["tool"] == "validate_skills"
    assert any(e["code"] == "frontmatter-key" for e in out["errors"])


# --------------------------------------------------------------------------- validator: frontmatter


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
def test_folded_and_literal_descriptions_parse(tmp_path, use_pyyaml):
    root = make_repo(tmp_path)
    fm = (
        "---\nname: alpha-audit\ndescription: >-\n  Audits example things for problems.\n"
        "  Use when the user asks to audit an example.\nlicense: 'Apache-2.0'\n"
        "compatibility: |\n  Python 3.9+ standard library.\nmetadata:\n  author: \"howardhsieh\"\n"
        "  version: \"0.1.0\"  # comment\n  repository: https://github.com/howardhsieh/agentsec-kit\n---\n"
    )
    set_skill_md(root, "alpha-audit", fm)
    report = run(root, use_pyyaml)
    assert report.errors == [], report.findings


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
@pytest.mark.parametrize(
    "fm_name, code",
    [
        ("Alpha-Audit", "name-format"),
        ("alpha--audit", "name-format"),
        ("-alpha-audit", "name-format"),
        ("alpha_audit", "name-format"),
        ("other-name", "name-mismatch"),
    ],
)
def test_bad_names(tmp_path, use_pyyaml, fm_name, code):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter(fm_name))
    assert code in error_codes(run(root, use_pyyaml))


@pytest.mark.parametrize("word", ["claude", "anthropic"])
def test_name_with_reserved_word(tmp_path, word):
    name = "%s-helper" % word
    root = make_repo(tmp_path, names=("alpha-audit", name))
    assert "name-reserved-word" in error_codes(run(root))


def test_name_too_long(tmp_path):
    name = "a" * 65
    root = make_repo(tmp_path, names=("alpha-audit", name))
    codes = error_codes(run(root))
    assert "name-format" in codes


def test_name_missing(tmp_path):
    root = make_repo(tmp_path)
    fm = '---\ndescription: Does things. Use when asked.\nlicense: Apache-2.0\nmetadata:\n  version: "0.1.0"\n---\n'
    set_skill_md(root, "alpha-audit", fm)
    assert "name-missing" in error_codes(run(root))


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
def test_unknown_frontmatter_key(tmp_path, use_pyyaml):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", extra="argument-hint: path\n"))
    report = run(root, use_pyyaml)
    assert "frontmatter-key" in error_codes(report)
    assert any("argument-hint" in f.message for f in report.errors)


def test_all_six_spec_keys_allowed(tmp_path):
    root = make_repo(tmp_path)
    extra = "compatibility: Python 3.9+\nallowed-tools: Read Grep Bash(python3 scripts/*)\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", extra=extra))
    report = run(root)
    assert report.errors == [] and report.warnings == [], report.findings


def test_description_length_limits(tmp_path):
    root = make_repo(tmp_path)
    base = "Audits things. Use when asked. "
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", base + "x" * (1025 - len(base))))
    assert "description-length" in error_codes(run(root))

    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", base + "x" * (501 - len(base))))
    report = run(root)
    assert "description-length" not in error_codes(report)
    assert "description-length" in warning_codes(report)

    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", base + "x" * (500 - len(base))))
    assert "description-length" not in warning_codes(run(root))


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
@pytest.mark.parametrize("desc", ['"Parses <html> files. Use when asked."', "Use when x > y for audits."])
def test_description_angle_brackets(tmp_path, use_pyyaml, desc):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", desc))
    assert "description-angle-bracket" in error_codes(run(root, use_pyyaml))


def test_description_empty(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", '""'))
    assert "description-format" in error_codes(run(root))


def test_description_style_warnings(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", "I audit example things for you."))
    assert "description-style" in warning_codes(run(root))


def test_license_required(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", license_line=""))
    assert "license-missing" in error_codes(run(root))


def test_license_other_value_warns(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", license_line="license: MIT\n"))
    report = run(root)
    assert "license-format" in warning_codes(report)
    assert report.errors == []


def test_metadata_version_required(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", metadata="metadata:\n  author: howardhsieh\n"))
    assert "metadata-version" in error_codes(run(root))
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", metadata=""))
    assert "metadata-missing" in error_codes(run(root))


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
def test_metadata_values_must_be_strings(tmp_path, use_pyyaml):
    root = make_repo(tmp_path)
    # Unquoted 0.1 is a float in YAML; the spec wants string values.
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", metadata="metadata:\n  version: 0.1\n"))
    report = run(root, use_pyyaml)
    assert "metadata-format" in error_codes(report)


def test_metadata_version_mismatch_warns(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", metadata='metadata:\n  version: "0.2.0"\n'))
    assert "version-mismatch" in warning_codes(run(root))


def test_allowed_tools_must_be_string_and_scoped(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit", extra="allowed-tools: Read Bash\n"))
    assert "allowed-tools-shell" in warning_codes(run(root))


@pytest.mark.parametrize("use_pyyaml", PARSER_MODES)
@pytest.mark.parametrize(
    "fm",
    [
        "name: alpha-audit\ndescription: Use when: broken\n",  # ': ' inside a plain scalar
        'name: alpha-audit\ndescription: "unterminated\n',
        "name: alpha-audit\nmetadata:\n\tversion: x\n",  # tab indentation
    ],
)
def test_invalid_yaml_is_an_error(tmp_path, use_pyyaml, fm):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "SKILL.md", "---\n" + fm + "---\n\n# Body\n")
    assert "frontmatter-yaml" in error_codes(run(root, use_pyyaml))


def test_missing_frontmatter(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "SKILL.md", "# No frontmatter\n")
    assert "frontmatter" in error_codes(run(root))
    write(root / "skills" / "alpha-audit" / "SKILL.md", "---\nname: alpha-audit\n# never closed\n")
    assert "frontmatter" in error_codes(run(root))


def test_missing_skill_md(tmp_path):
    root = make_repo(tmp_path)
    (root / "skills" / "alpha-audit" / "SKILL.md").unlink()
    write(root / "skills" / "alpha-audit" / "skill.md", frontmatter("alpha-audit"))
    report = run(root)
    assert "skill-md-missing" in error_codes(report)


def test_builtin_parser_flags_unsupported_yaml_without_pyyaml(tmp_path):
    root = make_repo(tmp_path)
    fm = frontmatter("alpha-audit", metadata='metadata:\n  version: "0.1.0"\n  tags: [a, b]\n')
    set_skill_md(root, "alpha-audit", fm)
    assert "frontmatter-yaml" in error_codes(run(root, use_pyyaml=False))
    if HAVE_YAML:
        report = run(root, use_pyyaml=True)
        assert "frontmatter-yaml" in warning_codes(report)
        assert "metadata-format" in error_codes(report)  # list is not a string value


# --------------------------------------------------------------------------- validator: body and files


def test_body_length_limits(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body="line\n" * 501)
    assert "body-length" in error_codes(run(root))
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body="line\n" * 301)
    report = run(root)
    assert "body-length" not in error_codes(report)
    assert "body-length" in warning_codes(report)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body="line\n" * 299)
    assert "body-length" not in warning_codes(run(root))


def test_broken_relative_link(tmp_path):
    root = make_repo(tmp_path)
    body = "See [missing](references/nope.md) and [ok](references/checklist.md#section).\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    report = run(root)
    broken = [f for f in report.errors if f.code == "link-broken"]
    assert len(broken) == 1 and "nope.md" in broken[0].message
    assert broken[0].line is not None and broken[0].line > 6  # reported at the file line, after frontmatter


def test_link_outside_skill_folder(tmp_path):
    root = make_repo(tmp_path)
    body = "See [sibling](../beta-review/SKILL.md).\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    assert "link-outside-skill" in error_codes(run(root))


def test_links_that_are_ignored(tmp_path):
    root = make_repo(tmp_path)
    body = (
        "External [spec](https://agentskills.io/specification) and [mail](mailto:a@example.com).\n"
        "Anchor [here](#section). Code span `[x](references/nope.md)` is not a link.\n\n"
        "```markdown\n[also not a link](references/missing.md)\n```\n"
    )
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    report = run(root)
    assert report.errors == [], report.findings


def test_reference_definition_links_checked(tmp_path):
    root = make_repo(tmp_path)
    body = "See [the guide][g].\n\n[g]: references/guide.md\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    assert "link-broken" in error_codes(run(root))


def test_links_inside_reference_files_checked(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "references" / "checklist.md", "# C\n\nSee [x](other.md).\n")
    report = run(root)
    assert any(f.code == "link-broken" and f.path.endswith("references/checklist.md") for f in report.errors)


def test_absolute_link_is_an_error(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body="See [x](/etc/hosts).\n")
    assert "link-absolute" in error_codes(run(root))


def test_link_with_wrong_letter_case(tmp_path):
    root = make_repo(tmp_path)
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body="See [c](references/Checklist.md).\n")
    codes = error_codes(run(root))
    # Case-sensitive filesystems report a broken link; case-insensitive ones a case mismatch.
    assert codes & {"link-broken", "link-case"}


def test_link_to_directory_and_encoded_path(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "assets" / "report template.md", "x\n")
    body = "See [assets](assets/) and [tpl](assets/report%20template.md) and [angle](<assets/report template.md>).\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    report = run(root)
    assert not ({"link-broken", "link-case"} & error_codes(report)), report.findings
    assert "filename-space" in error_codes(report)  # the space itself is still a problem


def test_mentioned_script_path_missing_warns(tmp_path):
    root = make_repo(tmp_path)
    body = "Run `scripts/missing.py` or:\n\n```bash\npython3 scripts/also_missing.py --json\n```\n"
    set_skill_md(root, "alpha-audit", frontmatter("alpha-audit"), body=body)
    report = run(root)
    mentions = [f for f in report.warnings if f.code == "path-mention-missing"]
    assert {m.message.split("'")[1] for m in mentions} == {"scripts/missing.py", "scripts/also_missing.py"}


def test_reference_toc_warning(tmp_path):
    root = make_repo(tmp_path)
    ref = root / "skills" / "alpha-audit" / "references" / "long.md"
    write(ref, "# Long\n\n" + "text\n" * 120)
    report = run(root)
    assert any(f.code == "reference-toc" and f.path.endswith("long.md") for f in report.warnings)

    write(ref, "# Long\n\n## Contents\n\n- [A](#a)\n\n" + "text\n" * 120)
    assert "reference-toc" not in warning_codes(run(root))

    write(ref, "# Long\n\n**Table of contents**\n\n" + "text\n" * 120)
    assert "reference-toc" not in warning_codes(run(root))

    write(ref, "# Short\n\n" + "text\n" * 50)
    assert "reference-toc" not in warning_codes(run(root))


def test_filename_with_space(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "assets" / "my template.md", "x\n")
    assert "filename-space" in error_codes(run(root))


def test_top_level_bin_dir(tmp_path):
    root = make_repo(tmp_path)
    write(root / "bin" / "tool", "#!/bin/sh\n")
    report = run(root)
    assert "repo-bin-dir" in error_codes(report)
    assert "plugin-bin-dir" not in error_codes(report)  # reported once for a root-level plugin


def test_bin_dir_inside_skill_is_fine(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "bin" / "helper.py", "print('x')\n")
    assert "repo-bin-dir" not in error_codes(run(root))


def test_pycache_is_ignored(tmp_path):
    root = make_repo(tmp_path)
    write(root / "skills" / "alpha-audit" / "scripts" / "__pycache__" / "scan cpython.pyc", "x")
    assert run(root).errors == []


# --------------------------------------------------------------------------- validator: marketplace


def test_marketplace_must_list_exactly_present_skills(tmp_path):
    root = make_repo(tmp_path)
    make_marketplace(root, ["alpha-audit"])
    assert "marketplace-missing-skill" in error_codes(run(root))

    make_marketplace(root, ["alpha-audit", "beta-review", "gamma-ghost"])
    assert "marketplace-unknown-skill" in error_codes(run(root))

    make_marketplace(root, ["alpha-audit", "beta-review", "alpha-audit"])
    assert "marketplace-duplicate-skill" in error_codes(run(root))


def test_marketplace_missing(tmp_path):
    root = make_repo(tmp_path)
    (root / ".claude-plugin" / "marketplace.json").unlink()
    assert "marketplace-missing" in error_codes(run(root))


def test_marketplace_invalid_json(tmp_path):
    root = make_repo(tmp_path)
    write(root / ".claude-plugin" / "marketplace.json", "{not json")
    assert "marketplace-json" in error_codes(run(root))


@pytest.mark.parametrize("name", ["agent-skills", "claude-plugins-official", "claude.code.plugins", "github",
                                  "claudeai-mine", "my marketplace", "a/b"])
def test_marketplace_reserved_or_invalid_names(tmp_path, name):
    root = make_repo(tmp_path)
    make_marketplace(root, ["alpha-audit", "beta-review"], name=name)
    assert "marketplace-name" in error_codes(run(root))


def test_marketplace_source_and_skill_paths(tmp_path):
    root = make_repo(tmp_path)
    mp = root / ".claude-plugin" / "marketplace.json"
    data = json.loads(mp.read_text(encoding="utf-8"))
    data["plugins"][0]["source"] = "plugins/x"
    write(mp, json.dumps(data))
    assert "marketplace-source" in error_codes(run(root))

    data["plugins"][0]["source"] = "./"
    data["plugins"][0]["skills"] = ["skills/alpha-audit", "./skills/beta-review"]
    write(mp, json.dumps(data))
    assert "marketplace-skills" in error_codes(run(root))

    data["plugins"][0]["skills"] = ["./skills/alpha-audit", "./skills/../skills/beta-review"]
    write(mp, json.dumps(data))
    assert "marketplace-skills" in error_codes(run(root))


def test_marketplace_owner_and_plugin_names(tmp_path):
    root = make_repo(tmp_path)
    mp = root / ".claude-plugin" / "marketplace.json"
    data = json.loads(mp.read_text(encoding="utf-8"))
    data["owner"] = {}
    data["plugins"][0]["name"] = "bad name"
    write(mp, json.dumps(data))
    codes = error_codes(run(root))
    assert "marketplace-owner" in codes
    assert "marketplace-plugin" in codes


def test_strict_false_with_plugin_json_conflict(tmp_path):
    root = make_repo(tmp_path)
    write(root / ".claude-plugin" / "plugin.json", json.dumps({"name": "test-plugin"}))
    assert "plugin-manifest-conflict" in error_codes(run(root))


# --------------------------------------------------------------------------- validator: evals and real files


def test_eval_files_checked(tmp_path):
    root = make_repo(tmp_path)
    (root / "evals" / "beta-review.json").unlink()
    write(root / "evals" / "alpha-audit.json", json.dumps({"skill": "alpha-audit", "should_trigger": []}))
    report = run(root)
    assert "eval-missing" in warning_codes(report)
    assert "eval-format" in warning_codes(report)
    assert report.errors == []


def test_real_marketplace_json_lists_the_six_skills():
    """Checks the committed marketplace.json only; does not need the skills to be written."""
    data = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert data["name"] == "agent-security-skills"
    assert data["owner"]["name"] == "Howard Hsieh"
    plugin = data["plugins"][0]
    assert plugin["name"] == "agentsec-kit"
    assert plugin["source"] == "./skills"  # ship only the skills, not tests or fixtures
    manifest = json.loads((REPO / "skills" / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == plugin["name"]
    assert sorted(manifest["skills"]) == sorted("./%s" % s for s in EXPECTED_SKILLS)
    report = vs.Report(REPO)
    vs.check_marketplace(report, REPO, set(EXPECTED_SKILLS))
    assert report.errors == [], report.findings


def test_real_eval_files_are_well_formed():
    for skill in EXPECTED_SKILLS:
        path = REPO / "evals" / ("%s.json" % skill)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["skill"] == skill
        assert len(data["should_trigger"]) == 3
        assert len(data["should_not_trigger"]) == 2
        assert 4 <= len(data["expected_behaviors"]) <= 6
        for text in data["should_trigger"] + data["should_not_trigger"] + data["expected_behaviors"]:
            assert isinstance(text, str) and text.strip()


def test_workflows_parse():
    yaml_mod = pytest.importorskip("yaml")
    for name in ("ci.yml", "release.yml"):
        doc = yaml_mod.safe_load((REPO / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        assert doc.get("jobs"), name
        # PyYAML reads the bare key `on` as True.
        assert "on" in doc or True in doc, name


# --------------------------------------------------------------------------- YAML subset parser


SUBSET_CASES = [
    ("name: a-b\ndescription: Does X. Use when Y.\n", {"name": "a-b", "description": "Does X. Use when Y."}),
    ("d: >\n  one\n  two\n\n  three\n", {"d": "one two\nthree\n"}),
    ("d: >-\n  one\n  two\n", {"d": "one two"}),
    ("d: |\n  a\n   b\n", {"d": "a\n b\n"}),
    ("d: 'it''s: fine'\n", {"d": "it's: fine"}),
    ('d: "q \\"x\\" \\u00e9"\n', {"d": 'q "x" \u00e9'}),
    ("d: first\n  second\n", {"d": "first second"}),
    ('metadata:\n  author: me\n  version: "0.1.0"\n', {"metadata": {"author": "me", "version": "0.1.0"}}),
    ("a: 1\nb: 1.5\nc: yes\nd: ~\ne: 0.1.0\n", {"a": 1, "b": 1.5, "c": True, "d": None, "e": "0.1.0"}),
    ("# comment\nname: x # trailing\n", {"name": "x"}),
    ("url: https://example.com/a\n", {"url": "https://example.com/a"}),
]


@pytest.mark.parametrize("text, expected", SUBSET_CASES)
def test_yaml_subset_parser(text, expected):
    data, _ = vs.parse_yaml_subset(text)
    assert data == expected


@pytest.mark.skipif(not HAVE_YAML, reason="PyYAML not installed")
@pytest.mark.parametrize("text, expected", SUBSET_CASES)
def test_yaml_subset_parser_matches_pyyaml(text, expected):
    import yaml as yaml_mod

    assert vs.parse_yaml_subset(text)[0] == yaml_mod.safe_load(text)


@pytest.mark.parametrize(
    "text, unsupported",
    [
        ("d: Use when: x\n", False),
        ("a: 1\na: 2\n", False),
        ('d: "open\n', False),
        ("d: [a, b]\n", True),
        ("d:\n  - a\n", True),
        ("m:\n  a:\n    b: c\n", True),
        ("d: &anchor x\n", True),
    ],
)
def test_yaml_subset_parser_errors(text, unsupported):
    with pytest.raises(vs.YamlSubsetError) as info:
        vs.parse_yaml_subset(text)
    assert info.value.unsupported is unsupported


def test_trailing_comment_in_plain_description_warns():
    _, warnings = vs.parse_yaml_subset("description: Scan repos #security for leaks\n")
    assert warnings


# --------------------------------------------------------------------------- packager


def _names(path: Path):
    with zipfile.ZipFile(str(path)) as zf:
        return zf.namelist()


def test_package_per_skill_zip_layout(tmp_path):
    root = make_repo(tmp_path)
    skill = root / "skills" / "alpha-audit"
    write(skill / "scripts" / "__pycache__" / "scan.cpython-311.pyc", "junk")
    write(skill / "scripts" / "stale.pyc", "junk")
    write(skill / ".DS_Store", "junk")
    write(skill / "assets" / "report-template.md", "# Report\n")
    out = tmp_path / "dist"
    results = ps.build(root, out)

    per_skill = out / "alpha-audit.zip"
    assert per_skill.is_file()
    names = _names(per_skill)
    assert names == sorted(names)
    assert names == [
        "alpha-audit/SKILL.md",
        "alpha-audit/assets/report-template.md",
        "alpha-audit/references/checklist.md",
        "alpha-audit/scripts/scan.py",
    ]
    # Every entry sits under exactly one top-level folder named after the skill.
    assert {n.split("/", 1)[0] for n in names} == {"alpha-audit"}
    assert not any("__pycache__" in n or n.endswith((".pyc", ".DS_Store")) for n in names)
    assert {Path(str(r["path"])).name for r in results} == {
        "alpha-audit.zip", "beta-review.zip", "agent-security-skills-0.1.0.zip"}
    assert all(int(r["bytes"]) > 0 for r in results)


def test_package_zip_metadata_is_fixed(tmp_path):
    root = make_repo(tmp_path)
    out = tmp_path / "dist"
    ps.build(root, out, bundle=False)
    with zipfile.ZipFile(str(out / "alpha-audit.zip")) as zf:
        assert zf.testzip() is None
        for info in zf.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.compress_type == zipfile.ZIP_DEFLATED
            mode = (info.external_attr >> 16) & 0o777
            assert mode == (0o755 if info.filename.endswith("scripts/scan.py") else 0o644)
        assert zf.read("alpha-audit/SKILL.md").decode("utf-8").startswith("---\nname: alpha-audit\n")


def test_package_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    root = make_repo(tmp_path)
    a, b = tmp_path / "a", tmp_path / "b"
    ps.build(root, a)
    # Touch files so mtimes differ; output must not change.
    for p in (root / "skills").rglob("*"):
        if p.is_file():
            os.utime(str(p), (1_700_000_000, 1_700_000_000))
    ps.build(root, b)
    for z in sorted(a.glob("*.zip")):
        assert z.read_bytes() == (b / z.name).read_bytes(), z.name


def test_package_honors_source_date_epoch(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790640000")  # 2026-09-29T00:00:00Z
    root = make_repo(tmp_path)
    out = tmp_path / "dist"
    ps.build(root, out, bundle=False)
    with zipfile.ZipFile(str(out / "alpha-audit.zip")) as zf:
        assert zf.infolist()[0].date_time == (2026, 9, 29, 0, 0, 0)


def test_package_bundle_layout_and_version(tmp_path):
    root = make_repo(tmp_path)
    make_marketplace(root, ["alpha-audit", "beta-review"], version="1.2.3")
    out = tmp_path / "dist"
    ps.build(root, out)
    bundle = out / "agent-security-skills-1.2.3.zip"
    names = _names(bundle)
    assert names == sorted(names)
    assert "agent-security-skills-1.2.3/LICENSE" in names
    assert "agent-security-skills-1.2.3/README.txt" in names
    assert "agent-security-skills-1.2.3/skills/alpha-audit/SKILL.md" in names
    assert "agent-security-skills-1.2.3/skills/beta-review/SKILL.md" in names
    assert all(n.startswith("agent-security-skills-1.2.3/") for n in names)


def test_package_version_override_and_single_skill(tmp_path):
    root = make_repo(tmp_path)
    out = tmp_path / "dist"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = ps.main(["--root", str(root), "--out", str(out), "--skill", "beta-review"])
    assert rc == 0
    assert sorted(p.name for p in out.glob("*.zip")) == ["beta-review.zip"]
    assert "beta-review.zip" in buf.getvalue() and "files" in buf.getvalue()

    with redirect_stdout(io.StringIO()):
        assert ps.main(["--root", str(root), "--out", str(out), "--version", "9.9.9", "--clean"]) == 0
    assert (out / "agent-security-skills-9.9.9.zip").is_file()
    assert not (out / "agent-security-skills-0.1.0.zip").exists()


def test_package_cli_prints_sizes(tmp_path):
    root = make_repo(tmp_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert ps.main(["--root", str(root), "--out", str(tmp_path / "dist")]) == 0
    out = buf.getvalue()
    assert "alpha-audit.zip" in out and "agent-security-skills-0.1.0.zip" in out
    assert "KB" in out or " B" in out
    assert "wrote 3 archive(s)" in out


def test_package_refuses_skill_without_skill_md(tmp_path):
    root = make_repo(tmp_path)
    (root / "skills" / "alpha-audit" / "SKILL.md").unlink()
    with pytest.raises(SystemExit):
        ps.build(root, tmp_path / "dist")


def test_package_unknown_skill(tmp_path):
    root = make_repo(tmp_path)
    with pytest.raises(SystemExit):
        ps.build(root, tmp_path / "dist", only=["nope"])


def test_package_refuses_symlinks(tmp_path):
    root = make_repo(tmp_path)
    link = root / "skills" / "alpha-audit" / "references" / "link.md"
    try:
        os.symlink(str(root / "LICENSE"), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this platform")
    with pytest.raises(ValueError):
        ps.build(root, tmp_path / "dist")


def test_packaged_zip_passes_validator_after_extraction(tmp_path):
    """Round trip: a packaged skill extracts to a folder the validator accepts."""
    root = make_repo(tmp_path)
    out = tmp_path / "dist"
    ps.build(root, out, bundle=False)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(str(out / "alpha-audit.zip")) as zf:
        zf.extractall(str(extracted / "skills"))
    make_marketplace(extracted, ["alpha-audit"])
    report = run(extracted)
    assert report.errors == [], report.findings
