#!/usr/bin/env python3
"""Locate AI agent artifacts during incident response. Read-only.

Subcommands
  find-skill NAME_OR_PATH   every installed copy of a skill or plugin, matched by
                            directory name, SKILL.md frontmatter name, plugin
                            manifest name, or (given a reference copy) file hash
  recent-changes --since T  files changed since T in agent configs, skill and
                            plugin dirs, instruction files, shell startup files,
                            git hooks, SSH files and autostart locations
  search-sessions PATTERN   Claude Code session transcripts that mention a
                            string or regex: session id, project, time span,
                            matching lines, tool names, short redacted excerpts

The script only stats and reads files. It never executes, modifies or deletes
anything, never follows symlinked directories while walking, only opens regular
files, and never uses the network. Secrets are redacted in every output.
Python 3.9+, standard library only, macOS / Linux / Windows.

Exit codes: 0 ran fine, 1 usage or IO error, 2 --fail-on threshold met.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

TOOL = "locate_agent_artifacts"
VERSION = "0.2.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Framework references (editions pinned; see verified sources in SKILL.md).
R_AST01 = "AST01 (OWASP Agentic Skills Top 10 v1.0)"
R_AST07 = "AST07 (OWASP Agentic Skills Top 10 v1.0)"
R_AST10 = "AST10 (OWASP Agentic Skills Top 10 v1.0)"
R_ASI01 = "ASI01 (Agentic Top 10 2026)"
R_ASI02 = "ASI02 (Agentic Top 10 2026)"
R_ASI04 = "ASI04 (Agentic Top 10 2026)"
R_ASI06 = "ASI06 (Agentic Top 10 2026)"
R_T0010 = "AML.T0010.005 (MITRE ATLAS v2026.09)"
R_T0081 = "AML.T0081 (MITRE ATLAS v2026.09)"
R_T0080 = "AML.T0080.000 (MITRE ATLAS v2026.09)"
R_T0086 = "AML.T0086 (MITRE ATLAS v2026.09)"
R_T0112 = "AML.T0112.000 (MITRE ATLAS v2026.09)"
R_T0051 = "AML.T0051.001 (MITRE ATLAS v2026.09)"
R_ATTACK = "(MITRE ATT&CK Enterprise v19)"

CHECKS: Dict[str, Dict[str, Any]] = {
    # find-skill
    "AIR001": {"severity": "high", "title": "Installed copy matches the suspect name",
               "fix": "Copy it to the evidence folder with hashes, then remove it after approval.",
               "refs": [R_AST01, R_ASI04, R_T0010]},
    "AIR002": {"severity": "high", "title": "Renamed copy: SKILL.md or manifest name matches, directory name differs",
               "fix": "Treat as the same skill under another folder name; preserve, then remove after approval.",
               "refs": [R_AST01, R_AST10, R_ASI04]},
    "AIR003": {"severity": "high", "title": "Installed copy is identical in content to the reference copy",
               "fix": "Preserve one copy as evidence, then remove every identical copy after approval.",
               "refs": [R_AST01, R_AST10, R_ASI04, R_T0010]},
    "AIR004": {"severity": "medium", "title": "Installed item shares files with the reference copy",
               "fix": "Review the shared files; a skill or plugin reusing the suspect's scripts may be a variant.",
               "refs": [R_AST01, R_AST07, R_ASI04]},
    "AIR005": {"severity": "medium", "title": "Command or agent file carries the suspect name",
               "fix": "Read it as text (do not run it) and remove it after approval if it belongs to the suspect.",
               "refs": [R_AST01, R_ASI04]},
    "AIR008": {"severity": "medium", "title": "Agent config or lock file references the suspect name",
               "fix": "Note the entry (enabledPlugins, install record, lock file) and remove it during containment.",
               "refs": [R_ASI04, R_T0081]},
    "AIR006": {"severity": "medium", "title": "Installed copies of the suspect differ from each other",
               "fix": "Preserve every variant; the skill may have changed after install (update drift).",
               "refs": [R_AST07, R_ASI04]},
    "AIR007": {"severity": "info", "title": "No installed copy found in scanned locations",
               "fix": "Absence here is not proof; add --extra-root for other agents and search sessions and backups.",
               "refs": [R_AST10]},
    # recent-changes
    "AIR010": {"severity": "high", "title": "Agent configuration file changed in the window",
               "fix": "Diff against a known-good copy for new hooks, MCP servers, permissions or env entries.",
               "refs": [R_T0081, R_ASI04, R_T0112]},
    "AIR011": {"severity": "high", "title": "Skill, plugin or extension files changed in the window",
               "fix": "Identify who installed or edited them; run find-skill and skill-supply-chain-audit on them.",
               "refs": [R_AST01, R_AST07, R_ASI04]},
    "AIR012": {"severity": "high", "title": "Shell startup file changed in the window",
               "fix": "Review new lines (aliases, PATH, sourced files, curl or eval); restore from a known-good copy.",
               "refs": ["T1546.004 " + R_ATTACK, "T1546.013 " + R_ATTACK]},
    "AIR013": {"severity": "high", "title": "Git hook added or changed in the window",
               "fix": "Read the hook as text; remove it after approval if nobody on the team added it.",
               "refs": ["T1546 " + R_ATTACK, R_T0112]},
    "AIR014": {"severity": "high", "title": "Autostart entry added or changed in the window",
               "fix": "Inspect the entry's command; unload and remove it after evidence copy and approval.",
               "refs": ["T1543.001 " + R_ATTACK, "T1543.002 " + R_ATTACK,
                        "T1547.001 " + R_ATTACK, "T1547.013 " + R_ATTACK]},
    "AIR015": {"severity": "medium", "title": "Agent instruction or memory file changed in the window",
               "fix": "Read for injected instructions (exfiltrate, disable checks, install); restore known-good text.",
               "refs": [R_ASI06, R_T0080]},
    "AIR016": {"severity": "high", "title": "SSH access file changed in the window",
               "fix": "Check authorized_keys for unknown keys and ssh config for ProxyCommand or LocalCommand.",
               "refs": ["T1098.004 " + R_ATTACK]},
    "AIR017": {"severity": "medium", "title": "Git config changed in the window",
               "fix": "Check core.hooksPath and core.fsmonitor; both can point git at a command to run.",
               "refs": ["T1546 " + R_ATTACK]},
    "AIR018": {"severity": "medium", "title": "IDE configuration or extension changed in the window",
               "fix": "Check tasks that run on folder open, MCP entries and new extensions.",
               "refs": ["T1176.002 " + R_ATTACK, R_ASI04]},
    "AIR019": {"severity": "info", "title": "Manual check required: location not readable by this script",
               "fix": "Run the listed command from a clean terminal and compare with known entries.",
               "refs": ["T1053 " + R_ATTACK, "T1547.001 " + R_ATTACK]},
    # search-sessions
    "AIR030": {"severity": "high", "title": "Pattern appears on transcript lines where tools executed, wrote or sent data",
               "fix": "Reconstruct what those tool calls did; rotate any credential they could read or send.",
               "refs": [R_ASI01, R_ASI02, R_T0051, R_T0086]},
    "AIR031": {"severity": "medium", "title": "Pattern appears in a session transcript",
               "fix": "Open the session read-only from a clean terminal to establish when and how the pattern entered.",
               "refs": [R_ASI01, R_T0051]},
}

CATEGORY_CHECK = {
    "agent-config": "AIR010", "extension": "AIR011", "shell": "AIR012", "git-hook": "AIR013",
    "autostart": "AIR014", "instructions": "AIR015", "ssh": "AIR016", "git-config": "AIR017",
    "ide": "AIR018",
}

# Tool names that execute code, write files, or can send data out. Any mcp__* tool
# also counts because MCP tools can do all three.
ACTION_TOOLS = {"Bash", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch",
                "WebSearch", "Task", "Agent", "Skill", "KillShell", "BashOutput"}

MANUAL_CHECKS = [
    ("User crontab (Linux, macOS)", "crontab -l",
     "The per-user cron spool is readable only by root; list your own entries with crontab -l."),
    ("systemd user timers (Linux)", "systemctl --user list-timers --all",
     "Timers can start a unit that lives outside the scanned unit folders."),
    ("Windows Run and RunOnce keys", r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
     "Registry autostart values are not files; also query the RunOnce key."),
    ("Windows scheduled tasks", "schtasks /query /fo LIST /v",
     "Scheduled tasks are stored by the Task Scheduler service, not in the user profile."),
    ("macOS login and background items", "System Settings > General > Login Items",
     "Login and background items are managed by the OS, not only by LaunchAgents plists."),
    ("Git hook redirection", "git config --show-origin --get-regexp ^core[.](hookspath|fsmonitor)$",
     "core.hooksPath or core.fsmonitor can point outside .git/hooks; inspect the target they name."),
    ("IDE extensions", "code --list-extensions --show-versions",
     "Compare with what the team expects; this script checks only the extension folder timestamps."),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
PROJECT_SKIP_DIRS = SKIP_DIRS | {"dist", "build", "target", ".next", ".cache"}
COMMON_FILES = {"license", "license.txt", "license.md", "copying", "notice", "notice.txt",
                ".gitignore", ".ds_store", ".npmignore"}
MANIFESTS = (".claude-plugin/plugin.json", "plugin.json", ".codex-plugin/plugin.json",
             "gemini-extension.json")
INSTALL_PARENTS = {"skills", "synced", ".trash", "marketplaces", "data", "plugins", "extensions"}
MAX_HASH_BYTES = 20 * 1024 * 1024
MAX_UNIT_FILES = 5000
MIN_PARTIAL_BYTES = 32
MAX_EXCERPT = 120
MAX_EVIDENCE = 160


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; the repo convention reserves 2 for --fail-on."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(1)


# --------------------------------------------------------------------------------------
# Redaction and output hygiene
# --------------------------------------------------------------------------------------
_PREFIX_PATTERNS = [re.compile(p) for p in (
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    r"\bsk-ant-[A-Za-z0-9_\-]{10,}",
    r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bglpat-[A-Za-z0-9_\-]{16,}",
    r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
    r"\bxapp-[A-Za-z0-9\-]{10,}",
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    r"\bAIza[0-9A-Za-z_\-]{30,}",
    r"\bnpm_[A-Za-z0-9]{30,}",
    r"\bpypi-[A-Za-z0-9_\-]{30,}",
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{20,}=*",
    r"\bhvs\.[A-Za-z0-9_\-]{20,}",
)]
# (prefix, secret) pairs: only group 2 is redacted
_CLI_SECRET_RES = [
    re.compile(r"(?i)((?:^|[\s\"'])(?:-u|--user|--proxy-user)\s*[\"']?[^\s:\"'/]+:)([^\s\"'@]+)"),
    re.compile(r"(?i)(\bsshpass\s+-p\s*[\"']?)([^\s\"']+)"),
    re.compile(r"(\bmysql(?:dump|admin)?\b[^\n|;&]*?\s-p)([^\s\"'-][^\s\"']{2,})"),
    re.compile(r"(?i)(--password[=\s]+[\"']?)(?![$<])([^\s\"']{3,})"),
]
_KV_RE = re.compile(
    r"(?i)([\w.\-]*(?:token|secret|passw(?:or)?d|pwd|api[_\-]?key|access[_\-]?key|private[_\-]?key"
    r"|auth|credential|key)[\w.\-]*)(\\?[\"']?\s*[:=]\s*\\?[\"']?)([^\s\"'\\,;{}<>]{20,})")
_URL_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@\"'<>]+:)([^\s@/\"'<>]+)(@)")
_AUTHZ_RE = re.compile(r"(?i)(authorization\\?[\"']?\s*[:=]\s*\\?[\"']?\s*(?:bearer|token|basic)\s+)"
                       r"([A-Za-z0-9._~+/\-=]{12,})")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_secret(value: str) -> bool:
    has_alpha = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return len(value) >= 20 and (_entropy(value) >= 3.0 or (has_alpha and has_digit))


def _secret_spans(text: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for rx in _PREFIX_PATTERNS:
        spans.extend((m.start(), m.end()) for m in rx.finditer(text))
    for m in _KV_RE.finditer(text):
        if _looks_secret(m.group(3)):
            spans.append((m.start(3), m.end(3)))
    for m in _URL_CRED_RE.finditer(text):
        spans.append((m.start(2), m.end(2)))
    for m in _AUTHZ_RE.finditer(text):
        spans.append((m.start(2), m.end(2)))
    for rx in _CLI_SECRET_RES:
        for m in rx.finditer(text):
            spans.append((m.start(2), m.end(2)))
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


def redact_with_pos(text: str, pos: int = 0) -> Tuple[str, int]:
    """Redact secrets; also map an index in `text` to the matching index in the result."""
    out: List[str] = []
    last = 0
    new_pos: Optional[int] = None
    length = 0
    for s, e in _secret_spans(text):
        chunk = text[last:s]
        if new_pos is None and pos < s:
            new_pos = length + (pos - last)
        out.append(chunk)
        length += len(chunk)
        if new_pos is None and s <= pos < e:
            new_pos = length
        repl = f"<redacted:{e - s} chars>"
        out.append(repl)
        length += len(repl)
        last = e
    if new_pos is None:
        new_pos = length + max(0, pos - last)
    out.append(text[last:])
    return "".join(out), new_pos


def redact(text: str) -> str:
    return redact_with_pos(text, 0)[0]


def clean(text: str) -> str:
    """Remove control and format characters (ANSI escapes, bidi overrides) and fold whitespace."""
    out = []
    for ch in text:
        if ch in "\r\n\t":
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf"):
            out.append("?")
        else:
            out.append(ch)
    return re.sub(r" {2,}", " ", "".join(out)).strip()


def trim(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def safe(text: str, limit: Optional[int] = None) -> str:
    value = clean(redact(text))
    return trim(value, limit) if limit else value


def redact_excerpt(text: str, start: int, end: int, width: int = MAX_EXCERPT) -> str:
    """Excerpt of at most `width` chars around text[start:end], redacted before cutting."""
    red, pos = redact_with_pos(text, start)
    mlen = max(1, min(end - start, width // 2))
    inner = width - 6
    lo = max(0, pos - (inner - mlen) // 2)
    hi = min(len(red), lo + inner)
    lo = max(0, hi - inner)
    piece = clean(red[lo:hi])
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(red) else ""
    return trim(prefix + piece + suffix, width)


# --------------------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------------------
_UTC = _dt.timezone.utc
_ISO_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
    r"\s*(Z|z|[+-]\d{2}:?\d{2})?\s*$")
_TS_FIELD_RE = re.compile(r'"timestamp"\s*:\s*"([^"]{10,40})"')


def parse_timestamp(value: Any) -> Optional[_dt.datetime]:
    """ISO 8601 string (naive = UTC) or epoch seconds/milliseconds -> aware UTC datetime."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        secs = value / 1000.0 if value > 1e11 else float(value)
        try:
            return _dt.datetime.fromtimestamp(secs, tz=_UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    m = _ISO_RE.match(value)
    if not m:
        return None
    y, mo, d, hh, mi, ss, frac, tz = m.groups()
    try:
        micro = int((frac or "0")[:6].ljust(6, "0"))
        tzinfo = _UTC
        if tz and tz not in ("Z", "z"):
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            offset = _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
            tzinfo = _dt.timezone(sign * offset)
        stamp = _dt.datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0),
                             micro, tzinfo=tzinfo)
        return stamp.astimezone(_UTC)
    except ValueError:
        return None


def parse_since(text: str, now: Optional[_dt.datetime] = None) -> _dt.datetime:
    """'24', '24h', '90m', '7d' (relative) or an ISO 8601 time (naive = UTC)."""
    now = now or _dt.datetime.now(tz=_UTC)
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([hHdDmM]?)\s*$", text)
    if m:
        amount = float(m.group(1))
        unit = (m.group(2) or "h").lower()
        delta = {"h": _dt.timedelta(hours=amount), "d": _dt.timedelta(days=amount),
                 "m": _dt.timedelta(minutes=amount)}[unit]
        return now - delta
    stamp = parse_timestamp(text)
    if stamp is None:
        raise UsageError(f"--since: cannot parse {text!r}; use hours (24, 24h), 7d, 90m or ISO 8601")
    return stamp


def iso(stamp: Optional[_dt.datetime]) -> Optional[str]:
    return stamp.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if stamp else None


def iso_ts(seconds: float) -> str:
    return _dt.datetime.fromtimestamp(seconds, tz=_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------
# Locations (verified against vendor docs on 2026-09-29; see SKILL.md "Limits")
# --------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, home: Path, project: Optional[Path], include_system: bool,
                 env: Optional[Dict[str, str]] = None) -> None:
        env = env or {}
        self.home = home
        self.project = project
        self.include_system = include_system
        self.env_used: Dict[str, str] = {}

        def pick(var: str, default: Path) -> Path:
            val = (env.get(var) or "").strip()
            if val:
                self.env_used[var] = val
                return Path(val).expanduser()
            return default

        self.claude = pick("CLAUDE_CONFIG_DIR", home / ".claude")
        self.codex = pick("CODEX_HOME", home / ".codex")
        self.config = pick("XDG_CONFIG_HOME", home / ".config")
        self.appdata = pick("APPDATA", home / "AppData" / "Roaming")
        self.state = pick("XDG_STATE_HOME", home / ".local" / "state")
        self.plugins = pick("CLAUDE_CODE_PLUGIN_CACHE_DIR", self.claude / "plugins")

    def reference_files(self) -> List[Path]:
        """Config, install-record and lock files that name installed skills and plugins."""
        files = [self.claude / "settings.json", self.claude / "settings.local.json",
                 self.home / ".claude.json", self.plugins / "installed_plugins.json",
                 self.plugins / "known_marketplaces.json",
                 self.plugins / "known_marketplaces_claudeai.json",
                 self.plugins / "flagged-plugins.json",
                 self.home / ".agents" / ".skill-lock.json",
                 self.state / "skills" / ".skill-lock.json",
                 self.codex / "config.toml", self.home / ".gemini" / "settings.json"]
        if self.project is not None:
            p = self.project
            files += [p / ".claude" / "settings.json", p / ".claude" / "settings.local.json",
                      p / ".mcp.json", p / "skills-lock.json", p / ".codex" / "config.toml",
                      p / ".gemini" / "settings.json", p / "opencode.json"]
        return files

    def display(self, path: Path) -> str:
        text = str(path)
        home = str(self.home)
        if text == home:
            return "~"
        if text.startswith(home.rstrip(os.sep) + os.sep):
            return "~" + os.sep + text[len(home.rstrip(os.sep)) + 1:]
        return text


class Loc:
    def __init__(self, lid: str, agent: str, scope: str, category: str, path: Path,
                 kind: str = "dir", max_depth: int = 12, exclude: Sequence[str] = (),
                 skill_search: bool = False, file_match: bool = False, note: str = "") -> None:
        self.lid, self.agent, self.scope, self.category = lid, agent, scope, category
        self.path, self.kind, self.max_depth = path, kind, max_depth
        self.exclude = tuple(exclude)
        self.skill_search, self.file_match = skill_search, file_match
        self.note = note


ROUTINE = "rewritten routinely by the agent: diff it, mtime alone is weak"


def _git_dirs(project: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """Return (hooks dir, config file) for a checkout, following a worktree .git file."""
    dot_git = project / ".git"
    if dot_git.is_dir():
        return dot_git / "hooks", dot_git / "config"
    if dot_git.is_file():
        try:
            first = dot_git.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        except (OSError, IndexError):
            return None, None
        if first.startswith("gitdir:"):
            gitdir = Path(first.split(":", 1)[1].strip())
            if not gitdir.is_absolute():
                gitdir = project / gitdir
            common = gitdir
            commondir = gitdir / "commondir"
            if commondir.is_file():
                try:
                    rel = commondir.read_text(encoding="utf-8", errors="replace").strip()
                    common = (gitdir / rel) if rel else gitdir
                except OSError:
                    pass
            return common / "hooks", common / "config"
    return None, None


def _nested_skill_dirs(project: Path, max_depth: int = 4) -> List[Path]:
    """Nested <dir>/.claude|.agents|.cursor|.gemini|.opencode|.github|.codex/skills below the root."""
    containers = {".claude", ".agents", ".cursor", ".gemini", ".opencode", ".github", ".codex"}
    found: List[Path] = []
    base_depth = len(project.parts)
    for dirpath, dirnames, _files in os.walk(project, followlinks=False):
        here = Path(dirpath)
        depth = len(here.parts) - base_depth
        keep = []
        for name in dirnames:
            if name in containers:
                skills = here / name / "skills"
                if depth >= 1 and skills.is_dir():
                    found.append(skills)
                continue
            if name in PROJECT_SKIP_DIRS or name.startswith("."):
                continue
            keep.append(name)
        dirnames[:] = keep if depth < max_depth else []
    return found


def build_catalog(ctx: Ctx) -> List[Loc]:
    H, C, X, CFG, AD, PL = ctx.home, ctx.claude, ctx.codex, ctx.config, ctx.appdata, ctx.plugins
    out: List[Loc] = []

    def add(*args: Any, **kw: Any) -> None:
        out.append(Loc(*args, **kw))

    # Claude Code: code.claude.com/docs skills, plugins/loading, settings, memory, mcp.
    add("cc-skills", "Claude Code", "user", "extension", C / "skills", skill_search=True, max_depth=5,
        note="synced/ is refreshed from claude.ai about every 10 minutes")
    add("cc-plugins", "Claude Code", "user", "extension", PL, skill_search=True, max_depth=8,
        note="includes auto-updates and plugin data/ dirs")
    add("cc-commands", "Claude Code", "user", "extension", C / "commands", file_match=True, max_depth=3)
    add("cc-agents", "Claude Code", "user", "extension", C / "agents", file_match=True, max_depth=3)
    add("cc-settings", "Claude Code", "user", "agent-config", C / "settings.json", "file")
    add("cc-settings-local", "Claude Code", "user", "agent-config", C / "settings.local.json", "file")
    add("cc-global-config", "Claude Code", "user", "agent-config", H / ".claude.json", "file", note=ROUTINE)
    add("cc-claude-md", "Claude Code", "user", "instructions", C / "CLAUDE.md", "file")
    add("cc-rules", "Claude Code", "user", "instructions", C / "rules")
    projects = C / "projects"
    if projects.is_dir():
        try:
            for child in sorted(projects.iterdir()):
                if (child / "memory").is_dir():
                    add("cc-auto-memory", "Claude Code", "user", "instructions", child / "memory")
        except OSError:
            pass
    # Claude Desktop MCP config (modelcontextprotocol.io "Connect to local MCP servers").
    add("claude-desktop", "Claude Desktop", "user", "agent-config",
        H / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "file")
    add("claude-desktop", "Claude Desktop", "user", "agent-config",
        AD / "Claude" / "claude_desktop_config.json", "file")
    # Shared Agent Skills dirs: Codex, Gemini CLI, Copilot, Cursor, OpenCode docs; vercel-labs/skills.
    add("agents-skills", "Codex/Gemini/Copilot/Cursor/OpenCode", "user", "extension",
        H / ".agents" / "skills", skill_search=True, max_depth=5)
    add("agents-skill-lock", "npx skills", "user", "extension", H / ".agents" / ".skill-lock.json", "file")
    add("agents-plugins", "Codex", "user", "extension", H / ".agents" / "plugins", max_depth=6)
    add("xdg-agents-skills", "npx skills (universal)", "user", "extension",
        CFG / "agents" / "skills", skill_search=True, max_depth=5)
    # Codex: developers.openai.com codex config, hooks, AGENTS.md, plugins.
    add("codex-skills", "Codex (npx skills) / Cursor", "user", "extension", X / "skills",
        skill_search=True, max_depth=5)
    add("codex-plugins", "Codex", "user", "extension", X / "plugins", skill_search=True, max_depth=8)
    add("codex-config", "Codex", "user", "agent-config", X / "config.toml", "file")
    add("codex-hooks", "Codex", "user", "agent-config", X / "hooks.json", "file")
    add("codex-agents-md", "Codex", "user", "instructions", X / "AGENTS.md", "file")
    add("codex-agents-md", "Codex", "user", "instructions", X / "AGENTS.override.md", "file")
    # Cursor: cursor.com/docs skills, mcp, hooks.
    add("cursor-skills", "Cursor", "user", "extension", H / ".cursor" / "skills", skill_search=True,
        max_depth=6)
    add("cursor-mcp", "Cursor", "user", "agent-config", H / ".cursor" / "mcp.json", "file")
    add("cursor-hooks", "Cursor", "user", "agent-config", H / ".cursor" / "hooks.json", "file")
    # Gemini CLI: geminicli.com skills, extensions, configuration, GEMINI.md.
    add("gemini-skills", "Gemini CLI", "user", "extension", H / ".gemini" / "skills", skill_search=True,
        max_depth=5)
    add("gemini-extensions", "Gemini CLI", "user", "extension", H / ".gemini" / "extensions",
        skill_search=True, max_depth=6)
    add("gemini-settings", "Gemini CLI", "user", "agent-config", H / ".gemini" / "settings.json", "file")
    add("gemini-md", "Gemini CLI", "user", "instructions", H / ".gemini" / "GEMINI.md", "file")
    # OpenCode: opencode.ai/docs skills, config.
    add("opencode-skills", "OpenCode", "user", "extension", CFG / "opencode" / "skills",
        skill_search=True, max_depth=5)
    add("opencode-plugins", "OpenCode", "user", "extension", CFG / "opencode" / "plugins", max_depth=5)
    add("opencode-config", "OpenCode", "user", "agent-config", CFG / "opencode" / "opencode.json", "file")
    # GitHub Copilot: docs.github.com "About agent skills".
    add("copilot-skills", "GitHub Copilot", "user", "extension", H / ".copilot" / "skills",
        skill_search=True, max_depth=5)
    # VS Code: settings.json per OS is documented; the user-profile mcp.json path next to it is
    # an assumption (docs name only "your user profile folder").
    for base in (CFG / "Code" / "User", H / "Library" / "Application Support" / "Code" / "User",
                 AD / "Code" / "User"):
        add("vscode-user", "VS Code", "user", "ide", base / "settings.json", "file")
        add("vscode-user", "VS Code", "user", "ide", base / "mcp.json", "file")
    add("vscode-extensions", "VS Code", "user", "ide", H / ".vscode" / "extensions", max_depth=1)
    # Shell startup files (bash, zsh, fish; PowerShell about_profiles).
    for rel in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
                ".zprofile", ".zlogin"):
        add("shell-rc", "shell", "user", "shell", H / rel, "file")
    add("fish-config", "fish", "user", "shell", CFG / "fish" / "config.fish", "file")
    add("fish-confd", "fish", "user", "shell", CFG / "fish" / "conf.d", max_depth=1)
    for rel in (("Documents", "PowerShell"), ("Documents", "WindowsPowerShell"),
                (".config", "powershell")):
        for name in ("Microsoft.PowerShell_profile.ps1", "profile.ps1"):
            add("powershell-profile", "PowerShell", "user", "shell", H.joinpath(*rel) / name, "file")
    # SSH and git user config.
    add("ssh-authorized-keys", "OpenSSH", "user", "ssh", H / ".ssh" / "authorized_keys", "file")
    add("ssh-config", "OpenSSH", "user", "ssh", H / ".ssh" / "config", "file")
    add("git-user-config", "git", "user", "git-config", H / ".gitconfig", "file")
    add("git-user-config", "git", "user", "git-config", CFG / "git" / "config", "file")
    # Autostart: launchd (Apple), systemd.unit(5), XDG autostart, Windows Startup folder.
    add("launch-agents", "macOS launchd", "user", "autostart", H / "Library" / "LaunchAgents", max_depth=2)
    add("systemd-user", "systemd", "user", "autostart", CFG / "systemd" / "user", max_depth=3)
    add("systemd-user", "systemd", "user", "autostart", H / ".local" / "share" / "systemd" / "user",
        max_depth=3)
    add("xdg-autostart", "XDG autostart", "user", "autostart", CFG / "autostart", max_depth=1)
    add("windows-startup", "Windows", "user", "autostart",
        AD / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", max_depth=1)

    P = ctx.project
    if P is not None:
        dc, dg, dcu = P / ".claude", P / ".agents", P / ".cursor"
        add("proj-cc-skills", "Claude Code", "project", "extension", dc / "skills", skill_search=True,
            max_depth=5)
        add("proj-cc-commands", "Claude Code", "project", "extension", dc / "commands", file_match=True,
            max_depth=3)
        add("proj-cc-agents", "Claude Code", "project", "extension", dc / "agents", file_match=True,
            max_depth=3)
        add("proj-cc-settings", "Claude Code", "project", "agent-config", dc / "settings.json", "file")
        add("proj-cc-settings", "Claude Code", "project", "agent-config", dc / "settings.local.json", "file")
        add("proj-mcp-json", "Claude Code / VS Code", "project", "agent-config", P / ".mcp.json", "file")
        add("proj-cc-marketplace", "Claude Code", "project", "extension", P / ".claude-plugin", max_depth=2)
        for name in ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md",
                     ".cursorrules"):
            add("proj-instructions", "agents", "project", "instructions", P / name, "file")
        add("proj-instructions", "Claude Code", "project", "instructions", dc / "CLAUDE.md", "file")
        add("proj-instructions", "Claude Code", "project", "instructions", dc / "rules")
        add("proj-instructions", "Cursor", "project", "instructions", dcu / "rules")
        add("proj-instructions", "GitHub Copilot", "project", "instructions",
            P / ".github" / "copilot-instructions.md", "file")
        add("proj-agents-skills", "Codex/Gemini/Copilot/Cursor/OpenCode", "project", "extension",
            dg / "skills", skill_search=True, max_depth=5)
        add("proj-agents-plugins", "Codex", "project", "extension", dg / "plugins", max_depth=6)
        add("proj-skills-lock", "npx skills", "project", "extension", P / "skills-lock.json", "file")
        add("proj-codex-skills", "Cursor (compat)", "project", "extension", P / ".codex" / "skills",
            skill_search=True, max_depth=5)
        add("proj-codex-config", "Codex", "project", "agent-config", P / ".codex" / "config.toml", "file")
        add("proj-codex-hooks", "Codex", "project", "agent-config", P / ".codex" / "hooks.json", "file")
        add("proj-cursor-skills", "Cursor", "project", "extension", dcu / "skills", skill_search=True,
            max_depth=6)
        add("proj-cursor-mcp", "Cursor", "project", "agent-config", dcu / "mcp.json", "file")
        add("proj-cursor-hooks", "Cursor", "project", "agent-config", dcu / "hooks.json", "file")
        add("proj-gemini-skills", "Gemini CLI", "project", "extension", P / ".gemini" / "skills",
            skill_search=True, max_depth=5)
        add("proj-gemini-settings", "Gemini CLI", "project", "agent-config",
            P / ".gemini" / "settings.json", "file")
        add("proj-opencode-skills", "OpenCode", "project", "extension", P / ".opencode" / "skills",
            skill_search=True, max_depth=5)
        add("proj-opencode-plugins", "OpenCode", "project", "extension", P / ".opencode" / "plugins",
            max_depth=5)
        add("proj-opencode-config", "OpenCode", "project", "agent-config", P / "opencode.json", "file")
        add("proj-github-skills", "GitHub Copilot", "project", "extension", P / ".github" / "skills",
            skill_search=True, max_depth=5)
        for name in ("settings.json", "mcp.json", "tasks.json"):
            add("proj-vscode", "VS Code", "project", "ide", P / ".vscode" / name, "file")
        hooks, gconf = _git_dirs(P)
        if hooks is not None:
            add("proj-git-hooks", "git", "project", "git-hook", hooks, max_depth=2, exclude=("*.sample",))
        if gconf is not None:
            add("proj-git-config", "git", "project", "git-config", gconf, "file")
        walk_nested = P != H and P.parent != P
        for nested in (_nested_skill_dirs(P) if walk_nested else []):
            add("proj-nested-skills", "agents", "project-nested", "extension", nested, skill_search=True,
                max_depth=5)

    if ctx.include_system:
        for base in (Path("/etc/claude-code"), Path("/Library/Application Support/ClaudeCode"),
                     Path("C:/Program Files/ClaudeCode")):
            add("cc-managed", "Claude Code (managed)", "system", "agent-config",
                base / "managed-settings.json", "file")
            add("cc-managed", "Claude Code (managed)", "system", "agent-config", base / "managed-settings.d",
                max_depth=2)
            add("cc-managed", "Claude Code (managed)", "system", "agent-config", base / "managed-mcp.json",
                "file")
            add("cc-managed", "Claude Code (managed)", "system", "instructions", base / "CLAUDE.md", "file")
            add("cc-managed-skills", "Claude Code (managed)", "system", "extension",
                base / ".claude" / "skills", skill_search=True, max_depth=5)
        add("codex-admin-skills", "Codex (admin)", "system", "extension", Path("/etc/codex/skills"),
            skill_search=True, max_depth=5)
        for base in (Path("/etc/gemini-cli"), Path("/Library/Application Support/GeminiCli"),
                     Path("C:/ProgramData/gemini-cli")):
            add("gemini-system", "Gemini CLI (system)", "system", "agent-config", base / "settings.json",
                "file")
            add("gemini-system", "Gemini CLI (system)", "system", "agent-config",
                base / "system-defaults.json", "file")
        for path in (Path("/etc/cursor/hooks.json"), Path("/Library/Application Support/Cursor/hooks.json"),
                     Path("C:/ProgramData/Cursor/hooks.json")):
            add("cursor-enterprise-hooks", "Cursor (enterprise)", "system", "agent-config", path, "file")
        for path in (Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"),
                     Path("/etc/systemd/user"), Path("/etc/xdg/autostart"), Path("/etc/cron.d"),
                     Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp")):
            add("system-autostart", "OS", "system", "autostart", path, max_depth=2)
        add("system-autostart", "cron", "system", "autostart", Path("/etc/crontab"), "file")
    return out


def _dedupe(locs: Sequence[Loc]) -> List[Loc]:
    seen: Set[Tuple[str, str]] = set()
    out: List[Loc] = []
    for loc in locs:
        try:
            key = (os.path.realpath(str(loc.path)), loc.category)
        except (OSError, ValueError):
            key = (str(loc.path), loc.category)
        if key in seen:
            continue
        seen.add(key)
        out.append(loc)
    return out


# --------------------------------------------------------------------------------------
# File helpers
# --------------------------------------------------------------------------------------
def _is_regular(path: Path) -> Optional[os.stat_result]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def sha256_file(path: Path) -> Optional[str]:
    st = _is_regular(path)
    if st is None or st.st_size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def frontmatter_name(skill_md: Path) -> Optional[str]:
    if _is_regular(skill_md) is None:
        return None
    try:
        with open(skill_md, encoding="utf-8", errors="replace") as fh:
            head = fh.read(16384)
    except OSError:
        return None
    lines = head.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for line in lines[1:300]:
        if line.strip() == "---":
            break
        m = re.match(r"^name\s*:\s*(.*?)\s*$", line)
        if m:
            value = re.sub(r"\s+#.*$", "", m.group(1)).strip().strip("\"'").strip()
            return value or None
    return None


def manifest_name(directory: Path) -> Optional[Tuple[str, str]]:
    for rel in MANIFESTS:
        path = directory / rel
        st = _is_regular(path)
        if st is None or st.st_size > 1024 * 1024:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            return data["name"], rel
    return None


def _is_unit(directory: Path) -> bool:
    if (directory / "SKILL.md").is_file():
        return True
    return any((directory / rel).is_file() for rel in MANIFESTS)


def _partial_eligible(path: Path, size: int) -> bool:
    return size >= MIN_PARTIAL_BYTES and path.name.lower() not in COMMON_FILES


# --------------------------------------------------------------------------------------
# find-skill
# --------------------------------------------------------------------------------------
def load_reference(path: Path) -> Dict[str, Any]:
    if path.is_file():
        if path.name != "SKILL.md":
            raise UsageError("reference path must be a skill/plugin directory or its SKILL.md")
        path = path.parent
    files: List[Tuple[str, str]] = []
    sizes: Set[int] = set()
    partial: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = sorted(n for n in dirnames if n not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            st = _is_regular(p)
            digest = sha256_file(p) if st else None
            if st is None or digest is None:
                continue
            files.append((p.relative_to(path).as_posix(), digest))
            if _partial_eligible(p, st.st_size):
                sizes.add(st.st_size)
                partial.add(digest)
    if not files:
        raise UsageError(f"reference copy has no readable files: {path}")
    names = {path.name.lower()}
    fm = frontmatter_name(path / "SKILL.md")
    if fm:
        names.add(fm.lower())
    man = manifest_name(path)
    if man:
        names.add(man[0].lower())
    return {"path": path, "files": files, "sizes": sizes, "partial": partial, "names": names,
            "tree": _tree_hash(files)}


def _tree_hash(files: Sequence[Tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    for rel, sha in sorted(files):
        digest.update(f"{rel}\0{sha}\n".encode("utf-8"))
    return digest.hexdigest()


def _unit_stats(path: Path, ref: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    target = Path(os.path.realpath(str(path))) if path.is_symlink() else path
    files: List[Tuple[str, str]] = []
    count = 0
    total = 0
    newest = 0.0
    newest_rel = ""
    truncated = False
    if target.is_file():
        walk: Iterator[Tuple[str, List[str], List[str]]] = iter([(str(target.parent), [], [target.name])])
        target = target.parent
    else:
        walk = os.walk(target, followlinks=False)
    for dirpath, dirnames, filenames in walk:
        dirnames[:] = sorted(n for n in dirnames if n not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                lst = os.lstat(p)
            except OSError:
                continue
            count += 1
            if lst.st_mtime > newest:
                newest, newest_rel = lst.st_mtime, p.relative_to(target).as_posix()
            st = _is_regular(p)
            if st is None:
                continue
            total += st.st_size
            if len(files) >= MAX_UNIT_FILES:
                truncated = True
                continue
            digest = sha256_file(p)
            if digest:
                files.append((p.relative_to(target).as_posix(), digest))
    result: Dict[str, Any] = {
        "file_count": count, "total_bytes": total,
        "newest_mtime": iso_ts(newest) if newest else None, "newest_file": newest_rel or None,
        "tree_sha256": None if truncated else _tree_hash(files), "hash_truncated": truncated,
        "identical_to_reference": False, "shared_files_with_reference": 0,
    }
    if ref is not None:
        mine = sorted(sha for _, sha in files)
        result["identical_to_reference"] = (not truncated) and mine == sorted(s for _, s in ref["files"])
        result["shared_files_with_reference"] = len(set(mine) & ref["partial"])
    return result


def _removal_hint(path: Path, ctx: Ctx, loc: Loc) -> Tuple[str, Optional[str]]:
    """Suggested containment step and the owning plugin/source, from where the copy lives."""
    def rel_parts(base: Path) -> Optional[Tuple[str, ...]]:
        try:
            return path.relative_to(base).parts
        except ValueError:
            return None

    parts = rel_parts(ctx.plugins)
    if parts:
        if parts[0] == "cache" and len(parts) >= 3:
            pid = f"{parts[2]}@{parts[1]}"
            return (f"Claude Code plugin {pid}: run claude plugin uninstall {pid} for each scope "
                    "(or /plugin), then confirm the cache folder is gone.", pid)
        if parts[0] == "synced" and len(parts) >= 2:
            pid = f"{parts[1]}@synced"
            return (f"Synced from claude.ai ({pid}): turn it off on claude.ai; run claude plugin "
                    f"disable {pid} meanwhile.", pid)
        if parts[0] == "marketplaces" and len(parts) >= 2:
            return (f"Inside marketplace clone {parts[1]}: run claude plugin marketplace remove "
                    f"{parts[1]} if the marketplace itself is untrusted.", parts[1])
        if parts[0] == ".trash":
            return ("Already unloaded by claude.ai sync (.trash); delete after evidence copy.", None)
        if parts[0] == "data" and len(parts) >= 2:
            return (f"Persistent data of plugin id {parts[1]}; remove after uninstall if it remains.", parts[1])
    parts = rel_parts(ctx.claude / "skills")
    if parts and parts[0] == "synced":
        return ("Synced from claude.ai: turn the skill off on claude.ai; a manual delete is "
                "re-downloaded while it stays enabled.", "claude.ai")
    if parts and parts[0] == ".trash":
        return ("Already unloaded by claude.ai sync (.trash); delete after evidence copy.", None)
    parts = rel_parts(ctx.codex / "plugins")
    if parts and parts[0] == "cache" and len(parts) >= 3:
        pid = f"{parts[2]}@{parts[1]}"
        return (f"Codex plugin {pid}: disable and uninstall it in Codex, then confirm the cache "
                "folder is gone.", pid)
    parts = rel_parts(ctx.home / ".gemini" / "extensions")
    if parts:
        return (f"Gemini CLI extension {parts[0]}: run gemini extensions uninstall {parts[0]}.", parts[0])
    if loc.lid in ("agents-skills", "xdg-agents-skills", "codex-skills", "cursor-skills",
                   "gemini-skills", "opencode-skills", "copilot-skills"):
        return ("Directory install (possibly npx skills); after evidence copy remove it with "
                "npx skills remove NAME -g or delete the folder, and every symlink to it.", None)
    return ("Delete this folder after the evidence copy and approval; check for symlinks to it.", None)


def _container(path: Path, root: Path) -> Optional[Dict[str, str]]:
    cur = path.parent
    while True:
        try:
            cur.relative_to(root)
        except ValueError:
            return None
        man = manifest_name(cur)
        if man:
            return {"path": str(cur), "manifest": man[1], "name": man[0]}
        if cur == root or cur.parent == cur:
            return None
        cur = cur.parent


def _scan_skill_root(loc: Loc, names: Set[str], ref: Optional[Dict[str, Any]],
                     budget: List[int]) -> Tuple[Dict[Path, Dict[str, Any]], List[Dict[str, Any]]]:
    root = loc.path
    cands: Dict[Path, Dict[str, Any]] = {}
    file_hits: List[Dict[str, Any]] = []
    base_depth = len(root.parts)
    unit_cache: Dict[Path, bool] = {}

    def install_slot(d: Path) -> bool:
        """Is `d` where an installer puts a skill or plugin (not a subfolder inside one)?"""
        if d.parent == root or d.parent.name.lower() in INSTALL_PARENTS:
            return True
        return d.parent.parent.name.lower() == "cache" or unit_cache.setdefault(d, _is_unit(d))

    def examine(d: Path, is_link: bool) -> None:
        reasons: Set[str] = set()
        fm = frontmatter_name(d / "SKILL.md")
        man = manifest_name(d)
        if d.name.lower() in names and install_slot(d):
            reasons.add("dir-name")
        if fm and fm.lower() in names:
            reasons.add("frontmatter-name")
        if man and man[0].lower() in names:
            reasons.add("manifest-name")
        if reasons:
            entry = cands.setdefault(d, {"reasons": set(), "symlink": is_link})
            entry["reasons"] |= reasons
            entry["frontmatter_name"] = fm
            entry["manifest_name"] = man[0] if man else None

    def unit_for(file_path: Path) -> Path:
        cur = file_path.parent
        while cur != root and len(cur.parts) > base_depth:
            if cur not in unit_cache:
                unit_cache[cur] = _is_unit(cur)
            if unit_cache[cur]:
                return cur
            cur = cur.parent
        rel = file_path.relative_to(root).parts
        return root / rel[0] if len(rel) > 1 else file_path

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        depth = len(here.parts) - base_depth
        keep = []
        for name in sorted(dirnames):
            if name in SKIP_DIRS:
                continue
            child = here / name
            is_link = child.is_symlink()
            examine(child, is_link)
            if not is_link:
                keep.append(name)
        dirnames[:] = keep if depth + 1 < loc.max_depth else []
        for name in sorted(filenames):
            budget[0] -= 1
            if budget[0] < 0:
                dirnames[:] = []
                break
            p = here / name
            if loc.file_match and p.suffix.lower() == ".md" and p.stem.lower() in names:
                file_hits.append({"path": p})
            if ref is None:
                continue
            st = _is_regular(p)
            if st is None or st.st_size not in ref["sizes"] or not _partial_eligible(p, st.st_size):
                continue
            digest = sha256_file(p)
            if digest and digest in ref["partial"]:
                unit = unit_for(p)
                entry = cands.setdefault(unit, {"reasons": set(), "symlink": unit.is_symlink()})
                entry["reasons"].add("hash-partial")
                entry.setdefault("frontmatter_name", frontmatter_name(unit / "SKILL.md"))
                man = manifest_name(unit) if unit.is_dir() else None
                entry.setdefault("manifest_name", man[0] if man else None)
    # Keep the outermost match; fold nested matches into it.
    kept: Dict[Path, Dict[str, Any]] = {}
    for path in sorted(cands, key=lambda p: len(p.parts)):
        parent = next((k for k in kept if k in path.parents), None)
        if parent is not None:
            kept[parent].setdefault("nested", []).append(str(path))
            kept[parent]["reasons"] |= {r for r in cands[path]["reasons"] if r != "dir-name"}
            for key in ("frontmatter_name", "manifest_name"):
                if not kept[parent].get(key) and cands[path].get(key):
                    kept[parent][key] = cands[path][key]
            continue
        kept[path] = cands[path]
    return kept, file_hits


def cmd_find_skill(args: argparse.Namespace, ctx: Ctx) -> Dict[str, Any]:
    target = args.name_or_path
    ref: Optional[Dict[str, Any]] = None
    candidate_path = Path(target).expanduser()
    if candidate_path.exists():
        ref = load_reference(candidate_path)
        names = set(ref["names"])
    else:
        if "/" in target or "\\" in target:
            raise UsageError(f"path not found: {target}")
        name = target.strip()
        names = set()
        if "@" in name:
            # Claude Code plugin id NAME@MARKETPLACE; its data dir is the id with every character
            # other than a letter, digit, _ or - replaced by - (plugins manifest reference).
            names.add(re.sub(r"[^A-Za-z0-9_\-]", "-", name).lower())
            name = name.split("@", 1)[0]
        if not name:
            raise UsageError("empty skill name")
        names.add(name.lower())
    locs = _dedupe([loc for loc in build_catalog(ctx) if loc.skill_search or loc.file_match])
    for extra in args.extra_root or []:
        locs.append(Loc("extra-root", "user-supplied", "extra", "extension", Path(extra).expanduser(),
                        skill_search=True, file_match=True, max_depth=8))
    budget = [args.max_files]
    records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    scanned: List[Dict[str, Any]] = []
    notes: List[str] = []
    for loc in locs:
        present = loc.path.is_dir()
        scanned.append({"location": ctx.display(loc.path), "agent": loc.agent, "scope": loc.scope,
                        "present": present})
        if not present:
            continue
        cands, file_hits = _scan_skill_root(loc, names, ref, budget)
        for path, info in cands.items():
            stats = _unit_stats(path, ref)
            reasons = set(info["reasons"])
            if stats["identical_to_reference"]:
                reasons.add("hash-identical")
                reasons.discard("hash-partial")
            elif stats["shared_files_with_reference"]:
                reasons.add("hash-partial")
            hint, owner = _removal_hint(path, ctx, loc)
            container = _container(path, loc.path)
            is_ref = ref is not None and os.path.realpath(str(path)) == os.path.realpath(str(ref["path"]))
            record = {
                "path": str(path), "display": ctx.display(path), "agent": loc.agent, "scope": loc.scope,
                "location_id": loc.lid, "matched_by": sorted(reasons),
                "frontmatter_name": info.get("frontmatter_name"),
                "manifest_name": info.get("manifest_name"),
                "symlink_target": os.path.realpath(str(path)) if info.get("symlink") else None,
                "container": container, "owner": owner, "is_reference": is_ref,
                "nested_matches": info.get("nested", []), "removal_hint": hint,
            }
            record.update(stats)
            records.append(record)
            if "hash-identical" in reasons:
                cid = "AIR003"
            elif reasons & {"frontmatter-name", "manifest-name"} and "dir-name" not in reasons:
                cid = "AIR002"
            elif reasons & {"dir-name", "frontmatter-name", "manifest-name"}:
                cid = "AIR001"
            else:
                cid = "AIR004"
            evidence = (f"matched_by={','.join(sorted(reasons))}; files={stats['file_count']}; "
                        f"newest_mtime={stats['newest_mtime']}; agent={loc.agent}")
            if record["symlink_target"]:
                evidence += "; symlink"
            if stats["shared_files_with_reference"] and cid != "AIR003":
                evidence += f"; shared_files={stats['shared_files_with_reference']}"
            findings.append(make_finding(cid, ctx.display(path), evidence, fix=hint))
        for hit in file_hits:
            p = hit["path"]
            try:
                mtime = iso_ts(os.lstat(p).st_mtime)
            except OSError:
                mtime = None
            records.append({"path": str(p), "display": ctx.display(p), "agent": loc.agent,
                            "scope": loc.scope, "location_id": loc.lid, "matched_by": ["file-name"],
                            "file_count": 1, "newest_mtime": mtime})
            findings.append(make_finding("AIR005", ctx.display(p),
                                         f"matched_by=file-name; mtime={mtime}; agent={loc.agent}"))
    if budget[0] < 0:
        notes.append(f"Stopped after --max-files={args.max_files} files; results may be incomplete.")
    config_refs = _config_references(ctx, names)
    for ref_hit in config_refs:
        lines_txt = ", ".join(str(n) for n in ref_hit["lines"][:10])
        findings.append(make_finding(
            "AIR008", ref_hit["display"],
            f"{ref_hit['occurrences']} occurrence(s) on line(s) {lines_txt}"))
    copies = [r for r in records if r.get("tree_sha256") and
              set(r["matched_by"]) & {"dir-name", "frontmatter-name", "manifest-name", "hash-identical"}]
    variants = sorted({r["tree_sha256"] for r in copies})
    if len(variants) > 1:
        findings.append(make_finding(
            "AIR006", f"{len(copies)} copies",
            f"{len(variants)} distinct content trees across {len(copies)} copies; compare tree_sha256 "
            "in --json output"))
    if not records:
        present = sum(1 for s in scanned if s["present"])
        findings.append(make_finding("AIR007", f"{present} of {len(scanned)} locations present",
                                     f"names={','.join(sorted(names))}"))
    reference = None
    if ref is not None:
        reference = {"path": str(ref["path"]), "names": sorted(ref["names"]),
                     "file_count": len(ref["files"]), "tree_sha256": ref["tree"],
                     "files": [{"path": r, "sha256": s} for r, s in ref["files"]]}
    return report("find-skill", target, findings, records=records, scanned=scanned, notes=notes,
                  extra={"reference": reference, "names": sorted(names),
                         "config_references": config_refs})


def _config_references(ctx: Ctx, names: Set[str]) -> List[Dict[str, Any]]:
    """Line numbers where a name appears as a whole token. Contents are never returned."""
    if not names:
        return []
    alternation = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    rx = re.compile(r"(?<![A-Za-z0-9_\-])(?:" + alternation + r")(?![A-Za-z0-9_\-])", re.IGNORECASE)
    hits: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for path in ctx.reference_files():
        st = _is_regular(path)
        real = os.path.realpath(str(path))
        if st is None or st.st_size > MAX_HASH_BYTES or real in seen:
            continue
        seen.add(real)
        lines: List[int] = []
        count = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for number, line in enumerate(fh, 1):
                    found = len(rx.findall(line))
                    if found:
                        count += found
                        lines.append(number)
        except OSError:
            continue
        if count:
            hits.append({"path": str(path), "display": ctx.display(path), "occurrences": count,
                         "lines": lines})
    return hits


# --------------------------------------------------------------------------------------
# recent-changes
# --------------------------------------------------------------------------------------
def _group_key(root: Path, path: Path) -> Path:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return path
    if not parts:
        return root
    depth = 1
    if parts[0] == "cache":
        depth = 3
    elif parts[0] in ("synced", ".trash", "marketplaces", "data"):
        depth = 2
    return root.joinpath(*parts[:depth])


def _walk_changed(loc: Loc, since_ts: float, use_ctime: bool, budget: List[int]
                  ) -> Iterator[Tuple[Path, os.stat_result, str]]:
    root = loc.path

    def changed(st: os.stat_result) -> bool:
        return st.st_mtime >= since_ts or (use_ctime and st.st_ctime >= since_ts)

    if loc.kind == "file":
        try:
            st = os.lstat(root)
        except OSError:
            return
        if changed(st):
            yield root, st, "symlink" if stat.S_ISLNK(st.st_mode) else "file"
        return
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        depth = len(here.parts) - base_depth
        try:
            st = os.lstat(here)
            if changed(st):
                yield here, st, "dir"
        except OSError:
            pass
        keep = []
        descend = depth + 1 < loc.max_depth
        for name in sorted(dirnames):
            child = here / name
            if name in SKIP_DIRS or any(fnmatch.fnmatch(name, pat) for pat in loc.exclude):
                continue
            is_link = child.is_symlink()
            if is_link or not descend:
                # Not walked: report the entry itself (new extension folder, symlinked skill).
                try:
                    lst = os.lstat(child)
                except OSError:
                    continue
                if changed(lst):
                    yield child, lst, "symlink" if is_link else "dir"
                continue
            keep.append(name)
        dirnames[:] = keep
        if depth + 1 > loc.max_depth:
            continue
        for name in sorted(filenames):
            if any(fnmatch.fnmatch(name, pat) for pat in loc.exclude):
                continue
            budget[0] -= 1
            if budget[0] < 0:
                dirnames[:] = []
                return
            p = here / name
            try:
                lst = os.lstat(p)
            except OSError:
                continue
            if changed(lst):
                yield p, lst, "symlink" if stat.S_ISLNK(lst.st_mode) else "file"


def cmd_recent_changes(args: argparse.Namespace, ctx: Ctx) -> Dict[str, Any]:
    since = parse_since(args.since)
    since_ts = since.timestamp()
    locs = _dedupe(build_catalog(ctx))
    budget = [args.max_files]
    records: List[Dict[str, Any]] = []
    scanned: List[Dict[str, Any]] = []
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    seen: Set[str] = set()
    notes: List[str] = []
    if since > _dt.datetime.now(tz=_UTC):
        notes.append("--since is in the future; nothing can match.")
    for loc in locs:
        present = loc.path.exists() or loc.path.is_symlink()
        scanned.append({"location": ctx.display(loc.path), "agent": loc.agent, "scope": loc.scope,
                        "category": loc.category, "present": present})
        if not present:
            continue
        for path, st, kind in _walk_changed(loc, since_ts, args.use_ctime, budget):
            real = os.path.realpath(str(path)) if kind != "symlink" else str(path)
            if real in seen:
                continue
            seen.add(real)
            rec = {"mtime": iso_ts(st.st_mtime), "size": st.st_size if kind == "file" else None,
                   "path": str(path), "display": ctx.display(path), "type": kind,
                   "category": loc.category, "agent": loc.agent, "scope": loc.scope,
                   "location_id": loc.lid}
            if args.use_ctime:
                rec["ctime"] = iso_ts(st.st_ctime)
                rec["ctime_only"] = st.st_mtime < since_ts <= st.st_ctime
            if kind == "symlink":
                try:
                    rec["symlink_target"] = os.readlink(path)
                except OSError:
                    rec["symlink_target"] = None
            records.append(rec)
            key_path = path if loc.kind == "file" else _group_key(loc.path, path)
            group = groups.setdefault((loc.category, str(key_path)), {
                "loc": loc, "path": key_path, "count": 0, "newest": 0.0, "newest_path": path,
                "ctime_only": 0})
            group["count"] += 1
            if st.st_mtime >= group["newest"]:
                group["newest"], group["newest_path"] = st.st_mtime, path
            if rec.get("ctime_only"):
                group["ctime_only"] += 1
            if loc.note:
                rec["note"] = loc.note
    if budget[0] < 0:
        notes.append(f"Stopped after --max-files={args.max_files} entries; results may be incomplete.")
    findings: List[Dict[str, Any]] = []
    busy_roots = {str(g["loc"].path) for g in groups.values() if g["path"] != g["loc"].path}
    for (category, _), group in sorted(groups.items(), key=lambda kv: -kv[1]["newest"]):
        loc = group["loc"]
        if loc.kind == "dir" and group["path"] == loc.path and str(loc.path) in busy_roots:
            continue  # the root folder's own mtime moved because of a change reported below it
        try:
            rel = group["newest_path"].relative_to(group["path"]).as_posix()
        except ValueError:
            rel = ""
        evidence = f"{group['count']} changed; newest {iso_ts(group['newest'])}"
        if rel and rel != ".":
            evidence += f" {rel}"
        if group["ctime_only"]:
            evidence += f"; {group['ctime_only']} with ctime after window but older mtime (check timestomping)"
        evidence += f"; {loc.agent}"
        if loc.note:
            evidence += f"; {loc.note}"
        findings.append(make_finding(CATEGORY_CHECK[category], ctx.display(group["path"]), evidence))
    for label, command, why in MANUAL_CHECKS:
        findings.append(make_finding("AIR019", label, why, fix=f"Run: {command}"))
    records.sort(key=lambda r: r["mtime"], reverse=True)
    truncated = len(records) > args.limit
    if truncated:
        notes.append(f"Showing the {args.limit} newest of {len(records)} changed entries (--limit).")
    return report("recent-changes", f"since {iso(since)}", findings, records=records[: args.limit],
                  scanned=scanned, notes=notes,
                  extra={"since": iso(since), "changed_entries": len(records)})


# --------------------------------------------------------------------------------------
# search-sessions
# --------------------------------------------------------------------------------------
def _leaves(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _leaves(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _leaves(value)
    elif isinstance(obj, str):
        yield obj


def _match_sites(rec: Any, rx: "re.Pattern[str]") -> List[Tuple[str, str, "re.Match[str]"]]:
    sites: List[Tuple[str, str, "re.Match[str]"]] = []
    if not isinstance(rec, dict):
        for leaf in _leaves(rec):
            m = rx.search(leaf)
            if m:
                sites.append(("other", leaf, m))
        return sites
    msg = rec.get("message")
    if isinstance(msg, dict):
        content = msg.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
        if isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                site = btype if btype in ("tool_use", "tool_result", "text", "thinking") else "other"
                for leaf in _leaves(block):
                    m = rx.search(leaf)
                    if m:
                        sites.append((site, leaf, m))
        for key, value in msg.items():
            if key == "content":
                continue
            for leaf in _leaves(value):
                m = rx.search(leaf)
                if m:
                    sites.append(("metadata", leaf, m))
    for key, value in rec.items():
        if key == "message":
            continue
        site = {"toolUseResult": "tool_result", "attachment": "attachment"}.get(key, "metadata")
        for leaf in _leaves(value):
            m = rx.search(leaf)
            if m:
                sites.append((site, leaf, m))
    return sites


def _blocks(rec: Any) -> List[Dict[str, Any]]:
    if not isinstance(rec, dict):
        return []
    msg = rec.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def _transcript_files(roots: Sequence[Path]) -> Iterator[Tuple[Path, Path, str]]:
    """Yield (root, path, kind): kind 'jsonl' for transcripts, 'spill' for large tool outputs
    Claude Code writes to <session>/tool-results/ instead of inlining them."""
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(n for n in dirnames if n != "memory")
            in_spill = Path(dirpath).name == "tool-results"
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.is_symlink() or _is_regular(p) is None:
                    continue
                if name.endswith(".jsonl") or re.search(r"\.jsonl\.superseded-", name):
                    yield root, p, "jsonl"
                elif in_spill and (_is_regular(p).st_size <= MAX_HASH_BYTES):  # type: ignore[union-attr]
                    yield root, p, "spill"


def _project_dir(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root).parts
        return rel[0] if len(rel) > 1 else root.name
    except ValueError:
        return path.parent.name


def _scan_spill(path: Path, root: Path, rx: "re.Pattern[str]", since: Optional[_dt.datetime],
                id_to_name: Dict[str, str], max_excerpts: int) -> Optional[Dict[str, Any]]:
    count = 0
    excerpts: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = rx.search(line)
                if not m:
                    continue
                count += 1
                if len(excerpts) < max_excerpts:
                    ex = redact_excerpt(line, m.start(), m.end())
                    if ex not in excerpts:
                        excerpts.append(ex)
    except OSError:
        return None
    if not count:
        return None
    try:
        mtime = _dt.datetime.fromtimestamp(os.stat(path).st_mtime, tz=_UTC)
    except OSError:
        mtime = None
    if since is not None and mtime is not None and mtime < since:
        return None
    tool_id = path.stem
    tool = safe(id_to_name.get(tool_id, "unknown-tool"), 80)
    session_dir = path.parent.parent
    return {
        "session_id": safe(session_dir.name, 80), "agent_id": None, "is_subagent": False,
        "project_dir": safe(_project_dir(path, root), 200), "cwd": None, "transcript": str(path),
        "display": "",
        "kind": "spilled-tool-output", "tool_use_id": tool_id,
        "first_timestamp": iso(mtime), "last_timestamp": iso(mtime),
        "first_match": None, "last_match": None, "matching_lines": count,
        "tool_names": {tool: count}, "match_in": {"tool_result": count}, "excerpts": excerpts,
        "unparsed_matching_lines": 0,
    }


def _scan_transcript(path: Path, root: Path, rx: "re.Pattern[str]", since: Optional[_dt.datetime],
                     max_excerpts: int, id_to_name: Optional[Dict[str, str]] = None
                     ) -> Optional[Dict[str, Any]]:
    """Search decoded JSON string values (not raw JSON text), so escapes do not hide matches."""
    if id_to_name is None:
        id_to_name = {}
    matches: List[Dict[str, Any]] = []
    first_ts: Optional[_dt.datetime] = None
    last_ts: Optional[_dt.datetime] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    cwd: Optional[str] = None
    unparsed = 0
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return None
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec: Any = json.loads(line)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                line_ts = parse_timestamp(rec.get("timestamp"))
                if session_id is None and isinstance(rec.get("sessionId"), str):
                    session_id = rec["sessionId"]
                if agent_id is None and isinstance(rec.get("agentId"), str):
                    agent_id = rec["agentId"]
                if cwd is None and isinstance(rec.get("cwd"), str):
                    cwd = rec["cwd"]
            else:
                m_ts = _TS_FIELD_RE.search(line)
                line_ts = parse_timestamp(m_ts.group(1)) if m_ts else None
            if line_ts:
                first_ts = line_ts if first_ts is None or line_ts < first_ts else first_ts
                last_ts = line_ts if last_ts is None or line_ts > last_ts else last_ts
            blocks = _blocks(rec)
            for block in blocks:
                if block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                    id_to_name[block["id"]] = str(block.get("name") or "?")
            if rec is not None:
                sites = _match_sites(rec, rx)
            else:
                hit = rx.search(line)
                sites = [("raw", line, hit)] if hit else []
                unparsed += 1 if hit else 0
            if not sites:
                continue
            tools: List[str] = []
            for block in blocks:
                if block.get("type") == "tool_use":
                    tools.append(safe(str(block.get("name") or "?"), 80))
                elif block.get("type") == "tool_result":
                    tools.append(safe(id_to_name.get(str(block.get("tool_use_id")), "unknown-tool"), 80))
            _site, text, m = sites[0]
            site_names = sorted({s for s, _, _ in sites})
            excerpt = redact_excerpt(text, m.start(), m.end()) if len(matches) < 200 else None
            matches.append({"ts": line_ts, "tools": tools, "sites": site_names, "excerpt": excerpt})
    if not matches:
        return None
    if since is not None:
        session_recent = last_ts is not None and last_ts >= since
        matches = [m for m in matches
                   if (m["ts"] is not None and m["ts"] >= since) or (m["ts"] is None and session_recent)]
        if not matches:
            return None
    tool_counts: Dict[str, int] = {}
    site_counts: Dict[str, int] = {}
    for m in matches:
        for name in m["tools"]:
            tool_counts[name] = tool_counts.get(name, 0) + 1
        for s in m["sites"]:
            site_counts[s] = site_counts.get(s, 0) + 1
    excerpts: List[str] = []
    for m in matches:
        if m["excerpt"] and m["excerpt"] not in excerpts:
            excerpts.append(m["excerpt"])
        if len(excerpts) >= max_excerpts:
            break
    stamps = [m["ts"] for m in matches if m["ts"] is not None]
    return {
        "session_id": safe(session_id or path.name.split(".")[0], 80),
        "agent_id": safe(agent_id, 80) if agent_id else None, "is_subagent": "subagents" in path.parts,
        "project_dir": safe(_project_dir(path, root), 200), "cwd": safe(cwd, 300) if cwd else None,
        "transcript": str(path), "display": "",
        "kind": "transcript", "tool_use_id": None,
        "first_timestamp": iso(first_ts), "last_timestamp": iso(last_ts),
        "first_match": iso(min(stamps)) if stamps else None,
        "last_match": iso(max(stamps)) if stamps else None,
        "matching_lines": len(matches), "tool_names": dict(sorted(tool_counts.items())),
        "match_in": dict(sorted(site_counts.items())), "excerpts": excerpts,
        "unparsed_matching_lines": unparsed,
    }


def _is_action_tool(name: str) -> bool:
    return name in ACTION_TOOLS or name.startswith("mcp__")


def cmd_search_sessions(args: argparse.Namespace, ctx: Ctx) -> Dict[str, Any]:
    pattern = args.pattern
    if not pattern:
        raise UsageError("empty pattern")
    flags = re.IGNORECASE if args.ignore_case else 0
    try:
        rx = re.compile(pattern if args.regex else re.escape(pattern), flags)
    except re.error as exc:
        raise UsageError(f"invalid regex: {exc}")
    since = parse_since(args.since) if args.since else None
    roots = [ctx.claude / "projects"] + [Path(p).expanduser() for p in (args.transcripts or [])]
    scanned = [{"location": ctx.display(r), "present": r.is_dir()} for r in roots]
    records: List[Dict[str, Any]] = []
    files = 0
    id_to_name: Dict[str, str] = {}
    spills: List[Tuple[Path, Path]] = []
    for root, path, kind in _transcript_files(roots):
        files += 1
        if kind == "spill":
            spills.append((root, path))
            continue
        rec = _scan_transcript(path, root, rx, since, args.max_excerpts, id_to_name)
        if rec is not None:
            records.append(rec)
    for root, path in spills:
        rec = _scan_spill(path, root, rx, since, id_to_name, args.max_excerpts)
        if rec is not None:
            records.append(rec)
    for rec in records:
        rec["display"] = ctx.display(Path(rec["transcript"]))
    records.sort(key=lambda r: (r["first_match"] or r["first_timestamp"] or "", r["transcript"]))
    findings: List[Dict[str, Any]] = []
    for rec in records:
        actions = [n for n in rec["tool_names"] if _is_action_tool(n)]
        cid = "AIR030" if actions else "AIR031"
        tools = ",".join(f"{n}:{c}" for n, c in rec["tool_names"].items()) or "none"
        evidence = (f"session={rec['session_id'][:13]} lines={rec['matching_lines']} tools={tools} "
                    f"first={rec['first_match'] or rec['first_timestamp']}")
        findings.append(make_finding(cid, rec["display"], evidence))
    notes = [f"Searched {files} transcript and spilled tool-output files."]
    return report("search-sessions", pattern, findings, records=records, scanned=scanned, notes=notes,
                  extra={"since": iso(since), "regex": bool(args.regex),
                         "ignore_case": bool(args.ignore_case)})


# --------------------------------------------------------------------------------------
# Report plumbing
# --------------------------------------------------------------------------------------
def make_finding(cid: str, location: str, evidence: str, fix: Optional[str] = None) -> Dict[str, Any]:
    check = CHECKS[cid]
    return {"id": cid, "severity": check["severity"], "title": check["title"],
            "location": safe(location), "evidence": safe(evidence, MAX_EVIDENCE),
            "fix": safe(fix or check["fix"]), "refs": list(check["refs"])}


def report(command: str, target: str, findings: List[Dict[str, Any]], records: List[Dict[str, Any]],
           scanned: List[Dict[str, Any]], notes: List[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    findings.sort(key=lambda f: (_SEV_RANK[f["severity"]], f["id"], f["location"]))
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f["severity"]] += 1
    out: Dict[str, Any] = {
        "tool": TOOL, "version": VERSION, "target": safe(target),
        "generated_at": _dt.datetime.now(tz=_UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": findings, "summary": summary, "command": command,
        "records": records, "scanned": scanned, "notes": notes,
    }
    out.update(extra)
    return out


def render_text(rep: Dict[str, Any], quiet: bool) -> str:
    s = rep["summary"]
    counts = ", ".join(f"{k} {s[k]}" for k in SEVERITIES)
    header = f"{rep['tool']} {rep['command']}  target: {rep['target']}  findings: {len(rep['findings'])} ({counts})"
    present = sum(1 for x in rep["scanned"] if x.get("present"))
    if rep["command"] == "find-skill":
        tail = f"{len(rep['records'])} item(s) found; scanned {present} present of {len(rep['scanned'])} locations."
    elif rep["command"] == "recent-changes":
        tail = (f"{rep['changed_entries']} changed entries since {rep['since']}; "
                f"scanned {present} present of {len(rep['scanned'])} locations.")
    else:
        tail = f"{len(rep['records'])} matching session transcript(s). {' '.join(rep['notes'])}"
    if quiet:
        return tail
    lines = [header, ""]
    by_path = {r.get("display"): r for r in rep["records"]}
    for f in rep["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['id']}  {f['title']}")
        lines.append(f"  at {f['location']}")
        lines.append(f"  evidence: {f['evidence']}")
        lines.append(f"  fix: {f['fix']}")
        rec = by_path.get(f["location"])
        if rep["command"] == "search-sessions" and rec:
            tools = ", ".join(f"{n} x{c}" for n, c in rec["tool_names"].items()) or "none"
            lines.append(f"  session: {clean(rec['session_id'])}  project: {clean(rec['project_dir'])}"
                         f"{'  subagent: ' + clean(str(rec['agent_id'])) if rec['is_subagent'] else ''}")
            lines.append(f"  span: {rec['first_timestamp']} .. {rec['last_timestamp']}  "
                         f"matching lines: {rec['matching_lines']}  match in: "
                         + ", ".join(f"{k} x{v}" for k, v in rec["match_in"].items()))
            lines.append(f"  tools on matching lines: {clean(tools)}")
            for ex in rec["excerpts"]:
                lines.append(f"  excerpt: {ex}")
        elif rep["command"] == "find-skill" and rec and rec.get("symlink_target"):
            lines.append(f"  symlink to: {clean(rec['symlink_target'])}")
        lines.append("")
    if rep["command"] == "recent-changes" and rep["records"]:
        lines.append(f"Changed entries since {rep['since']} (mtime UTC, size, path):")
        for r in rep["records"]:
            size = "-" if r["size"] is None else str(r["size"])
            extra = f"  [{r['type']}]" if r["type"] != "file" else ""
            lines.append(f"  {r['mtime']}  {size:>9}  {clean(r['display'])}{extra}")
        lines.append("")
    for note in rep["notes"]:
        if rep["command"] != "search-sessions":
            lines.append(f"note: {note}")
    lines.append(tail)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", help="home directory to inspect (default: current user's home; "
                        "when set, CLAUDE_CONFIG_DIR, CODEX_HOME, XDG_CONFIG_HOME, APPDATA and "
                        "CLAUDE_CODE_PLUGIN_CACHE_DIR are ignored)")
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")
    common.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        help="exit 2 if any finding is at or above this severity")
    common.add_argument("--quiet", action="store_true", help="print only the summary line")
    common.add_argument("--max-files", type=int, default=200000,
                        help="stop walking after this many files (default 200000)")
    project = argparse.ArgumentParser(add_help=False)
    project.add_argument("--project", help="project directory to include (default: current directory)")
    project.add_argument("--no-project", action="store_true", help="skip project locations")
    project.add_argument("--include-system", action="store_true",
                         help="also scan system-wide managed config, admin skills and autostart dirs")
    parser = _Parser(prog="locate_agent_artifacts.py",
                     description="Read-only locator for incident response on AI agent setups.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    fs = sub.add_parser("find-skill", parents=[common, project],
                        help="find every installed copy of a skill or plugin")
    fs.add_argument("name_or_path", help="skill/plugin name, or path to a reference copy (dir or SKILL.md)")
    fs.add_argument("--extra-root", action="append", metavar="DIR",
                    help="additional skill directory to scan (repeatable)")
    rc = sub.add_parser("recent-changes", parents=[common, project],
                        help="list files changed since a time in persistence and config locations")
    rc.add_argument("--since", required=True,
                    help="hours (24 or 24h), minutes (90m), days (7d) or ISO 8601 (naive = UTC)")
    rc.add_argument("--use-ctime", action="store_true",
                    help="also flag entries whose inode change time is in the window (POSIX)")
    rc.add_argument("--limit", type=int, default=2000, help="max changed entries to list (default 2000)")
    ss = sub.add_parser("search-sessions", parents=[common],
                        help="search Claude Code transcripts for a string or regex")
    ss.add_argument("pattern", help="literal string (default) or regex with --regex")
    ss.add_argument("--regex", action="store_true", help="treat PATTERN as a Python regex")
    ss.add_argument("-i", "--ignore-case", action="store_true", help="case-insensitive match")
    ss.add_argument("--since", help="only matches at or after this time (same formats as recent-changes)")
    ss.add_argument("--transcripts", action="append", metavar="DIR",
                    help="additional directory of .jsonl transcripts to search (repeatable)")
    ss.add_argument("--max-excerpts", type=int, default=3,
                    help=f"redacted excerpts per session, each at most {MAX_EXCERPT} chars (default 3)")
    return parser


def make_ctx(args: argparse.Namespace, environ: Optional[Dict[str, str]] = None) -> Ctx:
    if args.home:
        home = Path(args.home).expanduser()
        if not home.is_dir():
            raise UsageError(f"--home is not a directory: {args.home}")
        env: Dict[str, str] = {}
    else:
        home = Path.home()
        env = dict(os.environ if environ is None else environ)
    project: Optional[Path] = None
    if not getattr(args, "no_project", True):
        project = Path(args.project).expanduser() if getattr(args, "project", None) else Path.cwd()
        if not project.is_dir():
            raise UsageError(f"--project is not a directory: {project}")
    return Ctx(home.absolute(), project.absolute() if project else None,
               bool(getattr(args, "include_system", False)), env)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        ctx = make_ctx(args)
        if args.command == "find-skill":
            rep = cmd_find_skill(args, ctx)
        elif args.command == "recent-changes":
            rep = cmd_recent_changes(args, ctx)
        else:
            rep = cmd_search_sessions(args, ctx)
    except UsageError as exc:
        sys.stderr.write(f"error: {safe(str(exc))}\n")
        return 1
    except OSError as exc:
        sys.stderr.write(f"error: {safe(str(exc))}\n")
        return 1
    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=False))
    else:
        print(render_text(rep, args.quiet))
    if args.fail_on:
        limit = _SEV_RANK[args.fail_on]
        if any(_SEV_RANK[f["severity"]] <= limit for f in rep["findings"]):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
