#!/usr/bin/env python3
"""Validate the skills and plugin marketplace in this repository.

Checks every ``skills/<name>/SKILL.md`` against the Agent Skills specification
(https://agentskills.io/specification) and the rules in CONTRIBUTING.md, and
checks ``.claude-plugin/marketplace.json`` against the Claude Code marketplace
reference (https://code.claude.com/docs/en/plugins/marketplace-reference).

Standard library only (Python 3.9+). When PyYAML is importable it is used as
the authoritative YAML parser and the built-in parser checks that the
frontmatter stays inside a portable YAML subset (plain and quoted scalars,
folded and literal blocks, one-level ``metadata:`` map). Without PyYAML the
built-in parser is used on its own.

Exit codes: 0 = no errors (and no warnings under --strict), 1 = errors found
(or warnings under --strict), 2 = usage error.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote

try:  # Optional dependency: used only to double-check frontmatter.
    import yaml as _yaml  # type: ignore
except Exception:  # pragma: no cover - depends on the environment
    _yaml = None

TOOL_VERSION = "0.1.0"
DEFAULT_ROOT = Path(__file__).resolve().parent.parent

# Agent Skills spec fields. CONTRIBUTING.md: anything else breaks claude.ai uploads.
ALLOWED_KEYS = ("name", "description", "license", "compatibility", "metadata", "allowed-tools")
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NAME_MAX = 64
FORBIDDEN_NAME_WORDS = ("claude", "anthropic")
DESC_MAX = 1024  # spec: error
DESC_WARN = 500  # CONTRIBUTING.md: keep under 500
COMPAT_MAX = 500
BODY_MAX = 500  # spec: keep SKILL.md under 500 lines
BODY_WARN = 300  # CONTRIBUTING.md: body under 300 lines
REF_TOC_MIN_LINES = 100  # reference files longer than this need a TOC
TOC_SEARCH_LINES = 50
EXPECTED_LICENSE = "Apache-2.0"
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
TOC_RE = re.compile(r"^\s{0,3}(?:#{1,6}\s+|\*\*|__)(?:table\s+of\s+)?contents\b", re.IGNORECASE)
PORTABLE_BAD_CHARS = set('<>:"\\|?*')
UNRESTRICTED_SHELL = {"bash", "bash(*)", "bash(*:*)", "shell", "powershell"}

# Marketplace names Claude Code refuses (marketplace reference, "Reserved names").
RESERVED_MARKETPLACE_NAMES = {
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official",
    "anthropic-marketplace", "anthropic-plugins", "agent-skills", "anthropic-agent-skills",
    "life-sciences", "knowledge-work-plugins", "claude-for-legal",
    "claude-for-financial-services", "financial-services-plugins", "first-party-plugins",
    "claude-tag-plugins", "claude-community", "claude-plugins-community", "healthcare",
    "anthropic-plugin-directory", "claude-plugin-directory", "inline", "builtin",
    "skills-dir", "synced", "claude-plugin-test", "npm", "pip", "uv", "cargo", "github", "gh",
}
DESKTOP_RESERVED_NAMES = {"org", "org-provisioned", "unknown"}
DESKTOP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
COMPONENT_FIELDS = ("commands", "agents", "skills", "hooks", "outputStyles", "themes")


# --------------------------------------------------------------------------- findings


class Finding:
    """One validation result. A plain class (not a dataclass) so the module
    also works when loaded with importlib without a sys.modules entry."""

    __slots__ = ("level", "code", "path", "message", "line")

    def __init__(self, level: str, code: str, path: str, message: str, line: Optional[int] = None) -> None:
        self.level = level  # "error" or "warning"
        self.code = code
        self.path = path
        self.message = message
        self.line = line

    def as_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "code": self.code, "path": self.path, "message": self.message, "line": self.line}

    def __repr__(self) -> str:
        return "Finding(%r, %r, %r, %r, %r)" % (self.level, self.code, self.path, self.message, self.line)

    def render(self) -> str:
        loc = self.path + (":%d" % self.line if self.line else "")
        return "%-7s %-26s %s: %s" % (self.level.upper(), self.code, loc, self.message)


class Report:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: List[Finding] = []
        self.skills: List[str] = []
        self.parser = "pyyaml" if _yaml is not None else "builtin"

    def _rel(self, path: Any) -> str:
        if isinstance(path, Path):
            try:
                return path.resolve().relative_to(self.root.resolve()).as_posix()
            except ValueError:
                return path.as_posix()
        return str(path)

    def error(self, code: str, path: Any, message: str, line: Optional[int] = None) -> None:
        self.findings.append(Finding("error", code, self._rel(path), message, line))

    def warn(self, code: str, path: Any, message: str, line: Optional[int] = None) -> None:
        self.findings.append(Finding("warning", code, self._rel(path), message, line))

    @property
    def errors(self) -> List[Finding]:
        return [f for f in self.findings if f.level == "error"]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.level == "warning"]

    def codes(self, level: Optional[str] = None) -> Set[str]:
        return {f.code for f in self.findings if level is None or f.level == level}


# --------------------------------------------------------------------------- YAML subset


class YamlSubsetError(Exception):
    """Problem found by the built-in parser.

    ``unsupported`` marks valid YAML that the portable subset does not cover
    (flow collections, anchors, sequences, deep nesting). Everything else is a
    definite problem.
    """

    def __init__(self, message: str, line: Optional[int] = None, unsupported: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.unsupported = unsupported


_KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)[ \t]*:(?:[ \t]+(.*))?$")
_BLOCK_HEADER_RE = re.compile(r"^([|>])([1-9])?([+-])?([1-9])?[ \t]*(?:#.*)?$")
_NULL_WORDS = {"", "~", "null", "Null", "NULL"}
_TRUE_WORDS = {"yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON"}
_FALSE_WORDS = {"no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF"}
_INT_RE = re.compile(r"^[-+]?(?:0|[1-9][0-9_]*)$")
_INT_BASE_RE = re.compile(r"^[-+]?(?:0b[01_]+|0x[0-9a-fA-F_]+|0[0-7_]+)$")
_FLOAT_RE = re.compile(
    r"^(?:[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?"
    r"|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DQ_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v",
    "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
    "N": "\x85", "_": "\xa0", "L": " ", "P": " ",
}
_DQ_HEX = {"x": 2, "u": 4, "U": 8}


def _resolve_plain(text: str) -> Any:
    """Resolve a plain scalar the way YAML 1.1 (PyYAML) does for common types."""
    if text in _NULL_WORDS:
        return None
    if text in _TRUE_WORDS:
        return True
    if text in _FALSE_WORDS:
        return False
    if _INT_RE.match(text):
        return int(text.replace("_", ""))
    if _INT_BASE_RE.match(text):
        t = text.replace("_", "")
        sign = -1 if t.startswith("-") else 1
        t = t.lstrip("+-")
        if t.startswith("0b"):
            return sign * int(t[2:], 2)
        if t.startswith("0x"):
            return sign * int(t[2:], 16)
        return sign * int(t, 8)
    if _FLOAT_RE.match(text):
        t = text.replace("_", "").lower()
        if t.endswith(".inf"):
            return float("-inf") if t.startswith("-") else float("inf")
        if t == ".nan":
            return float("nan")
        return float(t)
    if _DATE_RE.match(text):
        try:
            return _dt.date.fromisoformat(text)
        except ValueError:
            return text
    return text


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def _check_indent_tabs(raw: str, lineno: int) -> None:
    lead = raw[: len(raw) - len(raw.lstrip(" \t"))]
    if "\t" in lead:
        raise YamlSubsetError("tab character used for indentation", lineno)


def _plain_fragment(raw: str, lineno: int, warnings: List[Tuple[Optional[int], str]]) -> str:
    """Check one line of a plain scalar and strip a trailing comment."""
    m = re.search(r"[ \t]#", raw)
    if m:
        dropped = raw[m.start():].strip()
        raw = raw[: m.start()]
        warnings.append((
            lineno,
            "text after ' #' is a YAML comment and is dropped (%r); quote the value to keep it"
            % (dropped[:40],),
        ))
    raw = raw.strip()
    if ": " in raw or ":\t" in raw or raw.endswith(":"):
        raise YamlSubsetError(
            "unquoted value contains ': ', which YAML reads as a nested mapping; quote the value",
            lineno,
        )
    return raw


def _parse_plain(lines: List[str], i: int, parent_indent: int, first: str,
                 ln, warnings: List[Tuple[Optional[int], str]]) -> Tuple[Any, int]:
    head = first.strip()
    if head[:1] in ("[", "{"):
        raise YamlSubsetError("flow collections ([...] or {...}) are outside the portable subset",
                              ln(i), unsupported=True)
    if head[:1] in ("&", "*", "!"):
        raise YamlSubsetError("anchors, aliases and tags are outside the portable subset",
                              ln(i), unsupported=True)
    if head[:1] in (",", "]", "}", "%", "@", "`") or head in ("-", "?", ":") or head[:2] in ("- ", "? ", ": "):
        raise YamlSubsetError("value starts with the YAML indicator %r; quote the value" % head[:1], ln(i))
    parts = [_plain_fragment(first, ln(i), warnings)]
    j = i + 1
    last = i
    blanks = 0
    while j < len(lines):
        raw = lines[j]
        if not raw.strip():
            blanks += 1
            j += 1
            continue
        if _indent_of(raw) <= parent_indent or raw.strip().startswith("#"):
            break
        _check_indent_tabs(raw, ln(j))
        frag = _plain_fragment(raw, ln(j), warnings)
        parts.append(("\n" * blanks if blanks else " ") + frag)
        blanks = 0
        last = j
        j += 1
    text = "".join(parts)
    if last == i:
        return _resolve_plain(text), i + 1
    return text, last + 1


def _find_close(text: str, quote: str) -> Optional[int]:
    k = 0
    while k < len(text):
        ch = text[k]
        if quote == "'" and ch == "'":
            if text[k + 1:k + 2] == "'":
                k += 2
                continue
            return k
        if quote == '"':
            if ch == "\\":
                k += 2
                continue
            if ch == '"':
                return k
        k += 1
    return None


def _unescape_double(text: str, lineno: int) -> str:
    out: List[str] = []
    k = 0
    while k < len(text):
        ch = text[k]
        if ch != "\\":
            out.append(ch)
            k += 1
            continue
        nxt = text[k + 1:k + 2]
        if nxt in _DQ_ESCAPES:
            out.append(_DQ_ESCAPES[nxt])
            k += 2
        elif nxt in _DQ_HEX:
            width = _DQ_HEX[nxt]
            digits = text[k + 2:k + 2 + width]
            if len(digits) != width or not re.match(r"^[0-9A-Fa-f]+$", digits):
                raise YamlSubsetError("invalid \\%s escape in double-quoted string" % nxt, lineno)
            out.append(chr(int(digits, 16)))
            k += 2 + width
        else:
            raise YamlSubsetError("unknown escape \\%s in double-quoted string" % nxt, lineno)
    return "".join(out)


def _parse_quoted(lines: List[str], i: int, first: str, ln) -> Tuple[str, int]:
    quote = first.lstrip()[0]
    rest = first.lstrip()[1:]
    segments: List[str] = []
    j = i
    while True:
        end = _find_close(rest, quote)
        if end is not None:
            segments.append(rest[:end])
            after = rest[end + 1:]
            break
        segments.append(rest)
        j += 1
        if j >= len(lines):
            raise YamlSubsetError("unterminated %s-quoted string" % ("double" if quote == '"' else "single"), ln(i))
        rest = lines[j]
    tail = after.strip()
    if tail and not (tail.startswith("#") and after[:1] in (" ", "\t")):
        raise YamlSubsetError("unexpected text after the closing quote: %r" % tail[:40], ln(j))
    # Fold line breaks the way YAML flow scalars do.
    if len(segments) == 1:
        raw = segments[0]
    else:
        pieces = [segments[0].rstrip(" \t")]
        blanks = 0
        for idx, seg in enumerate(segments[1:], start=1):
            is_last = idx == len(segments) - 1
            seg = seg.strip(" \t") if not is_last else seg.lstrip(" \t")
            if not seg and not is_last:
                blanks += 1
                continue
            prev = pieces[-1]
            escaped_break = quote == '"' and (len(prev) - len(prev.rstrip("\\"))) % 2 == 1
            if escaped_break:
                pieces[-1] = prev[:-1]
                pieces.append(seg)
            else:
                pieces.append(("\n" * blanks if blanks else " ") + seg)
            blanks = 0
        raw = "".join(pieces)
    if quote == "'":
        return raw.replace("''", "'"), j + 1
    return _unescape_double(raw, ln(i)), j + 1


def _fold_block(content: List[str]) -> str:
    out = ""
    first = True
    prev_more = False
    pending = 0
    for line in content:
        if line == "":
            pending += 1
            continue
        more = line[:1] in (" ", "\t")
        if first:
            out += "\n" * pending + line
        elif pending == 0:
            out += ("\n" if (more or prev_more) else " ") + line
        else:
            out += "\n" * (pending + (1 if (more or prev_more) else 0)) + line
        pending = 0
        first = False
        prev_more = more
    return out


def _parse_block(lines: List[str], i: int, parent_indent: int, header: str, ln) -> Tuple[str, int]:
    m = _BLOCK_HEADER_RE.match(header.strip())
    if not m:
        raise YamlSubsetError("malformed block scalar header %r" % header.strip(), ln(i))
    style, d1, chomp, d2 = m.groups()
    digit = d1 or d2
    block_indent: Optional[int] = parent_indent + int(digit) if digit else None
    content: List[str] = []
    j = i + 1
    while j < len(lines):
        raw = lines[j]
        if not raw.strip():
            content.append("")
            j += 1
            continue
        cur = _indent_of(raw)
        if block_indent is None:
            if cur <= parent_indent:
                break
            block_indent = cur
        if cur < block_indent:
            if cur > parent_indent:
                raise YamlSubsetError("line is less indented than the block scalar it belongs to", ln(j))
            break
        content.append(raw[block_indent:])
        j += 1
    trailing = 0
    while content and content[-1] == "":
        content.pop()
        trailing += 1
    body = "\n".join(content) if style == "|" else _fold_block(content)
    final_break = "\n"
    if j >= len(lines):
        # split("\n") leaves an empty last element when the text ends with a
        # newline; it is not a blank line of the block. Text that ends without
        # a newline gives the block's last line no line break.
        if lines and lines[-1] == "" and trailing:
            trailing -= 1
        elif lines and lines[-1] != "":
            final_break = ""
    if chomp == "-":
        value = body
    elif chomp == "+":
        value = (body + final_break + "\n" * trailing) if content else "\n" * trailing
    else:
        value = body + final_break if content else ""
    return value, j


def _next_content(lines: List[str], j: int) -> Optional[int]:
    while j < len(lines):
        s = lines[j].strip()
        if s and not s.startswith("#"):
            return j
        j += 1
    return None


def _parse_value(lines: List[str], i: int, parent_indent: int, rest: str, ln,
                 warnings: List[Tuple[Optional[int], str]], allow_map: bool) -> Tuple[Any, int]:
    stripped = rest.strip()
    if not stripped or stripped.startswith("#"):
        j = _next_content(lines, i + 1)
        if j is not None and _indent_of(lines[j]) > parent_indent:
            _check_indent_tabs(lines[j], ln(j))
            child = lines[j].strip()
            if child == "-" or child.startswith("- "):
                raise YamlSubsetError("block sequences are outside the portable subset",
                                      ln(j), unsupported=True)
            if not allow_map:
                raise YamlSubsetError("nested mappings deeper than one level are outside the portable subset",
                                      ln(j), unsupported=True)
            return _parse_map(lines, j, _indent_of(lines[j]), ln, warnings, nested=True)
        return None, i + 1
    if stripped[0] in "|>":
        return _parse_block(lines, i, parent_indent, stripped, ln)
    if stripped[0] in "'\"":
        return _parse_quoted(lines, i, rest, ln)
    return _parse_plain(lines, i, parent_indent, rest, ln, warnings)


def _parse_map(lines: List[str], j: int, indent: int, ln,
               warnings: List[Tuple[Optional[int], str]], nested: bool = False) -> Tuple[Dict[str, Any], int]:
    result: Dict[str, Any] = {}
    while j < len(lines):
        raw = lines[j]
        s = raw.strip()
        if not s or s.startswith("#"):
            j += 1
            continue
        _check_indent_tabs(raw, ln(j))
        cur = _indent_of(raw)
        if cur < indent:
            break
        if cur > indent:
            raise YamlSubsetError("unexpected indentation", ln(j))
        m = _KEY_RE.match(raw[cur:])
        if not m:
            if s.startswith("- ") or s == "-":
                raise YamlSubsetError("block sequences are outside the portable subset", ln(j), unsupported=True)
            if s[:1] in ("'", '"', "?", "{", "["):
                raise YamlSubsetError("quoted or complex keys are outside the portable subset",
                                      ln(j), unsupported=True)
            raise YamlSubsetError("expected 'key: value'", ln(j))
        key, rest = m.group(1), m.group(2) or ""
        if key in result:
            raise YamlSubsetError("duplicate key '%s'" % key, ln(j))
        value, j = _parse_value(lines, j, cur, rest, ln, warnings, allow_map=not nested)
        result[key] = value
    return result, j


def parse_yaml_subset(text: str, line_offset: int = 0) -> Tuple[Dict[str, Any], List[Tuple[Optional[int], str]]]:
    """Parse frontmatter written in the portable YAML subset.

    Returns ``(data, warnings)``; raises YamlSubsetError. ``line_offset`` is
    added to reported line numbers (frontmatter starts on file line 2, so the
    caller passes 1).
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    warnings: List[Tuple[Optional[int], str]] = []

    def ln(idx: int) -> int:
        return idx + 1 + line_offset

    first = _next_content(lines, 0)
    if first is None:
        return {}, warnings
    _check_indent_tabs(lines[first], ln(first))
    if _indent_of(lines[first]) != 0:
        raise YamlSubsetError("unexpected indentation", ln(first))
    data, end = _parse_map(lines, first, 0, ln, warnings)
    rest = _next_content(lines, end)
    if rest is not None:
        raise YamlSubsetError("unexpected indentation", ln(rest))
    return data, warnings


def split_frontmatter(text: str) -> Tuple[str, List[str], int]:
    """Split SKILL.md text into (frontmatter, body lines, first body line number)."""
    if text.startswith("\ufeff"):
        raise YamlSubsetError("file starts with a UTF-8 byte order mark; save it without a BOM", 1)
    lines = text.splitlines()
    if not lines or lines[0].rstrip() != "---":
        raise YamlSubsetError("SKILL.md must start with a '---' frontmatter line", 1)
    for idx in range(1, len(lines)):
        if lines[idx].rstrip() == "---":
            fm = "\n".join(lines[1:idx])
            return (fm + "\n" if fm else fm), lines[idx + 1:], idx + 2
    raise YamlSubsetError("frontmatter is not closed with a '---' line", 1)


def _one_line(exc: BaseException) -> str:
    return re.sub(r"\s+", " ", str(exc)).strip()[:200]


def load_frontmatter(fm_text: str, use_pyyaml: bool = True, line_offset: int = 1
                     ) -> Tuple[Optional[Any], List[Tuple[Optional[int], str]], List[Tuple[Optional[int], str]]]:
    """Parse frontmatter. Returns (data or None, errors, warnings)."""
    errors: List[Tuple[Optional[int], str]] = []
    warnings: List[Tuple[Optional[int], str]] = []
    subset_data: Optional[Dict[str, Any]] = None
    subset_exc: Optional[YamlSubsetError] = None
    try:
        subset_data, subset_warnings = parse_yaml_subset(fm_text, line_offset)
        warnings.extend(subset_warnings)
    except YamlSubsetError as exc:
        subset_exc = exc
    if use_pyyaml and _yaml is not None:
        try:
            ydata = _yaml.safe_load(fm_text) if fm_text.strip() else {}
        except _yaml.YAMLError as exc:  # type: ignore[union-attr]
            mark = getattr(exc, "problem_mark", None)
            line = mark.line + 1 + line_offset if mark is not None else None
            errors.append((line, "invalid YAML: %s" % _one_line(exc)))
            return None, errors, warnings
        if subset_exc is not None:
            if subset_exc.unsupported:
                warnings.append((subset_exc.line, "%s; some skill loaders may reject it" % subset_exc.message))
            else:
                errors.append((subset_exc.line, subset_exc.message))
        return ydata, errors, warnings
    if subset_exc is not None:
        msg = subset_exc.message
        if subset_exc.unsupported:
            msg += " (install PyYAML to parse full YAML)"
        errors.append((subset_exc.line, msg))
        return None, errors, warnings
    return subset_data, errors, warnings


# --------------------------------------------------------------------------- file helpers


def read_text(path: Path, report: Report) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        report.error("encoding", path, "file is not valid UTF-8")
        return data.decode("utf-8", errors="replace")


def _is_inside(target: str, base: Path) -> bool:
    base_abs = os.path.normcase(os.path.abspath(str(base)))
    tgt_abs = os.path.normcase(os.path.abspath(target))
    try:
        return os.path.commonpath([base_abs, tgt_abs]) == base_abs
    except ValueError:  # different drives on Windows
        return False


def _exists_exact_case(target: str, base: Path) -> bool:
    """True if every path component of target below base matches the disk's letter case.

    Only components inside base are compared, so short (8.3) names or case
    differences in the part of the path above the skill folder do not matter.
    """
    rel = os.path.relpath(os.path.abspath(target), os.path.abspath(str(base)))
    current = os.path.abspath(str(base))
    for part in Path(rel).parts:
        if part in (".", ""):
            continue
        try:
            entries = os.listdir(current)
        except OSError:
            return True
        if part not in entries:
            return False
        current = os.path.join(current, part)
    return True


def skill_dirs(root: Path) -> List[Path]:
    base = root / "skills"
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))


# --------------------------------------------------------------------------- SKILL.md checks


def _check_fields(report: Report, skill_dir: Path, skill_md: Path, data: Dict[str, Any],
                  expected_version: Optional[str]) -> None:
    unknown = sorted(str(k) for k in data if k not in ALLOWED_KEYS)
    if unknown:
        report.error("frontmatter-key", skill_md,
                     "unknown frontmatter key(s): %s (allowed: %s)" % (", ".join(unknown), ", ".join(ALLOWED_KEYS)))

    # name
    name = data.get("name")
    if name is None:
        report.error("name-missing", skill_md, "required field 'name' is missing")
    elif not isinstance(name, str):
        report.error("name-format", skill_md, "'name' must be a string")
    else:
        if not name:
            report.error("name-format", skill_md, "'name' must not be empty")
        if len(name) > NAME_MAX:
            report.error("name-format", skill_md, "'name' is %d characters (max %d)" % (len(name), NAME_MAX))
        if name and not NAME_RE.match(name):
            report.error("name-format", skill_md,
                         "'name' %r must be lowercase a-z, 0-9 and single hyphens, "
                         "not starting or ending with a hyphen" % name)
        if name != skill_dir.name:
            report.error("name-mismatch", skill_md,
                         "'name' %r does not match directory name %r" % (name, skill_dir.name))
        for word in FORBIDDEN_NAME_WORDS:
            if word in name.lower():
                report.error("name-reserved-word", skill_md, "'name' must not contain %r" % word)

    # description
    desc = data.get("description")
    if desc is None:
        report.error("description-missing", skill_md, "required field 'description' is missing")
    elif not isinstance(desc, str):
        report.error("description-format", skill_md, "'description' must be a string")
    elif not desc.strip():
        report.error("description-format", skill_md, "'description' must not be empty")
    else:
        if len(desc) > DESC_MAX:
            report.error("description-length", skill_md,
                         "'description' is %d characters (spec max %d)" % (len(desc), DESC_MAX))
        elif len(desc) > DESC_WARN:
            report.warn("description-length", skill_md,
                        "'description' is %d characters; CONTRIBUTING.md asks for under %d" % (len(desc), DESC_WARN))
        if "<" in desc or ">" in desc:
            report.error("description-angle-bracket", skill_md, "'description' must not contain '<' or '>'")
        if re.match(r"^\s*(I|I'm|You|You're|Your|We|We're|Our|Let's)\b", desc):
            report.warn("description-style", skill_md, "'description' should be written in the third person")
        if not re.search(r"\b(use|when)\b", desc, re.IGNORECASE):
            report.warn("description-style", skill_md,
                        "'description' should say when to use the skill (e.g. 'Use when ...')")

    # license
    lic = data.get("license")
    if lic is None:
        report.error("license-missing", skill_md, "'license' is required in this repo (use %s)" % EXPECTED_LICENSE)
    elif not isinstance(lic, str) or not lic.strip():
        report.error("license-format", skill_md, "'license' must be a non-empty string")
    elif lic.strip() != EXPECTED_LICENSE:
        report.warn("license-format", skill_md, "'license' is %r; this repo uses %s" % (lic, EXPECTED_LICENSE))

    # compatibility
    if "compatibility" in data:
        compat = data["compatibility"]
        if not isinstance(compat, str) or not compat.strip():
            report.error("compatibility-format", skill_md, "'compatibility' must be a non-empty string")
        elif len(compat) > COMPAT_MAX:
            report.error("compatibility-format", skill_md,
                         "'compatibility' is %d characters (max %d)" % (len(compat), COMPAT_MAX))

    # metadata
    meta = data.get("metadata")
    if meta is None:
        report.error("metadata-missing", skill_md, "'metadata' with a 'version' key is required in this repo")
    elif not isinstance(meta, dict):
        report.error("metadata-format", skill_md, "'metadata' must be a mapping of string keys to string values")
    else:
        for key, value in meta.items():
            if not isinstance(key, str):
                report.error("metadata-format", skill_md, "metadata key %r must be a string" % (key,))
            if isinstance(value, dict):
                report.error("metadata-format", skill_md, "metadata.%s must be a string, not a nested map" % key)
            elif not isinstance(value, str):
                report.error("metadata-format", skill_md,
                             "metadata.%s must be a string, got %s %r; quote it" % (key, type(value).__name__, value))
        version = meta.get("version")
        if version is None:
            report.error("metadata-version", skill_md, "'metadata.version' is required")
        elif isinstance(version, str):
            if not SEMVER_RE.match(version):
                report.warn("metadata-version", skill_md, "metadata.version %r is not semantic versioning" % version)
            elif expected_version and version != expected_version:
                report.warn("version-mismatch", skill_md,
                            "metadata.version %r differs from the plugin version %r in marketplace.json"
                            % (version, expected_version))

    # allowed-tools
    if "allowed-tools" in data:
        tools = data["allowed-tools"]
        if not isinstance(tools, str):
            report.error("allowed-tools-format", skill_md,
                         "'allowed-tools' must be a space-separated string (Agent Skills spec)")
        else:
            broad = [t for t in tools.split() if t.lower() in UNRESTRICTED_SHELL]
            if broad:
                report.warn("allowed-tools-shell", skill_md,
                            "'allowed-tools' pre-approves unrestricted shell (%s); scope it, e.g. "
                            "Bash(python3 scripts/*)" % ", ".join(broad))


_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1")
_INLINE_LINK_RE = re.compile(
    r"!?\[(?:[^\[\]\\]|\\.|\[[^\[\]]*\])*\]\(\s*(<[^<>\n]*>|[^\s)]+)(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)"
)
_REF_DEF_RE = re.compile(r"^\s{0,3}\[([^\]^][^\]]*)\]:\s*(<[^<>\n]*>|\S+)")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_PATH_MENTION_RE = re.compile(
    r"(?<![\w./-])((?:references|scripts|assets)/[A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]+)(?![\w/-])"
)
_SCRIPT_CMD_RE = re.compile(
    r"\b(?:python3?|py|bash|sh|node|pwsh|powershell)(?:\s+-[A-Za-z0-9]+)*\s+(scripts/[A-Za-z0-9_][A-Za-z0-9_./-]*)"
)


def _scan_markdown(text: str) -> Tuple[List[Tuple[int, str]], List[Tuple[int, str]], List[Tuple[int, str]]]:
    """Return (link destinations, code-span texts, fenced lines) with 1-based line numbers."""
    links: List[Tuple[int, str]] = []
    spans: List[Tuple[int, str]] = []
    fenced: List[Tuple[int, str]] = []
    fence: Optional[str] = None
    for idx, line in enumerate(text.splitlines(), start=1):
        m = _FENCE_RE.match(line)
        if fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
                fence = None
            else:
                fenced.append((idx, line))
            continue
        if m:
            fence = m.group(1)
            continue
        for sm in _CODE_SPAN_RE.finditer(line):
            spans.append((idx, sm.group(2)))
        plain = _CODE_SPAN_RE.sub(lambda mm: " " * len(mm.group(0)), line)
        for lm in _INLINE_LINK_RE.finditer(plain):
            links.append((idx, lm.group(1)))
        dm = _REF_DEF_RE.match(plain)
        if dm:
            links.append((idx, dm.group(2)))
    return links, spans, fenced


def _check_links(report: Report, skill_dir: Path, md_file: Path, text: str, line_offset: int,
                 check_mentions: bool) -> None:
    links, spans, fenced = _scan_markdown(text)
    for line, dest in links:
        dest = dest.strip()
        if dest.startswith("<") and dest.endswith(">"):
            dest = dest[1:-1].strip()
        if not dest or dest.startswith("#") or dest.startswith("//"):
            continue
        if _WIN_ABS_RE.match(dest) or dest.startswith(("/", "\\")):
            report.error("link-absolute", md_file, "link uses an absolute path %r; use a path relative to the file" % dest,
                         line + line_offset)
            continue
        if _SCHEME_RE.match(dest):
            continue
        path_part = unquote(dest.split("#", 1)[0].split("?", 1)[0])
        if not path_part:
            continue
        target = os.path.normpath(os.path.join(str(md_file.parent), path_part))
        if not _is_inside(target, skill_dir):
            report.error("link-outside-skill", md_file,
                         "link %r points outside the skill folder; it breaks once the skill is installed or zipped"
                         % dest, line + line_offset)
        elif not os.path.exists(target):
            report.error("link-broken", md_file, "relative link %r does not resolve to a file" % dest, line + line_offset)
        elif not _exists_exact_case(target, skill_dir):
            report.error("link-case", md_file,
                         "relative link %r differs in letter case from the file on disk; it breaks on Linux" % dest,
                         line + line_offset)
    if not check_mentions:
        return
    seen: Set[str] = set()
    candidates: List[Tuple[int, str]] = []
    for line, span in spans:
        candidates.extend((line, m.group(1)) for m in _PATH_MENTION_RE.finditer(span))
    for line, code in fenced:
        candidates.extend((line, m.group(1)) for m in _SCRIPT_CMD_RE.finditer(code))
    for line, rel in candidates:
        rel = rel.rstrip(".")
        if rel in seen:
            continue
        seen.add(rel)
        if not (skill_dir / rel).exists():
            report.warn("path-mention-missing", md_file,
                        "mentions %r but no such file exists in the skill folder" % rel, line + line_offset)


def _check_references(report: Report, skill_dir: Path) -> None:
    ref_dir = skill_dir / "references"
    if not ref_dir.is_dir():
        return
    for ref in sorted(ref_dir.rglob("*.md")):
        if not ref.is_file():
            continue
        rel_parts = ref.relative_to(ref_dir).parts
        if len(rel_parts) > 1:
            report.warn("reference-depth", ref, "reference files should sit directly in references/ (one level deep)")
        text = read_text(ref, report)
        lines = text.splitlines()
        if len(lines) > REF_TOC_MIN_LINES and not any(TOC_RE.match(l) for l in lines[:TOC_SEARCH_LINES]):
            report.warn("reference-toc", ref,
                        "%d lines but no table of contents heading (e.g. '## Contents') in the first %d lines"
                        % (len(lines), TOC_SEARCH_LINES))
        _check_links(report, skill_dir, ref, text, 0, check_mentions=False)


def check_skill(report: Report, skill_dir: Path, use_pyyaml: bool = True,
                expected_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        other = [p.name for p in skill_dir.iterdir() if p.name.lower() == "skill.md"]
        if other:
            report.error("skill-md-missing", skill_dir, "found %s; the file must be named SKILL.md" % other[0])
        else:
            report.error("skill-md-missing", skill_dir, "no SKILL.md in skill directory")
        return None
    text = read_text(skill_md, report)
    try:
        fm_text, body_lines, body_start = split_frontmatter(text)
    except YamlSubsetError as exc:
        report.error("frontmatter", skill_md, exc.message, exc.line)
        return None
    if "---" in fm_text:
        report.warn("frontmatter-dashes", skill_md,
                    "frontmatter contains '---' inside a value; some parsers (skills-ref) split on it")
    data, errors, warnings = load_frontmatter(fm_text, use_pyyaml=use_pyyaml, line_offset=1)
    for line, msg in errors:
        report.error("frontmatter-yaml", skill_md, msg, line)
    for line, msg in warnings:
        report.warn("frontmatter-yaml", skill_md, msg, line)
    if data is None:
        return None
    if not isinstance(data, dict):
        report.error("frontmatter", skill_md, "frontmatter must be a YAML mapping")
        return None
    _check_fields(report, skill_dir, skill_md, data, expected_version)

    n_body = len(body_lines)
    if n_body > BODY_MAX:
        report.error("body-length", skill_md, "body is %d lines (max %d)" % (n_body, BODY_MAX))
    elif n_body > BODY_WARN:
        report.warn("body-length", skill_md, "body is %d lines; CONTRIBUTING.md asks for under %d" % (n_body, BODY_WARN))
    if not any(l.strip() for l in body_lines):
        report.warn("body-empty", skill_md, "SKILL.md has no instructions after the frontmatter")

    _check_links(report, skill_dir, skill_md, "\n".join(body_lines), body_start - 1, check_mentions=True)
    _check_references(report, skill_dir)
    return data


# --------------------------------------------------------------------------- repo-level checks


def check_filenames(report: Report, root: Path) -> None:
    base = root / "skills"
    if not base.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(str(base)):
        dirnames[:] = sorted(d for d in dirnames if d not in ("__pycache__", ".pytest_cache"))
        for name in list(dirnames) + sorted(filenames):
            path = Path(dirpath) / name
            if re.search(r"\s", name):
                report.error("filename-space", path, "file or directory name contains whitespace")
            bad = sorted(c for c in set(name) if c in PORTABLE_BAD_CHARS or ord(c) < 32)
            if bad or name.endswith((".", " ")):
                report.error("filename-portable", path,
                             "name is not portable to Windows (characters %s or trailing dot/space)" % "".join(bad))
            if path.is_symlink():
                report.warn("symlink", path, "symlinks are not preserved in zip uploads and may point outside the skill")


def _reserved_spelling(name: str) -> Optional[str]:
    lowered = name.lower()
    if lowered in RESERVED_MARKETPLACE_NAMES:
        return lowered
    normalized = re.sub(r"[^a-z0-9_]", "-", lowered.rstrip("."))
    if normalized in RESERVED_MARKETPLACE_NAMES:
        return normalized
    return None


def check_marketplace(report: Report, root: Path, present: Set[str]) -> Optional[str]:
    """Validate .claude-plugin/marketplace.json. Returns the plugin version, if any."""
    mp_path = root / ".claude-plugin" / "marketplace.json"
    if not mp_path.is_file():
        report.error("marketplace-missing", mp_path, "marketplace.json not found")
        return None
    try:
        data = json.loads(read_text(mp_path, report))
    except ValueError as exc:
        report.error("marketplace-json", mp_path, "invalid JSON: %s" % _one_line(exc))
        return None
    if not isinstance(data, dict):
        report.error("marketplace-json", mp_path, "top level must be a JSON object")
        return None

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        report.error("marketplace-name", mp_path, "'name' is required")
    else:
        if re.search(r"\s", name):
            report.error("marketplace-name", mp_path, "'name' must not contain spaces; use kebab-case")
        if "/" in name or "\\" in name or ".." in name or name == ".":
            report.error("marketplace-name", mp_path, "'name' must not contain path separators or '..'")
        if any(ord(c) > 127 or ord(c) < 32 for c in name):
            report.error("marketplace-name", mp_path, "'name' must be ASCII with no control characters")
        reserved = _reserved_spelling(name)
        if reserved:
            report.error("marketplace-name", mp_path, "'name' %r is reserved by Claude Code (%s)" % (name, reserved))
        if name.lower().startswith("claudeai-"):
            report.error("marketplace-name", mp_path, "names starting with 'claudeai-' are reserved for claude.ai")
        if not DESKTOP_NAME_RE.match(name) or name.lower() in DESKTOP_RESERVED_NAMES:
            report.warn("marketplace-name", mp_path, "'name' %r is not accepted by Claude Desktop" % name)
        if any(w in name.lower() for w in FORBIDDEN_NAME_WORDS + ("official",)):
            report.warn("marketplace-name", mp_path, "'name' may be refused as impersonating an official marketplace")

    owner = data.get("owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("name"), str) or not owner["name"].strip():
        report.error("marketplace-owner", mp_path, "'owner.name' is required")
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    if not data.get("description") and not meta.get("description"):
        report.warn("marketplace-description", mp_path, "no marketplace description")

    plugins = data.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        report.error("marketplace-plugins", mp_path, "'plugins' must be a non-empty array")
        return None

    listed: Dict[str, int] = {}
    seen_names: Set[str] = set()
    version: Optional[str] = None
    for idx, entry in enumerate(plugins):
        where = "plugins[%d]" % idx
        if not isinstance(entry, dict):
            report.error("marketplace-plugin", mp_path, "%s must be an object" % where)
            continue
        pname = entry.get("name")
        if not isinstance(pname, str) or not pname.strip():
            report.error("marketplace-plugin", mp_path, "%s.name is required" % where)
        else:
            if re.search(r"\s", pname) or any(c in pname for c in "@:/\\"):
                report.error("marketplace-plugin", mp_path, "%s.name %r must be kebab-case without spaces, '@', ':' or slashes"
                             % (where, pname))
            if pname in seen_names:
                report.error("marketplace-plugin", mp_path, "duplicate plugin name %r" % pname)
            seen_names.add(pname)
        if not entry.get("description"):
            report.warn("marketplace-plugin", mp_path, "%s has no description" % where)
        if isinstance(entry.get("version"), str) and version is None:
            version = entry["version"]
        source = entry.get("source")
        if source is None:
            report.error("marketplace-source", mp_path, "%s.source is required" % where)
            continue
        if not isinstance(source, str):
            continue  # remote source types are fetched at install time; nothing local to check
        if not (source == "." or source.startswith("./")):
            report.error("marketplace-source", mp_path, "%s.source %r must start with './'" % (where, source))
            continue
        if ".." in source.split("/") or "\\" in source:
            report.error("marketplace-source", mp_path, "%s.source %r must not contain '..' or backslashes" % (where, source))
            continue
        plugin_root = (root / source).resolve()
        if not plugin_root.is_dir():
            report.error("marketplace-source", mp_path, "%s.source %r is not a directory" % (where, source))
            continue
        if plugin_root != root.resolve() and (plugin_root / "bin").is_dir():
            report.error("plugin-bin-dir", plugin_root / "bin",
                         "a top-level bin/ directory stops claude.ai and Cowork from installing the plugin")
        declares_components = [f for f in COMPONENT_FIELDS if f in entry]
        if entry.get("strict") is False and declares_components and (plugin_root / ".claude-plugin" / "plugin.json").is_file():
            report.error("plugin-manifest-conflict", mp_path,
                         "%s sets strict: false and declares %s while plugin.json exists; the plugin fails to load"
                         % (where, ", ".join(declares_components)))
        skills = entry.get("skills")
        if skills is None:
            continue
        if isinstance(skills, str):
            skills = [skills]
        if not isinstance(skills, list):
            report.error("marketplace-skills", mp_path, "%s.skills must be a path or an array of paths" % where)
            continue
        for sp in skills:
            if not isinstance(sp, str) or not sp.startswith("./"):
                report.error("marketplace-skills", mp_path, "%s.skills entry %r must start with './'" % (where, sp))
                continue
            if ".." in sp.split("/") or "\\" in sp:
                report.error("marketplace-skills", mp_path, "%s.skills entry %r must not contain '..' or backslashes" % (where, sp))
                continue
            target = (plugin_root / sp).resolve()
            try:
                rel = target.relative_to((root / "skills").resolve())
            except ValueError:
                report.error("marketplace-skills", mp_path, "%s.skills entry %r is not under skills/" % (where, sp))
                continue
            if len(rel.parts) != 1:
                report.error("marketplace-skills", mp_path, "%s.skills entry %r must name one skills/<name> folder" % (where, sp))
                continue
            listed[rel.parts[0]] = listed.get(rel.parts[0], 0) + 1

    for skill, count in sorted(listed.items()):
        if count > 1:
            report.error("marketplace-duplicate-skill", mp_path, "skill %r is listed %d times" % (skill, count))
        if skill not in present:
            report.error("marketplace-unknown-skill", mp_path, "lists skills/%s, which does not exist" % skill)
    for skill in sorted(present - set(listed)):
        report.error("marketplace-missing-skill", mp_path, "skills/%s is not listed in any plugin's 'skills'" % skill)

    top_version = meta.get("version") or data.get("version")
    if version and top_version and version != top_version:
        report.warn("version-mismatch", mp_path,
                    "plugin version %r differs from marketplace metadata.version %r" % (version, top_version))
    return version or top_version


def check_evals(report: Report, root: Path, present: Set[str]) -> None:
    evals_dir = root / "evals"
    if not evals_dir.is_dir():
        return
    covered: Set[str] = set()
    for path in sorted(evals_dir.glob("*.json")):
        try:
            data = json.loads(read_text(path, report))
        except ValueError as exc:
            report.error("eval-json", path, "invalid JSON: %s" % _one_line(exc))
            continue
        skill = data.get("skill") if isinstance(data, dict) else None
        if not isinstance(skill, str):
            report.warn("eval-format", path, "missing 'skill' key")
            continue
        covered.add(skill)
        if skill not in present:
            report.warn("eval-unknown-skill", path, "eval targets %r, which is not a skill in skills/" % skill)
        for key in ("should_trigger", "should_not_trigger", "expected_behaviors"):
            if not isinstance(data.get(key), list) or not data.get(key):
                report.warn("eval-format", path, "%r must be a non-empty list" % key)
    for skill in sorted(present - covered):
        report.warn("eval-missing", evals_dir, "no evals/%s.json for skill %r" % (skill, skill))


def validate_repo(root: Path, use_pyyaml: bool = True) -> Report:
    root = Path(root)
    report = Report(root)
    if not use_pyyaml or _yaml is None:
        report.parser = "builtin"
    dirs = skill_dirs(root)
    if not dirs:
        report.error("skills-missing", root / "skills", "no skill directories found under skills/")
    present = {d.name for d in dirs}
    if (root / "bin").is_dir():
        report.error("repo-bin-dir", root / "bin",
                     "a top-level bin/ directory stops claude.ai and Cowork from installing the plugin")
    plugin_version = check_marketplace(report, root, present)
    check_filenames(report, root)
    for d in dirs:
        report.skills.append(d.name)
        check_skill(report, d, use_pyyaml=use_pyyaml, expected_version=plugin_version)
    check_evals(report, root, present)
    return report


# --------------------------------------------------------------------------- CLI


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Validate skills/*/SKILL.md and .claude-plugin/marketplace.json "
                    "against the Agent Skills spec and this repo's rules.")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="repository root (default: %(default)s)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--json", action="store_true", help="print a JSON report")
    ap.add_argument("--no-pyyaml", action="store_true", help="use only the built-in YAML subset parser")
    ap.add_argument("-q", "--quiet", action="store_true", help="print errors and the summary only")
    ap.add_argument("--version", action="version", version="%(prog)s " + TOOL_VERSION)
    args = ap.parse_args(argv)

    root = args.root.resolve()
    report = validate_repo(root, use_pyyaml=not args.no_pyyaml)
    failed = bool(report.errors) or (args.strict and bool(report.warnings))

    if args.json:
        print(json.dumps({
            "tool": "validate_skills",
            "version": TOOL_VERSION,
            "root": str(root),
            "parser": report.parser,
            "skills": report.skills,
            "errors": [f.as_dict() for f in report.errors],
            "warnings": [f.as_dict() for f in report.warnings],
            "ok": not failed,
        }, indent=2))
        return 1 if failed else 0

    ordered = sorted(report.findings, key=lambda f: (f.level != "error", f.path, f.line or 0, f.code))
    for f in ordered:
        if args.quiet and f.level != "error":
            continue
        print(f.render())
    print("validate_skills: %d skill(s), %d error(s), %d warning(s) [yaml parser: %s]%s"
          % (len(report.skills), len(report.errors), len(report.warnings), report.parser,
             " [strict]" if args.strict else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
