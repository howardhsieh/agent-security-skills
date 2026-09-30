#!/usr/bin/env python3
"""sigma_check.py - validate Sigma rules and test them against flat JSONL events.

  validate RULE...                      check rules against Sigma spec v2.1.0 essentials
  test RULE... --events FILE [--expect-match | --expect-no-match]
                                        evaluate rules against flat events (see normalize.py --format flat)

This is a small, documented evaluator for this skill's rules and your own
rules written in the same style. It is not a full Sigma backend: for your SIEM,
convert rules with pySigma / sigma-cli and a field-mapping pipeline.

Supported: field maps (list values = OR, keys = AND), lists of maps (OR),
null values, wildcards * and ? in plain values, modifiers contains, startswith,
endswith, re (with i, m, s), all, exists, cased; conditions with and, or, not,
parentheses, `1 of X*`, `all of X*`, `1 of them`, `all of them`.
Pipeline convention: `tool_parameters.<key>` reads a key from the
tool_parameters JSON string that Claude Code emits.

Requires PyYAML (pip install pyyaml). No network access.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None

TOOL = "sigma_check"
VERSION = "0.2.1"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TAG_RE = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVEL = {"informational", "low", "medium", "high", "critical"}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "i", "m", "s", "all", "exists", "cased"}
KNOWN_MODS = SUPPORTED_MODS | {"windash", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "neq",
                               "lt", "lte", "gt", "gte", "minute", "hour", "day", "week", "month", "year",
                               "cidr", "expand", "fieldref"}
KEYWORDS = {"and", "or", "not", "of", "them", "(", ")"}


class RuleError(Exception):
    pass


# ---------------------------------------------------------------- loading

def load_rule(path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise RuleError("PyYAML is required: pip install pyyaml")
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        raise RuleError("YAML parse error: %s" % exc)
    docs = [d for d in docs if d is not None]
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise RuleError("expected exactly one YAML mapping (multi-document rule collections are not supported)")
    return docs[0]


# ---------------------------------------------------------------- condition parsing

def tokenize(cond: str) -> List[str]:
    return re.findall(r"\(|\)|[^\s()]+", cond)


class Parser:
    """Recursive descent: expr := term ('or' term)*; term := factor ('and' factor)*;
    factor := 'not' factor | '(' expr ')' | quantifier | identifier."""

    def __init__(self, tokens: List[str], idents: List[str]):
        self.toks = tokens
        self.pos = 0
        self.idents = idents
        self.used: List[str] = []

    def peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def take(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None or (expected is not None and tok.lower() != expected):
            raise RuleError("condition: expected %r, got %r" % (expected, tok))
        self.pos += 1
        return tok

    def parse(self) -> Any:
        node = self.expr()
        if self.peek() is not None:
            raise RuleError("condition: unexpected token %r" % self.peek())
        return node

    def expr(self) -> Any:
        node = self.term()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.term())
        return node

    def term(self) -> Any:
        node = self.factor()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.factor())
        return node

    def factor(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise RuleError("condition: unexpected end")
        low = tok.lower()
        if low == "not":
            self.take()
            return ("not", self.factor())
        if tok == "(":
            self.take()
            node = self.expr()
            self.take(")")
            return node
        if low in ("1", "any", "all") and self.pos + 1 < len(self.toks) and self.toks[self.pos + 1].lower() == "of":
            self.take()
            self.take("of")
            target = self.take()
            if target.lower() == "them":
                names = [i for i in self.idents if not i.startswith("_")]
            else:
                names = [i for i in self.idents if fnmatch.fnmatchcase(i, target)]
            if not names:
                raise RuleError("condition: %r matches no search identifier" % target)
            self.used.extend(names)
            return ("all" if low == "all" else "any", names)
        if low in KEYWORDS:
            raise RuleError("condition: unexpected keyword %r" % tok)
        if tok not in self.idents:
            raise RuleError("condition: unknown search identifier %r" % tok)
        self.take()
        self.used.append(tok)
        return ("id", tok)


def parse_condition(cond: Any, idents: List[str]) -> Tuple[List[Any], List[str]]:
    conds = cond if isinstance(cond, list) else [cond]
    trees, used = [], []
    for c in conds:
        if not isinstance(c, str) or not c.strip():
            raise RuleError("detection.condition must be a non-empty string or list of strings")
        p = Parser(tokenize(c), idents)
        trees.append(p.parse())
        used.extend(p.used)
    return trees, used


# ---------------------------------------------------------------- validation

def validate(rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    for key in ("title", "logsource", "detection"):
        if key not in rule:
            errors.append("missing required field %r" % key)
    if "title" in rule and (not isinstance(rule["title"], str) or len(rule["title"]) > 256):
        errors.append("title must be a string of at most 256 characters")
    if "id" not in rule:
        warnings.append("no id (a UUID is recommended)")
    elif not UUID_RE.match(str(rule["id"])):
        errors.append("id is not a lowercase UUID: %r" % rule["id"])
    if "status" in rule and rule["status"] not in STATUS:
        errors.append("status %r not in %s" % (rule["status"], sorted(STATUS)))
    if "level" in rule and rule["level"] not in LEVEL:
        errors.append("level %r not in %s" % (rule["level"], sorted(LEVEL)))
    if "level" not in rule:
        warnings.append("no level")
    for key in ("date", "modified"):
        if key in rule:
            val = rule[key]
            text = val.isoformat() if isinstance(val, (_dt.date, _dt.datetime)) else str(val)
            if not DATE_RE.match(text):
                errors.append("%s must be YYYY-MM-DD" % key)
    for tag in rule.get("tags", []) or []:
        if not TAG_RE.match(str(tag)):
            errors.append("tag %r does not match %s" % (tag, TAG_RE.pattern))
    if not rule.get("falsepositives"):
        warnings.append("no falsepositives section")
    ls = rule.get("logsource")
    if ls is not None and (not isinstance(ls, dict) or not ({"category", "product", "service"} & set(ls))):
        errors.append("logsource needs at least one of category, product, service")
    det = rule.get("detection")
    if isinstance(det, dict):
        if "condition" not in det:
            errors.append("detection.condition missing")
        idents = [k for k in det if k != "condition" and k != "timeframe"]
        for ident in idents:
            errors.extend(check_search(ident, det[ident], warnings))
        if "condition" in det:
            try:
                _, used = parse_condition(det["condition"], idents)
                unused = sorted(set(i for i in idents if not i.startswith("_")) - set(used))
                if unused:
                    warnings.append("search identifiers not used in condition: %s" % ", ".join(unused))
            except RuleError as exc:
                errors.append(str(exc))
    elif det is not None:
        errors.append("detection must be a mapping")
    return errors, warnings


def check_search(ident: str, search: Any, warnings: List[str]) -> List[str]:
    errors: List[str] = []
    maps = search if isinstance(search, list) else [search]
    for m in maps:
        if isinstance(m, str):
            errors.append("%s: keyword searches are not supported by this evaluator" % ident)
            continue
        if not isinstance(m, dict):
            errors.append("%s: selection must be a mapping or list of mappings" % ident)
            continue
        for key in m:
            parts = str(key).split("|")
            for mod in parts[1:]:
                if mod not in KNOWN_MODS:
                    errors.append("%s: unknown modifier %r" % (ident, mod))
                elif mod not in SUPPORTED_MODS:
                    warnings.append("%s: modifier %r is valid Sigma but not evaluated by sigma_check test" % (ident, mod))
    return errors


# ---------------------------------------------------------------- evaluation

def field_value(event: Dict[str, Any], field: str) -> Tuple[bool, Any]:
    if field in event:
        return True, event[field]
    if field.startswith("tool_parameters."):
        raw = event.get("tool_parameters")
        params = raw
        if isinstance(raw, str):
            try:
                params = json.loads(raw)
            except ValueError:
                params = None
        if isinstance(params, dict):
            key = field[len("tool_parameters."):]
            if key in params:
                return True, params[key]
    return False, None


def as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def match_one(actual: Any, expected: Any, mods: List[str]) -> bool:
    cased = "cased" in mods
    text = as_text(actual)
    exp = as_text(expected)
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        return re.search(exp, text, flags) is not None
    if not cased:
        text, exp = text.lower(), exp.lower()
    if "contains" in mods:
        return exp.replace("*", "") in text if "*" not in exp.strip("*") else fnmatch.fnmatchcase(text, "*" + exp + "*")
    if "startswith" in mods:
        return text.startswith(exp) if "*" not in exp else fnmatch.fnmatchcase(text, exp + "*")
    if "endswith" in mods:
        return text.endswith(exp) if "*" not in exp else fnmatch.fnmatchcase(text, "*" + exp)
    if "*" in exp or "?" in exp:
        return fnmatch.fnmatchcase(text, exp)
    return text == exp


def match_field(event: Dict[str, Any], key: str, expected: Any) -> bool:
    parts = str(key).split("|")
    field, mods = parts[0], parts[1:]
    present, actual = field_value(event, field)
    if "exists" in mods:
        want = expected if isinstance(expected, bool) else as_text(expected).lower() == "true"
        return present == want
    values = expected if isinstance(expected, list) else [expected]
    if values == [None]:
        return not present or actual is None
    if not present:
        return False
    actuals = actual if isinstance(actual, list) else [actual]
    hits = [any(match_one(a, v, mods) for a in actuals) for v in values]
    return all(hits) if "all" in mods else any(hits)


def match_search(event: Dict[str, Any], search: Any) -> bool:
    maps = search if isinstance(search, list) else [search]
    return any(isinstance(m, dict) and all(match_field(event, k, v) for k, v in m.items()) for m in maps)


def evaluate(node: Any, results: Dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "id":
        return results[node[1]]
    if kind == "not":
        return not evaluate(node[1], results)
    if kind == "and":
        return evaluate(node[1], results) and evaluate(node[2], results)
    if kind == "or":
        return evaluate(node[1], results) or evaluate(node[2], results)
    if kind == "any":
        return any(results[n] for n in node[1])
    if kind == "all":
        return all(results[n] for n in node[1])
    raise RuleError("bad node %r" % (node,))


def rule_matches(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    det = rule["detection"]
    idents = [k for k in det if k not in ("condition", "timeframe")]
    trees, _ = parse_condition(det["condition"], idents)
    results = {i: match_search(event, det[i]) for i in idents}
    return any(evaluate(t, results) for t in trees)


def load_events(path: Path) -> List[Dict[str, Any]]:
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
    return events


# ---------------------------------------------------------------- CLI

def expand(paths: List[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            out.extend(sorted(list(p.rglob("*.yml")) + list(p.rglob("*.yaml"))))
        else:
            out.append(p)
    return out


def cmd_validate(args: argparse.Namespace) -> int:
    failed = 0
    rules = expand(args.rules)
    for path in rules:
        try:
            rule = load_rule(path)
            errors, warnings = validate(rule)
        except (OSError, RuleError) as exc:
            errors, warnings = [str(exc)], []
        status = "FAIL" if errors else "ok"
        failed += bool(errors)
        print("%-4s %s" % (status, path))
        for e in errors:
            print("     error: %s" % e)
        if not args.quiet:
            for w in warnings:
                print("     warning: %s" % w)
    print("%d rule(s), %d failed" % (len(rules), failed))
    return 1 if failed or not rules else 0


def cmd_test(args: argparse.Namespace) -> int:
    events = load_events(Path(args.events))
    exit_code = 0
    report = []
    for path in expand(args.rules):
        try:
            rule = load_rule(path)
            errors, _ = validate(rule)
            if errors:
                raise RuleError("; ".join(errors))
            hits = [i for i, ev in enumerate(events) if rule_matches(rule, ev)]
        except (OSError, RuleError) as exc:
            print("ERROR %s: %s" % (path, exc))
            exit_code = 1
            continue
        ok = True
        if args.expect_match and not hits:
            ok = False
        if args.expect_no_match and hits:
            ok = False
        exit_code = exit_code or (0 if ok else 1)
        report.append({"rule": str(path), "title": rule.get("title"), "level": rule.get("level"), "matches": hits, "ok": ok})
        if not args.json:
            print("%-4s %-8s %3d match(es)  %s  [%s]" % ("ok" if ok else "FAIL", rule.get("level", "-"), len(hits), rule.get("title"), path.name))
            if hits and not args.quiet:
                for i in hits[:5]:
                    ev = events[i]
                    print("       event #%d %s %s %s" % (i, ev.get("event.name"), ev.get("session.id", ""), ev.get("tool_name", "")))
    if args.json:
        print(json.dumps({"tool": TOOL, "version": VERSION, "events": args.events, "results": report}, indent=2))
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description="Validate and test Sigma rules for agent telemetry.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate rule files or directories")
    v.add_argument("rules", nargs="+")
    v.add_argument("--quiet", action="store_true", help="hide warnings")
    t = sub.add_parser("test", help="evaluate rules against flat JSONL events")
    t.add_argument("rules", nargs="+")
    t.add_argument("--events", required=True, help="flat JSONL events (normalize.py --format flat)")
    g = t.add_mutually_exclusive_group()
    g.add_argument("--expect-match", action="store_true", help="exit 1 unless every rule matches at least one event")
    g.add_argument("--expect-no-match", action="store_true", help="exit 1 if any rule matches")
    t.add_argument("--json", action="store_true")
    t.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    if yaml is None:
        sys.stderr.write("%s: error: PyYAML is required (pip install pyyaml)\n" % TOOL)
        return 1
    return cmd_validate(args) if args.cmd == "validate" else cmd_test(args)


if __name__ == "__main__":
    sys.exit(main())
