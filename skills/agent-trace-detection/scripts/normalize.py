#!/usr/bin/env python3
"""normalize.py - turn Claude Code telemetry into detection-ready JSONL.

Inputs (files or directories, auto-detected per line):
  * Claude Code session transcripts   ~/.claude/projects/<project>/<session>.jsonl
  * OpenTelemetry log exports          OTLP/JSON from a Collector file exporter
                                       ({"resourceLogs": [...]}) or flat JSON lines
                                       that already carry an "event.name" key

Outputs (--format):
  tracesig  TraceSig trace schema, one tool call per line, with provenance
            labels (web, untrusted, mcp, file, secret) and category-suffixed
            Bash tool names: Bash(network), Bash(publish), Bash(destructive),
            Bash(install), Bash
  flat      one flat JSON object per event with dotted keys, shaped like Claude
            Code OTel events (tool_result etc.), for sigma_check.py

Read-only, standard library only, no network. Credential-looking strings are
redacted in args and previews.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

TOOL = "normalize"
VERSION = "0.2.1"
PREVIEW_CHARS = 300

# ---------------------------------------------------------------- redaction

TOKEN_RE = re.compile(
    r"(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$))")
KV_SECRET = re.compile(r"((?:[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|apikey|credential)[A-Za-z0-9_.-]*)\s*[:=]\s*[\"']?)([^\s\"',;}]{12,})", re.I)
BEARER = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{12,})")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


EXTRA_SECRET_RES = [
    re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@\"'<>]+:)([^\s@/\"'<>]+)(@)"),
    re.compile(r"(?i)((?:^|[\s\"'])(?:-u|--user|--proxy-user)\s*[\"']?[^\s:\"'/]+:)([^\s\"'@]+)"),
    re.compile(r"(?i)(\bsshpass\s+-p\s*[\"']?)([^\s\"']+)"),
    re.compile(r"(\bmysql(?:dump|admin)?\b[^\n|;&]*?\s-p)([^\s\"'-][^\s\"']{2,})"),
    re.compile(r"(?i)(--password[=\s]+[\"']?)(?![$<])([^\s\"']{3,})"),
    re.compile(r"()(\bhvs\.[A-Za-z0-9_-]{20,})"),
]


def redact(text: str) -> str:
    text = TOKEN_RE.sub(lambda m: "<redacted:%d chars>" % len(m.group(0)), text)
    for rx in EXTRA_SECRET_RES:
        text = rx.sub(lambda m: m.group(0) if m.group(2).startswith("<") else
                      m.group(1) + "<redacted:%d chars>" % len(m.group(2)) + (m.group(3) if m.lastindex and m.lastindex >= 3 else ""), text)
    text = KV_SECRET.sub(lambda m: m.group(1) + ("<redacted:%d chars>" % len(m.group(2)) if not m.group(2).startswith(("$", "<")) else m.group(2)), text)
    return BEARER.sub(lambda m: m.group(1) + "<redacted:%d chars>" % len(m.group(2)), text)


def preview(value: Any) -> str:
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, str):
                parts.append(item)
        value = "\n".join(parts)
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = CONTROL.sub(" ", str(value or ""))
    return redact(text[: PREVIEW_CHARS * 2])[:PREVIEW_CHARS]


# ---------------------------------------------------------------- classification

SECRET_PATH = re.compile(
    r"(?:(?:^|/)\.env(?:\.[A-Za-z0-9_-]+)?$|(?:^|/)\.env(?:\.[A-Za-z0-9_-]+)?(?=[\s'\";)])|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|/\.ssh/|^~?/?\.ssh/"
    r"|\.aws/credentials|\.npmrc\b|\.netrc\b|\.pypirc\b|\.git-credentials\b|\.pem\b|\.key\b|credentials\.json\b"
    r"|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config)")
BASH_CATEGORIES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("install", re.compile(
        r"(?:\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(?:npm|pnpm)\s+(?:i|install|add)\b|\byarn\s+add\b"
        r"|\bpip3?\s+install\b|\buv\s+(?:pip\s+install|add)\b|\bpipx\s+install\b|\bbrew\s+install\b|\bapt(?:-get)?\s+install\b"
        r"|\bgo\s+install\b|\bcargo\s+install\b|\bgem\s+install\b)", re.I)),
    ("publish", re.compile(
        r"(?:\bgit\s+push\b|\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b"
        r"|\bdocker\s+push\b|\bgh\s+(?:release\s+create|pr\s+create|gist\s+create|repo\s+create)\b)", re.I)),
    ("destructive", re.compile(
        r"(?:\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\b|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bdropdb\b|\bDROP\s+(?:TABLE|DATABASE)\b"
        r"|\bkubectl\s+delete\b|\bterraform\s+destroy\b|\bmkfs\b|\bdd\s+if=)", re.I)),
    ("network", re.compile(
        r"(?:\b(?:curl|wget|nc|ncat|netcat|scp|sftp|ftp|telnet|ssh)\b|\brsync\b[^\n]*\S+:\S*|Invoke-WebRequest|Invoke-RestMethod"
        r"|\bpython3?\s+-c\s+[\"'][^\"']*(?:urllib|requests|http\.client|socket))", re.I)),
]
FORCE_PUSH = re.compile(r"\bgit\s+push\b[^\n;&|]*(?:\s--force\b|\s-f\b|\s--force-with-lease\b|\s\+\S)", re.I)


def bash_category(command: str) -> str:
    if FORCE_PUSH.search(command):
        return "destructive"
    for name, rx in BASH_CATEGORIES:
        if rx.search(command):
            return name
    return ""


def classify(tool: str, params: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (normalized tool name, provenance labels)."""
    labels: List[str] = []
    name = tool
    if tool in ("WebFetch", "WebSearch"):
        labels = ["web", "untrusted"]
    elif tool.startswith("mcp__"):
        labels = ["mcp", "untrusted"]
    elif tool in ("Read", "Grep", "Glob", "NotebookRead"):
        path = str(params.get("file_path") or params.get("path") or params.get("pattern") or params.get("notebook_path") or "")
        labels = ["file", "secret"] if SECRET_PATH.search(path) else ["file"]
    elif tool in ("Bash", "PowerShell"):
        command = str(params.get("command") or params.get("bash_command") or params.get("full_command") or "")
        cat = bash_category(command)
        if cat:
            name = "%s(%s)" % (tool, cat)
        if SECRET_PATH.search(command):
            labels.append("secret")
    return name, labels


# ---------------------------------------------------------------- readers

def iter_input_files(paths: List[str]) -> Iterator[Path]:
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames.sort()
                for name in sorted(filenames):
                    if name.endswith((".jsonl", ".json")):
                        yield Path(dirpath) / name
        elif p.is_file():
            yield p
        else:
            raise FileNotFoundError(raw)


def iter_json_lines(path: Path) -> Iterator[Tuple[int, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "{" and path.suffix == ".json":
            try:
                yield 0, json.load(fh)
                return
            except ValueError:
                fh.seek(0)
        for i, line in enumerate(fh):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield i, json.loads(line)
            except ValueError:
                continue


def otlp_value(v: Any) -> Any:
    if not isinstance(v, dict):
        return v
    for key in ("stringValue", "boolValue", "intValue", "doubleValue"):
        if key in v:
            val = v[key]
            return int(val) if key == "intValue" and isinstance(val, str) and val.lstrip("-").isdigit() else val
    if "arrayValue" in v:
        return [otlp_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv.get("key"): otlp_value(kv.get("value")) for kv in v["kvlistValue"].get("values", [])}
    return None


def flatten_otlp(doc: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    for rl in doc.get("resourceLogs", []) or []:
        res = {a.get("key"): otlp_value(a.get("value")) for a in (rl.get("resource") or {}).get("attributes", []) or []}
        for sl in rl.get("scopeLogs", []) or []:
            for rec in sl.get("logRecords", []) or []:
                ev: Dict[str, Any] = dict(res)
                for a in rec.get("attributes", []) or []:
                    ev[a.get("key")] = otlp_value(a.get("value"))
                body = otlp_value(rec.get("body"))
                if isinstance(body, str):
                    ev.setdefault("body", body)
                if "event.timestamp" not in ev and rec.get("timeUnixNano"):
                    ev["time_unix_nano"] = rec["timeUnixNano"]
                if "event.name" in ev:
                    yield ev


def tool_params(ev: Dict[str, Any]) -> Dict[str, Any]:
    raw = ev.get("tool_parameters")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            return json.loads(raw)
        except ValueError:
            return {}
    return {}


class Collector:
    def __init__(self) -> None:
        self.trace: List[Dict[str, Any]] = []   # tracesig events (unsorted)
        self.flat: List[Dict[str, Any]] = []    # flat events
        self.stats = {"files": 0, "transcript_tool_calls": 0, "otel_events": 0}

    # --- transcripts
    def add_transcript(self, path: Path, records: List[Tuple[int, Dict[str, Any]]]) -> None:
        pending: Dict[str, Dict[str, Any]] = {}
        for order, rec in records:
            if rec.get("type") == "assistant":
                content = (rec.get("message") or {}).get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_use":
                        continue
                    params = block.get("input") if isinstance(block.get("input"), dict) else {}
                    tool = str(block.get("name", ""))
                    name, labels = classify(tool, params)
                    ev = {"session_id": str(rec.get("sessionId", path.stem)), "tool": name,
                          "args": redact(json.dumps(params, ensure_ascii=False, sort_keys=True)),
                          "labels": labels, "result_preview": "", "ts": rec.get("timestamp"),
                          "agent": "claude-code", "tool_use_id": block.get("id"), "raw_tool": tool,
                          "is_sidechain": bool(rec.get("isSidechain")), "cwd": rec.get("cwd"),
                          "_order": (str(rec.get("timestamp") or ""), order)}
                    self.trace.append(ev)
                    self.stats["transcript_tool_calls"] += 1
                    if block.get("id"):
                        pending[str(block["id"])] = ev
                    self.flat.append(self._flat_from_transcript(ev, tool, params))
            elif rec.get("type") == "user":
                content = (rec.get("message") or {}).get("content")
                if not isinstance(content, list):
                    continue
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        ev = pending.get(str(block.get("tool_use_id")))
                        if ev is not None:
                            ev["result_preview"] = preview(block.get("content"))
                            ev["is_error"] = bool(block.get("is_error"))

    @staticmethod
    def _flat_from_transcript(ev: Dict[str, Any], tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        tp: Dict[str, Any] = {}
        if tool in ("Bash", "PowerShell"):
            cmd = redact(str(params.get("command", "")))
            tp = {"bash_command": cmd, "full_command": cmd, "description": params.get("description", ""),
                  "dangerouslyDisableSandbox": bool(params.get("dangerouslyDisableSandbox", False))}
        elif tool.startswith("mcp__"):
            parts = tool.split("__")
            tp = {"mcp_server_name": parts[1] if len(parts) > 1 else "", "mcp_tool_name": parts[-1]}
        elif tool == "Skill":
            tp = {"skill_name": params.get("skill") or params.get("name") or ""}
        elif tool in ("Agent", "Task"):
            tp = {"subagent_type": params.get("subagent_type", "")}
        return {"event.name": "tool_result", "source": "transcript", "session.id": ev["session_id"],
                "event.timestamp": ev["ts"], "tool_name": tool, "tool_use_id": ev["tool_use_id"],
                "tool_parameters": json.dumps(tp, sort_keys=True)}

    # --- otel
    def add_otel_event(self, ev: Dict[str, Any]) -> None:
        self.stats["otel_events"] += 1
        for key in ("tool_parameters", "prompt", "error", "response"):
            if isinstance(ev.get(key), str):
                ev[key] = redact(ev[key])
        self.flat.append(ev)
        if ev.get("event.name") != "tool_result":
            return
        params = tool_params(ev)
        tool = str(ev.get("tool_name", ""))
        if tool.startswith("mcp") and params.get("mcp_server_name"):
            tool = "mcp__%s__%s" % (params.get("mcp_server_name"), params.get("mcp_tool_name", ""))
        name, labels = classify(tool, params)
        seq = ev.get("event.sequence")
        self.trace.append({"session_id": str(ev.get("session.id", "otel")), "tool": name,
                           "args": redact(json.dumps(params, ensure_ascii=False, sort_keys=True)),
                           "labels": labels, "result_preview": "", "ts": ev.get("event.timestamp"),
                           "agent": "claude-code", "success": ev.get("success"),
                           "_order": (str(ev.get("event.timestamp") or ""), int(seq) if str(seq or "").isdigit() else 0)})

    def add_file(self, path: Path) -> None:
        self.stats["files"] += 1
        records: List[Tuple[int, Dict[str, Any]]] = []
        for order, obj in iter_json_lines(path):
            if not isinstance(obj, dict):
                continue
            if "resourceLogs" in obj:
                for ev in flatten_otlp(obj):
                    self.add_otel_event(ev)
            elif "event.name" in obj:
                self.add_otel_event(dict(obj))
            elif obj.get("type") in ("user", "assistant") and "sessionId" in obj:
                records.append((order, obj))
        if records:
            self.add_transcript(path, records)

    def tracesig(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        by_session: Dict[str, List[Dict[str, Any]]] = {}
        for ev in self.trace:
            by_session.setdefault(ev["session_id"], []).append(ev)
        for sid in sorted(by_session):
            events = sorted(by_session[sid], key=lambda e: e["_order"])
            for seq, ev in enumerate(events):
                row = {k: v for k, v in ev.items() if not k.startswith("_") and v is not None}
                row["seq"] = seq
                out.append(row)
        return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description="Normalize Claude Code transcripts or OTel exports for detection rules.")
    ap.add_argument("inputs", nargs="+", help="transcript .jsonl files, OTel JSON/JSONL exports, or directories")
    ap.add_argument("--format", choices=["tracesig", "flat"], default="tracesig", help="output schema (default: tracesig)")
    ap.add_argument("--out", help="write to this file instead of stdout")
    ap.add_argument("--session", help="only keep this session id")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    col = Collector()
    try:
        for path in iter_input_files(args.inputs):
            col.add_file(path)
    except FileNotFoundError as exc:
        sys.stderr.write("%s: error: input not found: %s\n" % (TOOL, exc))
        return 1
    rows = col.tracesig() if args.format == "tracesig" else col.flat
    if args.session:
        key = "session_id" if args.format == "tracesig" else "session.id"
        rows = [r for r in rows if str(r.get(key)) == args.session]
    lines = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)
    if args.out:
        Path(args.out).write_text(lines, encoding="utf-8")
    else:
        sys.stdout.write(lines)
    sys.stderr.write("%s: %d file(s), %d transcript tool call(s), %d OTel event(s) -> %d %s row(s)\n" % (
        TOOL, col.stats["files"], col.stats["transcript_tool_calls"], col.stats["otel_events"], len(rows), args.format))
    return 0


if __name__ == "__main__":
    sys.exit(main())
