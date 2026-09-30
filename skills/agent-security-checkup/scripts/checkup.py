#!/usr/bin/env python3
"""checkup.py - one-command security checkup of your AI coding-agent setup, graded A-F.

Combines two sibling skills from agentsec-kit:
  * agent-config-audit       Claude Code / Codex / Cursor settings, hooks, sandbox, MCP
  * skill-supply-chain-audit every installed skill and plugin, across agents

and writes a text summary, JSON, Markdown, and a self-contained HTML report.

Read-only, standard library only, no network. Secret values are never printed.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL = "agent-security-checkup"
VERSION = "0.2.2"
HERE = Path(__file__).resolve().parent
SKILLS_ROOT = HERE.parent.parent
REPO_URL = "https://github.com/howardhsieh/agent-security-skills"
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# ---------------------------------------------------------------- scoring (kept explicit and in the report)
DEDUCTION = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
WEIGHTS = {"configuration": 0.40, "packages": 0.35, "mcp": 0.25}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
CRITICAL_CAP = 69  # any critical finding caps the overall score (grade D at best)
SCORING_TEXT = [
    "Each category starts at 100.",
    "Every distinct problem is deducted once: critical 25, high 10, medium 4, low 1, info 0.",
    "Configuration and MCP count each check once; installed packages count each check once per package.",
    "Overall = 40% configuration + 35% installed skills and plugins + 25% MCP servers "
    "(weights are renormalized when a category cannot be checked).",
    "Any critical finding caps the overall score at 69 (grade D at best).",
    "Grades: A 90+, B 80+, C 70+, D 60+, F below 60.",
]

# ---------------------------------------------------------------- where agents keep skills and plugins
USER_SKILL_DIRS = [
    ("claude-code", ".claude/skills"), ("claude.ai sync", ".claude/skills/synced"), ("shared", ".agents/skills"),
    ("codex", ".codex/skills"), ("cursor", ".cursor/skills"), ("gemini", ".gemini/skills"),
    ("opencode", ".config/opencode/skills"), ("copilot", ".copilot/skills"),
]
PROJECT_SKILL_DIRS = [
    ("claude-code", ".claude/skills"), ("shared", ".agents/skills"), ("cursor", ".cursor/skills"),
    ("copilot", ".github/skills"), ("gemini", ".gemini/skills"), ("opencode", ".opencode/skills"),
]
PLUGIN_CACHE = ".claude/plugins/cache"
MAX_PACKAGES = 200
OWN_SKILLS = {"agent-config-audit", "agent-incident-response", "agent-security-checkup", "agent-threat-model",
              "agent-trace-detection", "mcp-server-security-review", "skill-supply-chain-audit"}
OWN_PLUGIN = "agentsec-kit"
OWN_GUARD_PLUGIN = "agentsec-guard"
TOKEN_SCRUB = re.compile(
    r"(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,})")


def scrub(text: str) -> str:
    return TOKEN_SCRUB.sub(lambda m: "<redacted:%d chars>" % len(m.group(0)), text)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_sibling(skill: str, script: str) -> Tuple[Optional[Any], str]:
    path = SKILLS_ROOT / skill / "scripts" / script
    if not path.is_file():
        return None, "%s is not installed next to this skill; install the full agentsec-kit pack for this check" % skill
    spec = importlib.util.spec_from_file_location("agentsec_%s" % script.replace(".py", ""), str(path))
    if spec is None or spec.loader is None:
        return None, "could not load %s" % path.name
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception as exc:  # a broken sibling must not break the checkup
        return None, "could not load %s: %s" % (path.name, exc.__class__.__name__)
    return mod, ""


def tilde(path: str, home: Path) -> str:
    h = str(home)
    return "~" + path[len(h):] if path.startswith(h) else path


# ---------------------------------------------------------------- installed packages

def discover_packages(home: Path, project: Path) -> List[Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}

    def add(root: Path, agent: str, scope: str, kind: str, name: str) -> None:
        try:
            real = os.path.realpath(str(root))
        except OSError:
            return
        if not os.path.isdir(real):
            return
        entry = found.get(real)
        if entry:
            if agent not in entry["agents"]:
                entry["agents"].append(agent)
            return
        found[real] = {"name": name, "agents": [agent], "scope": scope, "kind": kind, "root": real,
                       "display": tilde(str(root), home)}

    for base, scope, dirs in ((home, "user", USER_SKILL_DIRS), (project, "project", PROJECT_SKILL_DIRS)):
        for agent, rel in dirs:
            d = base / rel
            if not d.is_dir():
                continue
            for child in sorted(d.iterdir()):
                if child.name.startswith(".") or (agent == "claude-code" and scope == "user" and child.name == "synced"):
                    continue
                if (child / "SKILL.md").is_file() or child.is_symlink():
                    add(child, agent, scope, "skill", child.name)
    cache = home / PLUGIN_CACHE
    if cache.is_dir():
        for market in sorted(p for p in cache.iterdir() if p.is_dir()):
            for plugin in sorted(p for p in market.iterdir() if p.is_dir()):
                versions = [v for v in plugin.iterdir() if v.is_dir() and not v.name.startswith(".")]
                if not versions:
                    continue
                newest = max(versions, key=lambda v: v.stat().st_mtime)
                add(newest, "claude-code", "user", "plugin", "%s@%s" % (plugin.name, market.name))
    return sorted(found.values(), key=lambda e: (e["scope"], e["name"]))[:MAX_PACKAGES]


def own_prefix(pkg: Dict[str, Any]) -> Optional[str]:
    """Return the baseline path prefix if this package is agentsec-kit or agentsec-guard, else None.

    Only reviewed lines listed in the shipped baselines are suppressed, so a
    package that merely borrows the name still gets every other finding.
    """
    root = Path(pkg["root"])
    manifest = root / ".claude-plugin" / "plugin.json"
    if manifest.is_file():
        try:
            name = json.loads(manifest.read_text(encoding="utf-8")).get("name")
        except (OSError, ValueError):
            return None
        if name == OWN_PLUGIN:
            return ""
        if name == OWN_GUARD_PLUGIN:
            return OWN_GUARD_PLUGIN + "/"
    skill_md = root / "SKILL.md"
    if root.name in OWN_SKILLS and skill_md.is_file():
        try:
            head = skill_md.read_text(encoding="utf-8", errors="replace")[:2000]
        except OSError:
            return None
        if "howardhsieh/agent-security-skills" in head:
            return root.name + "/"
    return None


def load_self_baseline() -> set:
    accepted: set = set()
    for name in ("self-baseline.json", "self-baseline-guard.json"):
        path = HERE.parent / "assets" / name
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        accepted |= {"%s|%s|%s" % (a.get("id"), a.get("path"), a.get("line_sha256")) for a in data.get("accepted", [])}
    return accepted


def scan_packages(skillmod: Any, packages: List[Dict[str, Any]], home: Path) -> List[Dict[str, Any]]:
    baseline = load_self_baseline()
    results = []
    for pkg in packages:
        root = Path(pkg["root"])
        rep = skillmod.Report(root)
        for p in skillmod.iter_files(root):
            skillmod.scan_file(rep, p)
        skillmod.report_links(rep, root)
        skillmod.check_bin_dirs(rep, root)
        prefix = own_prefix(pkg)
        kept = []
        for f in rep.findings:
            cid, rel, digest = f["_key"].split("|", 2)
            if prefix is not None and "%s|%s%s|%s" % (cid, prefix, rel, digest) in baseline:
                continue
            kept.append({k: v for k, v in f.items() if not k.startswith("_")})
        kept.sort(key=lambda f: (RANK[f["severity"]], f["id"]))
        worst: Dict[str, str] = {}
        for f in kept:
            if f["id"] not in worst or RANK[f["severity"]] < RANK[worst[f["id"]]]:
                worst[f["id"]] = f["severity"]
        counts = {s: sum(1 for v in worst.values() if v == s) for s in SEVERITIES}
        inv = rep.inventory
        results.append(dict(pkg, self_package=prefix is not None, files=inv["files"],
                            hooks=sum(inv["hooks"].values()), mcp_servers=len(set(inv["mcp_servers"])),
                            worst=min(worst.values(), key=lambda s: RANK[s]) if worst else "none",
                            counts=counts, checks=worst,
                            top_findings=[f for f in kept if f["severity"] in ("critical", "high", "medium")][:5]))
    return results


# ---------------------------------------------------------------- scoring

def category_score(unique: Dict[Any, str]) -> int:
    return max(0, 100 - sum(DEDUCTION[s] for s in unique.values()))


def grade_for(score: float) -> str:
    return next(g for floor, g in GRADES if score >= floor)


def unique_by_id(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    worst: Dict[str, str] = {}
    for f in findings:
        if f["id"] not in worst or RANK[f["severity"]] < RANK[worst[f["id"]]]:
            worst[f["id"]] = f["severity"]
    return worst


def build_report(home: Path, project: Path, include_system: bool) -> Dict[str, Any]:
    cfgmod, cfg_note = load_sibling("agent-config-audit", "audit_agent_config.py")
    skillmod, skill_note = load_sibling("skill-supply-chain-audit", "audit_skill.py")
    categories: Dict[str, Dict[str, Any]] = {}
    cfg_findings: List[Dict[str, Any]] = []
    mcp_findings: List[Dict[str, Any]] = []
    plan: List[Dict[str, Any]] = []
    if cfgmod is not None:
        cfg = cfgmod.audit(home, project, include_system=include_system)
        for f in cfg["findings"]:
            (mcp_findings if f["id"].startswith("MCP") else cfg_findings).append(f)
        plan = cfg.get("hardening_plan", [])
        u_cfg, u_mcp = unique_by_id(cfg_findings), unique_by_id(mcp_findings)
        categories["configuration"] = {"label": "Agent configuration", "available": True, "score": category_score(u_cfg),
                                       "checks": u_cfg, "sources": len(cfg.get("sources", []))}
        categories["mcp"] = {"label": "MCP servers", "available": True, "score": category_score(u_mcp), "checks": u_mcp}
    else:
        for key, label in (("configuration", "Agent configuration"), ("mcp", "MCP servers")):
            categories[key] = {"label": label, "available": False, "score": None, "checks": {}, "note": cfg_note}
    packages: List[Dict[str, Any]] = []
    if skillmod is not None:
        packages = scan_packages(skillmod, discover_packages(home, project), home)
        u_pkg = {(p["name"], cid): sev for p in packages for cid, sev in p["checks"].items()}
        categories["packages"] = {"label": "Installed skills and plugins", "available": True,
                                  "score": category_score(u_pkg), "checks": {"%s:%s" % k: v for k, v in u_pkg.items()}}
    else:
        categories["packages"] = {"label": "Installed skills and plugins", "available": False, "score": None,
                                  "checks": {}, "note": skill_note}

    available = {k: v for k, v in categories.items() if v["available"]}
    total_w = sum(WEIGHTS[k] for k in available) or 1.0
    score = sum(WEIGHTS[k] * v["score"] for k, v in available.items()) / total_w if available else 0.0
    all_sev = [s for v in available.values() for s in v["checks"].values()]
    capped = "critical" in all_sev and score > CRITICAL_CAP
    if capped:
        score = CRITICAL_CAP
    score = int(round(score))

    risks = []
    for f in cfg_findings + mcp_findings:
        if f["severity"] in ("critical", "high"):
            risks.append({"severity": f["severity"], "id": f["id"], "title": f["title"],
                          "where": "%s (%s)" % (f.get("location", ""), f.get("agent", "")), "fix": f["fix"]})
    for p in packages:
        for f in p["top_findings"]:
            if f["severity"] in ("critical", "high"):
                risks.append({"severity": f["severity"], "id": f["id"], "title": f["title"],
                              "where": "%s: %s" % (p["name"], f["location"]), "fix": f["fix"]})
    risks.sort(key=lambda r: (RANK[r["severity"]], r["id"]))
    seen, top_risks = set(), []
    for r in risks:
        k = (r["id"], r["where"].split(":")[0])
        if k not in seen:
            seen.add(k)
            top_risks.append(r)

    titles = {f["id"]: f["title"] for f in cfg_findings + mcp_findings}
    wins = []
    for p in plan[:5]:
        fixed = [titles[a] for a in p.get("addresses", []) if a in titles][:2]
        lead = ("Fixes: " + "; ".join(fixed) + ".") if fixed else ""
        wins.append({"severity": p.get("severity", "medium"), "target": p.get("target", ""),
                     "note": " ".join(x for x in (lead, p.get("note", "")) if x),
                     "lang": p.get("lang", "text"), "snippet": p.get("snippet", ""), "addresses": p.get("addresses", [])})
    for p in packages:
        if p["worst"] in ("critical", "high") and not p["self_package"] and len(wins) < 8:
            wins.append({"severity": p["worst"], "target": p["display"], "addresses": sorted(p["checks"]),
                         "note": "Review this %s before using it again (%d critical, %d high). Remove it if you cannot "
                                 "explain every hook and script." % (p["kind"], p["counts"]["critical"], p["counts"]["high"]),
                         "lang": "text", "snippet": "Ask your agent: \"Audit %s with skill-supply-chain-audit\"" % p["display"]})

    mcp_servers = [{"agent": f.get("agent", ""), "where": f.get("location", ""), "detail": f.get("evidence", "")}
                   for f in mcp_findings if f["id"] == "MCP005"]
    summary = {s: 0 for s in SEVERITIES}
    for v in available.values():
        for s in v["checks"].values():
            summary[s] += 1
    for v in categories.values():
        v["issues"] = {s: sum(1 for x in v["checks"].values() if x == s) for s in SEVERITIES}
    return {
        "tool": TOOL, "version": VERSION, "generated_at": now_iso(),
        "target": {"home": "~", "project": tilde(str(project), home)},
        "grade": grade_for(score), "score": score, "capped_by_critical": capped,
        "categories": {k: {kk: vv for kk, vv in v.items() if kk != "checks"} for k, v in categories.items()},
        "summary": summary, "top_risks": top_risks[:10], "quick_wins": wins,
        "packages": [{k: v for k, v in p.items() if k not in ("root", "checks")} for p in packages],
        "mcp_servers": mcp_servers,
        "scoring": {"deduction": DEDUCTION, "weights": WEIGHTS, "critical_cap": CRITICAL_CAP, "explained": SCORING_TEXT},
    }


# ---------------------------------------------------------------- renderers

def render_text(r: Dict[str, Any]) -> str:
    lines = ["Agent security checkup  %s  grade %s (%d/100)%s" % (r["generated_at"], r["grade"], r["score"],
                                                                  "  [capped: critical finding]" if r["capped_by_critical"] else "")]
    for key in ("configuration", "packages", "mcp"):
        c = r["categories"][key]
        if c["available"]:
            iss = c["issues"]
            lines.append("  %-30s %3d/100   %d critical, %d high, %d medium" % (c["label"], c["score"], iss["critical"], iss["high"], iss["medium"]))
        else:
            lines.append("  %-30s  n/a   %s" % (c["label"], c.get("note", "")))
    lines.append("  Installed packages scanned: %d; MCP servers found: %d" % (len(r["packages"]), len(r["mcp_servers"])))
    if r["top_risks"]:
        lines.append("")
        lines.append("Top risks:")
        for t in r["top_risks"][:5]:
            lines.append("  [%s] %s %s  (%s)" % (t["severity"].upper(), t["id"], t["title"], t["where"]))
    if r["quick_wins"]:
        lines.append("")
        lines.append("Quick wins:")
        for i, w in enumerate(r["quick_wins"][:5], 1):
            lines.append("  %d. %s  %s" % (i, w["target"], w["note"]))
    lines.append("")
    lines.append("Score is a conversation starter, not a certification. Details: --html report.html")
    return scrub("\n".join(lines))


def render_md(r: Dict[str, Any]) -> str:
    out = ["## Agent security checkup: grade %s (%d/100)" % (r["grade"], r["score"]), "",
           "| Category | Score | Critical | High | Medium |", "|---|---:|---:|---:|---:|"]
    for key in ("configuration", "packages", "mcp"):
        c = r["categories"][key]
        if c["available"]:
            out.append("| %s | %d | %d | %d | %d |" % (c["label"], c["score"], c["issues"]["critical"], c["issues"]["high"], c["issues"]["medium"]))
        else:
            out.append("| %s | n/a | | | |" % c["label"])
    if r["top_risks"]:
        out += ["", "**Top risks**", ""]
        out += ["- **%s** `%s` %s (%s)" % (t["severity"], t["id"], t["title"], t["where"]) for t in r["top_risks"][:5]]
    out += ["", "_Generated by [agentsec-kit](%s) %s on %s. Read-only; no data left the machine._" % (REPO_URL, VERSION, r["generated_at"])]
    return scrub("\n".join(out))


GRADE_COLORS = {"A": "#1a7f37", "B": "#1f7a8c", "C": "#9a6700", "D": "#bc4c00", "F": "#cf222e"}
SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info", "none": "none"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1f2328;--muted:#57606a;--line:#d8dee4;--bar:#e6e9ed;
--crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#57606a;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#8d96a0;--line:#30363d;
--bar:#21262d;--crit:#ff7b72;--high:#ffa657;--med:#d29922;--low:#8d96a0;--ok:#3fb950}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:0 0 12px;letter-spacing:.2px}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
.hero{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center}
.grade{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;color:#fff;
font-size:64px;font-weight:700;line-height:1}
.grade small{display:block;font-size:14px;font-weight:600;opacity:.9;margin-top:-10px}
.cat{display:grid;grid-template-columns:220px 1fr 64px;gap:12px;align-items:center;margin:8px 0}
.track{height:10px;background:var(--bar);border-radius:6px;overflow:hidden}
.fill{height:100%;border-radius:6px}
.num{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.pill{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;
padding:2px 8px;border-radius:999px;border:1px solid currentColor}
.crit{color:var(--crit)}.high{color:var(--high)}.med{color:var(--med)}.low,.info,.none{color:var(--low)}
ul.risks{list-style:none;padding:0;margin:0}ul.risks li{padding:10px 0;border-top:1px solid var(--line)}
ul.risks li:first-child{border-top:0}.where{color:var(--muted);font-size:13px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 6px;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;border-top:0}td.n{text-align:right;font-variant-numeric:tabular-nums}
pre{background:var(--bar);padding:12px;border-radius:8px;overflow:auto;font-size:12px;margin:8px 0 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.win{padding:12px 0;border-top:1px solid var(--line)}.win:first-of-type{border-top:0}
footer{color:var(--muted);font-size:12px;margin-top:24px;text-align:center}
footer a{color:inherit}
@media (max-width:640px){.hero{grid-template-columns:1fr;justify-items:center;text-align:center}
.cat{grid-template-columns:1fr 48px}.cat .track{grid-column:1/-1;grid-row:2}}
"""


def e(value: Any) -> str:
    return html.escape(scrub(str(value)), quote=True)


def render_html(r: Dict[str, Any]) -> str:
    color = GRADE_COLORS[r["grade"]]
    cats = []
    for key in ("configuration", "packages", "mcp"):
        c = r["categories"][key]
        if c["available"]:
            s = c["score"]
            fill = "var(--ok)" if s >= 90 else "var(--med)" if s >= 70 else "var(--high)" if s >= 60 else "var(--crit)"
            cats.append('<div class="cat"><div>%s <span class="sub">(%d%%)</span></div><div class="track"><div class="fill" '
                        'style="width:%d%%;background:%s"></div></div><div class="num">%d</div></div>'
                        % (e(c["label"]), int(WEIGHTS[key] * 100), s, fill, s))
        else:
            cats.append('<div class="cat"><div>%s</div><div class="sub">%s</div><div class="num">n/a</div></div>'
                        % (e(c["label"]), e(c.get("note", ""))))
    risks = "".join('<li><span class="pill %s">%s</span> <strong>%s</strong> <code>%s</code><div class="where">%s</div>'
                    '<div class="sub">%s</div></li>' % (SEV_CLASS[t["severity"]], e(t["severity"]), e(t["title"]), e(t["id"]),
                                                       e(t["where"]), e(t["fix"])) for t in r["top_risks"][:8])
    risks = risks or '<li class="sub">No critical or high findings. Keep reviewing plugins before you install them.</li>'
    rows = "".join('<tr><td><strong>%s</strong><div class="where">%s</div></td><td>%s</td><td>%s</td>'
                   '<td><span class="pill %s">%s</span></td><td class="n">%d</td><td class="n">%d</td><td class="n">%d</td>'
                   '<td class="n">%d</td><td class="n">%d</td></tr>'
                   % (e(p["name"]), e(p["display"]), e(", ".join(p["agents"])), e(p["kind"]), SEV_CLASS[p["worst"]],
                      e(p["worst"]), p["counts"]["critical"], p["counts"]["high"], p["counts"]["medium"], p["hooks"],
                      p["mcp_servers"]) for p in r["packages"])
    pkg_table = ('<table><tr><th>Package</th><th>Agents</th><th>Kind</th><th>Worst</th><th>Crit</th><th>High</th>'
                 '<th>Med</th><th>Hooks</th><th>MCP</th></tr>%s</table>' % rows) if rows else '<p class="sub">No installed skills or plugins found.</p>'
    mcp_rows = "".join('<tr><td>%s</td><td class="where">%s</td><td><code>%s</code></td></tr>'
                       % (e(m["agent"]), e(m["where"]), e(m["detail"])) for m in r["mcp_servers"])
    mcp_table = ('<table><tr><th>Agent</th><th>Defined in</th><th>Server</th></tr>%s</table>' % mcp_rows) if mcp_rows \
        else '<p class="sub">No MCP servers configured.</p>'
    wins = "".join('<div class="win"><span class="pill %s">%s</span> <strong>%s</strong><div class="sub">%s</div>%s</div>'
                   % (SEV_CLASS.get(w["severity"], "med"), e(w["severity"]), e(w["target"]), e(w["note"]),
                      ('<pre><code>%s</code></pre>' % e(w["snippet"])) if w["snippet"] else "") for w in r["quick_wins"])
    wins = wins or '<p class="sub">Nothing urgent.</p>'
    s = r["summary"]
    capped = '<div class="sub">Capped at D because of a critical finding.</div>' if r["capped_by_critical"] else ""
    how = "".join("<li>%s</li>" % e(t) for t in SCORING_TEXT)
    doc = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent security checkup: %(grade)s</title><style>%(css)s</style></head><body><main>
<header><h1>Agent security checkup</h1><div class="sub">%(when)s &middot; project %(project)s &middot; agentsec-kit %(version)s</div></header>
<section class="card hero"><div class="grade" style="background:%(color)s">%(grade)s<small>%(score)d/100</small></div>
<div><h2>%(headline)s</h2>%(cats)s%(capped)s
<div class="sub">%(crit)d critical &middot; %(high)d high &middot; %(med)d medium &middot; %(npkg)d packages &middot; %(nmcp)d MCP servers</div></div></section>
<section class="card"><h2>Top risks</h2><ul class="risks">%(risks)s</ul></section>
<section class="card"><h2>Quick wins</h2>%(wins)s</section>
<section class="card"><h2>Installed skills and plugins</h2>%(pkgs)s</section>
<section class="card"><h2>MCP servers</h2>%(mcp)s</section>
<section class="card"><h2>How the score is computed</h2><ul class="sub">%(how)s</ul>
<p class="sub">A static, point-in-time check. It is a conversation starter, not a certification. Nothing left this machine.</p></section>
<footer>Generated by <a href="%(repo)s">agentsec-kit</a> &middot; read-only &middot; no network</footer>
</main></body></html>
""" % {"grade": e(r["grade"]), "css": CSS, "when": e(r["generated_at"]), "project": e(r["target"]["project"]),
       "version": e(r["version"]), "color": color, "score": r["score"],
       "headline": e({"A": "Well hardened", "B": "Solid, a few gaps", "C": "Needs attention", "D": "Risky setup",
                      "F": "High risk: act now"}[r["grade"]]),
       "cats": "".join(cats), "capped": capped, "crit": s["critical"], "high": s["high"], "med": s["medium"],
       "npkg": len(r["packages"]), "nmcp": len(r["mcp_servers"]), "risks": risks, "wins": wins, "pkgs": pkg_table,
       "mcp": mcp_table, "how": how, "repo": REPO_URL}
    return scrub(doc)


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog=TOOL, description="Security checkup of your AI coding-agent setup, graded A-F. Read-only.")
    ap.add_argument("--home", help="home directory to check (default: your home)")
    ap.add_argument("--project", help="project directory to check (default: current directory)")
    ap.add_argument("--no-system", action="store_true", help="skip managed/system settings files")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report to FILE")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    ap.add_argument("--md", action="store_true", help="print a Markdown summary")
    ap.add_argument("--fail-below", choices=["A", "B", "C", "D"], help="exit 2 if the grade is below this")
    args = ap.parse_args(argv)
    home = Path(args.home).expanduser() if args.home else Path.home()
    project = Path(args.project).expanduser() if args.project else Path.cwd()
    for label, p in (("--home", home), ("--project", project)):
        if not p.is_dir():
            sys.stderr.write("%s: error: %s is not a directory: %s\n" % (TOOL, label, p))
            return 1
    report = build_report(home.resolve(), project.resolve(), not args.no_system)
    if args.html:
        out = Path(args.html).expanduser()
        out.write_text(render_html(report), encoding="utf-8")
        sys.stderr.write("%s: wrote %s\n" % (TOOL, out))
    if args.json:
        sys.stdout.write(scrub(json.dumps(report, indent=2)) + "\n")
    elif args.md:
        sys.stdout.write(render_md(report) + "\n")
    else:
        sys.stdout.write(render_text(report) + "\n")
    if args.fail_below and "ABCDF".index(report["grade"]) > "ABCDF".index(args.fail_below):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
