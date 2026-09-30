#!/usr/bin/env python3
"""Turn an audit_skill.py --json report into GitHub Action outputs and a job summary.

Used by the repository's action.yml. Standard library only.
"""
from __future__ import annotations

import json
import os
import sys

SEVERITIES = ("critical", "high", "medium", "low", "info")


def main(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    counts = {s: int(summary.get(s, 0)) for s in SEVERITIES}
    total = sum(counts.values())
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("total=%d\n" % total)
            for s in SEVERITIES:
                fh.write("%s=%d\n" % (s, counts[s]))
    inv = report.get("inventory", {})
    lines = [
        "### agentsec-kit skill audit",
        "",
        "Scanned `%s`: %d files, skills: %s, hooks: %d, MCP servers: %d." % (
            os.environ.get("AUDIT_PATH", report.get("target", "")), inv.get("files", 0),
            ", ".join(inv.get("skills", [])) or "none", sum((inv.get("hooks") or {}).values()),
            len(inv.get("mcp_servers", []))),
        "",
        "| Critical | High | Medium | Low | Info | Suppressed by baseline |",
        "|---:|---:|---:|---:|---:|---:|",
        "| %d | %d | %d | %d | %d | %d |" % (counts["critical"], counts["high"], counts["medium"], counts["low"],
                                          counts["info"], int(report.get("suppressed_by_baseline", 0))),
        "",
    ]
    top = [f for f in findings if f.get("severity") in ("critical", "high", "medium")][:15]
    if top:
        lines += ["| Severity | Check | Location | Finding |", "|---|---|---|---|"]
        for f in top:
            text = "%s: %s" % (f.get("title", ""), f.get("evidence", ""))
            text = text.replace("|", "\\|").replace("\n", " ")[:200]
            lines.append("| %s | `%s` | `%s` | %s |" % (f.get("severity"), f.get("id"), f.get("location"), text))
        lines.append("")
    lines.append("Static triage: read every hook and script before approving. "
                 "[agentsec-kit](https://github.com/howardhsieh/agent-security-skills)")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
