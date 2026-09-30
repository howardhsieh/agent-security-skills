#!/usr/bin/env python3
"""Build upload-ready zip archives of the skills in this repository.

For each ``skills/<name>/`` this writes ``dist/<name>.zip`` with the skill
folder as the single top-level entry (``<name>/SKILL.md``, ...), which is the
layout claude.ai expects for Customize > Skills > Upload a skill. It also
writes ``dist/agent-security-skills-<version>.zip`` holding all skills under
a top-level ``agent-security-skills-<version>/skills/`` folder with the
LICENSE and a short README, for people who install by copying folders.

Archives are deterministic: entries are sorted, timestamps are fixed
(SOURCE_DATE_EPOCH if set, else 1980-01-01), permissions are normalized, and
caches (__pycache__, *.pyc, .DS_Store, ...) are excluded, so the same tree
always produces byte-identical zips.

Standard library only (Python 3.9+). Reads the repo; writes only to --out.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

TOOL_VERSION = "0.2.2"
DEFAULT_ROOT = Path(__file__).resolve().parent.parent
BUNDLE_PREFIX = "agent-security-skills"

EXCLUDED_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git", ".venv", "node_modules"}
EXCLUDED_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".swp", "~")
EXECUTABLE_SUFFIXES = (".py", ".sh")
ZIP_EPOCH_MIN = (1980, 1, 1, 0, 0, 0)
# Size limits from the Claude plugin docs (per plugin: 5,000 files, 200 MB).
MAX_FILES = 5000
MAX_BYTES = 200 * 1024 * 1024

BUNDLE_README = """agent-security-skills {version}
================================

Defensive Agent Skills for teams that build and run AI agents.
Source, docs and issues: https://github.com/howardhsieh/agent-security-skills

Each folder under skills/ is one Agent Skill (a folder with a SKILL.md).
Copy the folders you want into your agent's skills directory, for example:

  Claude Code        ~/.claude/skills/ (personal) or .claude/skills/ (project)
  Codex, Cursor,
  Gemini CLI,
  OpenCode, Copilot  ~/.agents/skills/ (personal) or .agents/skills/ (project)

For claude.ai, upload the per-skill zips (<skill-name>.zip) from the same
release under Customize > Skills instead of this bundle.

Licensed under the Apache License, Version 2.0. See LICENSE.
"""


def zip_timestamp() -> Tuple[int, int, int, int, int, int]:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if raw.isdigit():
        t = time.gmtime(int(raw))
        stamp = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2)
        return max(stamp, ZIP_EPOCH_MIN)
    return ZIP_EPOCH_MIN


def is_excluded(name: str, is_dir: bool) -> bool:
    if is_dir:
        return name in EXCLUDED_DIRS or name.endswith(".egg-info")
    return name in EXCLUDED_FILES or name.endswith(EXCLUDED_SUFFIXES)


def collect_files(skill_dir: Path) -> List[Tuple[str, Path]]:
    """Return (posix path relative to skill_dir, absolute path) for every file to package."""
    out: List[Tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(str(skill_dir)):
        base = Path(dirpath)
        kept_dirs = []
        for d in dirnames:
            if is_excluded(d, True):
                continue
            if (base / d).is_symlink():
                raise ValueError("refusing to package symlinked directory %s" % (base / d))
            kept_dirs.append(d)
        dirnames[:] = sorted(kept_dirs)
        for f in sorted(filenames):
            if is_excluded(f, False):
                continue
            path = base / f
            if path.is_symlink():
                raise ValueError("refusing to package symlink %s" % path)
            if not path.is_file():
                continue
            out.append((path.relative_to(skill_dir).as_posix(), path))
    out.sort(key=lambda item: item[0])
    return out


def _zipinfo(arcname: str, stamp: Tuple[int, int, int, int, int, int], executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname, date_time=stamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # Unix, so external_attr permission bits are honored
    mode = 0o755 if executable else 0o644
    info.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
    return info


def write_zip(dest: Path, entries: Sequence[Tuple[str, bytes]]) -> None:
    """Write entries (arcname, data) to dest deterministically, sorted by arcname."""
    stamp = zip_timestamp()
    names = [a for a, _ in entries]
    if len(set(names)) != len(names):
        raise ValueError("duplicate archive entries in %s" % dest.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with zipfile.ZipFile(str(tmp), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in sorted(entries, key=lambda e: e[0]):
            executable = arcname.endswith(EXECUTABLE_SUFFIXES) and "/scripts/" in "/" + arcname
            zf.writestr(_zipinfo(arcname, stamp, executable), data, compress_type=zipfile.ZIP_DEFLATED,
                        compresslevel=9)
    os.replace(str(tmp), str(dest))


def skill_entries(skill_dir: Path, prefix: str) -> List[Tuple[str, bytes]]:
    return [("%s/%s" % (prefix, rel), path.read_bytes()) for rel, path in collect_files(skill_dir)]


def find_skills(root: Path, only: Optional[Iterable[str]] = None) -> List[Path]:
    base = root / "skills"
    if not base.is_dir():
        raise SystemExit("error: no skills/ directory under %s" % root)
    dirs = sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))
    if only:
        wanted = set(only)
        unknown = wanted - {d.name for d in dirs}
        if unknown:
            raise SystemExit("error: unknown skill(s): %s" % ", ".join(sorted(unknown)))
        dirs = [d for d in dirs if d.name in wanted]
    return dirs


def repo_version(root: Path) -> str:
    """Plugin version from .claude-plugin/marketplace.json (entry version, then metadata.version)."""
    path = root / ".claude-plugin" / "marketplace.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "0.0.0"
    for entry in data.get("plugins") or []:
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            return entry["version"]
    meta = data.get("metadata") or {}
    return str(meta.get("version") or data.get("version") or "0.0.0")


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return ("%d %s" % (size, unit)) if unit == "B" else ("%.1f %s" % (size, unit))
        size /= 1024
    return "%d B" % n  # pragma: no cover


def build(root: Path, out_dir: Path, version: Optional[str] = None, only: Optional[Iterable[str]] = None,
          bundle: bool = True) -> List[Dict[str, object]]:
    """Build the archives. Returns one dict per zip written: path, files, bytes."""
    root = Path(root)
    out_dir = Path(out_dir)
    version = version or repo_version(root)
    if not re.match(r"^[0-9A-Za-z][0-9A-Za-z.+-]*$", version):
        raise SystemExit("error: invalid version %r" % version)
    skills = find_skills(root, only)
    if not skills:
        raise SystemExit("error: no skills found under %s" % (root / "skills"))
    results: List[Dict[str, object]] = []
    bundle_entries: List[Tuple[str, bytes]] = []
    bundle_root = "%s-%s" % (BUNDLE_PREFIX, version)
    for skill_dir in skills:
        if not (skill_dir / "SKILL.md").is_file():
            raise SystemExit("error: %s has no SKILL.md; run tools/validate_skills.py" % skill_dir)
        entries = skill_entries(skill_dir, skill_dir.name)
        total = sum(len(d) for _, d in entries)
        if len(entries) > MAX_FILES or total > MAX_BYTES:
            raise SystemExit("error: %s exceeds upload limits (%d files, %s)" % (skill_dir.name, len(entries), human(total)))
        dest = out_dir / ("%s.zip" % skill_dir.name)
        write_zip(dest, entries)
        results.append({"path": dest, "files": len(entries), "bytes": dest.stat().st_size})
        bundle_entries.extend(("%s/skills/%s" % (bundle_root, a), d) for a, d in entries)
    if bundle:
        license_path = root / "LICENSE"
        if license_path.is_file():
            bundle_entries.append(("%s/LICENSE" % bundle_root, license_path.read_bytes()))
        bundle_entries.append(("%s/README.txt" % bundle_root, BUNDLE_README.format(version=version).encode("utf-8")))
        dest = out_dir / ("%s.zip" % bundle_root)
        write_zip(dest, bundle_entries)
        results.append({"path": dest, "files": len(bundle_entries), "bytes": dest.stat().st_size})
    return results


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build dist/<skill>.zip for each skill (claude.ai upload format) "
                                             "and dist/agent-security-skills-<version>.zip with all skills.")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="repository root (default: %(default)s)")
    ap.add_argument("--out", type=Path, default=None, help="output directory (default: <root>/dist)")
    ap.add_argument("--version", default=None, help="bundle version (default: plugin version in marketplace.json)")
    ap.add_argument("--skill", action="append", default=None, metavar="NAME",
                    help="package only this skill (repeatable); implies --no-bundle")
    ap.add_argument("--no-bundle", action="store_true", help="skip the all-skills bundle zip")
    ap.add_argument("--clean", action="store_true", help="delete existing *.zip in the output directory first")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--tool-version", action="version", version="%(prog)s " + TOOL_VERSION)
    args = ap.parse_args(argv)

    root = args.root.resolve()
    out_dir = (args.out or (root / "dist")).resolve()
    if args.clean and out_dir.is_dir():
        for old in out_dir.glob("*.zip"):
            old.unlink()
    try:
        results = build(root, out_dir, version=args.version, only=args.skill,
                        bundle=not (args.no_bundle or args.skill))
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([{"path": str(r["path"]), "files": r["files"], "bytes": r["bytes"]} for r in results],
                         indent=2))
        return 0
    width = max(len(Path(str(r["path"])).name) for r in results)
    for r in results:
        print("%-*s  %4d files  %10s" % (width, Path(str(r["path"])).name, r["files"], human(int(r["bytes"]))))
    print("wrote %d archive(s) to %s" % (len(results), out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
