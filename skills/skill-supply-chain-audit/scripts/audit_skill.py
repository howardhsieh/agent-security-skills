#!/usr/bin/env python3
"""audit_skill.py - review an Agent Skill, plugin or marketplace repo before you install it.

Read-only, standard library only, no network. Three subcommands:

  scan PATH   inventory + findings (hooks, MCP servers, scripts, hidden text, ...)
  lock PATH   write a hash lockfile of exactly what you reviewed
  diff PATH   compare against a lockfile and re-scan only what changed

Static checks are triage, not a verdict: read every hook and script the
report lists before you approve a package.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL = "audit_skill"
VERSION = "0.2.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_READ = 2 * 1024 * 1024  # bytes per file
MAX_FILES = 5000
DECODE_EXEC_WINDOW = 10  # lines between a decode and an exec/eval to call it decode-then-execute
HEX_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache"}

AST = "OWASP Agentic Skills Top 10 v1.0"
ASI04 = "ASI04 (Agentic Top 10 2026)"
ASI05 = "ASI05 (Agentic Top 10 2026)"

# id: (severity, title, fix, refs)
CHECKS: Dict[str, Tuple[str, str, str, List[str]]] = {
    "SKL001": ("medium", "SKILL.md frontmatter missing or unparseable",
               "Start SKILL.md with a YAML frontmatter block containing name and description.",
               ["https://agentskills.io/specification", "AST04 (%s)" % AST]),
    "SKL002": ("low", "Skill name breaks the naming rules or does not match its directory",
               "Use lowercase a-z, 0-9 and hyphens (max 64) and match the directory name; check for look-alike names of popular skills.",
               ["https://agentskills.io/specification"]),
    "SKL003": ("info", "Frontmatter uses fields outside the portable Agent Skills spec",
               "Agent-specific fields (hooks, allowed-tools extensions, model, shell) change behavior on some agents only; review what each does. claude.ai uploads reject them.",
               ["https://agentskills.io/specification", "AST10 (%s)" % AST]),
    "SKL004": ("low", "Description contains angle brackets or exceeds 1024 characters",
               "Keep the description plain text under 1024 characters.",
               ["https://agentskills.io/specification", "AST04 (%s)" % AST]),
    "SKL010": ("high", "Invisible or bidirectional Unicode characters",
               "Remove the characters and read the file in a hex-aware viewer; text a reviewer cannot see can still steer the model.",
               ["AST01 (%s)" % AST, "AST08 (%s)" % AST, "AML.T0110.000 AI Agent Tool Poisoning (MITRE ATLAS v2026.09)"]),
    "SKL011": ("medium", "HTML comment hidden from the rendered Markdown",
               "Read the comment; instructions in comments are invisible on GitHub but visible to the model.",
               ["AST01 (%s)" % AST, "AST08 (%s)" % AST]),
    "SKL012": ("high", "Skill or command runs shell commands when it loads",
               "Inline shell in SKILL.md or commands runs before the model sees the text. Review each command; organizations can set disableSkillShellExecution.",
               [ASI05, "AST06 (%s)" % AST, "https://code.claude.com/docs/en/skills"]),
    "SKL013": ("medium", "Instructions ask the agent to weaken safety, override instructions or act covertly",
               "Legitimate skills do not need the agent to bypass permissions, hide actions or ignore the user. Reject unless clearly explanatory text.",
               ["AST01 (%s)" % AST, "ASI01 (Agentic Top 10 2026)", "AML.T0051 LLM Prompt Injection (MITRE ATLAS v2026.09)"]),
    "SKL014": ("medium", "Instructions pull behavior from a remote source at runtime",
               "Remote instructions can change after review. Vendor the content into the skill and pin it.",
               ["AST05 (%s)" % AST, "AST07 (%s)" % AST]),
    "SKL015": ("medium", "allowed-tools pre-approves unrestricted shell or wildcards",
               "Narrow allowed-tools to the specific commands the skill needs.",
               ["AST03 (%s)" % AST, "LLM06:2025 Excessive Agency"]),
    "SKL016": ("medium", "Instructions tell the agent to install more skills or plugins",
               "Chained installs bypass your review. Install dependencies yourself after reviewing them.",
               ["AST02 (%s)" % AST, ASI04]),
    "SKL020": ("info", "Hook registered",
               "Hooks run shell commands with your privileges on agent events. Read every command before installing.",
               ["https://code.claude.com/docs/en/hooks", "AST06 (%s)" % AST]),
    "SKL021": ("critical", "Downloads and executes remote code",
               "Reject, or replace with a vendored, reviewed, pinned script.",
               [ASI05, ASI04, "AST01 (%s)" % AST]),
    "SKL022": ("high", "Hook sends data to a remote host or reads credentials",
               "Hooks should not contact the network or read secrets. Reject unless the destination and data are documented and expected.",
               ["AML.T0086 Exfiltration via AI Agent Tool Invocation (MITRE ATLAS v2026.09)", "AML.T0098 AI Agent Tool Credential Harvesting (MITRE ATLAS v2026.09)", ASI04]),
    "SKL023": ("high", "Writes to a persistence location",
               "Shell profiles, cron, launch agents, systemd units, startup folders and git hooks survive uninstall. Reject unless essential and documented.",
               ["AML.T0112.000 Machine Compromise: Local AI Agent (MITRE ATLAS v2026.09)", "AST06 (%s)" % AST]),
    "SKL024": ("low", "Hook runs very often (every session, prompt or tool call)",
               "Frequent hooks see a lot of data. Confirm the matcher is as narrow as the feature needs.",
               ["https://code.claude.com/docs/en/hooks"]),
    "SKL030": ("medium", "Script makes network calls",
               "Confirm every destination is documented and necessary; skills that only transform local files should not need the network.",
               ["AST06 (%s)" % AST, "AML.T0086 Exfiltration via AI Agent Tool Invocation (MITRE ATLAS v2026.09)"]),
    "SKL031": ("medium", "Script executes dynamically built code or uses a shell",
               "Check what reaches eval/exec/shell=True; prefer argument lists over shell strings.",
               [ASI05]),
    "SKL032": ("high", "Script references credential stores or secret variables",
               "A skill rarely needs your SSH keys, cloud credentials or tokens. Reject unless the purpose is explicit.",
               ["AML.T0098 AI Agent Tool Credential Harvesting (MITRE ATLAS v2026.09)", "LLM02:2025 Sensitive Information Disclosure"]),
    "SKL033": ("medium", "Long encoded blob, high-entropy line or minified code",
               "Decode and read it. Obfuscation has no place in a skill you are asked to trust.",
               ["AST08 (%s)" % AST]),
    "SKL034": ("critical", "Decodes data and executes it",
               "Decode-then-execute is the classic way to hide a payload from review. Reject.",
               [ASI05, "AST01 (%s)" % AST]),
    "SKL035": ("high", "Binary executable or native library in the package",
               "Binaries cannot be reviewed as text. Require source and a reproducible build, or reject.",
               ["AST01 (%s)" % AST, "AST08 (%s)" % AST]),
    "SKL036": ("low", "Archive inside the package",
               "Unpack and review archive contents; scanners often skip them.",
               ["AST08 (%s)" % AST]),
    "SKL037": ("medium", "Plugin ships a bin/ directory placed on the agent's PATH",
               "Executables in bin/ can shadow common commands the agent runs. Review each file.",
               ["https://code.claude.com/docs/en/plugins-reference", ASI04]),
    "SKL038": ("info", "File too large to scan fully",
               "Review large files by hand or split them.",
               ["AST08 (%s)" % AST]),
    "SKL039": ("high", "Symbolic link or special file in the package",
               "Packages should ship regular files only. A link can point at your secrets or system files once installed; it is reported, never followed.",
               ["AST01 (%s)" % AST, "AST06 (%s)" % AST]),
    "SKL040": ("medium", "MCP server launched from an unpinned package",
               "Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) so updates cannot change code after review.",
               ["AST07 (%s)" % AST, ASI04]),
    "SKL041": ("high", "Remote MCP server over plaintext HTTP",
               "Use https:// for any non-local server.",
               [ASI04, "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"]),
    "SKL042": ("high", "Literal credential in package configuration",
               "Never ship tokens in config. Reference an environment variable, and treat the leaked value as compromised.",
               ["LLM02:2025 Sensitive Information Disclosure", ASI04]),
    "SKL043": ("info", "MCP server declared",
               "Review the server with mcp-server-security-review before enabling it.",
               [ASI04]),
    "SKL050": ("medium", "Marketplace entry points to another repository without a pinned sha",
               "Add a 40-character sha to the source so the reviewed commit is what installs.",
               ["AST07 (%s)" % AST, "https://code.claude.com/docs/en/plugin-marketplaces"]),
    "SKL051": ("low", "Plugin source installs from npm or runs a command",
               "npm and command sources execute code at install time; review the package or command.",
               ["AST02 (%s)" % AST]),
}

# ---------------------------------------------------------------- patterns

INVISIBLE = re.compile("[\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
BOM = "\ufeff"
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
INLINE_SHELL = re.compile(r"!`[^`\n]+`")
FENCED_SHELL = re.compile(r"^\s*```!\s*$", re.M)

DOWNLOAD_EXEC = re.compile(
    r"(?:\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n;]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby|iex|Invoke-Expression)\b"
    r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
    r"|\$\(\s*(?:curl|wget)\b[^)]*\)\s*$"
    r"|\b(?:iex|Invoke-Expression)\b\s*\(?\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(New-Object\s+Net\.WebClient\))"
    r"|\b(?:sh|bash)\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b)",
    re.I)
NET_CMD = re.compile(r"\b(?:curl|wget|nc|ncat|netcat|scp|sftp|ftp|tftp|telnet|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", re.I)
NET_CODE = re.compile(
    r"\b(?:requests\.(?:get|post|put|patch|delete|request|Session)|urllib\.request|urlopen\(|http\.client|httpx\.|aiohttp\."
    r"|socket\.(?:socket|create_connection)|fetch\(|axios\b|https?\.(?:request|get)\(|net\.(?:connect|createConnection)\("
    r"|XMLHttpRequest|new\s+WebSocket\(|Net\.WebClient|System\.Net\.Http)")
URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+)(?::\d+)?", re.I)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
CRED = re.compile(
    r"(?:~/\.ssh\b|\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/(?:credentials|config)|\.config/gh\b|\bgh/hosts\.yml"
    r"|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.docker/config\.json|\.kube/config|\.gnupg\b"
    r"|Library/Keychains|\bsecurity\s+find-(?:generic|internet)-password|Login\s+Data|Local\s+State|Cookies\.sqlite"
    r"|(?:^|[\s/'\"=])\.env(?:\.[A-Za-z0-9_-]+)?(?=$|[\s'\"`;)])"
    r"|\b(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|SLACK_BOT_TOKEN)\b)")
PERSIST = re.compile(
    r"(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|(?:^|[\s/~])\.profile\b|config\.fish|\bcrontab\b|/etc/cron"
    r"|LaunchAgents|LaunchDaemons|\blaunchctl\b|\bschtasks\b|systemctl\s+--user|\.config/systemd|\.config/autostart"
    r"|\.git/hooks|Start Menu[\\/]Programs[\\/]Startup|CurrentVersion[\\/]Run\b|Microsoft\.PowerShell_profile)", re.I)
WRITE_HINT = re.compile(r"(?:>>|(?<![<>=!])>(?!=)|\btee\b|\bcp\b|\bmv\b|\bln\s+-s|\bwrite|open\([^)]*['\"][wa]|appendFile|writeFile|Set-Content|Add-Content|Out-File|\binstall\b|\bload\b|\benable\b|crontab\s+-|schtasks\s+/create)", re.I)
DYN_EXEC = re.compile(
    r"(?:\beval\s*\(|\bexec\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\("
    r"|new\s+Function\s*\(|\bchild_process\b|\bexecSync\s*\(|\bspawnSync?\s*\([^)]*shell\s*:\s*true"
    r"|\bInvoke-Expression\b|(?:^|[;&|]\s*)iex\b|(?:^|[;&|]\s*)eval\s)", re.I | re.M)
DECODE = re.compile(r"(?:base64\s+(?:-d|--decode|-D)\b|b64decode|\batob\s*\(|FromBase64String|Buffer\.from\([^)]*['\"]base64['\"]|codecs\.decode\([^)]*rot)", re.I)
BLOB_B64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
BLOB_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){60,}|\b[0-9a-fA-F]{200,}\b")

RED_FLAGS = [
    ("SKL013", re.compile(r"--dangerously-skip-permissions|\bbypassPermissions\b|--dangerously-bypass|--yolo\b|dangerouslyDisableSandbox"
                          r"|\b(?:disable|turn off|switch off)\s+(?:the\s+)?(?:sandbox|approvals?|permission prompts?)"
                          r"|\bskip\s+(?:all\s+)?(?:the\s+)?(?:permission|approval)s?\b", re.I)),
    ("SKL013", re.compile(r"\b(?:do not|don'?t|never)\s+(?:tell|inform|mention(?:\s+this)?\s+to|notify|alert|show)\s+the\s+user"
                          r"|\bwithout\s+(?:telling|asking|informing|notifying)\s+the\s+user|\bsilently\s+(?:run|execute|send|upload|install|delete)", re.I)),
    ("SKL013", re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions|\bdisregard\s+(?:the\s+)?(?:system|previous|prior)\s+(?:prompt|instructions)", re.I)),
    ("SKL014", re.compile(r"\b(?:follow|obey|load|apply)\s+(?:the\s+)?(?:latest\s+)?(?:instructions|rules|steps|guidelines)\s+(?:at|from|in)\s+https?://"
                          r"|\b(?:fetch|download|curl|wget|retrieve)\s+(?:the\s+)?(?:latest\s+)?(?:instructions|rules|prompt|guidelines|skill)\s+from\s+https?://", re.I)),
    ("SKL016", re.compile(r"/plugin\s+(?:install|marketplace\s+add)\b|\bclaude\s+plugin\s+(?:install|marketplace\s+add)\b|\bnpx\s+skills(?:@\S+)?\s+add\b|\bgh\s+skill\s+install\b", re.I)),
]

TOKEN_RE = re.compile(
    r"(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
EXTRA_SECRET_RES = [
    re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@\"'<>]+:)([^\s@/\"'<>]+)(@)"),            # scheme://user:pass@host
    re.compile(r"(?i)((?:^|[\s\"'])(?:-u|--user|--proxy-user)\s*[\"']?[^\s:\"'/]+:)([^\s\"'@]+)"),  # curl -u user:pass
    re.compile(r"(?i)(\bsshpass\s+-p\s*[\"']?)([^\s\"']+)"),                                        # sshpass -p pass
    re.compile(r"(\bmysql(?:dump|admin)?\b[^\n|;&]*?\s-p)([^\s\"'-][^\s\"']{2,})"),                  # mysql -pPASS
    re.compile(r"(?i)(--password[=\s]+[\"']?)(?![$<])([^\s\"']{3,})"),                              # --password X
    re.compile(r"()(\bhvs\.[A-Za-z0-9_-]{20,})"),                                                      # Vault tokens
]
SECRET_KEY_NAME = re.compile(r"(?:token|secret|passw(?:or)?d|api[_-]?key|apikey|auth|credential|private[_-]?key|bearer)", re.I)
ENV_REF = re.compile(r"^\s*\$\{?[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}?\s*$|^\s*<[^>]+>\s*$|^\s*$|^(?:your|changeme|xxx+|placeholder)", re.I)

SCRIPT_EXT = {".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".ps1", ".psm1",
              ".rb", ".pl", ".php", ".bat", ".cmd", ".go", ".rs", ".lua"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".node", ".wasm", ".jar", ".class", ".pyc"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".whl", ".skill", ".plugin"}
MAGIC = [(b"\x7fELF", "ELF"), (b"MZ", "PE"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xfe\xed\xfa\xcf", "Mach-O"),
         (b"\xca\xfe\xba\xbe", "Mach-O/Java"), (b"\x00asm", "WebAssembly")]
PORTABLE_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FREQUENT_EVENTS = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolBatch", "Stop", "Notification"}


# ---------------------------------------------------------------- helpers

def redact(text: str) -> str:
    """Replace credential-looking substrings; never return raw secrets."""
    text = TOKEN_RE.sub(lambda m: "<redacted:%d chars>" % len(m.group(0)), text)

    def _kv(m: "re.Match[str]") -> str:
        val = m.group(3)
        if ENV_REF.match(val) or val.startswith("<redacted"):
            return m.group(0)
        return "%s%s<redacted:%d chars>" % (m.group(1), m.group(2), len(val))
    text = re.sub(r"((?:[\"']?[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|apikey|credential)[A-Za-z0-9_.-]*[\"']?))(\s*[:=]\s*[\"']?)([^\s\"',;}]{12,})",
                  _kv, text, flags=re.I)
    text = re.sub(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{12,})", lambda m: m.group(1) + "<redacted:%d chars>" % len(m.group(2)), text)
    for rx in EXTRA_SECRET_RES:
        text = rx.sub(lambda m: m.group(0) if m.group(2).startswith("<") else
                      m.group(1) + "<redacted:%d chars>" % len(m.group(2)) + (m.group(3) if m.lastindex and m.lastindex >= 3 else ""), text)
    return text


def clip(text: str, n: int = 160) -> str:
    text = INVISIBLE.sub(lambda m: "<U+%04X>" % ord(m.group(0)), text).replace(BOM, "<U+FEFF>")
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Report:
    def __init__(self, root: Path):
        self.root = root
        self.findings: List[Dict[str, Any]] = []
        self.inventory: Dict[str, Any] = {"files": 0, "bytes": 0, "skills": [], "plugins": [], "marketplaces": [],
                                          "hooks": {}, "mcp_servers": [], "scripts": 0, "binaries": 0}
        self._seen: set = set()

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def add(self, cid: str, path: Path, line: int, raw: str, evidence: Optional[str] = None,
            severity: Optional[str] = None, extra: str = "") -> None:
        sev, title, fix, refs = CHECKS[cid]
        rel = self.rel(path)
        key = (cid, rel, line, raw.strip()[:200])
        if key in self._seen:
            return
        self._seen.add(key)
        ev = clip(redact(evidence if evidence is not None else raw))
        self.findings.append({
            "id": cid, "severity": severity or sev, "title": title + (" (%s)" % extra if extra else ""),
            "location": "%s:%d" % (rel, line) if line else rel, "evidence": ev, "fix": fix, "refs": list(refs),
            "_key": "%s|%s|%s" % (cid, rel, sha256_bytes(raw.strip().encode("utf-8", "replace"))),
        })


def iter_entries(root: Path) -> Iterable[Tuple[Path, str]]:
    """Yield (path, kind) without following links. kind: file, link, special."""
    if not root.is_dir():
        yield root, entry_kind(root)
        return
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                yield Path(dirpath) / d, "link"
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            count += 1
            if count > MAX_FILES:
                return
            p = Path(dirpath) / name
            yield p, entry_kind(p)


def entry_kind(path: Path) -> str:
    try:
        st = os.lstat(path)
    except OSError:
        return "special"
    if stat.S_ISLNK(st.st_mode):
        return "link"
    return "file" if stat.S_ISREG(st.st_mode) else "special"


def iter_files(root: Path) -> Iterable[Path]:
    """Regular files only; links and special files are never opened."""
    for p, kind in iter_entries(root):
        if kind == "file":
            yield p


def report_links(rep: Report, root: Path) -> None:
    base = root if root.is_dir() else root.parent
    for p, kind in iter_entries(root):
        if kind == "link":
            try:
                target = os.readlink(p)
            except OSError:
                target = "?"
            resolved = os.path.normpath(os.path.join(os.path.dirname(str(p)), target))
            inside = os.path.isabs(target) is False and within(Path(resolved), base)
            rep.add("SKL039", p, 0, "link %s -> %s" % (rep.rel(p), target),
                    evidence="symlink -> %s%s" % (target, "" if inside else " (outside the package)"),
                    severity=None if not inside else "medium")
        elif kind == "special":
            rep.add("SKL039", p, 0, "special %s" % rep.rel(p), evidence="not a regular file (device, FIFO or socket)")


def within(path: Path, base: Path) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(str(path)), os.path.realpath(str(base))]) == os.path.realpath(str(base))
    except ValueError:
        return False


def read_text(path: Path) -> Tuple[Optional[str], bytes]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ + 1)
    except OSError:
        return None, b""
    head = data[:4096]
    if b"\x00" in head:
        return None, data
    try:
        return data.decode("utf-8"), data
    except UnicodeDecodeError:
        return data.decode("latin-1"), data


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def line_at(text: str, lineno: int) -> str:
    lines = text.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    return line_of(text, idx) if idx >= 0 else 0


def remote_hosts(text: str) -> List[str]:
    return [h for h in URL.findall(text) if h.lower() not in LOCAL_HOSTS and not h.lower().endswith(".localhost")]


# ---------------------------------------------------------------- frontmatter

def parse_frontmatter(text: str) -> Tuple[Optional[Dict[str, str]], int]:
    """Minimal frontmatter reader: top-level keys -> raw value text. Returns (fields, body_start_line)."""
    lines = text.lstrip(BOM).splitlines()
    if not lines or lines[0].strip() != "---":
        return None, 0
    fields: Dict[str, str] = {}
    current = None
    for i, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            return fields, i
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            current = m.group(1)
            fields[current] = m.group(2).strip()
        elif current is not None:
            fields[current] = (fields[current] + "\n" + line).strip()
    return None, 0


def scalar(value: str) -> str:
    value = value.strip()
    if value[:1] in (">", "|"):
        value = " ".join(l.strip() for l in value.splitlines()[1:])
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.strip()


# ---------------------------------------------------------------- checks

def check_text_common(rep: Report, path: Path, text: str) -> None:
    body = text[1:] if text.startswith(BOM) else text
    for m in INVISIBLE.finditer(body):
        ln = line_of(body, m.start())
        cps = sorted({"U+%04X" % ord(c) for c in INVISIBLE.findall(line_at(body, ln))})
        rep.add("SKL010", path, ln, line_at(body, ln), evidence="codepoints %s on this line" % ", ".join(cps[:6]))
    if BOM in body:
        ln = line_of(body, body.index(BOM))
        rep.add("SKL010", path, ln, line_at(body, ln), evidence="U+FEFF inside the file")


def check_markdown(rep: Report, path: Path, text: str, is_skill_md: bool, is_command: bool) -> None:
    for m in HTML_COMMENT.finditer(text):
        content = m.group(1).strip()
        if content:
            rep.add("SKL011", path, line_of(text, m.start()), m.group(0), evidence="<!-- %s -->" % clip(content, 120))
    if is_skill_md or is_command:
        for m in INLINE_SHELL.finditer(text):
            ln = line_of(text, m.start())
            rep.add("SKL012", path, ln, line_at(text, ln), evidence=m.group(0))
            analyze_command(rep, path, ln, m.group(0)[2:-1], hook=True)
        for m in FENCED_SHELL.finditer(text):
            rep.add("SKL012", path, line_of(text, m.start()), m.group(0), evidence="fenced shell block (```!)")
    for cid, rx in RED_FLAGS:
        for m in rx.finditer(text):
            ln = line_of(text, m.start())
            rep.add(cid, path, ln, line_at(text, ln))
    if is_skill_md:
        check_skill_frontmatter(rep, path, text)


def check_skill_frontmatter(rep: Report, path: Path, text: str) -> None:
    fields, _ = parse_frontmatter(text)
    if fields is None or "name" not in fields or "description" not in fields:
        rep.add("SKL001", path, 1, text.splitlines()[0] if text else "", evidence="missing frontmatter or name/description")
        rep.inventory["skills"].append(path.parent.name)
        return
    name = scalar(fields["name"])
    rep.inventory["skills"].append(name)
    if not NAME_RE.match(name) or len(name) > 64 or name != path.parent.name:
        rep.add("SKL002", path, find_line(text, "name:"), "name: " + name,
                evidence="name %r in directory %r" % (name, path.parent.name))
    extra = sorted(set(fields) - PORTABLE_FIELDS)
    if extra:
        rep.add("SKL003", path, find_line(text, extra[0] + ":"), ",".join(extra), evidence="non-portable fields: %s" % ", ".join(extra))
    desc = scalar(fields["description"])
    if "<" in desc or ">" in desc or len(desc) > 1024:
        rep.add("SKL004", path, find_line(text, "description:"), desc, evidence="%d chars%s" % (len(desc), ", has angle brackets" if ("<" in desc or ">" in desc) else ""))
    tools = fields.get("allowed-tools", "")
    if tools and re.search(r"(?:^|[\s,\[])(?:Bash|Shell|PowerShell)(?:\(\s*\*?\s*\))?(?=$|[\s,\]])|\*", tools):
        rep.add("SKL015", path, find_line(text, "allowed-tools:"), "allowed-tools: " + tools)
    if "hooks" in fields:
        hooks_text = fields["hooks"]
        rep.add("SKL020", path, find_line(text, "hooks:"), "hooks: " + hooks_text, evidence="skill-level hooks in frontmatter")
        analyze_command(rep, path, find_line(text, "hooks:"), hooks_text, hook=True, event="(skill frontmatter)")


def analyze_command(rep: Report, path: Path, line: int, cmd: str, hook: bool, event: str = "") -> None:
    """Risk analysis for a hook command or one script line."""
    if DOWNLOAD_EXEC.search(cmd):
        rep.add("SKL021", path, line, cmd)
    creds = bool(CRED.search(cmd))
    remote = remote_hosts(cmd)
    net = bool(NET_CMD.search(cmd)) or bool(remote)
    if hook and (creds or (net and remote)):
        rep.add("SKL022", path, line, cmd, extra=", ".join(x for x in (("credentials" if creds else ""), ("network: " + ", ".join(sorted(set(remote))[:3]) if remote else ("network" if net else ""))) if x))
    if PERSIST.search(cmd) and WRITE_HINT.search(cmd):
        rep.add("SKL023", path, line, cmd)


def check_script(rep: Report, path: Path, text: str) -> None:
    rep.inventory["scripts"] += 1
    decode_lines = [line_of(text, m.start()) for m in DECODE.finditer(text)]
    exec_lines = [line_of(text, m.start()) for m in DYN_EXEC.finditer(text)]
    pairs = [(d, e) for d in decode_lines for e in exec_lines if abs(d - e) <= DECODE_EXEC_WINDOW]
    if pairs:
        d, e = min(pairs, key=lambda de: abs(de[0] - de[1]))
        rep.add("SKL034", path, d, line_at(text, d), extra="decode at line %d, execute at line %d" % (d, e))
    for ln, line in enumerate(text.splitlines(), start=1):
        if len(line) > 5000:
            rep.add("SKL033", path, ln, line[:200], evidence="line of %d chars (minified or packed)" % len(line))
            continue
        if DOWNLOAD_EXEC.search(line):
            rep.add("SKL021", path, ln, line)
        if NET_CMD.search(line) or NET_CODE.search(line):
            rep.add("SKL030", path, ln, line)
        if DYN_EXEC.search(line):
            rep.add("SKL031", path, ln, line)
        if CRED.search(line):
            rep.add("SKL032", path, ln, line)
        if PERSIST.search(line) and WRITE_HINT.search(line):
            rep.add("SKL023", path, ln, line)
        if BLOB_B64.search(line) or BLOB_HEX.search(line):
            rep.add("SKL033", path, ln, line, evidence="encoded blob of %d+ chars" % 200)


def iter_hook_commands(hooks: Any) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield (event, matcher, handler) from a Claude Code hooks object."""
    if isinstance(hooks, dict) and "hooks" in hooks and isinstance(hooks["hooks"], (dict, list)) and not any(
            k[:1].isupper() for k in hooks if isinstance(k, str)):
        hooks = hooks["hooks"]
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = str(group.get("matcher", "*"))
            for handler in group.get("hooks", []) or []:
                if isinstance(handler, dict):
                    yield str(event), matcher, handler


def check_hooks_obj(rep: Report, path: Path, text: str, hooks: Any) -> None:
    for event, matcher, handler in iter_hook_commands(hooks):
        htype = str(handler.get("type", "command"))
        target = str(handler.get("command") or handler.get("url") or handler.get("prompt") or "")
        ln = find_line(text, target[:40]) if target else find_line(text, event)
        rep.inventory["hooks"][event] = rep.inventory["hooks"].get(event, 0) + 1
        rep.add("SKL020", path, ln, "%s %s %s" % (event, matcher, target),
                evidence="%s [matcher %s] %s: %s" % (event, matcher, htype, target))
        if event in FREQUENT_EVENTS and matcher in ("*", "", ".*"):
            rep.add("SKL024", path, ln, "freq %s %s" % (event, target), evidence="%s on every event" % event)
        if htype == "http":
            hosts = remote_hosts(target)
            if hosts:
                rep.add("SKL022", path, ln, target, extra="HTTP hook to %s" % ", ".join(hosts[:3]))
        else:
            analyze_command(rep, path, ln, target, hook=True, event=event)
            script_ref = re.search(r"(?:\$\{?CLAUDE_PLUGIN_ROOT\}?|\$\{?CLAUDE_PROJECT_DIR\}?)[\"']?/([^\s\"']+)", target)
            if script_ref:
                root_dir = plugin_root_for(path)
                ref = root_dir / script_ref.group(1)
                if entry_kind(ref) == "file" and within(ref, root_dir):
                    stext, _ = read_text(ref)
                    if stext:
                        for sln, sline in enumerate(stext.splitlines(), start=1):
                            analyze_command(rep, ref, sln, sline, hook=True, event=event)


def plugin_root_for(path: Path) -> Path:
    for parent in [path.parent] + list(path.parents):
        if (parent / ".claude-plugin").is_dir():
            return parent
    return path.parent.parent if path.parent.name == "hooks" else path.parent


def check_mcp_servers(rep: Report, path: Path, text: str, servers: Any) -> None:
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        rep.inventory["mcp_servers"].append(str(name))
        ln = find_line(text, '"%s"' % name)
        cmd = str(cfg.get("command", ""))
        args = [str(a) for a in cfg.get("args", []) or []]
        url = str(cfg.get("url", ""))
        rep.add("SKL043", path, ln, "mcp %s" % name, evidence="%s: %s" % (name, url or " ".join([cmd] + args)))
        unpinned = unpinned_launch(cmd, args)
        if unpinned:
            rep.add("SKL040", path, ln, " ".join([cmd] + args), extra=unpinned)
        full = " ".join([cmd] + args)
        if cmd:
            analyze_command(rep, path, ln, full, hook=False)
        m = URL.search(url)
        if url.lower().startswith("http://") and m and m.group(1).lower() not in LOCAL_HOSTS:
            rep.add("SKL041", path, ln, url)
        for section in ("env", "headers"):
            values = cfg.get(section) or {}
            if isinstance(values, dict):
                for key, val in values.items():
                    sval = str(val)
                    if TOKEN_RE.search(sval) or (SECRET_KEY_NAME.search(str(key)) and not ENV_REF.match(sval) and "${" not in sval and len(sval) >= 12):
                        rep.add("SKL042", path, find_line(text, '"%s"' % key) or ln, "%s=%s" % (key, sval),
                                evidence="%s.%s.%s = <redacted:%d chars>" % (name, section, key, len(sval)))


def unpinned_launch(cmd: str, args: List[str]) -> str:
    base = os.path.basename(cmd).lower().replace(".cmd", "").replace(".exe", "")
    rest = [a for a in args if a]
    if base in ("npx", "bunx") or (base in ("pnpm", "yarn") and rest[:1] == ["dlx"]):
        pkgs = [a for a in rest if not a.startswith("-") and a != "dlx"]
        if pkgs:
            pkg = pkgs[0]
            body = pkg[1:] if pkg.startswith("@") else pkg
            if "@" not in body or body.endswith("@latest"):
                return "%s %s" % (base, pkg)
    if base in ("uvx", "pipx"):
        pkgs = [a for a in rest if not a.startswith("-") and a != "run"]
        if pkgs and not re.search(r"==|@", pkgs[0]):
            return "%s %s" % (base, pkgs[0])
    if base in ("docker", "podman") and "run" in rest:
        after = rest[rest.index("run") + 1:]
        imgs = [a for a in after if not a.startswith("-") and "=" not in a]
        if imgs:
            img = imgs[0]
            if "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
                return "%s image %s" % (base, img)
    return ""


def check_json(rep: Report, path: Path, text: str) -> None:
    name = path.name
    interesting = name in ("hooks.json", "plugin.json", "marketplace.json", ".mcp.json", "settings.json", "settings.local.json", "mcp.json")
    if not interesting:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    if name == "hooks.json" or "hooks" in data:
        hooks = data.get("hooks", data) if name != "hooks.json" else data
        if isinstance(hooks, (dict, list)):
            check_hooks_obj(rep, path, text, hooks)
    if "mcpServers" in data:
        check_mcp_servers(rep, path, text, data["mcpServers"])
    if name == "plugin.json":
        rep.inventory["plugins"].append(str(data.get("name", path.parent.parent.name)))
    if name == "marketplace.json":
        rep.inventory["marketplaces"].append(str(data.get("name", "?")))
        for entry in data.get("plugins", []) or []:
            if not isinstance(entry, dict):
                continue
            src = entry.get("source")
            ln = find_line(text, '"%s"' % entry.get("name", "")) or 1
            if isinstance(src, dict):
                stype = str(src.get("source", ""))
                if stype in ("github", "url", "git-subdir") and not re.fullmatch(r"[0-9a-f]{40}", str(src.get("sha", ""))):
                    rep.add("SKL050", path, ln, json.dumps(src, sort_keys=True), evidence="%s -> %s %s" % (entry.get("name"), stype, src.get("repo") or src.get("url")))
                if stype in ("npm", "command"):
                    rep.add("SKL051", path, ln, json.dumps(src, sort_keys=True), evidence="%s uses %s source" % (entry.get("name"), stype))


def scan_file(rep: Report, path: Path) -> None:
    rep.inventory["files"] += 1
    try:
        size = path.stat().st_size
    except OSError:
        return
    rep.inventory["bytes"] += size
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXT or path.name.endswith((".tar.gz", ".tar.xz")):
        rep.add("SKL036", path, 0, path.name, evidence=path.name)
        return
    text, data = read_text(path)
    magic = next((label for sig, label in MAGIC if data.startswith(sig)), None)
    if suffix in BINARY_EXT or (text is None and magic):
        rep.inventory["binaries"] += 1
        rep.add("SKL035", path, 0, path.name, evidence="%s (%s, %d bytes)" % (path.name, magic or suffix, size))
        return
    if text is None:
        return
    if size > MAX_READ:
        rep.add("SKL038", path, 0, path.name, evidence="%d bytes; first %d scanned" % (size, MAX_READ))
    check_text_common(rep, path, text)
    parts = {p.lower() for p in path.parts}
    if suffix in (".md", ".markdown", ".mdx"):
        check_markdown(rep, path, text, is_skill_md=(path.name == "SKILL.md"),
                       is_command=("commands" in parts))
    elif suffix == ".json":
        check_json(rep, path, text)
    is_exec = os.access(path, os.X_OK) and os.name != "nt"
    if suffix in SCRIPT_EXT or text.startswith("#!") or (is_exec and suffix not in (".md", ".json", ".txt", ".yml", ".yaml")):
        check_script(rep, path, text)
    elif suffix in (".yml", ".yaml", ".toml"):
        for ln, line in enumerate(text.splitlines(), start=1):
            if DOWNLOAD_EXEC.search(line):
                rep.add("SKL021", path, ln, line)


def check_bin_dirs(rep: Report, root: Path) -> None:
    base = root if root.is_dir() else root.parent
    for dirpath, dirnames, _ in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "bin" in dirnames and (Path(dirpath) / ".claude-plugin").is_dir():
            bdir = Path(dirpath) / "bin"
            names = sorted(p.name for p in bdir.iterdir())[:8]
            rep.add("SKL037", bdir, 0, "bin " + ",".join(names), evidence="bin/: %s" % ", ".join(names))


# ---------------------------------------------------------------- baseline, output

def load_baseline(path: Optional[str]) -> set:
    if not path:
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit("%s: error: cannot read baseline %s: %s" % (TOOL, path, exc))
    return {"%s|%s|%s" % (a.get("id"), a.get("path"), a.get("line_sha256")) for a in data.get("accepted", [])}


def write_baseline(path: str, findings: List[Dict[str, Any]]) -> None:
    accepted = []
    for f in findings:
        cid, rel, digest = f["_key"].split("|", 2)
        accepted.append({"id": cid, "path": rel, "line_sha256": digest, "title": f["title"], "location": f["location"],
                         "reason": "TODO: explain why this is acceptable"})
    Path(path).write_text(json.dumps({"version": 1, "tool": TOOL, "generated_at": now_iso(), "accepted": accepted}, indent=2) + "\n",
                          encoding="utf-8")


def finalize(rep: Report, target: str, baseline: set, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kept, suppressed = [], 0
    for f in rep.findings:
        if f["_key"] in baseline:
            suppressed += 1
        else:
            kept.append(f)
    kept.sort(key=lambda f: (RANK[f["severity"]], f["id"], f["location"]))
    summary = {s: sum(1 for f in kept if f["severity"] == s) for s in SEVERITIES}
    inv = dict(rep.inventory)
    inv["skills"] = sorted(set(inv["skills"]))
    inv["mcp_servers"] = sorted(set(inv["mcp_servers"]))
    out = {"tool": TOOL, "version": VERSION, "target": target, "generated_at": now_iso(),
           "inventory": inv, "suppressed_by_baseline": suppressed,
           "findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in kept], "summary": summary}
    if extra:
        out.update(extra)
    return out


def render_text(report: Dict[str, Any], quiet: bool) -> str:
    s = report["summary"]
    inv = report["inventory"]
    lines = ["%s %s  target=%s  (%d critical, %d high, %d medium, %d low, %d info)" % (
        TOOL, VERSION, report["target"], s["critical"], s["high"], s["medium"], s["low"], s["info"])]
    lines.append("Inventory: %d files, %d bytes; skills: %s; plugins: %s; marketplaces: %s; hooks: %s; MCP servers: %s; scripts: %d; binaries: %d" % (
        inv["files"], inv["bytes"], ", ".join(inv["skills"]) or "-", ", ".join(inv["plugins"]) or "-",
        ", ".join(inv["marketplaces"]) or "-",
        ", ".join("%s x%d" % kv for kv in sorted(inv["hooks"].items())) or "-",
        ", ".join(inv["mcp_servers"]) or "-", inv["scripts"], inv["binaries"]))
    if "changes" in report:
        c = report["changes"]
        lines.append("Changes since lock: %d added, %d modified, %d removed" % (len(c["added"]), len(c["modified"]), len(c["removed"])))
        for kind in ("added", "modified", "removed"):
            for p in c[kind]:
                lines.append("  %-8s %s" % (kind, p))
    if report.get("suppressed_by_baseline"):
        lines.append("Suppressed by baseline: %d" % report["suppressed_by_baseline"])
    current = None
    for f in report["findings"]:
        if quiet and f["severity"] == "info":
            continue
        if f["severity"] != current:
            current = f["severity"]
            lines.append("")
        lines.append("[%s] %s  %s" % (f["severity"].upper(), f["id"], f["title"]))
        lines.append("  at %s" % f["location"])
        lines.append("  evidence: %s" % f["evidence"])
        lines.append("  fix: %s" % f["fix"])
    lines.append("")
    lines.append("Summary: %d critical, %d high, %d medium, %d low, %d info. Static triage only: read every hook and script before approving." % (
        s["critical"], s["high"], s["medium"], s["low"], s["info"]))
    return "\n".join(lines)


def emit(report: Dict[str, Any], args: argparse.Namespace) -> int:
    text = json.dumps(report, indent=2) if args.json else render_text(report, args.quiet)
    sys.stdout.write(redact(text) + "\n")
    if args.fail_on:
        limit = RANK[args.fail_on]
        if any(RANK[f["severity"]] <= limit for f in report["findings"]):
            return 2
    return 0


# ---------------------------------------------------------------- SARIF

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
REPO_URL = "https://github.com/howardhsieh/agent-security-skills"


def write_sarif(path: str, rep: Report, baseline: set, uri_prefix: str = "") -> int:
    """Write SARIF 2.1.0 for GitHub code scanning; baseline-suppressed findings are omitted."""
    kept = [f for f in rep.findings if f["_key"] not in baseline]
    rules, index = [], {}
    for cid in sorted(CHECKS):
        sev, title, fix, refs = CHECKS[cid]
        index[cid] = len(rules)
        rules.append({
            "id": cid, "name": re.sub(r"[^A-Za-z0-9]+", "", title.title())[:60] or cid,
            "shortDescription": {"text": title}, "fullDescription": {"text": title},
            "help": {"text": fix + (" References: " + "; ".join(refs) if refs else "")},
            "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
            "properties": {"tags": ["security", "supply-chain", "agent-skills"], "security-severity": SECURITY_SEVERITY[sev],
                           "precision": "medium"},
        })
    prefix = uri_prefix.strip().strip("/").replace("\\", "/")
    prefix = "" if prefix in ("", ".") else prefix + "/"
    results = []
    for f in sorted(kept, key=lambda x: (RANK[x["severity"]], x["id"], x["location"])):
        loc = f["location"]
        m = re.match(r"^(.*?):(\d+)$", loc)
        file_part, line = (m.group(1), int(m.group(2))) if m else (loc, 0)
        phys = {"artifactLocation": {"uri": prefix + file_part, "uriBaseId": "%SRCROOT%"}}
        if line > 0:
            phys["region"] = {"startLine": line}
        results.append({
            "ruleId": f["id"], "ruleIndex": index[f["id"]], "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": "%s: %s" % (f["title"], f["evidence"])},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"agentsecFindingKey/v1": sha256_bytes(f["_key"].encode("utf-8"))},
            "properties": {"severity": f["severity"]},
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "agentsec-kit skill-supply-chain-audit", "version": VERSION,
                                         "informationUri": REPO_URL, "rules": rules}},
                     "results": results}]}
    Path(path).write_text(redact(json.dumps(doc, indent=2)) + "\n", encoding="utf-8")
    return len(results)


# ---------------------------------------------------------------- lock / diff

def file_hashes(root: Path) -> Dict[str, str]:
    hashes = {}
    base = root if root.is_dir() else root.parent
    for p, kind in iter_entries(root):
        rel = p.relative_to(base).as_posix()
        if kind == "link":
            try:
                hashes[rel] = "symlink:" + sha256_bytes(os.readlink(p).encode("utf-8", "replace"))
            except OSError:
                continue
        elif kind == "file":
            h = hashlib.sha256()
            try:
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
            except OSError:
                continue
            hashes[rel] = h.hexdigest()
    return dict(sorted(hashes.items()))


def tree_hash(entries: Dict[str, str]) -> str:
    h = hashlib.sha256()
    for path, digest in sorted(entries.items()):
        h.update(("%s\0%s\n" % (path, digest)).encode("utf-8"))
    return h.hexdigest()


def git_commit(root: Path) -> Optional[str]:
    """Read HEAD's commit from files only, never following paths outside .git."""
    git_dir = root / ".git"
    head = git_dir / "HEAD"
    if entry_kind(git_dir) == "link" or entry_kind(head) != "file":
        return None
    try:
        ref = head.read_text(encoding="utf-8", errors="replace")[:512].strip()
    except OSError:
        return None
    if HEX_SHA.fullmatch(ref):
        return ref
    if not ref.startswith("ref: refs/"):
        return None
    name = ref[5:].strip()
    if ".." in name.split("/") or not re.fullmatch(r"[A-Za-z0-9._/-]+", name):
        return None
    ref_path = git_dir / name
    if entry_kind(ref_path) == "file" and within(ref_path, git_dir):
        try:
            value = ref_path.read_text(encoding="utf-8", errors="replace")[:128].strip()
        except OSError:
            value = ""
        if HEX_SHA.fullmatch(value):
            return value
    packed = git_dir / "packed-refs"
    if entry_kind(packed) == "file":
        try:
            for line in packed.read_text(encoding="utf-8", errors="replace").splitlines()[:100000]:
                parts = line.split()
                if len(parts) == 2 and parts[1] == name and HEX_SHA.fullmatch(parts[0]):
                    return parts[0]
        except OSError:
            return None
    return None


def cmd_lock(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    files = file_hashes(root)
    skills = {}
    for rel in files:
        if rel.endswith("SKILL.md"):
            prefix = rel[: -len("SKILL.md")]
            skills[prefix.rstrip("/") or "."] = tree_hash({k: v for k, v in files.items() if k.startswith(prefix)})
    lock = {"version": 1, "tool": TOOL, "tool_version": VERSION, "generated_at": now_iso(), "root": root.name,
            "git_commit": git_commit(root), "tree_sha256": tree_hash(files), "skills": skills, "files": files}
    Path(args.out).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write("Locked %d files (%d skills) from %s into %s\ntree_sha256 %s\n" % (
        len(files), len(skills), root, args.out, lock["tree_sha256"]))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    try:
        lock = json.loads(Path(args.lock).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        sys.stderr.write("%s: error: cannot read lockfile: %s\n" % (TOOL, exc))
        return 1
    old = lock.get("files", {})
    new = file_hashes(root)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified = sorted(p for p in set(new) & set(old) if new[p] != old[p])
    rep = Report(root if root.is_dir() else root.parent)
    base = root if root.is_dir() else root.parent
    for rel in added + modified:
        kind = entry_kind(base / rel)
        if kind == "file":
            scan_file(rep, base / rel)
        else:
            rep.add("SKL039", base / rel, 0, "%s %s" % (kind, rel), evidence="%s (not read)" % ("symlink" if kind == "link" else "special file"))
    baseline = load_baseline(args.baseline)
    report = finalize(rep, str(root), baseline,
                      {"changes": {"added": added, "modified": modified, "removed": removed},
                       "lock": {"file": args.lock, "generated_at": lock.get("generated_at"), "git_commit": lock.get("git_commit")}})
    if args.sarif:
        write_sarif(args.sarif, rep, baseline, args.sarif_uri_prefix)
    return emit(report, args)


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    rep = Report(root if root.is_dir() else root.parent)
    for p in iter_files(root):
        scan_file(rep, p)
    report_links(rep, root)
    check_bin_dirs(rep, root)
    if args.write_baseline:
        write_baseline(args.write_baseline, rep.findings)
        sys.stderr.write("Wrote %d accepted findings to %s; add a reason to each.\n" % (len(rep.findings), args.write_baseline))
    baseline = load_baseline(args.baseline)
    report = finalize(rep, str(root), baseline)
    if args.sarif:
        write_sarif(args.sarif, rep, baseline, args.sarif_uri_prefix)
    return emit(report, args)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description="Review an Agent Skill, plugin or marketplace before installing it. Read-only.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="machine-readable JSON output")
        p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 2 if any finding is at or above this severity")
        p.add_argument("--quiet", action="store_true", help="hide info findings in text output")
        p.add_argument("--baseline", help="JSON file of accepted findings to suppress")
        p.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0 (for GitHub code scanning) to FILE")
        p.add_argument("--sarif-uri-prefix", default="", metavar="DIR",
                       help="prefix SARIF file paths with DIR (the scanned path relative to the repository root)")

    p_scan = sub.add_parser("scan", help="inventory and findings for a skill, plugin or repo")
    p_scan.add_argument("path")
    common(p_scan)
    p_scan.add_argument("--write-baseline", help="write all current findings to this file as accepted")
    p_lock = sub.add_parser("lock", help="write a hash lockfile of what you reviewed")
    p_lock.add_argument("path")
    p_lock.add_argument("--out", required=True, help="lockfile path; keep it outside the reviewed package")
    p_diff = sub.add_parser("diff", help="show and re-scan files changed since a lockfile")
    p_diff.add_argument("path")
    p_diff.add_argument("--lock", required=True, help="lockfile written by the lock subcommand")
    common(p_diff)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = ap.parse_args(argv)
    if not os.path.lexists(args.path):
        sys.stderr.write("%s: error: path not found: %s\n" % (TOOL, args.path))
        return 1
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "lock":
        return cmd_lock(args)
    return cmd_diff(args)


if __name__ == "__main__":
    sys.exit(main())
