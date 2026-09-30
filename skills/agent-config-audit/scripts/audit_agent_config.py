#!/usr/bin/env python3
"""Audit the local configuration of AI coding agents for risky settings.

Read-only. Covers Claude Code (settings files, managed settings, ~/.claude.json,
.mcp.json, installed plugin hooks), OpenAI Codex (config.toml, profile files,
system managed files) and Cursor (mcp.json, sandbox.json). Every MCP server found
is also checked for supply-chain and transport risks.

The script never executes anything it reads, never writes, and never uses the
network. Secret-looking values are redacted in every output.

Vendor keys, paths and precedence rules were verified against vendor docs on
2026-09-29 (see references/). Settings evolve quickly; re-verify before relying
on a result for a policy decision.

Usage:
  python3 audit_agent_config.py [--home DIR] [--project DIR]
      [--agent {claude-code,codex,cursor,all}] [--json] [--fail-on SEVERITY]
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

try:  # Python 3.11+
    import tomllib  # type: ignore
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    tomllib = None  # type: ignore

TOOL = "audit_agent_config.py"
VERSION = "0.1.1"
DOCS_VERIFIED = "2026-09-29"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
AGENTS = ("claude-code", "codex", "cursor")
MAX_FILE_BYTES = 5 * 1024 * 1024

CC = "https://code.claude.com/docs/en/"
CX = "https://learn.chatgpt.com/docs/"
CU = "https://cursor.com/docs/"

ASI02 = "ASI02 (Agentic Top 10 2026)"
ASI03 = "ASI03 (Agentic Top 10 2026)"
ASI04 = "ASI04 (Agentic Top 10 2026)"
ASI05 = "ASI05 (Agentic Top 10 2026)"
ASI09 = "ASI09 (Agentic Top 10 2026)"
T0083 = "AML.T0083 Credentials from AI Agent Configuration (MITRE ATLAS v2026.09)"
T0086 = "AML.T0086 Exfiltration via AI Agent Tool Invocation (MITRE ATLAS v2026.09)"
T0098 = "AML.T0098 AI Agent Tool Credential Harvesting (MITRE ATLAS v2026.09)"
T0010 = "AML.T0010.005 AI Supply Chain Compromise: AI Agent Tool (MITRE ATLAS v2026.09)"
T0081 = "AML.T0081 Modify AI Agent Configuration (MITRE ATLAS v2026.09)"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM06 = "LLM06:2025 Excessive Agency"

# ---------------------------------------------------------------------------
# Check catalogue. Severity is the default; some checks adjust it by scope, as
# noted in the title comment. Keep this table in sync with SKILL.md.
# ---------------------------------------------------------------------------
CHECKS: Dict[str, Dict[str, Any]] = {
    # General
    "GEN001": {"severity": "medium", "title": "Configuration file could not be parsed",
               "fix": "Fix the syntax and re-run. Claude Code skips a user, project or local settings file it cannot parse (silently in -p runs), so deny rules and sandbox settings in it are not in effect; an unparseable managed settings file stops it from starting.",
               "refs": [CC + "settings#fix-a-broken-settings-file"]},
    "GEN002": {"severity": "info", "title": "Agent config directory is overridden by an environment variable",
               "fix": "The agent reads a different directory than this audit did. Re-run with --claude-dir or --codex-dir pointing at it.",
               "refs": [CC + "settings#settings-files-and-who-they-affect", CX + "config-file/config-reference"]},
    "GEN003": {"severity": "info", "title": "TOML parsed with the limited fallback parser",
               "fix": "Run on Python 3.11+ (tomllib) for full TOML support; the fallback handles tables, key = value lines, arrays and inline tables only.",
               "refs": ["https://docs.python.org/3/library/tomllib.html"]},
    # Claude Code
    "CC001": {"severity": "high", "title": "Sessions start in bypassPermissions mode (critical when the sandbox is off)",
              "fix": "Remove permissions.defaultMode bypassPermissions (use default or acceptEdits) and set permissions.disableBypassPermissionsMode to \"disable\"; reserve bypass for disposable containers or VMs.",
              "refs": [ASI02, ASI05, LLM06, CC + "settings-reference#permissions-defaultmode", CC + "permissions#permission-modes"]},
    "CC002": {"severity": "medium", "title": "Repository settings request auto or bypassPermissions mode",
              "fix": "Remove defaultMode from the repository file. Claude Code v2.1.257+ ignores auto and bypassPermissions in project and local settings, but older versions honored bypassPermissions from any file; update Claude Code.",
              "refs": [ASI04, T0081, CC + "settings-reference#permissions-defaultmode"]},
    "CC003": {"severity": "low", "title": "Sessions start in auto mode",
              "fix": "Auto mode lets a background classifier approve actions instead of you. Keep deterministic controls (deny rules, sandbox) in place and consider autoMode.classifyAllShell: true so every shell command is reviewed.",
              "refs": [ASI09, CC + "settings-reference#automode-classifyallshell", CC + "permissions#permission-modes"]},
    "CC004": {"severity": "medium", "title": "Bypass-mode confirmation dialog is skipped",
              "fix": "Remove skipDangerousModePermissionPrompt. With it set in user or managed settings, a session started in bypassPermissions also connects project .mcp.json servers without asking.",
              "refs": [ASI02, CC + "settings-reference#skipdangerousmodepermissionprompt", CC + "mcp#project-scope"]},
    "CC005": {"severity": "high", "title": "Allow rule approves every shell command",
              "fix": "Replace Bash / Bash(*) / PowerShell allow rules with specific command rules such as Bash(npm run test *), and enable the sandbox.",
              "refs": [ASI05, ASI02, LLM06, CC + "permissions#permission-rule-syntax"]},
    "CC006": {"severity": "medium", "title": "Allow rule approves an interpreter or command runner",
              "fix": "Rules like Bash(python *), Bash(npx *) or Bash(docker exec *) approve arbitrary code. Allow the exact inner command instead, e.g. Bash(devbox run npm test).",
              "refs": [ASI05, CC + "permissions#bash", CC + "settings-reference#automode-classifyallshell"]},
    "CC007": {"severity": "medium", "title": "Allow rule approves network-capable commands or any web fetch",
              "fix": "Remove broad curl/wget/scp/ssh and bare WebFetch or WebFetch(domain:*) allow rules; allow WebFetch(domain:<host>) for the hosts you need and rely on the sandbox network allowlist.",
              "refs": [ASI02, T0086, CC + "permissions#webfetch", CC + "permissions#bash-rule-limits"]},
    "CC008": {"severity": "medium", "title": "No deny rules protect common secret files",
              "fix": "Add Read deny rules for .env files, ~/.ssh and ~/.aws (see the hardening plan). With the sandbox on, Read deny rules also feed sandbox.filesystem.denyRead, so they bind subprocesses too.",
              "refs": [ASI03, T0098, LLM02, CC + "settings-reference#permissions-deny", CC + "permissions#read-and-edit"]},
    "CC009": {"severity": "low", "title": "Bash deny rules are relied on without the sandbox",
              "fix": "Bash deny rules match the command text only (Bash(curl *) does not stop /usr/bin/curl or sh -c 'curl ...'). Enable the sandbox for OS-level enforcement.",
              "refs": [ASI02, CC + "permissions#bash-rule-limits", CC + "sandboxing"]},
    "CC010": {"severity": "medium", "title": "Bash sandbox is not enabled",
              "fix": "Set sandbox.enabled: true in ~/.claude/settings.json (macOS, Linux, WSL2; needs bubblewrap and socat on Linux). Without it, commands Claude runs have your full filesystem and network access.",
              "refs": [ASI05, T0086, CC + "settings-reference#sandbox-enabled", CC + "sandboxing"]},
    "CC011": {"severity": "high", "title": "Sandbox network allowlist permits any host (low when the sandbox is off)",
              "fix": "Replace \"*\", TLD wildcards and WebFetch(domain:*) allow rules with the specific hosts your tools need.",
              "refs": [ASI02, T0086, CC + "settings-reference#sandbox-network-alloweddomains", CC + "sandboxing#network-isolation"]},
    "CC012": {"severity": "low", "title": "Sandbox escape hatch is enabled",
              "fix": "Set sandbox.allowUnsandboxedCommands: false (strict sandbox mode) so Claude cannot retry blocked commands outside the sandbox; list tools that cannot run sandboxed in excludedCommands.",
              "refs": [ASI05, CC + "settings-reference#sandbox-allowunsandboxedcommands", CC + "sandboxing#the-unsandboxed-retry-escape-hatch"]},
    "CC013": {"severity": "medium", "title": "Sandbox isolation weakened by an option",
              "fix": "Remove the option unless an outer boundary (container, VM) provides the isolation; prefer filesystem.allowWrite for specific paths over exclusions.",
              "refs": [ASI05, CC + "sandboxing#security-limitations", CC + "settings-reference#sandbox-settings"]},
    "CC014": {"severity": "high", "title": "All project MCP servers are auto-approved (medium in repository files)",
              "fix": "Remove enableAllProjectMcpServers. Approve reviewed servers by name with enabledMcpjsonServers, and reject others with disabledMcpjsonServers.",
              "refs": [ASI04, T0010, CC + "settings-reference#enableallprojectmcpservers", CC + "mcp#project-server-approvals-and-workspace-trust"]},
    "CC015": {"severity": "medium", "title": "Repository settings define hooks or helper commands",
              "fix": "Review every command before trusting the folder. Hooks, the env block and helpers such as apiKeyHelper from a repository also run in claude -p and SDK sessions, which never show the trust dialog; for untrusted repos start interactive sessions with claude --safe-mode, and run claude -p with --setting-sources user --strict-mcp-config.",
              "refs": [ASI04, ASI05, CC + "permissions#what-runs-before-you-trust-a-folder", CC + "hooks#hook-locations"]},
    "CC016": {"severity": "high", "title": "Hook or helper command downloads code, sends data out, or reads credentials (medium for your own files)",
              "fix": "Remove or rewrite the command so it does not fetch-and-run code, contact remote hosts or read credential stores; organizations can restrict hooks with allowManagedHooksOnly.",
              "refs": [ASI05, ASI04, T0086, CC + "hooks#command-hook-fields", CC + "settings-reference#allowmanagedhooksonly"]},
    "CC017": {"severity": "medium", "title": "HTTP hook sends event data to a non-local endpoint (high over plaintext HTTP)",
              "fix": "Hook payloads include tool inputs. Use an https endpoint you control and set allowedHttpHookUrls (and httpHookAllowedEnvVars) to pin where hooks may send data.",
              "refs": [ASI02, T0086, CC + "hooks#http-hook-fields", CC + "settings-reference#allowedhttphookurls"]},
    "CC018": {"severity": "high", "title": "Literal secret in Claude Code settings (medium in files that stay local)",
              "fix": "Move the value out of the file: export it in your shell or use apiKeyHelper; env values are plain text and reach every subprocess. Rotate it if the file was ever committed or shared.",
              "refs": [ASI03, T0083, LLM02, CC + "settings-reference#env", CC + "settings-reference#apikeyhelper"]},
    "CC019": {"severity": "high", "title": "Repository env block injects code or redirects traffic",
              "fix": "Remove the variable from the repository's env block. Project env values apply after you trust the folder, and at startup in claude -p.",
              "refs": [ASI04, ASI05, T0081, CC + "settings-reference#env"]},
    "CC020": {"severity": "medium", "title": "Repository settings loosen a protection",
              "fix": "Project settings override user settings, so a committed file can switch off your sandbox or re-enable hooks. Remove the key from the repository, or enforce the value from managed settings.",
              "refs": [ASI04, T0081, CC + "settings#settings-precedence", CC + "hooks#disable-or-remove-hooks"]},
    "CC021": {"severity": "low", "title": "Third-party plugin marketplace registered",
              "fix": "Plugins from a marketplace run code (hooks, MCP servers). Keep only marketplaces you trust and pin a ref; organizations can enforce strictKnownMarketplaces.",
              "refs": [ASI04, T0010, CC + "settings-reference#extraknownmarketplaces", CC + "settings-reference#strictknownmarketplaces"]},
    "CC022": {"severity": "low", "title": "bypassPermissions mode is not disabled",
              "fix": "Set permissions.disableBypassPermissionsMode to \"disable\" in your user settings (it works from any scope) so --dangerously-skip-permissions is rejected.",
              "refs": [ASI09, CC + "settings-reference#permissions-disablebypasspermissionsmode"]},
    "CC023": {"severity": "low", "title": "Managed-only key has no effect outside managed settings",
              "fix": "Move the key to managed settings (managed-settings.json, MDM or server-managed settings); Claude Code ignores it in user and project files.",
              "refs": [CC + "managed-settings#keys-only-a-managed-source-can-set"]},
    "CC024": {"severity": "info", "title": "Installed plugin ships hooks",
              "fix": "Review plugin hooks like any code you run; remove plugins you no longer use.",
              "refs": [ASI04, CC + "hooks#hook-locations", CC + "plugins/loading#find-plugins-on-disk"]},
    # Codex
    "CX001": {"severity": "high", "title": "Codex sandbox disabled with danger-full-access (critical with approval_policy never)",
              "fix": "Use sandbox_mode = \"workspace-write\" (or default_permissions = \":workspace\") with approval_policy = \"on-request\"; reserve full access for an isolated container.",
              "refs": [ASI05, ASI02, CX + "agent-approvals-security#sandbox-and-approvals", CX + "config-file/config-reference"]},
    "CX002": {"severity": "medium", "title": "Codex never asks for approval outside a read-only sandbox (high with network on)",
              "fix": "Use approval_policy = \"on-request\" for interactive work; reserve never for read-only CI runs.",
              "refs": [ASI09, LLM06, CX + "agent-approvals-security#common-sandbox-and-approval-combinations"]},
    "CX003": {"severity": "medium", "title": "Retired or deprecated approval_policy value (low for on-failure)",
              "fix": "approval_policy = \"untrusted\" is retired and can stop Codex from starting; on-failure is deprecated. Use on-request, or keep strict command approval via projects.<path>.trust_level = \"untrusted\".",
              "refs": [CX + "agent-approvals-security#migrate-from-the-retired-untrusted-approval-policy"]},
    "CX004": {"severity": "high", "title": "Codex sandboxed commands have unrestricted network access",
              "fix": "Keep network_access = false, or enable [features.network_proxy] with scoped domain allow rules; without the proxy, enabled network access is direct and unrestricted.",
              "refs": [ASI02, T0086, CX + "agent-approvals-security#network-isolation"]},
    "CX005": {"severity": "medium", "title": "Codex commands inherit secret-named environment variables (low without network access)",
              "fix": "Set [shell_environment_policy] ignore_default_excludes = false so variables containing KEY, SECRET or TOKEN are excluded (the documented default keeps them), or add exclude filters.",
              "refs": [ASI03, T0098, CX + "config-file/config-reference"]},
    "CX006": {"severity": "medium", "title": "Literal credential in Codex config (high in repository files)",
              "fix": "Reference credentials by environment variable (env_key for model providers, bearer_token_env_var / env_vars for MCP servers) and rotate the exposed value.",
              "refs": [ASI03, T0083, LLM02, CX + "config-file/config-reference"]},
    "CX007": {"severity": "info", "title": "Trusted Codex projects",
              "fix": "Trusted projects load their .codex/ config, hooks and rules. Remove trust for repositories you no longer work in.",
              "refs": [CX + "config-file/config-reference"]},
    "CX008": {"severity": "info", "title": "Repository Codex config present",
              "fix": "Codex loads project .codex/config.toml only when you trust the project; review it before trusting.",
              "refs": [ASI04, CX + "config-file/config-reference"]},
    "CX009": {"severity": "medium", "title": "Repository Codex config defines hooks",
              "fix": "Review hook commands before trusting the project; admins can set allow_managed_hooks_only in requirements.toml.",
              "refs": [ASI04, ASI05, CX + "config-file/config-reference"]},
    "CX010": {"severity": "high", "title": "Codex hook command downloads code, sends data out, or reads credentials (medium for your own files)",
              "fix": "Remove or rewrite the hook so it does not fetch-and-run code, contact remote hosts or read credential stores.",
              "refs": [ASI05, T0086, CX + "config-file/config-reference"]},
    "CX011": {"severity": "medium", "title": "Codex network proxy safety switch disabled",
              "fix": "Leave dangerously_allow_non_loopback_proxy and dangerously_allow_all_unix_sockets false outside tightly controlled environments.",
              "refs": [ASI02, CX + "agent-approvals-security#dangerous-settings"]},
    "CX012": {"severity": "low", "title": "Codex live web search enabled",
              "fix": "Live results expose the agent to arbitrary page content (prompt injection). Prefer web_search = \"cached\" (default) unless live retrieval is needed.",
              "refs": ["ASI01 (Agentic Top 10 2026)", CX + "agent-approvals-security#traffic-outside-the-command-network-proxy"]},
    # Cursor
    "CU001": {"severity": "high", "title": "Cursor sandbox disabled in sandbox.json",
              "fix": "Remove \"type\": \"insecure_none\"; the default workspace_readwrite sandbox limits file and network access for terminal commands.",
              "refs": [ASI05, CU + "reference/sandbox"]},
    "CU002": {"severity": "medium", "title": "Cursor sandbox allows all network destinations",
              "fix": "Use networkPolicy.default \"deny\" with specific allow entries; avoid \"*\" and 0.0.0.0/0.",
              "refs": [ASI02, T0086, CU + "reference/sandbox"]},
    "CU003": {"severity": "info", "title": "Cursor Run Mode is an app setting (manual check)",
              "fix": "Check Settings > Agents > Approvals & Execution: Run Everything runs every tool call automatically; prefer Auto-review or Allowlist with sandboxing, and keep the network mode off Allow All.",
              "refs": [ASI09, CU + "agent/security/run-modes"]},
    # MCP (all agents)
    "MCP001": {"severity": "medium", "title": "MCP server launched from an unpinned package",
               "fix": "Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) or install the server locally, so each launch does not fetch whatever was published last.",
               "refs": [ASI04, T0010, CC + "mcp#installing-mcp-servers", CU + "mcp"]},
    "MCP002": {"severity": "high", "title": "MCP server reached over plaintext HTTP to a non-local host",
               "fix": "Use an https:// URL; plaintext exposes credentials and tool traffic to the network path.",
               "refs": [ASI03, ASI04, "MCP Security Best Practices 2026-07-28 (https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)"]},
    "MCP003": {"severity": "high", "title": "Literal secret in MCP server configuration (medium in files that stay local)",
               "fix": "Reference secrets instead of embedding them: ${VAR} or headersHelper in Claude Code .mcp.json, bearer_token_env_var / env_vars / env_http_headers in Codex, ${env:NAME} or envFile in Cursor. Rotate the exposed value.",
               "refs": [ASI03, T0083, LLM02, CC + "mcp#environment-variable-expansion-in-mcp-json", CX + "config-file/config-reference", CU + "mcp"]},
    "MCP004": {"severity": "low", "title": "MCP server launched through a shell wrapper (high when it downloads and runs code)",
               "fix": "Launch the server binary directly with an args array; a shell string hides what actually runs and defeats serverCommand allowlists.",
               "refs": [ASI04, ASI05, CC + "settings-reference#allowedmcpservers"]},
    "MCP005": {"severity": "info", "title": "MCP server inventory",
               "fix": "Confirm you still need and trust each server; remove the rest.",
               "refs": [ASI04, CC + "mcp#mcp-installation-scopes"]},
    "MCP006": {"severity": "medium", "title": "Repository-supplied MCP server (low for remote servers)",
               "fix": "Review the server before approving it. Claude Code connects .mcp.json servers without asking in claude -p, SDK and cloud sessions; block unwanted ones with disabledMcpjsonServers.",
               "refs": [ASI04, T0010, CC + "mcp#project-scope", CC + "permissions#what-runs-before-you-trust-a-folder"]},
}

# ---------------------------------------------------------------------------
# Hardening plan snippets (verified against vendor docs on DOCS_VERIFIED).
# ---------------------------------------------------------------------------
SNIP_CC_DENY = """{
  "permissions": {
    "deny": [
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Read(~/.config/gh/**)",
      "Read(~/.netrc)",
      "Read(~/.git-credentials)",
      "Read(~/.docker/config.json)",
      "Read(~/.kube/config)"
    ]
  }
}"""
SNIP_CC_SANDBOX = """{
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.aws", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" },
        { "name": "NPM_TOKEN", "mode": "deny" }
      ]
    }
  }
}"""
SNIP_CC_BYPASS = """{
  "permissions": {
    "defaultMode": "default",
    "disableBypassPermissionsMode": "disable"
  }
}"""
SNIP_CC_ALLOW = """{
  "permissions": {
    "allow": ["Bash(npm run test *)", "Bash(git diff *)", "WebFetch(domain:docs.example.com)"],
    "ask": ["Bash(git push *)"]
  }
}"""
SNIP_CC_MCP_APPROVE = """{
  "enabledMcpjsonServers": ["<reviewed-server>"],
  "disabledMcpjsonServers": ["<unwanted-server>"]
}"""
SNIP_CC_UNTRUSTED_P = """claude --safe-mode                                     # interactive: no repo settings, hooks, skills or MCP
claude -p --setting-sources user --strict-mcp-config "..."   # non-interactive: user settings only, no .mcp.json servers
"""
SNIP_CC_HTTP_HOOKS = """{
  "allowedHttpHookUrls": ["https://hooks.example.com/*"],
  "httpHookAllowedEnvVars": ["HOOK_TOKEN"]
}"""
SNIP_CC_MCP_SECRET = """{
  "mcpServers": {
    "api-server": {
      "type": "http",
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer ${API_TOKEN}" }
    }
  }
}"""
SNIP_CX_BASE = """sandbox_mode    = "workspace-write"
approval_policy = "on-request"

[sandbox_workspace_write]
network_access = false

[shell_environment_policy]
ignore_default_excludes = false"""
SNIP_CX_NET = """[sandbox_workspace_write]
network_access = true

[features.network_proxy]
enabled = true
domains = { "registry.npmjs.org" = "allow" }"""
SNIP_CX_MCP = """[mcp_servers.remote-example]
url = "https://mcp.example.com/mcp"
bearer_token_env_var = "EXAMPLE_MCP_TOKEN"

[mcp_servers.local-example]
command = "example-mcp-server"
env_vars = ["EXAMPLE_API_KEY"]"""
SNIP_CX_REQ = """# /etc/codex/requirements.toml (admin-enforced)
allowed_approval_policies = ["untrusted", "on-request"]
allowed_sandbox_modes     = ["read-only", "workspace-write"]"""
SNIP_CU_MCP = """{
  "mcpServers": {
    "example": {
      "command": "npx",
      "args": ["-y", "example-mcp-server@1.2.3"],
      "env": { "API_KEY": "${env:EXAMPLE_API_KEY}" }
    }
  }
}"""
SNIP_CU_SANDBOX = """{
  "networkPolicy": {
    "default": "deny",
    "allow": ["registry.npmjs.org"]
  }
}"""
SNIP_MCP_PIN = """"args": ["-y", "@scope/example-mcp-server@1.4.2"]"""

SNIP_CC_DOMAINS = """{
  "sandbox": {
    "network": {
      "allowedDomains": ["github.com", "registry.npmjs.org", "api.example.com:443"]
    }
  }
}"""
SNIP_CC_SECRET = """{
  "apiKeyHelper": "~/.claude/bin/get-api-key.sh"
}"""
SNIP_CX_SECRET = """[model_providers.example]
base_url = "https://llm.example.com/v1"
env_key  = "EXAMPLE_API_KEY"
"""
SNIP_HTTPS = '"url": "https://mcp.example.com/mcp"'

# Plan items, in the order they are tried; the first item whose ids (and agent, if set) match a
# finding addresses it. Each item appears once, ranked by its most severe finding.
PLAN_ITEMS: List[Dict[str, Any]] = [
    {"ids": {"CC001", "CC002", "CC004", "CC022"}, "agent": "claude-code", "target": "~/.claude/settings.json",
     "lang": "json", "snippet": SNIP_CC_BYPASS,
     "note": "Also delete skipDangerousModePermissionPrompt, and any defaultMode set in repository files."},
    {"ids": {"CC005", "CC006", "CC007"}, "agent": "claude-code", "target": "the settings file each finding names",
     "lang": "json", "snippet": SNIP_CC_ALLOW, "note": "Replace broad allow rules with exact commands and hosts."},
    {"ids": {"CC008"}, "agent": "claude-code", "target": "~/.claude/settings.json (or managed settings)",
     "lang": "json", "snippet": SNIP_CC_DENY, "note": "Merge into the existing permissions.deny list."},
    {"ids": {"CC009", "CC010", "CC012", "CC013"}, "agent": "claude-code", "target": "~/.claude/settings.json (or managed settings)",
     "lang": "json", "snippet": SNIP_CC_SANDBOX,
     "note": "macOS, Linux and WSL2 only; Linux needs bubblewrap and socat. Remove weakening options the findings name."},
    {"ids": {"CC011"}, "agent": "claude-code", "target": "the settings file each finding names",
     "lang": "json", "snippet": SNIP_CC_DOMAINS, "note": "List only the hosts your tools need; remove \"*\" and WebFetch(domain:*)."},
    {"ids": {"CC014", "MCP006"}, "agent": "claude-code", "target": "~/.claude/settings.json or .claude/settings.local.json",
     "lang": "json", "snippet": SNIP_CC_MCP_APPROVE, "note": "Remove enableAllProjectMcpServers; approve reviewed servers by name."},
    {"ids": {"CC015", "CC019", "CC020"}, "agent": "claude-code", "target": "your shell, for repositories you have not reviewed",
     "lang": "sh", "snippet": SNIP_CC_UNTRUSTED_P,
     "note": "Keeps project hooks, env and .mcp.json out of non-interactive runs; review the repository files before trusting."},
    {"ids": {"CC016", "CX010"}, "agent": None, "target": "the hook or helper each finding names",
     "lang": "text", "snippet": "Delete the handler, or replace it with a reviewed local script that makes no network calls.",
     "note": "Organizations: allowManagedHooksOnly (Claude Code) or allow_managed_hooks_only (Codex requirements.toml)."},
    {"ids": {"CC017"}, "agent": "claude-code", "target": "~/.claude/settings.json (or managed settings)",
     "lang": "json", "snippet": SNIP_CC_HTTP_HOOKS, "note": "Pins where HTTP hooks may send event data."},
    {"ids": {"CC018"}, "agent": "claude-code", "target": "~/.claude/settings.json",
     "lang": "json", "snippet": SNIP_CC_SECRET, "note": "Remove the literal from env, export it in your shell or use a helper, and rotate it."},
    {"ids": {"CX001", "CX002", "CX003", "CX005"}, "agent": "codex", "target": "~/.codex/config.toml",
     "lang": "toml", "snippet": SNIP_CX_BASE, "note": "Admins can enforce this with requirements.toml (see org recommendations)."},
    {"ids": {"CX004", "CX011"}, "agent": "codex", "target": "~/.codex/config.toml",
     "lang": "toml", "snippet": SNIP_CX_NET, "note": "Or set network_access = false. The proxy does not filter MCP, web search or apps."},
    {"ids": {"CX006"}, "agent": "codex", "target": "~/.codex/config.toml",
     "lang": "toml", "snippet": SNIP_CX_SECRET, "note": "Reference credentials by environment variable, then rotate the exposed value."},
    {"ids": {"CU001", "CU002"}, "agent": "cursor", "target": "~/.cursor/sandbox.json or .cursor/sandbox.json",
     "lang": "json", "snippet": SNIP_CU_SANDBOX, "note": "Also check the network mode in Settings > Agents > Approvals & Execution."},
    {"ids": {"MCP003"}, "agent": "claude-code", "target": ".mcp.json or ~/.claude.json", "lang": "json",
     "snippet": SNIP_CC_MCP_SECRET, "note": "Rotate the exposed value. headersHelper is an alternative for short-lived tokens."},
    {"ids": {"MCP003"}, "agent": "codex", "target": "~/.codex/config.toml", "lang": "toml",
     "snippet": SNIP_CX_MCP, "note": "Rotate the exposed value."},
    {"ids": {"MCP003"}, "agent": "cursor", "target": ".cursor/mcp.json or ~/.cursor/mcp.json", "lang": "json",
     "snippet": SNIP_CU_MCP, "note": "Rotate the exposed value. envFile is an alternative for stdio servers."},
    {"ids": {"MCP001"}, "agent": None, "target": "the MCP config each finding names", "lang": "json",
     "snippet": SNIP_MCP_PIN, "note": "Pin exact versions (npm @x.y.z, PyPI ==x.y.z, container @sha256:...)."},
    {"ids": {"MCP002"}, "agent": None, "target": "the MCP config each finding names", "lang": "json",
     "snippet": SNIP_HTTPS, "note": "Use TLS for every non-local MCP endpoint."},
]

ORG_RECOMMENDATIONS = [
    ("claude-code", "allowManagedPermissionRulesOnly", "only managed allow/ask/deny rules apply"),
    ("claude-code", "allowManagedHooksOnly", "only managed, SDK and managed force-enabled plugin hooks run"),
    ("claude-code", "allowManagedMcpServersOnly", "only the managed allowedMcpServers list applies"),
    ("claude-code", "strictKnownMarketplaces", "allowlist of plugin marketplace sources"),
    ("claude-code", "disableSkillShellExecution", "replace inline !`...` shell in skills and commands (a managed true cannot be overridden)"),
    ("claude-code", "sandbox.network.allowManagedDomainsOnly", "only managed allowedDomains apply"),
    ("claude-code", "sandbox.filesystem.allowManagedReadPathsOnly", "only managed allowRead paths apply"),
    ("claude-code", "permissions.disableBypassPermissionsMode", "reject --dangerously-skip-permissions fleet-wide"),
    ("codex", "requirements.toml allowed_sandbox_modes / allowed_approval_policies", "block danger-full-access and never"),
    ("codex", "requirements.toml allow_managed_hooks_only", "skip user, project, session and plugin hooks"),
    ("cursor", "Team Settings > MCP Configuration allowlist; team Run Modes", "dashboard-managed; not in local files"),
]

MANUAL_CHECKS = {
    "claude-code": [
        "Managed policy can also come from server-managed settings, macOS MDM (com.anthropic.claudecode) or the Windows registry; run /status in Claude Code and read the Setting sources line.",
        "CLI flags and shell aliases (--dangerously-skip-permissions, --permission-mode, --allowedTools, --settings, --mcp-config) are invisible to this audit.",
        "claude.ai connectors are not in local files; review them at claude.ai/customize/connectors.",
        "A tracked .claude/settings.local.json is treated as repository-supplied; check with git ls-files.",
    ],
    "codex": [
        "Requirements delivered from the cloud or macOS MDM (com.openai.codex requirements_toml_base64) are not read; check the startup config summary.",
        "Standalone hooks.json files and execution-policy rules are not audited.",
    ],
    "cursor": [
        "Run Mode, sandbox network mode and Browser / File-Deletion / External-File Protection live in Settings > Agents > Approvals & Execution.",
        "Team dashboard policies (MCP allowlist, Run Modes, sandbox networking) override local files and are not visible here.",
    ],
    "all": [
        "OS keychains, IDE extensions, browser extensions with page access and connected accounts are out of scope; review them separately.",
    ],
}

# ---------------------------------------------------------------------------
# Secret detection and redaction
# ---------------------------------------------------------------------------
KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-ant-[A-Za-z0-9_\-]{8,}|sk-(?:proj-)?[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}|xox[abposr]-[A-Za-z0-9\-]{10,}|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
    r"|AIza[0-9A-Za-z_\-]{30,}|glpat-[A-Za-z0-9_\-]{16,}|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}"
    r"|hvs\.[A-Za-z0-9_\-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
)
SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|passw(or)?d|passphrase|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|credential|authorization|^auth$|bearer|cookie|session[_-]?id|signature|(^|[_-])key$)"
)
PASSWORD_KEY_RE = re.compile(r"(?i)(passw(or)?d|passphrase|pwd)")
PLACEHOLDER_RE = re.compile(
    r"(?i)^(<[^>]*>|your[-_ ].*|.*[-_]here|x{3,}|\*{3,}|changeme|placeholder|example|redacted|none|null|true|false|value|test)$"
)
URL_USERINFO_RE = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@:]+:[^/\s@]+@")
QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|key|api[_-]?key|apikey|access[_-]?token|auth|secret|password|sig|signature|code)=)([^&#\s\"']+)"
)
AUTH_SCHEME_RE = re.compile(r"(?i)\b(Bearer|Basic|Token)(\s+)(?!\$)([A-Za-z0-9._~+/=\-]{8,})")
KV_SECRET_RE = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token|secret|password|passwd|pwd)"
    r"[\"']?\s*[=:]\s*[\"']?)(?![$<])([^\s\"'&<>,;]{8,})"
)
FLAG_SECRET_RE = re.compile(
    r"(?i)(--?[\w-]*(?:token|api[_-]?key|secret|passw(?:or)?d)[\w-]*\s+[\"']?)(?![-$<])([^\s\"']{8,})"
)
CLI_SECRET_RES = [
    re.compile(r"(?i)((?:^|[\s\"'])(?:-u|--user|--proxy-user)\s*[\"']?[^\s:\"'/]+:)(?![$<])([^\s\"'@]+)"),  # curl -u user:pass
    re.compile(r"(?i)(\bsshpass\s+-p\s*[\"']?)([^\s\"']+)"),
    re.compile(r"(\bmysql(?:dump|admin)?\b[^\n|;&]*?\s-p)([^\s\"'-][^\s\"']{2,})"),
    re.compile(r"(?i)(--password=[\"']?)(?![$<])([^\s\"']{3,})"),
]
SECRET_FLAG_RE = re.compile(r"(?i)^--?[\w-]*(token|key|secret|passw(or)?d|auth)[\w-]*$")
ENV_REF_RE = re.compile(r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SCRIPT_TOKEN_RE = re.compile(r"[^\s;&|<>()=]+\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb|pl)\b")


def redact_value(value: str) -> str:
    return "<redacted:%d chars>" % len(value)


def redact_text(text: Any) -> str:
    """Redact anything secret-shaped inside free text (commands, URLs, args)."""
    s = str(text)
    s = URL_USERINFO_RE.sub(lambda m: m.group(1) + "<redacted>@", s)
    s = KNOWN_TOKEN_RE.sub(lambda m: redact_value(m.group(0)), s)
    s = QUERY_SECRET_RE.sub(lambda m: m.group(1) + redact_value(m.group(2)), s)
    s = AUTH_SCHEME_RE.sub(lambda m: m.group(1) + m.group(2) + redact_value(m.group(3)), s)
    s = KV_SECRET_RE.sub(lambda m: m.group(1) + redact_value(m.group(2)), s)
    s = FLAG_SECRET_RE.sub(lambda m: m.group(1) + redact_value(m.group(2)), s)
    for rx in CLI_SECRET_RES:
        s = rx.sub(lambda m: m.group(1) + redact_value(m.group(2)), s)
    return s


def _final_scrub(text: str) -> str:
    """Last-line defence on every emitted string: known token shapes and URL creds."""
    text = URL_USERINFO_RE.sub(lambda m: m.group(1) + "<redacted>@", text)
    return KNOWN_TOKEN_RE.sub(lambda m: redact_value(m.group(0)), text)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def is_reference(value: str) -> bool:
    """True if the whole value is an environment-variable reference."""
    return bool(ENV_REF_RE.match(value.strip()))


def looks_secret(key: Optional[str], value: Any) -> bool:
    """True if a config value looks like a literal credential."""
    if not isinstance(value, str):
        return False
    if KNOWN_TOKEN_RE.search(value):
        return True
    v = re.sub(r"(?i)^(bearer|basic|token)\s+", "", value.strip())
    if len(v) < 8 or is_reference(v) or "${" in v or "$(" in v:
        return False
    if not key or not SECRET_KEY_RE.search(str(key)) or re.search(r"(?i)(env_?vars?|env_?key|_env)$", str(key)):
        return False
    if re.search(r"\s", v) or PLACEHOLDER_RE.match(v) or ENV_NAME_RE.match(v):
        return False
    if v.startswith(("/", "~", "./", "../", "http://", "https://")) or re.match(r"^[A-Za-z]:\\", v):
        return False
    if PASSWORD_KEY_RE.search(str(key)):
        return True
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return len(v) >= 20 and _entropy(v) >= 3.0 and classes >= 2


def header_secret(name: str, value: Any) -> bool:
    """Literal credential in an HTTP header value (Authorization: Bearer <literal>, X-Api-Key: <literal>)."""
    if not isinstance(value, str):
        return False
    m = re.match(r"(?i)^(bearer|basic|token)\s+(\S+)$", value.strip())
    if m:
        cred = m.group(2)
        return len(cred) >= 8 and not is_reference(cred) and "${" not in cred and not PLACEHOLDER_RE.match(cred)
    return looks_secret(name, value)


def trunc(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def display_command(command: Any, args: Any = None) -> str:
    parts: List[str] = []
    if command:
        parts.append(str(command))
    prev_secret_flag = False
    for a in args or []:
        a = str(a)
        if prev_secret_flag and not a.startswith("-") and not is_reference(a):
            parts.append(redact_value(a))
        elif "=" in a and SECRET_FLAG_RE.match(a.split("=", 1)[0]) and not is_reference(a.split("=", 1)[1]):
            k, v = a.split("=", 1)
            parts.append(k + "=" + redact_value(v))
        else:
            parts.append(a)
        prev_secret_flag = bool(SECRET_FLAG_RE.match(a))
    return redact_text(" ".join(parts))


def _redact_segment(seg: str) -> str:
    if len(seg) >= 16 and re.search(r"[A-Za-z]", seg) and re.search(r"[0-9]", seg) and _entropy(seg) >= 3.0:
        return redact_value(seg)
    return seg


def display_url(url: str) -> str:
    """scheme://host[:port]/path with userinfo, query, fragment and secret-looking path segments removed."""
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        if u.port:
            host += ":%d" % u.port
        path = "/".join(_redact_segment(seg) for seg in u.path.split("/"))
        return redact_text("%s://%s%s%s" % (u.scheme, host, path, "?<query omitted>" if u.query else ""))
    except ValueError:
        return redact_text(url)


# ---------------------------------------------------------------------------
# Minimal TOML fallback (Python < 3.11). Handles comments, [tables],
# [[arrays of tables]], dotted and quoted keys, strings, numbers, booleans,
# dates (kept as strings), arrays (multi-line) and inline tables.
# ---------------------------------------------------------------------------
class TomlFallbackError(ValueError):
    pass


def _toml_strip_comment(line: str) -> str:
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _toml_balanced(text: str) -> bool:
    depth, quote, i = 0, None, 0
    if text.count('"""') % 2 or text.count("'''") % 2:
        return False
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth <= 0


def _toml_split_key(key: str) -> List[str]:
    parts, buf, quote = [], [], None
    for ch in key.strip():
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch == ".":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf).strip())
    if any(p == "" for p in parts):
        raise TomlFallbackError("invalid key")
    return parts


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "b": "\b", "f": "\f"}


def _toml_value(s: str, i: int) -> Tuple[Any, int]:
    while i < len(s) and s[i] in " \t\r\n":
        i += 1
    if i >= len(s):
        raise TomlFallbackError("missing value")
    if s.startswith('"""', i) or s.startswith("'''", i):
        q = s[i:i + 3]
        end = s.find(q, i + 3)
        if end < 0:
            raise TomlFallbackError("unterminated string")
        return s[i + 3:end].lstrip("\n"), end + 3
    ch = s[i]
    if ch == '"':
        out, j = [], i + 1
        while j < len(s):
            c = s[j]
            if c == "\\" and j + 1 < len(s):
                n = s[j + 1]
                if n == "u" and j + 5 < len(s):
                    out.append(chr(int(s[j + 2:j + 6], 16)))
                    j += 6
                    continue
                out.append(_ESCAPES.get(n, n))
                j += 2
                continue
            if c == '"':
                return "".join(out), j + 1
            out.append(c)
            j += 1
        raise TomlFallbackError("unterminated string")
    if ch == "'":
        end = s.find("'", i + 1)
        if end < 0:
            raise TomlFallbackError("unterminated string")
        return s[i + 1:end], end + 1
    if ch == "[":
        arr, j = [], i + 1
        while True:
            while j < len(s) and s[j] in " \t\r\n,":
                j += 1
            if j >= len(s):
                raise TomlFallbackError("unterminated array")
            if s[j] == "]":
                return arr, j + 1
            val, j = _toml_value(s, j)
            arr.append(val)
    if ch == "{":
        tbl: Dict[str, Any] = {}
        j = i + 1
        while True:
            while j < len(s) and s[j] in " \t,":
                j += 1
            if j >= len(s):
                raise TomlFallbackError("unterminated inline table")
            if s[j] == "}":
                return tbl, j + 1
            eq = _toml_find_eq(s, j)
            keys = _toml_split_key(s[j:eq])
            val, j = _toml_value(s, eq + 1)
            _toml_set(tbl, keys, val)
    m = re.compile(r"true|false").match(s, i)
    if m:
        return m.group(0) == "true", m.end()
    m = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}:\d{2}(?:\.\d+)?").match(s, i)
    if m:
        return m.group(0), m.end()
    m = re.compile(r"[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|inf|nan|[0-9_]+(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)").match(s, i)
    if m and m.group(0) not in ("+", "-"):
        txt = m.group(0).replace("_", "")
        try:
            if txt.lower().lstrip("+-").startswith(("0x", "0o", "0b")):
                return int(txt, 0), m.end()
            if any(c in txt.lower() for c in ".en") or txt.lower().lstrip("+-") in ("inf", "nan"):
                return float(txt), m.end()
            return int(txt), m.end()
        except ValueError:
            raise TomlFallbackError("invalid number")
    raise TomlFallbackError("invalid value")


def _toml_find_eq(s: str, start: int) -> int:
    quote = None
    for j in range(start, len(s)):
        ch = s[j]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "=":
            return j
    raise TomlFallbackError("expected '='")


def _toml_descend(root: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    cur: Any = root
    for k in keys:
        nxt = cur.get(k)
        if nxt is None:
            nxt = {}
            cur[k] = nxt
        if isinstance(nxt, list):
            if not nxt or not isinstance(nxt[-1], dict):
                raise TomlFallbackError("key conflict")
            nxt = nxt[-1]
        if not isinstance(nxt, dict):
            raise TomlFallbackError("key conflict")
        cur = nxt
    return cur


def _toml_set(table: Dict[str, Any], keys: List[str], value: Any) -> None:
    target = _toml_descend(table, keys[:-1])
    if keys[-1] in target:
        raise TomlFallbackError("duplicate key")
    target[keys[-1]] = value


def toml_fallback_loads(text: str) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    current = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _toml_strip_comment(lines[i]).strip()
        i += 1
        if not line:
            continue
        if line.startswith("[["):
            if not line.endswith("]]"):
                raise TomlFallbackError("invalid table header")
            keys = _toml_split_key(line[2:-2])
            parent = _toml_descend(root, keys[:-1])
            arr = parent.setdefault(keys[-1], [])
            if not isinstance(arr, list):
                raise TomlFallbackError("key conflict")
            current = {}
            arr.append(current)
        elif line.startswith("["):
            if not line.endswith("]"):
                raise TomlFallbackError("invalid table header")
            current = _toml_descend(root, _toml_split_key(line[1:-1]))
        else:
            buf = line
            while not _toml_balanced(buf) and i < len(lines):
                buf += "\n" + _toml_strip_comment(lines[i])
                i += 1
            eq = _toml_find_eq(buf, 0)
            keys = _toml_split_key(buf[:eq])
            value, end = _toml_value(buf, eq + 1)
            if buf[end:].strip():
                raise TomlFallbackError("trailing characters")
            _toml_set(current, keys, value)
    return root


def parse_toml(text: str) -> Tuple[Dict[str, Any], bool]:
    """Return (data, used_fallback)."""
    if tomllib is not None:
        return tomllib.loads(text), False
    return toml_fallback_loads(text), True


def strip_jsonc(text: str) -> str:
    out, i, quote = [], 0, False
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
class Source:
    def __init__(self, agent: str, kind: str, scope: str, path: Path, display: str,
                 shared: str = "", root: Optional[Path] = None, fmt: str = "json") -> None:
        self.agent = agent
        self.kind = kind
        self.scope = scope
        self.path = path
        self.display = display
        self.shared = shared  # why others can read it, e.g. "committed to the repository"
        self.root = root  # plugin root, for ${CLAUDE_PLUGIN_ROOT}
        self.fmt = fmt
        self.data: Any = None
        self.text = ""
        self.error: Optional[str] = None
        self.fallback = False
        self.exists = path.is_file()

    def label(self) -> str:
        return "%s %s%s" % (self.agent, self.scope, " (shared: %s)" % self.shared if self.shared else "")

    def find_line(self, keys: List[Any]) -> Optional[int]:
        if not self.text:
            return None
        lines = self.text.splitlines()
        idx, found = 0, None
        for k in keys:
            if not isinstance(k, str):
                continue
            if self.fmt == "json":
                pat = re.compile('"' + re.escape(k) + '"')
            else:
                pat = re.compile(r"(?<![\w-])[\"']?" + re.escape(k) + r"[\"']?(?![\w-])")
            for j in range(idx, len(lines)):
                if pat.search(lines[j]):
                    idx, found = j, j + 1
                    break
        return found


def _read(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def get(data: Any, dotted: str, default: Any = None) -> Any:
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def has(data: Any, dotted: str) -> bool:
    sentinel = object()
    return get(data, dotted, sentinel) is not sentinel


def walk_strings(obj: Any, path: Optional[List[Any]] = None) -> Iterator[Tuple[List[Any], str]]:
    path = path or []
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + [k])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + [i])
    elif isinstance(obj, str):
        yield path, obj


def jpath(keys: List[Any]) -> str:
    out = ""
    for k in keys:
        if isinstance(k, int):
            out += "[%d]" % k
        elif re.match(r"^[A-Za-z_][\w-]*$", str(k)):
            out += ("." if out else "") + str(k)
        else:
            out += '["%s"]' % k
    return out


# ---------------------------------------------------------------------------
# Command risk patterns (hooks, helpers, shell-wrapped MCP servers)
# ---------------------------------------------------------------------------
RISK_PATTERNS = {
    "download-and-execute": [
        r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
        r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)\b",
        r"\b(ba|z)?sh\s+<\(\s*(curl|wget)",
        r"\beval\s+[\"']?\$\(\s*(curl|wget)",
        r"\b(iex|Invoke-Expression)\b",
        r"\bbase64\s+(-d|--decode)\b[^|\n]*\|\s*(ba|z)?sh\b",
    ],
    "network": [
        r"\b(curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|telnet)\b",
        r"\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b",
        r"\bhttps?://(?!(localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))",
    ],
    "credential access": [
        r"~/\.ssh\b|/\.ssh/|\bid_(rsa|ed25519|ecdsa)\b",
        r"\.aws/credentials|~/\.aws\b",
        r"\.netrc\b|\.git-credentials\b|\.npmrc\b|\.docker/config\.json|\.kube/config|\.config/gh/hosts",
        r"(^|[\s/'\"=])\.env\b",
        r"\.credentials\.json|\.claude\.json\b",
        r"\bsecurity\s+find-(generic|internet)-password\b",
        r"\bprintenv\b|\benv\s*\||\bset\s*\|",
        r"\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|NPM_TOKEN)\b",
    ],
}
_RISK_RES = {k: [re.compile(p) for p in v] for k, v in RISK_PATTERNS.items()}


def risk_categories(text: str) -> List[str]:
    return [cat for cat, pats in _RISK_RES.items() if any(p.search(text) for p in pats)]


def referenced_scripts(command: str, src: Source, ctx: "Audit") -> List[Path]:
    """Script files a hook command points at, resolved inside home/project/plugin only."""
    out: List[Path] = []
    for m in SCRIPT_TOKEN_RE.finditer(command.replace('"', "").replace("'", "")):
        raw = m.group(0)
        base = src.root or ctx.project
        p = raw.replace("${CLAUDE_PROJECT_DIR}", str(ctx.project)).replace("$CLAUDE_PROJECT_DIR", str(ctx.project))
        if src.root:
            p = p.replace("${CLAUDE_PLUGIN_ROOT}", str(src.root)).replace("$CLAUDE_PLUGIN_ROOT", str(src.root))
        p = p.replace("$HOME", "~").replace("${HOME}", "~")
        if "$" in p:
            continue
        if p.startswith("~"):
            cand = Path(str(ctx.home) + p[1:])
        elif os.path.isabs(p):
            cand = Path(p)
        else:
            cand = base / p
        try:
            cand = cand.resolve()
        except OSError:
            continue
        roots = [r.resolve() for r in (ctx.project, ctx.home, src.root) if r]
        inside = any(str(cand).startswith(str(r).rstrip(os.sep) + os.sep) for r in roots)
        if inside and cand.is_file() and cand not in out:
            out.append(cand)
    return out


# ---------------------------------------------------------------------------
# Package pinning
# ---------------------------------------------------------------------------
NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig"}
UVX_VALUE_FLAGS = {"--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "-w", "--with-requirements"}
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--env-file", "-w",
                      "--workdir", "-u", "--user", "--entrypoint", "--mount", "-l", "--label", "--platform", "--add-host",
                      "--cap-add", "--cap-drop", "--pull", "-m", "--memory", "--cpus", "--device", "--gpus", "--ipc",
                      "--pid", "--security-opt", "--tmpfs", "--ulimit", "-h", "--hostname", "--restart", "--runtime"}


def _first_positional(args: List[str], value_flags: set) -> Tuple[Optional[str], Dict[str, str]]:
    flags: Dict[str, str] = {}
    skip = False
    prev = None
    for a in args:
        if skip:
            flags[prev or ""] = a
            skip = False
            continue
        if a.startswith("-"):
            if "=" in a:
                k, v = a.split("=", 1)
                flags[k] = v
            elif a in value_flags:
                skip, prev = True, a
            continue
        return a, flags
    return None, flags


def _npm_pinned(spec: str) -> Optional[bool]:
    if spec.startswith((".", "/", "~", "file:", "git+", "git:", "http:", "https:", "github:")) or re.match(r"^[A-Za-z]:\\", spec):
        return None  # local path or URL, not a registry package
    m = re.match(r"^(@[^/@\s]+/)?[^@\s/]+(?:@(.+))?$", spec)
    if not m:
        return None
    ver = m.group(2)
    if not ver or ver in ("latest", "next", "*", "x") or ver[0] in "^~><=" or "x" in ver.split("."):
        return False
    return True


def unpinned_launch(command: Any, args: Any) -> Optional[str]:
    """Return a description if the command launches an unpinned package."""
    if not isinstance(command, str):
        return None
    exe = re.sub(r"\.(cmd|exe|bat)$", "", os.path.basename(command.replace("\\", "/")).lower())
    a = [str(x) for x in (args or []) if isinstance(x, (str, int, float))]
    if exe in ("npx", "bunx", "pnpx") or (exe in ("npm", "pnpm", "yarn") and a[:1] in (["exec"], ["dlx"], ["x"])):
        rest = a[1:] if exe in ("npm", "pnpm", "yarn") else a
        pkg, flags = _first_positional(rest, NPX_VALUE_FLAGS)
        spec = flags.get("--package") or flags.get("-p") or pkg
        if spec and _npm_pinned(spec) is False:
            return "%s package %s has no exact version" % (exe, spec)
    elif exe in ("uvx", "pipx", "uv"):
        rest = a
        if exe == "pipx":
            if a[:1] != ["run"]:
                return None
            rest = a[1:]
        if exe == "uv":
            if a[:2] != ["tool", "run"]:
                return None
            rest = a[2:]
        pkg, flags = _first_positional(rest, UVX_VALUE_FLAGS | {"--spec"})
        spec = flags.get("--from") or flags.get("--spec") or pkg
        if spec and not spec.startswith((".", "/", "git+", "http")) and not re.search(r"==|@\s*\d|@v?\d", spec):
            return "%s package %s has no exact version" % (exe, spec)
    elif exe in ("docker", "podman") and "run" in a:
        image, _ = _first_positional(a[a.index("run") + 1:], DOCKER_VALUE_FLAGS)
        if image and "@sha256:" not in image:
            last = image.rsplit("/", 1)[-1]
            if ":" not in last or last.endswith(":latest"):
                return "%s image %s has no tag or digest (or uses latest)" % (exe, image)
    return None


SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-ec", "-e"}


def is_local_host(host: str) -> bool:
    h = (host or "").lower().strip("[]")
    return h in ("localhost", "::1", "0.0.0.0") or h.startswith("127.") or h.endswith(".localhost")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
INTERPRETERS = {"python", "python3", "python2", "node", "deno", "bun", "bash", "sh", "zsh", "fish", "dash", "ksh",
                "pwsh", "powershell", "perl", "ruby", "php", "lua", "osascript", "eval", "exec", "sudo", "env",
                "npx", "bunx", "pnpx", "uvx", "xargs", "nohup", "setsid"}
RUNNERS = {("docker", "exec"), ("docker", "run"), ("podman", "exec"), ("podman", "run"), ("devbox", "run"),
           ("direnv", "exec"), ("mise", "exec"), ("mise", "x"), ("uv", "run"), ("pipx", "run"), ("nix", "run"),
           ("npm", "exec"), ("pnpm", "dlx"), ("yarn", "dlx"), ("kubectl", "exec")}
NET_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ssh", "ftp", "telnet",
            "invoke-webrequest", "iwr", "invoke-restmethod", "irm"}
CODE_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "NODE_OPTIONS",
            "PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "BASH_ENV", "ENV", "ZDOTDIR",
            "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "PATH"}
REDIRECT_ENV = {"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy",
                "http_proxy", "all_proxy", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
CC_HELPER_KEYS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
                  "statusLine.command", "fileSuggestion.command", "subagentStatusLine.command"]
CC_MANAGED_ONLY = ["allowAllClaudeAiMcps", "allowedChannelPlugins", "allowManagedHooksOnly", "allowManagedMcpServersOnly",
                   "allowManagedPermissionRulesOnly", "blockedMarketplaces", "channelsEnabled", "disableCommandPluginSources",
                   "disableSideloadFlags", "forceRemoteSettingsRefresh", "managedMcpServers", "managedSourcesBehavior",
                   "parentSettingsBehavior", "pluginSuggestionMarketplaces", "pluginTrustMessage", "policyHelper",
                   "sandbox.filesystem.allowManagedReadPathsOnly", "sandbox.network.allowManagedDomainsOnly",
                   "strictKnownMarketplaces", "strictPluginOnlyCustomization", "wslInheritsWindowsSettings"]
SECRET_TARGETS = {
    ".env files": re.compile(r"(^|/|\*)\.env(\.\*|\*|\.[\w*-]+)?$"),
    "~/.ssh": re.compile(r"(^~/|/)\.ssh(/|$)"),
    "~/.aws": re.compile(r"(^~/|/)\.aws(/|$)"),
}
RULE_RE = re.compile(r"^\s*([A-Za-z_*][\w*-]*)\s*(?:\((.*)\))?\s*$", re.S)


def parse_rule(rule: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(rule, str):
        return None, None
    m = RULE_RE.match(rule)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def rule_prefix_tokens(spec: str) -> List[str]:
    prefix = spec.split("*", 1)[0].strip().rstrip(":").strip()
    return [t.lower() for t in prefix.split()]


class Audit:
    def __init__(self, home: Path, project: Path, agents: Tuple[str, ...], managed_dir: Optional[Path],
                 codex_system_dir: Optional[Path], include_system: bool, claude_dir: Optional[Path] = None,
                 codex_dir: Optional[Path] = None, environ: Optional[Dict[str, str]] = None) -> None:
        self.home = home
        self.project = project
        self.agents = agents
        self.include_system = include_system
        self.managed_dir = managed_dir or default_managed_dir()
        self.codex_system_dir = codex_system_dir
        self.claude_dir = claude_dir or home / ".claude"
        self.codex_dir = codex_dir or home / ".codex"
        self.environ = os.environ if environ is None else environ
        self.claude_dir_given = claude_dir is not None
        self.codex_dir_given = codex_dir is not None
        self.sources: List[Source] = []
        self.findings: List[Dict[str, Any]] = []
        self.servers: List[Dict[str, Any]] = []

    # ---- helpers -----------------------------------------------------------
    def disp(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.project.resolve()).as_posix()
        except ValueError:
            pass
        try:
            return "~/" + path.resolve().relative_to(self.home.resolve()).as_posix()
        except ValueError:
            return str(path)

    def add(self, cid: str, src: Optional[Source], keys: Optional[List[Any]] = None, evidence: str = "",
            severity: Optional[str] = None, note: str = "", agent: Optional[str] = None) -> None:
        chk = CHECKS[cid]
        loc = src.display if src else "(no file)"
        if src is not None and src.exists and keys:
            line = src.find_line(keys)
            if line:
                loc += ":%d" % line
        ev = evidence + (" [%s]" % note if note else "")
        self.findings.append({
            "id": cid,
            "severity": severity or chk["severity"],
            "title": chk["title"],
            "location": _final_scrub(loc),
            "evidence": _final_scrub(trunc(ev)),
            "fix": chk["fix"],
            "refs": list(chk["refs"]),
            "agent": agent or (src.agent if src else ""),
            "scope": src.label() if src else "",
        })

    def new_source(self, agent: str, kind: str, scope: str, path: Path, shared: str = "",
                   root: Optional[Path] = None, fmt: str = "json") -> Source:
        return Source(agent, kind, scope, path, self.disp(path), shared, root, fmt)

    def load(self, src: Source, tolerant: bool = False) -> None:
        text = _read(src.path)
        if text is None:
            src.error = "unreadable or larger than %d bytes" % MAX_FILE_BYTES
            self.add("GEN001", src, evidence="could not read file")
            return
        src.text = text
        if src.fmt == "toml":
            try:
                src.data, src.fallback = parse_toml(text)
            except (ValueError, TypeError) as exc:  # tomllib.TOMLDecodeError subclasses ValueError
                src.error = _final_scrub(str(exc).splitlines()[0][:120]) if str(exc) else "invalid TOML"
                self.add("GEN001", src, evidence="invalid TOML: %s" % src.error)
                return
            if src.fallback:
                self.add("GEN003", src, evidence="tomllib unavailable (Python %d.%d)" % sys.version_info[:2])
            return
        try:
            src.data = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            msg = "invalid JSON at line %s" % getattr(exc, "lineno", "?")
            try:
                src.data = json.loads(strip_jsonc(text))
            except ValueError:
                src.error = msg
                note = {"claude-json": "Claude Code offers to reset ~/.claude.json when it cannot parse it",
                        "settings": "Claude Code skips this file, so its rules are not in effect"}.get(src.kind, "")
                if src.scope == "managed" and src.kind == "settings":
                    note = "Claude Code refuses to start when a managed settings file cannot be parsed"
                self.add("GEN001", src, evidence=msg, note=note)
                return
            if not tolerant:
                src.error = msg + " (comments or trailing commas)"
                self.add("GEN001", src, evidence=msg + ": file has comments or trailing commas; strict JSON is required",
                         note="analyzed leniently below; the agent itself may skip the file")
        if not isinstance(src.data, dict):
            src.error = "top level is not an object"
            self.add("GEN001", src, evidence="top-level JSON value is not an object")
            src.data = None

    # ---- discovery -----------------------------------------------------------
    def discover(self) -> None:
        seen: set = set()

        def reg(src: Source) -> None:
            key = str(src.path.resolve()) if src.path.exists() else str(src.path)
            if key in seen or not src.exists:
                return
            seen.add(key)
            self.sources.append(src)

        if "claude-code" in self.agents:
            if self.include_system:
                md = self.managed_dir
                reg(self.new_source("claude-code", "settings", "managed", md / "managed-settings.json"))
                ddir = md / "managed-settings.d"
                if ddir.is_dir():
                    for p in sorted(ddir.iterdir(), key=lambda x: x.name):
                        if p.name.startswith(".") or p.suffix != ".json":
                            continue
                        reg(self.new_source("claude-code", "settings", "managed", p))
                reg(self.new_source("claude-code", "mcp-json", "managed", md / "managed-mcp.json",
                                    shared="readable by every user on the machine"))
            reg(self.new_source("claude-code", "settings", "user", self.claude_dir / "settings.json"))
            reg(self.new_source("claude-code", "settings", "project", self.project / ".claude" / "settings.json",
                                shared="committed to the repository"))
            reg(self.new_source("claude-code", "settings", "local", self.project / ".claude" / "settings.local.json"))
            reg(self.new_source("claude-code", "claude-json", "user", self.home / ".claude.json"))
            reg(self.new_source("claude-code", "mcp-json", "project", self.project / ".mcp.json",
                                shared="committed to the repository"))
            for root in self._plugin_roots():
                reg(self.new_source("claude-code", "plugin-hooks", "plugin", root / "hooks" / "hooks.json", root=root))
                reg(self.new_source("claude-code", "mcp-json", "plugin", root / ".mcp.json", root=root))
                reg(self.new_source("claude-code", "plugin-manifest", "plugin", root / ".claude-plugin" / "plugin.json", root=root))
        if "codex" in self.agents:
            if self.include_system:
                sysdir = self.codex_system_dir
                if sysdir is None:
                    if os.name == "nt":
                        pd = Path(self.environ.get("ProgramData", r"C:\ProgramData")) / "OpenAI" / "Codex"
                        reg(self.new_source("codex", "codex-requirements", "managed", pd / "requirements.toml", fmt="toml"))
                        reg(self.new_source("codex", "codex-config", "managed", self.codex_dir / "managed_config.toml", fmt="toml"))
                    else:
                        sysdir = Path("/etc/codex")
                if sysdir is not None:
                    reg(self.new_source("codex", "codex-requirements", "managed", sysdir / "requirements.toml", fmt="toml"))
                    reg(self.new_source("codex", "codex-config", "managed", sysdir / "managed_config.toml", fmt="toml"))
            reg(self.new_source("codex", "codex-config", "user", self.codex_dir / "config.toml", fmt="toml"))
            if self.codex_dir.is_dir():
                for p in sorted(self.codex_dir.glob("*.config.toml")):
                    reg(self.new_source("codex", "codex-config", "user-profile", p, fmt="toml"))
            reg(self.new_source("codex", "codex-config", "project", self.project / ".codex" / "config.toml",
                                shared="committed to the repository", fmt="toml"))
        if "cursor" in self.agents:
            reg(self.new_source("cursor", "cursor-mcp", "user", self.home / ".cursor" / "mcp.json"))
            reg(self.new_source("cursor", "cursor-mcp", "project", self.project / ".cursor" / "mcp.json",
                                shared="committed to the repository"))
            reg(self.new_source("cursor", "cursor-sandbox", "user", self.home / ".cursor" / "sandbox.json"))
            reg(self.new_source("cursor", "cursor-sandbox", "project", self.project / ".cursor" / "sandbox.json",
                                shared="committed to the repository"))

    def _plugin_roots(self) -> List[Path]:
        roots: List[Path] = []
        base = self.claude_dir / "plugins"
        for sub in ("cache", "synced"):
            top = base / sub
            if not top.is_dir():
                continue
            top_depth = len(top.parts)
            for dirpath, dirnames, _files in os.walk(top):
                depth = len(Path(dirpath).parts) - top_depth
                dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", ".venv", "__pycache__", ".trash")]
                if depth >= 5:
                    dirnames[:] = []
                p = Path(dirpath)
                if (p / "hooks" / "hooks.json").is_file() or (p / ".claude-plugin" / "plugin.json").is_file():
                    roots.append(p)
                    dirnames[:] = []
        return roots

    # ---- run -------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        self._env_overrides()
        self.discover()
        for src in self.sources:
            self.load(src, tolerant=src.agent == "cursor")
        if "claude-code" in self.agents:
            self.check_claude()
        if "codex" in self.agents:
            self.check_codex()
        if "cursor" in self.agents:
            self.check_cursor()
        self.check_mcp()
        return self.report()

    def _env_overrides(self) -> None:
        pairs = []
        if "claude-code" in self.agents and not self.claude_dir_given:
            pairs += [("CLAUDE_CONFIG_DIR", "claude-code", "--claude-dir"),
                      ("CLAUDE_CODE_PLUGIN_CACHE_DIR", "claude-code", "--claude-dir")]
        if "codex" in self.agents and not self.codex_dir_given:
            pairs.append(("CODEX_HOME", "codex", "--codex-dir"))
        for var, agent, flag in pairs:
            if self.environ.get(var):
                self.add("GEN002", None, agent=agent,
                         evidence="%s is set; this audit read the default location. Re-run with %s <dir> to audit the directory it names" % (var, flag))

    # ---- Claude Code -----------------------------------------------------------
    def cc_layers(self, valid_only: bool = False) -> List[Source]:
        """Settings layers, lowest precedence first. valid_only drops files the agent would skip (parse errors)."""
        order = {"user": 0, "project": 1, "local": 2, "managed": 3}
        layers = [s for s in self.sources if s.agent == "claude-code" and s.kind == "settings" and isinstance(s.data, dict)
                  and not (valid_only and s.error)]
        return sorted(layers, key=lambda s: order[s.scope])  # stable: managed files keep merge order

    def cc_effective(self, dotted: str) -> Tuple[Any, Optional[Source]]:
        for src in reversed(self.cc_layers(valid_only=True)):
            if has(src.data, dotted):
                return get(src.data, dotted), src
        return None, None

    def cc_trusted(self) -> Optional[bool]:
        for src in self.sources:
            if src.kind == "claude-json" and isinstance(src.data, dict):
                projects = src.data.get("projects")
                if isinstance(projects, dict):
                    for key in (str(self.project), self.project.as_posix(), str(self.project.resolve())):
                        entry = projects.get(key)
                        if isinstance(entry, dict) and "hasTrustDialogAccepted" in entry:
                            return bool(entry.get("hasTrustDialogAccepted"))
        return None

    def check_claude(self) -> None:
        layers = self.cc_layers()
        present = bool(layers) or self.claude_dir.is_dir() or any(s.agent == "claude-code" for s in self.sources)
        if not present:
            return
        user_src = next((s for s in layers if s.scope == "user"), None)
        anchor = user_src or self.new_source("claude-code", "settings", "user", self.claude_dir / "settings.json")
        if not anchor.exists:
            anchor.display += " (not present)"
        sandbox_on = self.cc_effective("sandbox.enabled")[0] is True
        trusted = self.cc_trusted()
        trust_note = {True: "folder trusted in ~/.claude.json", False: "folder not trusted yet",
                      None: "applies after you trust the folder"}[trusted]

        all_allow: List[Tuple[Source, str]] = []
        all_deny: List[Tuple[Source, str]] = []
        for src in layers:
            d = src.data
            is_repo = src.scope == "project"
            # defaultMode
            dm = get(d, "permissions.defaultMode")
            if dm == "bypassPermissions":
                if src.scope in ("user", "managed"):
                    self.add("CC001", src, ["permissions", "defaultMode"],
                             'permissions.defaultMode = "bypassPermissions"; sandbox.enabled is %s' % ("true" if sandbox_on else "not true"),
                             severity="high" if sandbox_on else "critical")
                else:
                    self.add("CC002", src, ["permissions", "defaultMode"],
                             'permissions.defaultMode = "bypassPermissions" in %s settings' % src.scope,
                             note="ignored on v2.1.257+, honored by older versions")
            elif dm == "auto":
                if src.scope in ("user", "managed"):
                    self.add("CC003", src, ["permissions", "defaultMode"], 'permissions.defaultMode = "auto"')
                else:
                    self.add("CC002", src, ["permissions", "defaultMode"],
                             'permissions.defaultMode = "auto" in %s settings' % src.scope, severity="low",
                             note="ignored in project and local settings")
            if get(d, "skipDangerousModePermissionPrompt") is True:
                self.add("CC004", src, ["skipDangerousModePermissionPrompt"], "skipDangerousModePermissionPrompt = true",
                         severity="low" if is_repo else None,
                         note="ignored in project settings; a repository setting it is suspicious" if is_repo else "")
            # rules
            for kind, bucket in (("allow", all_allow), ("deny", all_deny)):
                rules = get(d, "permissions." + kind)
                if isinstance(rules, list):
                    bucket.extend((src, r) for r in rules if isinstance(r, str))
            # enableAllProjectMcpServers
            if get(d, "enableAllProjectMcpServers") is True:
                self.add("CC014", src, ["enableAllProjectMcpServers"], "enableAllProjectMcpServers = true in %s settings" % src.scope,
                         severity="high" if src.scope in ("user", "managed") else "medium",
                         note={"user": "honored even in folders you have not trusted", "managed": "honored even in folders you have not trusted",
                               "project": "honored once you trust the folder", "local": "your own approval in this project"}[src.scope])
            if is_repo and isinstance(get(d, "enabledMcpjsonServers"), list):
                self.add("MCP006", src, ["enabledMcpjsonServers"], "repository approves its own .mcp.json servers: %s"
                         % redact_text(", ".join(map(str, get(d, "enabledMcpjsonServers")[:5]))),
                         severity="low", note="ignored until you trust the folder")
            # hooks and helpers
            self._cc_hooks(src, get(d, "hooks"), trust_note)
            helpers = [(k, get(d, k)) for k in CC_HELPER_KEYS if isinstance(get(d, k), str)]
            if is_repo and helpers:
                self.add("CC015", src, [helpers[0][0].split(".")[0]],
                         "repository defines helper command(s): %s" % ", ".join(k for k, _ in helpers),
                         note="helpers such as apiKeyHelper run only after trust in interactive sessions")
            for key, cmd in helpers:
                self._risky_command("CC016", src, [key.split(".")[0]], "%s" % key, cmd)
            # secrets anywhere in the file
            for path, value in walk_strings(d):
                last = next((k for k in reversed(path) if isinstance(k, str)), "")
                if looks_secret(last, value):
                    self.add("CC018", src, [k for k in path if isinstance(k, str)],
                             "%s = %s" % (jpath(path), redact_value(value)),
                             severity="high" if src.shared else "medium", note=src.shared)
            # repository env
            env = get(d, "env")
            if is_repo and isinstance(env, dict):
                for name, value in env.items():
                    if name in CODE_ENV or name in REDIRECT_ENV:
                        kind = "loads code" if name in CODE_ENV else "redirects traffic or weakens TLS"
                        self.add("CC019", src, ["env", name], "env.%s = %s (%s)" % (name, trunc(redact_text(value), 60), kind))
            # repository loosening
            if is_repo:
                for key, bad, why in (("sandbox.enabled", False, "turns off your sandbox in this repository"),
                                      ("disableAllHooks", False, "re-enables hooks you disabled in user settings"),
                                      ("sandbox.allowUnsandboxedCommands", True, "re-opens the unsandboxed retry")):
                    if has(d, key) and get(d, key) is bad:
                        self.add("CC020", src, key.split("."), "%s = %s: %s" % (key, json.dumps(bad), why))
                dirs = get(d, "permissions.additionalDirectories")
                if isinstance(dirs, list) and dirs:
                    self.add("CC020", src, ["permissions", "additionalDirectories"],
                             "permissions.additionalDirectories grants access to %d path(s) outside the project" % len(dirs),
                             severity="low", note=trust_note)
            # sandbox weakening
            self._cc_sandbox_weak(src)
            # marketplaces
            mk = get(d, "extraKnownMarketplaces") or get(d, "additionalMarketplaces")
            if isinstance(mk, dict):
                for name, entry in mk.items():
                    source = entry.get("source") if isinstance(entry, dict) else None
                    if not isinstance(source, dict):
                        continue
                    stype = source.get("source")
                    where = source.get("repo") or source.get("url") or source.get("path") or ""
                    official = stype == "github" and str(where).lower().startswith("anthropics/")
                    sev = "info" if official else "low"
                    if str(where).startswith("http://"):
                        sev = "medium"
                    self.add("CC021", src, ["extraKnownMarketplaces", name] if has(d, "extraKnownMarketplaces") else ["additionalMarketplaces", name],
                             "marketplace %s: %s %s%s" % (redact_text(name), stype, display_url(str(where)) if "://" in str(where) else redact_text(where),
                                                          ", autoUpdate" if isinstance(entry, dict) and entry.get("autoUpdate") else ""),
                             severity=sev, note=("registered only after you trust the folder" if is_repo else ""))
            # managed-only keys outside managed settings
            if src.scope != "managed":
                for key in CC_MANAGED_ONLY:
                    if has(d, key):
                        self.add("CC023", src, key.split("."), "%s is set in %s settings" % (key, src.scope))

        # allow rules
        for src, rule in all_allow:
            tool, spec = parse_rule(rule)
            note = trust_note if src.scope == "project" else ""
            if tool in ("Bash", "PowerShell"):
                if spec is None or re.fullmatch(r"[\s*:]*", spec or ""):
                    self.add("CC005", src, [rule], "allow rule %s" % redact_text(rule), note=note)
                    continue
                toks = rule_prefix_tokens(spec)
                if not toks:
                    self.add("CC006", src, [rule], "allow rule %s starts with a wildcard, so any program matches" % redact_text(rule),
                             note=note)
                    continue
                if (toks[0] in INTERPRETERS and len(toks) == 1) or (len(toks) == 2 and tuple(toks) in RUNNERS) or \
                        (len(toks) == 2 and toks[0] in ("npx", "bunx", "uvx") and toks[1] in ("-y", "--yes")):
                    self.add("CC006", src, [rule], "allow rule %s" % redact_text(rule), note=note)
                elif toks == ["git"] and "*" in spec:
                    self.add("CC006", src, [rule], "allow rule %s also matches git -c <option>=<program> forms" % redact_text(rule),
                             severity="low", note=note)
                elif toks[0] in NET_CMDS and "*" in spec:
                    self.add("CC007", src, [rule], "allow rule %s" % redact_text(rule), note=note)
            elif tool == "WebFetch":
                if spec is None:
                    self.add("CC007", src, [rule], "bare WebFetch allow: fetches any URL without prompting", note=note)
                elif spec.replace(" ", "") == "domain:*":
                    self.add("CC007", src, [rule], "WebFetch(domain:*) allow: fetches any URL and opens the sandbox to any host", note=note)

        # secrets deny coverage
        covered = {t: False for t in SECRET_TARGETS}
        bash_denies = []
        for src, rule in all_deny:
            if src.error:
                continue  # the agent skips a file it cannot parse, so its deny rules are not in effect
            tool, spec = parse_rule(rule)
            if tool in ("*", "Read") and spec is None:
                covered = {t: True for t in covered}
            if tool == "Read" and spec:
                s = spec.strip().rstrip("/").replace("/**", "")
                for t, pat in SECRET_TARGETS.items():
                    if pat.search(s):
                        covered[t] = True
            if tool in ("Bash", "PowerShell") and spec:
                bash_denies.append(rule)
        for src in self.cc_layers(valid_only=True):
            paths = list(get(src.data, "sandbox.filesystem.denyRead") or [])
            creds = get(src.data, "sandbox.credentials.files") or []
            paths += [c.get("path") for c in creds if isinstance(c, dict) and c.get("mode") in ("deny", "mask")]
            for p in paths:
                if isinstance(p, str):
                    s = p.strip().rstrip("/").replace("/**", "")
                    for t, pat in SECRET_TARGETS.items():
                        if pat.search(s):
                            covered[t] = True
        missing = [t for t, ok in covered.items() if not ok]
        if missing:
            self.add("CC008", anchor, ["permissions", "deny"], "no Read deny rule or sandbox denyRead covers: %s" % ", ".join(missing),
                     agent="claude-code")
        if bash_denies and not sandbox_on:
            self.add("CC009", anchor, ["permissions", "deny"],
                     "%d Bash deny rule(s), e.g. %s, and the sandbox is off" % (len(bash_denies), redact_text(bash_denies[0])),
                     agent="claude-code")
        # sandbox
        val, vsrc = self.cc_effective("sandbox.enabled")
        if val is not True:
            self.add("CC010", vsrc or anchor, ["sandbox", "enabled"],
                     "sandbox.enabled = %s%s" % (json.dumps(val) if vsrc else "unset (default false)",
                                                  " in %s settings" % vsrc.scope if vsrc else ""), agent="claude-code")
        else:
            val2, src2 = self.cc_effective("sandbox.allowUnsandboxedCommands")
            if val2 is not False:
                self.add("CC012", src2 or vsrc, ["sandbox", "allowUnsandboxedCommands"],
                         "sandbox.allowUnsandboxedCommands = %s" % (json.dumps(val2) if src2 else "unset (default true)"),
                         agent="claude-code")
        for src in layers:
            for dom in get(src.data, "sandbox.network.allowedDomains") or []:
                if isinstance(dom, str) and re.fullmatch(r"\*|\*\.\*|\*\.[A-Za-z]{2,}(:\d+)?|\*:\d+", dom.strip()):
                    self.add("CC011", src, ["allowedDomains", dom], "sandbox.network.allowedDomains contains %s" % dom,
                             severity="high" if sandbox_on else "low",
                             note="" if sandbox_on else "no effect until the sandbox is enabled")
        for src, rule in all_allow:
            tool, spec = parse_rule(rule)
            if tool == "WebFetch" and spec and spec.replace(" ", "") == "domain:*":
                self.add("CC011", src, [rule], "WebFetch(domain:*) allow adds every host to the sandbox allowlist",
                         severity="high" if sandbox_on else "low",
                         note="" if sandbox_on else "no effect on commands until the sandbox is enabled")
        if not any(get(s.data, "permissions.disableBypassPermissionsMode") == "disable" for s in self.cc_layers(valid_only=True)):
            self.add("CC022", anchor, ["permissions"], "permissions.disableBypassPermissionsMode is not \"disable\" in any settings file",
                     agent="claude-code")
        # plugin hooks and manifests
        for src in self.sources:
            if src.kind == "plugin-hooks" and isinstance(src.data, dict):
                hooks = src.data.get("hooks") if isinstance(src.data.get("hooks"), dict) else src.data
                n = self._cc_hooks(src, hooks, "")
                if n:
                    self.add("CC024", src, ["hooks"], "%d hook handler(s) in plugin %s" % (n, plugin_name(src.root)))
            if src.kind == "plugin-manifest" and isinstance(src.data, dict):
                inline = src.data.get("hooks")
                if isinstance(inline, dict):
                    hooks = inline.get("hooks") if isinstance(inline.get("hooks"), dict) else inline
                    n = self._cc_hooks(src, hooks, "")
                    if n:
                        self.add("CC024", src, ["hooks"], "%d inline hook handler(s) in plugin.json" % n)

    def _cc_hooks(self, src: Source, hooks: Any, trust_note: str) -> int:
        """Analyze a hooks object; return the number of handlers."""
        if not isinstance(hooks, dict):
            return 0
        count, events = 0, []
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict):
                    continue
                for h in group.get("hooks") or []:
                    if not isinstance(h, dict):
                        continue
                    count += 1
                    events.append(str(event))
                    htype = h.get("type", "command")
                    if htype == "command" and isinstance(h.get("command"), str):
                        args = h.get("args") if isinstance(h.get("args"), list) else []
                        cmd = " ".join([h["command"]] + [str(a) for a in args])
                        cid = "CX010" if src.agent == "codex" else "CC016"
                        self._risky_command(cid, src, ["hooks", str(event)], "%s hook" % event, cmd)
                    elif htype == "http" and src.agent == "claude-code" and isinstance(h.get("url"), str):
                        try:
                            u = urlsplit(h["url"])
                        except ValueError:
                            continue
                        if not is_local_host(u.hostname or ""):
                            self.add("CC017", src, ["hooks", str(event), "url"], "%s http hook -> %s" % (event, display_url(h["url"])),
                                     severity="high" if u.scheme == "http" else "medium")
        if count and src.scope == "project":
            cid = "CX009" if src.agent == "codex" else "CC015"
            self.add(cid, src, ["hooks"], "%d hook handler(s) on %s" % (count, ", ".join(sorted(set(events)))),
                     note=trust_note or ("loaded only if the project is trusted" if src.agent == "codex" else ""))
        return count

    def _risky_command(self, cid: str, src: Source, keys: List[Any], what: str, command: str) -> None:
        cats = risk_categories(command)
        where = ""
        if not cats:
            # Referenced scripts: flag only fetch/exec or outbound network. Credential paths alone are
            # common in defensive hooks (e.g. a PreToolUse guard that blocks reads of .env).
            for script in referenced_scripts(command, src, self):
                script_cats = risk_categories(_read(script) or "")
                if "download-and-execute" in script_cats or "network" in script_cats:
                    cats, where = script_cats, " (in referenced script %s)" % self.disp(script)
                    break
        if not cats:
            return
        third_party = src.scope in ("project", "plugin")
        sev = "high" if ("download-and-execute" in cats or third_party) else "medium"
        self.add(cid, src, keys, "%s: %s%s; command: %s" % (what, ", ".join(cats), where, redact_text(command)), severity=sev)

    def _cc_sandbox_weak(self, src: Source) -> None:
        d = src.data
        checks = [
            ("sandbox.network.allowAllUnixSockets", True, "every Unix socket reachable from the sandbox"),
            ("sandbox.enableWeakerNestedSandbox", True, "bind-mounts the container /proc; considerably weakens the Linux sandbox"),
            ("sandbox.enableWeakerNetworkIsolation", True, "opens com.apple.trustd.agent, a potential exfiltration path"),
        ]
        if src.scope in ("user", "managed"):
            checks.append(("sandbox.allowAppleEvents", True, "removes code-execution isolation on macOS"))
        if src.scope in ("user", "managed"):
            checks.append(("sandbox.filesystem.disabled", True, "turns off filesystem isolation; denyRead no longer enforced"))
        for key, bad, why in checks:
            if get(d, key) is bad:
                self.add("CC013", src, key.split("."), "%s = true: %s" % (key, why))
        socks = get(d, "sandbox.network.allowUnixSockets")
        if isinstance(socks, list) and any("docker.sock" in str(s) for s in socks):
            self.add("CC013", src, ["allowUnixSockets"], "sandbox.network.allowUnixSockets includes the Docker socket (host control)")
        for entry in get(d, "sandbox.excludedCommands") or []:
            if not isinstance(entry, str):
                continue
            toks = rule_prefix_tokens(entry)
            if not toks or (toks[0] in INTERPRETERS and len(toks) == 1):
                self.add("CC013", src, ["excludedCommands"], "sandbox.excludedCommands entry %s runs arbitrary code unsandboxed" % redact_text(entry))

    # ---- Codex ----------------------------------------------------------------
    def check_codex(self) -> None:
        configs = [s for s in self.sources if s.kind == "codex-config" and isinstance(s.data, dict)]
        reqs = next((s for s in self.sources if s.kind == "codex-requirements" and isinstance(s.data, dict)), None)
        user = next((s for s in configs if s.scope == "user"), None)
        base = user.data if user else {}
        allowed_modes = get(reqs.data, "allowed_sandbox_modes") if reqs else None
        allowed_policies = get(reqs.data, "allowed_approval_policies") if reqs else None
        trust_map: Dict[str, str] = {}
        projects = get(base, "projects")
        if isinstance(projects, dict):
            trust_map = {str(k): str(v.get("trust_level")) for k, v in projects.items() if isinstance(v, dict)}
        proj_trust = trust_map.get(str(self.project)) or trust_map.get(str(self.project.resolve()))

        for src in configs:
            d = src.data
            inherit = src.scope in ("user-profile", "project")

            def eff(key: str) -> Any:
                if has(d, key):
                    return get(d, key)
                return get(base, key) if inherit else None

            note = ""
            sev_cap = None
            if src.scope == "project":
                if proj_trust == "untrusted":
                    note, sev_cap = "ignored: project is marked untrusted", "info"
                elif proj_trust == "trusted":
                    note = "project is trusted, so this file is loaded"
                else:
                    note = "loaded only after you trust the project"
                self.add("CX008", src, None, "repository .codex/config.toml sets: %s" % ", ".join(sorted(d.keys())[:8]), note=note)

            def cap(sev: str) -> str:
                return sev_cap or sev

            sandbox = eff("sandbox_mode")
            perms = eff("default_permissions")
            approval = eff("approval_policy")
            np_ = eff("features.network_proxy")
            proxy_on = np_ is True or (isinstance(np_, dict) and np_.get("enabled") is True)
            net_on = eff("sandbox_workspace_write.network_access") is True
            # CX001
            for key, val in (("sandbox_mode", "danger-full-access"), ("default_permissions", ":danger-full-access")):
                if get(d, key) == val:
                    sev = "critical" if approval == "never" else "high"
                    extra = ""
                    if key == "sandbox_mode" and isinstance(allowed_modes, list) and val not in allowed_modes:
                        sev, extra = "low", "requirements.toml allowed_sandbox_modes disallows it; Codex falls back to a compatible value"
                    self.add("CX001", src, [key], '%s = "%s"; approval_policy = %s' % (key, val, json.dumps(approval)),
                             severity=cap(sev), note="; ".join(x for x in (extra, note) if x))
            # CX002
            if get(d, "approval_policy") == "never" and sandbox not in ("read-only", "danger-full-access") \
                    and perms not in (":read-only", ":danger-full-access"):
                sev, extra = ("high" if net_on else "medium"), ""
                if isinstance(allowed_policies, list) and "never" not in allowed_policies:
                    sev, extra = "low", "requirements.toml allowed_approval_policies disallows it"
                self.add("CX002", src, ["approval_policy"], 'approval_policy = "never" with sandbox_mode = %s%s'
                         % (json.dumps(sandbox), ", network_access = true" if net_on else ""),
                         severity=cap(sev), note="; ".join(x for x in (extra, note) if x))
            # CX003
            ap = get(d, "approval_policy")
            if ap in ("untrusted", "on-failure"):
                self.add("CX003", src, ["approval_policy"], 'approval_policy = "%s" (%s)' % (ap, "retired" if ap == "untrusted" else "deprecated"),
                         severity=cap("medium" if ap == "untrusted" else "low"), note=note)
            # CX004: reported where it is set; it takes effect whenever workspace-write is the active sandbox
            if get(d, "sandbox_workspace_write.network_access") is True and sandbox != "read-only":
                extra = "applies whenever workspace-write is active (e.g. another profile or --sandbox)" \
                    if sandbox == "danger-full-access" else ""
                self._cx_network(src, ["sandbox_workspace_write", "network_access"], "sandbox_workspace_write.network_access = true",
                                 proxy_on, np_, cap, "; ".join(x for x in (extra, note) if x))
            prof = get(d, "permissions")
            if isinstance(prof, dict):
                for name, body in prof.items():
                    if get(body, "network.enabled") is True:
                        self._cx_network(src, ["permissions", name, "network"], "permissions.%s.network.enabled = true" % name,
                                         proxy_on, np_, cap, note)
            # CX005
            sep = "shell_environment_policy"
            ide, inh = eff(sep + ".ignore_default_excludes"), eff(sep + ".inherit")
            filtered = any(eff(sep + "." + k) for k in ("filters", "exclude", "include_only"))
            explicit = has(d, sep + ".ignore_default_excludes") or has(d, sep + ".inherit")
            if ide is not False and inh not in ("none", "core") and not filtered and (src.scope == "user" or explicit):
                exposed = net_on or sandbox == "danger-full-access" or perms == ":danger-full-access"
                self.add("CX005", src, [sep] if has(d, sep) else None,
                         "shell_environment_policy.ignore_default_excludes = %s (documented default true), inherit = %s, no exclude "
                         "filters%s" % (json.dumps(ide) if ide is not None else "unset", json.dumps(inh) if inh is not None else "unset",
                                        "; commands also have network access" if exposed else ""),
                         severity=cap("medium" if exposed else "low"), note=note)
            # CX006 (non-MCP literal credentials)
            for path, value in walk_strings(d):
                if path and path[0] in ("mcp_servers", "projects"):
                    continue
                last = next((k for k in reversed(path) if isinstance(k, str)), "")
                if last in ("env_key", "bearer_token_env_var") or not looks_secret(last, value):
                    continue
                self.add("CX006", src, [k for k in path if isinstance(k, str)], "%s = %s" % (jpath(path), redact_value(value)),
                         severity=cap("high" if src.shared else "medium"), note=note or src.shared)
            # CX007
            if src.scope == "user" and trust_map:
                trusted = [k for k, v in trust_map.items() if v == "trusted"]
                if trusted:
                    self.add("CX007", src, ["projects"], "%d trusted project(s), e.g. %s" % (len(trusted), self.disp(Path(trusted[0]))))
            # hooks
            hooks = get(d, "hooks")
            if isinstance(hooks, dict):
                self._cc_hooks(src, hooks, note)
            # CX011
            for flag in ("dangerously_allow_non_loopback_proxy", "dangerously_allow_all_unix_sockets"):
                if get(d, "features.network_proxy." + flag) is True:
                    self.add("CX011", src, ["network_proxy", flag], "features.network_proxy.%s = true" % flag, severity=cap("medium"), note=note)
            # CX012
            if get(d, "web_search") == "live":
                self.add("CX012", src, ["web_search"], 'web_search = "live"', severity=cap("low"), note=note)

    def _cx_network(self, src: Source, keys: List[Any], what: str, proxy_on: bool, np_: Any, cap: Any, note: str) -> None:
        if not proxy_on:
            self.add("CX004", src, keys, "%s and features.network_proxy is off: direct, unrestricted outbound access" % what,
                     severity=cap("high"), note=note)
            return
        domains = np_.get("domains") if isinstance(np_, dict) else None
        if isinstance(domains, dict) and domains.get("*") == "allow":
            self.add("CX004", src, keys, "%s; network_proxy allows \"*\" (any public host)" % what, severity=cap("medium"), note=note)

    # ---- Cursor ---------------------------------------------------------------
    def check_cursor(self) -> None:
        cursor = [s for s in self.sources if s.agent == "cursor"]
        if not cursor and not (self.home / ".cursor").is_dir() and not (self.project / ".cursor").is_dir():
            return
        sandboxes = [s for s in cursor if s.kind == "cursor-sandbox" and isinstance(s.data, dict)]
        defaults = [get(s.data, "networkPolicy.default") for s in sandboxes]
        for src in sandboxes:
            d = src.data
            if d.get("type") == "insecure_none":
                self.add("CU001", src, ["type"], 'sandbox.json type = "insecure_none" (%s)' % src.scope)
            if get(d, "networkPolicy.default") == "allow" and "deny" not in defaults:
                self.add("CU002", src, ["networkPolicy", "default"], 'networkPolicy.default = "allow" and no sandbox.json sets "deny"')
            allow = get(d, "networkPolicy.allow")
            if isinstance(allow, list):
                for entry in allow:
                    if str(entry).strip() in ("*", "*.*", "0.0.0.0/0", "::/0"):
                        self.add("CU002", src, ["allow"], "networkPolicy.allow contains %s" % entry)
        anchor = cursor[0] if cursor else self.new_source("cursor", "cursor-mcp", "user", self.home / ".cursor" / "mcp.json")
        self.add("CU003", anchor, None, "Run Mode, sandbox network mode and protections are not stored in the files audited here",
                 agent="cursor")

    # ---- MCP (all agents) ----------------------------------------------------------
    def collect_servers(self) -> None:
        for src in self.sources:
            if not isinstance(src.data, dict):
                continue
            if src.kind in ("mcp-json", "cursor-mcp", "plugin-manifest"):
                block = src.data.get("mcpServers")
                if block is None and src.kind == "mcp-json" and src.scope == "plugin":
                    block = {k: v for k, v in src.data.items() if isinstance(v, dict) and ("command" in v or "url" in v)}
                self._add_servers(src, block, ["mcpServers"], src.scope)
            elif src.kind == "settings" and src.scope == "managed":
                self._add_servers(src, src.data.get("managedMcpServers"), ["managedMcpServers"], "managed")
            elif src.kind == "claude-json":
                self._add_servers(src, src.data.get("mcpServers"), ["mcpServers"], "user")
                projects = src.data.get("projects")
                if isinstance(projects, dict):
                    for ppath, entry in projects.items():
                        if isinstance(entry, dict):
                            self._add_servers(src, entry.get("mcpServers"), ["projects", ppath, "mcpServers"], "local",
                                              where="local scope for %s" % self.disp(Path(ppath)))
            elif src.kind == "codex-config":
                self._add_servers(src, src.data.get("mcp_servers"), ["mcp_servers"], src.scope)

    def _add_servers(self, src: Source, block: Any, prefix: List[Any], scope: str, where: str = "") -> None:
        if not isinstance(block, dict):
            return
        for name, cfg in block.items():
            if not isinstance(cfg, dict):
                continue
            url = cfg.get("url") if isinstance(cfg.get("url"), str) else None
            transport = str(cfg.get("type") or ("http" if url else "stdio"))
            headers = {}
            for hk in ("headers", "http_headers"):
                if isinstance(cfg.get(hk), dict):
                    headers.update({"%s.%s" % (hk, k): v for k, v in cfg[hk].items()})
            self.servers.append({
                "name": str(name), "src": src, "scope": scope, "keys": prefix + [name], "cfg": cfg, "url": url,
                "transport": transport, "command": cfg.get("command"),
                "args": cfg.get("args") if isinstance(cfg.get("args"), list) else [],
                "env": cfg.get("env") if isinstance(cfg.get("env"), dict) else {}, "headers": headers, "where": where,
            })

    def check_mcp(self) -> None:
        self.collect_servers()
        for s in self.servers:
            src, name, cfg, keys = s["src"], s["name"], s["cfg"], s["keys"]
            label = "%s server %s%s" % (src.agent, redact_text(name), " (%s)" % s["where"] if s["where"] else "")
            if s["url"]:
                desc = "%s %s" % (s["transport"], display_url(s["url"]))
            elif s["url"] is not None or s["transport"] in ("http", "sse", "ws", "streamable-http"):
                desc = "%s (no url configured)" % s["transport"]
            else:
                desc = "stdio: %s" % display_command(s["command"], s["args"])
            self.add("MCP005", src, keys, "%s: %s" % (label, desc))
            # MCP001
            why = unpinned_launch(s["command"], s["args"])
            if why:
                self.add("MCP001", src, keys, "%s: %s" % (label, redact_text(why)))
            # MCP002
            if s["url"]:
                try:
                    u = urlsplit(s["url"])
                    if u.scheme in ("http", "ws") and not is_local_host(u.hostname or ""):
                        self.add("MCP002", src, keys + ["url"], "%s: %s" % (label, display_url(s["url"])))
                except ValueError:
                    pass
            # MCP003
            hits: List[str] = []
            for k, v in s["env"].items():
                if looks_secret(k, v):
                    hits.append("env.%s = %s" % (k, redact_value(str(v))))
            for k, v in s["headers"].items():
                if header_secret(k.split(".", 1)[-1], v):
                    hits.append("%s = %s" % (k, redact_value(str(v))))
            prev = ""
            for a in s["args"]:
                a = str(a)
                if KNOWN_TOKEN_RE.search(a) or (SECRET_FLAG_RE.match(prev) and looks_secret("token", a)) or \
                        ("=" in a and SECRET_FLAG_RE.match(a.split("=", 1)[0]) and looks_secret("token", a.split("=", 1)[1])):
                    hits.append("args contain a credential (%s)" % redact_value(a))
                prev = a
            if s["url"] and (URL_USERINFO_RE.search(s["url"]) or QUERY_SECRET_RE.search(s["url"]) or KNOWN_TOKEN_RE.search(s["url"])):
                hits.append("url embeds a credential")
            auth = cfg.get("auth")
            if isinstance(auth, dict):
                for k, v in auth.items():
                    if k.upper() == "CLIENT_SECRET" and isinstance(v, str) and not is_reference(v) and len(v) >= 8:
                        hits.append("auth.%s = %s" % (k, redact_value(v)))
            if hits:
                self.add("MCP003", src, keys, "%s: %s" % (label, "; ".join(hits)),
                         severity="high" if src.shared else "medium", note=src.shared)
            # MCP004
            cmd = s["command"]
            if isinstance(cmd, str):
                exe = re.sub(r"\.(exe|cmd)$", "", os.path.basename(cmd.replace("\\", "/")).lower())
                if exe in SHELLS and any(str(a).lower() in SHELL_FLAGS for a in s["args"]):
                    joined = " ".join(str(a) for a in s["args"])
                    sev = "high" if "download-and-execute" in risk_categories(joined) else None
                    self.add("MCP004", src, keys, "%s: %s" % (label, display_command(cmd, s["args"])), severity=sev)
            # headersHelper (Claude Code) is a command the config runs
            helper = cfg.get("headersHelper")
            if isinstance(helper, str):
                if src.scope == "project":
                    self.add("CC015", src, keys + ["headersHelper"], "%s defines headersHelper: %s" % (label, redact_text(helper)),
                             note="runs only after you trust the folder")
                self._risky_command("CC016", src, keys + ["headersHelper"], "%s headersHelper" % label, helper)
            # MCP006
            if src.scope == "project":
                remote = s["url"] is not None
                note = {"claude-code": "claude -p, SDK and cloud sessions connect it without asking",
                        "codex": "loaded only if the project is trusted",
                        "cursor": "review before enabling"}.get(src.agent, "")
                self.add("MCP006", src, keys, "%s: %s" % (label, "remote %s" % display_url(s["url"]) if remote else
                                                          "local command %s" % display_command(s["command"], s["args"])),
                         severity="low" if remote else "medium", note=note)

    # ---- report ---------------------------------------------------------------
    def report(self) -> Dict[str, Any]:
        def loc_key(loc: str) -> Tuple[str, int]:
            m = re.match(r"^(.*):(\d+)$", loc)
            return (m.group(1), int(m.group(2))) if m else (loc, 0)
        self.findings.sort(key=lambda f: (RANK[f["severity"]], f["id"], loc_key(f["location"])))
        summary = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            summary[f["severity"]] += 1
        plan: List[Dict[str, Any]] = []
        by_item: Dict[int, Dict[str, Any]] = {}
        for f in self.findings:
            if f["severity"] == "info":
                continue
            idx = next((i for i, it in enumerate(PLAN_ITEMS)
                        if f["id"] in it["ids"] and it["agent"] in (None, f["agent"])), None)
            if idx is None:
                continue
            if idx not in by_item:
                it = PLAN_ITEMS[idx]
                by_item[idx] = {"severity": f["severity"], "addresses": [], "target": it["target"], "lang": it["lang"],
                                "snippet": it["snippet"], "note": it["note"], "agent": it["agent"] or "all"}
                plan.append(by_item[idx])
            if f["id"] not in by_item[idx]["addresses"]:
                by_item[idx]["addresses"].append(f["id"])
        agents_used = [a for a in AGENTS if a in self.agents]
        manual = [m for a in agents_used for m in MANUAL_CHECKS[a]] + MANUAL_CHECKS["all"]
        return {
            "tool": TOOL,
            "version": VERSION,
            "target": {"home": str(self.home), "project": str(self.project), "agents": agents_used},
            "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "docs_verified": DOCS_VERIFIED,
            "sources": [{"agent": s.agent, "scope": s.scope, "kind": s.kind, "path": s.display,
                         "shared": s.shared, "parsed": s.error is None} for s in self.sources],
            "findings": self.findings,
            "summary": summary,
            "hardening_plan": plan,
            "org_recommendations": [{"agent": a, "key": k, "effect": e} for a, k, e in ORG_RECOMMENDATIONS if a in agents_used],
            "manual_checks": manual,
        }


def plugin_name(root: Optional[Path]) -> str:
    """name@marketplace version for cache/<marketplace>/<plugin>/<version>, else the directory name."""
    if root is None:
        return "?"
    parts = root.parts
    if "cache" in parts:
        i = len(parts) - 1 - parts[::-1].index("cache")
        rest = parts[i + 1:]
        if len(rest) >= 3:
            return "%s@%s %s" % (rest[1], rest[0], rest[2])
    return root.name


def default_managed_dir() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if os.name == "nt":
        return Path(r"C:\Program Files\ClaudeCode")
    return Path("/etc/claude-code")


def audit(home: Path, project: Path, agents: Tuple[str, ...] = AGENTS, managed_dir: Optional[Path] = None,
          codex_system_dir: Optional[Path] = None, include_system: bool = True, claude_dir: Optional[Path] = None,
          codex_dir: Optional[Path] = None, environ: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return Audit(Path(home), Path(project), agents, managed_dir, codex_system_dir, include_system,
                 claude_dir, codex_dir, environ).run()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def render_text(rep: Dict[str, Any], quiet: bool = False) -> str:
    s = rep["summary"]
    counts = ", ".join("%d %s" % (s[k], k) for k in SEVERITIES)
    out = ["agent-config-audit %s  home=%s  project=%s  agents=%s  (%s)" % (
        rep["version"], rep["target"]["home"], rep["target"]["project"], ",".join(rep["target"]["agents"]), counts)]
    if not quiet:
        out.append("")
        out.append("Sources scanned (%d):" % len(rep["sources"]))
        for src in rep["sources"]:
            out.append("  - [%s %s] %s%s%s" % (src["agent"], src["scope"], src["path"],
                                               " (shared: %s)" % src["shared"] if src["shared"] else "",
                                               "" if src["parsed"] else " (parse error)"))
        if not rep["sources"]:
            out.append("  (no agent configuration files found)")
    shown = [f for f in rep["findings"] if not (quiet and f["severity"] == "info")]
    for sev in SEVERITIES:
        group = [f for f in shown if f["severity"] == sev]
        if not group:
            continue
        out.append("")
        for f in group:
            out.append("[%s] %s  %s" % (sev.upper(), f["id"], f["title"]))
            out.append("  at %s  (%s)" % (f["location"], f["scope"] or f["agent"]))
            out.append("  evidence: %s" % f["evidence"])
            out.append("  fix: %s" % f["fix"])
            out.append("  refs: %s" % "; ".join(f["refs"]))
    if rep["hardening_plan"] and not quiet:
        out.append("")
        out.append("Hardening plan (most severe first; review, then apply only with approval):")
        for i, p in enumerate(rep["hardening_plan"], 1):
            out.append("%2d. [%s] %s (addresses %s)" % (i, p["severity"].upper(), p["target"], ", ".join(p["addresses"])))
            out.append("    %s" % p["note"])
            out.append("    ```%s" % p["lang"])
            out.extend(("    " + line).rstrip() for line in p["snippet"].splitlines())
            out.append("    ```")
    if not quiet:
        if rep["org_recommendations"]:
            out.append("")
            out.append("For organizations (managed-only controls; recommendations, not findings):")
            for r in rep["org_recommendations"]:
                out.append("  - [%s] %s: %s" % (r["agent"], r["key"], r["effect"]))
        out.append("")
        out.append("Manual checks this script cannot do:")
        out.extend("  - " + m for m in rep["manual_checks"])
    out.append("")
    out.append("Summary: %s across %d file(s). Point-in-time result; vendor docs verified %s." % (
        counts, len(rep["sources"]), rep["docs_verified"]))
    return "\n".join(out)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # exit 1 on usage errors (repo convention)
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        sys.exit(1)


def main(argv: Optional[List[str]] = None) -> int:
    ap = _Parser(prog=TOOL, description="Audit local AI coding-agent configuration (Claude Code, Codex, Cursor) for risky "
                                        "settings. Read-only; never prints secret values.")
    ap.add_argument("--home", help="home directory to audit (default: your home)")
    ap.add_argument("--project", help="project directory to audit (default: current directory)")
    ap.add_argument("--agent", choices=list(AGENTS) + ["all"], default="all", help="limit to one agent (default: all)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--fail-on", choices=SEVERITIES[:4], help="exit 2 if any finding is at or above this severity")
    ap.add_argument("--quiet", action="store_true", help="text output: hide info findings, sources, plan and notes")
    ap.add_argument("--managed-dir", help="Claude Code managed settings directory (default: the OS system path)")
    ap.add_argument("--codex-system-dir", help="directory holding Codex requirements.toml / managed_config.toml "
                                               "(default: /etc/codex on macOS and Linux)")
    ap.add_argument("--no-system", action="store_true", help="skip managed/system files (audit only --home and --project)")
    ap.add_argument("--claude-dir", help="Claude Code config dir if not <home>/.claude (e.g. CLAUDE_CONFIG_DIR)")
    ap.add_argument("--codex-dir", help="Codex config dir if not <home>/.codex (e.g. CODEX_HOME)")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = ap.parse_args(argv)

    home = Path(args.home).expanduser() if args.home else Path.home()
    project = Path(args.project).expanduser() if args.project else Path.cwd()
    for label, p in (("--home", home), ("--project", project)):
        if not p.is_dir():
            sys.stderr.write("%s: error: %s is not a directory: %s\n" % (TOOL, label, p))
            return 1
    agents = AGENTS if args.agent == "all" else (args.agent,)
    try:
        rep = audit(home.resolve(), project.resolve(), agents,
                    Path(args.managed_dir) if args.managed_dir else None,
                    Path(args.codex_system_dir) if args.codex_system_dir else None,
                    not args.no_system,
                    Path(args.claude_dir).expanduser() if args.claude_dir else None,
                    Path(args.codex_dir).expanduser() if args.codex_dir else None)
    except OSError as exc:
        sys.stderr.write("%s: error: %s\n" % (TOOL, exc))
        return 1
    text = json.dumps(rep, indent=2) if args.json else render_text(rep, args.quiet)
    sys.stdout.write(_final_scrub(text) + "\n")
    if args.fail_on:
        limit = RANK[args.fail_on]
        if any(RANK[f["severity"]] <= limit for f in rep["findings"]):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
