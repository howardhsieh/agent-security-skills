# agentsec-kit (plugin folder)

This folder is the `agentsec-kit` Claude Code plugin: seven defensive Agent Skills
for people who run AI coding agents. They grade your whole agent setup A to F,
audit skills and plugins before you
install them, harden Claude Code, Codex and Cursor configuration, threat-model
agent applications, review MCP servers, detect hijacked agents in their own
telemetry, and guide incident response.

What the plugin runs: only the Python scripts under each skill's `scripts/`
folder, when a skill tells the agent to run them. They are read-only, make no
network calls, send nothing anywhere, and redact credential-looking values in
their output. The plugin ships no hooks, MCP servers or binaries.

Full documentation, install options and source: https://github.com/howardhsieh/agent-security-skills
