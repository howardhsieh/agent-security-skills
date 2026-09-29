# Tool handler vulnerability classes

Where classic vulnerabilities hide in MCP handlers, how to find candidate sinks, what safe
code looks like, and how to confirm reachability. Patterns find candidates, not bugs; every
hit needs the trace in [Confirming reachability](#confirming-reachability). Defensive use
only. Patterns target ripgrep 14 (`-t js -t ts` covers `.js/.mjs/.cjs/.jsx/.ts/.tsx`); add
`-uu` to include gitignored or vendored code, `-g '!**/test*/**'` to cut noise.

## Contents

1. [Threat model for handler inputs](#threat-model-for-handler-inputs)
2. [Command and argument injection](#command-and-argument-injection)
3. [Path traversal and file access outside roots](#path-traversal-and-file-access-outside-roots)
4. [SSRF and credential forwarding](#ssrf-and-credential-forwarding)
5. [SQL and NoSQL injection](#sql-and-nosql-injection)
6. [Unsafe deserialization](#unsafe-deserialization)
7. [Eval, dynamic code and template injection](#eval-dynamic-code-and-template-injection)
8. [Missing access control in handlers](#missing-access-control-in-handlers)
9. [Secrets in logs, errors and outputs](#secrets-in-logs-errors-and-outputs)
10. [Unbounded consumption](#unbounded-consumption)
11. [Dependency and launch risk](#dependency-and-launch-risk)
12. [Confirming reachability](#confirming-reachability)

## Threat model for handler inputs

Attacker-controlled sources: tool `arguments`, resource URIs and template variables, prompt
arguments, `requestState`, elicitation responses, and parsed upstream responses. Injected
text anywhere in model context can choose arguments (AML.T0051.001, ATLAS v2026.09); model
output reaching a shell, query or interpreter is LLM05:2025 Improper Output Handling.

| Class | Framework IDs |
| --- | --- |
| Command, eval, deserialization | ASI05 (Agentic Top 10 2026), LLM05:2025 |
| Path traversal, SSRF, SQL/NoSQL, access control | ASI02 (Agentic Top 10 2026), AML.T0086 / AML.T0101 (ATLAS v2026.09) |
| Secrets exposure | LLM02:2025, AML.T0098 (ATLAS v2026.09) |
| Unbounded consumption | LLM10:2025, ASI02 (Agentic Top 10 2026) |
| Dependencies and launch | ASI04 (Agentic Top 10 2026), LLM03:2025, AML.T0010.005 (ATLAS v2026.09) |

## Command and argument injection

Looks like: a `git_*`, `run_*` or `convert_*` tool builds a command string from arguments;
a fixed binary receives values it parses as options (leading `-`); a run-anything tool
with no sandbox.

```bash
rg -n -t js -t ts 'child_process|\bexec(Sync)?\(|\bspawn(Sync)?\(|execFile(Sync)?\(|shell:\s*true|execa|shelljs'
rg -n -t py 'subprocess\.\w+\(|os\.(system|popen|exec\w*|spawn\w*)\(|shell\s*=\s*True|create_subprocess_shell|pexpect'
rg -n -t go 'exec\.Command(Context)?\(|"(sh|bash|zsh|cmd(\.exe)?|powershell)"|"-c"|syscall\.Exec'
```

Safe: no shell. Use `execFile`/`spawn` with an argument array (Node), `subprocess.run([...])`
with `shell=False` (Python), `exec.Command(bin, args...)` with a constant binary (Go).
Allowlist subcommands and validate values; insert `--` before positional values where the
program supports it; reject values beginning with `-`. Run-anything tools need a container
or VM with no secrets, no default network and resource limits. Confirm: the argument
reaches the command or argv unallowlisted, and a shell is involved or the value lands in an
option position.

## Path traversal and file access outside roots

Looks like: `read_file`, `write_file`, `list_dir` or a `file:///{path}` resource template
joins an argument onto a base directory; archive extraction writes entry names to disk;
writes or deletes follow symlinks. The resources spec requires sanitizing `file://` paths.

```bash
rg -n -t js -t ts '\b(readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rm|rmdir|mkdir|rename|copyFile|readdir|open)(Sync)?\(|path\.(join|resolve)\('
rg -n -t py '\bopen\(|Path\(|os\.path\.join\(|shutil\.\w+\(|os\.(remove|unlink|rename|makedirs|listdir|scandir)\(|extractall\(|send_file\('
rg -n -t go 'os\.(Open|OpenFile|Create|ReadFile|WriteFile|Remove|RemoveAll|Rename|MkdirAll|ReadDir)\(|filepath\.Join\(|archive/(zip|tar)'
```

Safe: resolve the real path of the root once and of the target after joining (following
symlinks), then require containment on a separator boundary: Node `path.relative(root,
target)` must not start with `..` or be absolute; Python `Path(target).resolve()
.is_relative_to(root)` (3.9+); Go `os.OpenRoot` / `os.Root` (Go 1.24+) or `filepath.Rel`
plus symlink resolution. Decode before checking. Reject absolute, UNC and drive paths.
Validate archive entry names the same way (Python `tarfile` extraction filters where
available). Scope write and delete tools narrower than read tools.

Flag: `startsWith(root)` without a trailing separator, checks before URL-decoding,
`normalize` without `realpath`, check-then-open across a symlink race. Confirm: the
containment check is missing, bypassed by symlink or encoding, or absent on some paths.

## SSRF and credential forwarding

Looks like: `fetch_url`, `browse`, webhook, "import from URL", or an API client whose base
URL, host or path comes from arguments; headless browsers navigating to model-chosen URLs;
server API keys or OAuth tokens attached to requests whose destination the model picks.

```bash
rg -n -t js -t ts '\bfetch\(|axios|\bgot\(|undici|https?\.(get|request)\(|new URL\(|page\.goto\(|puppeteer|playwright'
rg -n -t py 'requests\.(get|post|put|patch|delete|request|Session)|httpx\.|urlopen\(|urllib\.request|aiohttp|urllib3|page\.goto\('
rg -n -t go 'http\.(Get|Post|Head|NewRequest|NewRequestWithContext)\(|\.Do\(|net\.Dial|resty'
```

Safe: fixed upstream hosts where possible; otherwise scheme and host allowlist, DNS
resolution with a block on private, loopback, link-local (cloud metadata) and IPv6 private
ranges, connection pinned to the checked IP, redirects disabled or re-validated per hop,
and an egress proxy. Use a vetted library, not hand-written IP parsing. Attach credentials
only for allowlisted hosts. Cap response size and time, and label fetched content as
untrusted when returned to the model.

Confirm: URL, host or path is argument-controlled with no post-resolution check; note
separately whether server credentials travel with the request.

## SQL and NoSQL injection

Looks like: query strings built with concatenation, template literals or f-strings;
filter objects passed straight from arguments into MongoDB-style queries; an
`execute_sql` tool that runs model-written SQL with the application's full-privilege role.

```bash
rg -n -t js -t ts '\.(query|execute|raw)\(\s*`|\.(query|execute)\([^,)]*\+|\$(queryRaw|executeRaw)Unsafe|knex\.raw|sequelize\.query|\$where'
rg -n -t py 'execute(many)?\(\s*f["\x27]|execute\([^)]*(%\s|\.format\(|\+)|text\(\s*f["\x27]|\.raw\(|\.extra\(|\$where'
rg -n -t go '(?i)fmt\.Sprintf\([^)]*(select|insert|update|delete|where)|\.(Query|QueryRow|Exec)(Context)?\([^,]*\+'
```

Safe: parameterized queries or a query builder for every value; identifiers (table,
column, sort) from an allowlist. For NoSQL, accept scalars in the schema and build the
filter server-side; disable server-side JavaScript operators. For SQL-by-design tools: a
read-only database role scoped to allowed schemas, statement-type allowlist, row and time
limits, tenancy enforced in the database. Confirm: an argument reaches query text, not a
bound parameter.

## Unsafe deserialization

Looks like: `requestState`, cache entries, uploaded files or upstream payloads decoded
with formats that can construct arbitrary objects or run code.

```bash
rg -n -t js -t ts 'node-serialize|serialize-javascript|funcster|\bunserialize\(|v8\.deserialize|yaml\.load\('
rg -n -t py 'pickle\.loads?\(|cPickle|dill\.|shelve\.|marshal\.loads?\(|jsonpickle|yaml\.(load|unsafe_load)\(|Loader\s*=\s*yaml\.(Unsafe|Full)?Loader|torch\.load\(|joblib\.load\('
rg -n -t go 'encoding/gob|gob\.NewDecoder|yaml\.Unmarshal|json\.Unmarshal\('
```

Safe: JSON into explicit types; `yaml.safe_load` / `SafeLoader` (Python), js-yaml 4 `load`
(js-yaml 3 needs `safeLoad`); no pickle-family formats on anything a client or third party
can influence; `torch.load(..., weights_only=True)` (check the pinned version's default).
In Go, decode into concrete structs with size limits (`http.MaxBytesReader`). Verify
`requestState` integrity before parsing it. Confirm: a client, the model or a third party
can influence the decoded bytes.

## Eval, dynamic code and template injection

Looks like: calculator, "transform", jq-like or scripting tools that evaluate expressions;
prompts or tool outputs rendered through a template engine using argument text as the
template; dynamic `import`/`require` of argument-derived module names.

```bash
rg -n -t js -t ts '\beval\(|new Function\(|vm\.(runIn\w+|Script|compileFunction)|vm2|\b(require|import)\(\s*[a-zA-Z_]|_\.template\(|ejs\.render|handlebars\.compile|pug\.(render|compile)|renderString'
rg -n -t py '\beval\(|\bexec\(|\bcompile\(|__import__\(|import_module\(|render_template_string|Template\(|\.(eval|query)\(\s*[a-z_]'
rg -n -t go 'text/template|html/template|\.Parse\(|goja|otto|yaegi|expr\.(Compile|Eval)|plugin\.Open'
```

Safe: purpose-built parsers (arithmetic grammar, JSONPath library) instead of language
eval; `ast.literal_eval` for Python literals only. Templates are constants; arguments are
passed as data, with autoescaping for the output context. Module names from a fixed map.
Node's documentation states `vm` is not a security mechanism; do not rely on in-process
JS sandboxes. Isolate untrusted code in a process or container. Confirm: argument text is
parsed as code or template.

## Missing access control in handlers

Looks like: on a multi-user server, a tool fetches or mutates a record by an ID from
arguments without checking that it belongs to the caller; identity read from an argument
(`user_id`, `email`) or from `clientInfo`; state handles looked up without an owner check;
admin tools registered for every caller.

Find every handler taking an identifier and check each lookup for an ownership or role
condition derived from the verified token subject:
`rg -n '(?i)(user_?id|owner|tenant|account_?id|org_?id|handle)' -g '*.{ts,js,py,go}'`

Safe: identity only from the validated token; ownership enforced in the query or by keying
storage on `<user_id>:<id>`; per-tool scope checks from server-side policy. Confirm: two
users of one deployment could reach each other's objects with a guessed or leaked ID.

## Secrets in logs, errors and outputs

Looks like: request headers, env or config objects logged; upstream error bodies or stack
traces returned as `isError` text (which enters model context and possibly other tools);
tokens embedded in URLs that are logged; debug tools that return configuration; stdio
servers printing diagnostics to stdout.

```bash
rg -n -t js -t ts 'console\.\w+\([^)]*(token|secret|key|passw|authorization|headers|process\.env)|JSON\.stringify\(\s*(req|request|err|error|process\.env|config)|\.stack\b'
rg -n -t py '(log|logger|logging)\.\w+\([^)]*(token|secret|key|passw|authorization|headers|environ)|print\([^)]*(token|secret|environ)|format_exc\(|str\(e\)|repr\(e\)'
rg -n -t go '(log|slog|logger|zap|logrus)\.\w+\([^)]*(?i:token|secret|key|passw|authorization|header)|os\.Environ\(|%\+v'
```

Safe: central redaction for known secret fields and patterns; structured logs with
allowlisted fields; user-facing and model-facing errors are generic plus a correlation ID,
with details only in server logs; no secrets in URLs; diagnostics to stderr on stdio.
Confirm: a real secret value (not a key name) can reach a log, error or tool result.

## Unbounded consumption

Looks like: no rate limit per user or tool; list or search tools without a maximum page
size; fetch or file-read tools returning unbounded bytes into model context; no timeouts
on upstream calls or subprocesses; recursive crawls; regexes compiled from arguments in
backtracking engines; costly upstream operations (paid APIs, email sends) callable in loops.

```bash
rg -n '(?i)rate.?limit|ratelimit|throttle|semaphore|p-limit|bottleneck|max_?(results|bytes|size|rows)|page_?size|timeout|maxBuffer|MaxBytesReader'
rg -n -t js -t ts 'new RegExp\(' ; rg -n -t py 're\.(compile|match|search|sub|findall)\(\s*[a-z_]'
```

Safe: per-principal rate limits and per-tool budgets (the spec requires rate limiting tool
invocations); schema `maximum` on counts plus server-side clamping; byte caps and
truncation markers on outputs; timeouts and concurrency limits on upstream calls and child
processes; stop work when a request is cancelled; safe regex engines or no user-supplied
patterns (Go's RE2-based `regexp` is linear-time).

Confirm: one call or a short loop can exhaust memory, CPU, context, quota or money.

## Dependency and launch risk

Looks like: README or install config launching with unpinned `npx`, `uvx`, `pipx run`,
`bunx` or `docker run` without a version or digest; `curl | sh` installers; install
lifecycle scripts; missing lockfiles; code or binaries downloaded at runtime; plugins
loaded from argument- or config-controlled paths.

```bash
rg -n '(npx|bunx)\s+(-y\s+)?@?[a-z]|uvx\s|pipx run|docker run|curl[^|\n]*\|\s*(sh|bash)|@latest|:latest' -g '*.{md,json,toml,yaml,yml}'
rg -n '"(preinstall|install|postinstall|prepare)"\s*:' -g 'package.json'
rg --files | rg '(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|uv\.lock|poetry\.lock|requirements.*\.txt|go\.sum)$'
```

Safe: exact version pins in launch commands (`npx pkg@1.2.3`, `uvx pkg@1.2.3`), images by
digest, committed lockfiles, hash-pinned Python installs, `npm ci --ignore-scripts` in CI,
vulnerability scanning (`npm audit`, `pip-audit`, `govulncheck`), no runtime code
download. For packaging and marketplace wrappers, run `skill-supply-chain-audit`. Confirm:
the documented install could resolve to code the reviewer has not seen.

## Confirming reachability

For each candidate, write the chain before assigning severity:

1. **Entry:** the tool, resource template or prompt name and its registration `file:line`.
2. **Source:** which argument or input field; who can control it (any content in model
   context, an authenticated user, an unauthenticated network caller, an upstream API).
3. **Path:** each function hop with `file:line`, including shared helpers used by other
   tools and any non-MCP HTTP routes that reach the same sink.
4. **Guards:** schema constraints, validation, normalization, encoding, authorization.
   State whether each guard covers every path, including error and retry paths.
5. **Sink:** the dangerous call with `file:line` and what it does with the value.
6. **Result:** `Confirmed`, `Candidate` (name the unresolved hop), or dropped.

For each fix, propose a negative unit test that feeds a benign boundary value (a
parent-directory path against a temp-dir fixture, a loopback host against a stub) and
asserts rejection. Tests assert rejection; they do not demonstrate exploitation.
