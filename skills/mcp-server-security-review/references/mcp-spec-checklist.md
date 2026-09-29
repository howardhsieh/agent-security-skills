# MCP spec security checklist (protocol 2026-07-28)

Derived from the official MCP 2026-07-28 Security Best Practices, Authorization,
transport and server-feature pages (verified 2026-09-29). Levels are the spec's keywords;
"Guidance" marks non-normative practice. Each table states which component it binds; if
the server is also an MCP client (gateway, hosted agent), spawns other servers, or bundles
an authorization server, those rows apply too. Spec keys resolve in [Sources](#sources).

## Contents

1. [Version notes: 2026-07-28 vs 2025-11-25](#version-notes-2026-07-28-vs-2025-11-25)
2. [Security Best Practices 1-11](#security-best-practices-1-11)
3. [Authorization: server requirements](#authorization-server-requirements)
4. [Transport and base protocol](#transport-and-base-protocol)
5. [Tools, resources, MRTR and elicitation](#tools-resources-mrtr-and-elicitation)
6. [Sources](#sources)

## Version notes: 2026-07-28 vs 2025-11-25

Establish which revisions the server negotiates before using the tables
(`rg -n "2025-11-25|2025-06-18|2026-07-28|LATEST_PROTOCOL_VERSION|protocolVersion"`).

2026-07-28 changes that affect review ([CHANGELOG]):

- Protocol-level sessions and the `Mcp-Session-Id` header are removed. MCP is stateless;
  the `initialize` handshake is gone and every request carries protocol version and client
  capabilities in `_meta`. Cross-call state uses explicit, server-minted handles passed as
  ordinary tool arguments (see BP 4).
- Server-initiated requests (sampling, elicitation, roots) are replaced by Multi
  Round-Trip Requests: an `InputRequiredResult` plus an opaque `requestState` the client
  echoes back. `requestState` is attacker-controlled input (section 5).
- The standalone HTTP GET stream and SSE resumability (`Last-Event-ID`) are removed.
- Dynamic Client Registration is deprecated in favor of Client ID Metadata Documents.
- Roots, Sampling and Logging are deprecated (still functional during the window).

A server that supports only 2026-07-28 and receives legacy traffic SHOULD answer HTTP GET
or DELETE on the MCP endpoint with 405, ignore `Mcp-Session-Id` (never mint or echo
session IDs) and ignore `Last-Event-ID` ([SHTTP]).

Servers still on 2025-11-25, or supporting it alongside 2026-07-28, must also meet the
2025-11-25 Session Hijacking rules ([BP-2025]): MUST verify all inbound requests; MUST NOT
use sessions for authentication; MUST use secure, non-deterministic session IDs; SHOULD
bind session IDs to user-specific information (`<user_id>:<session_id>`, user ID from the
token). That page also describes injection through shared event queues keyed by session
ID, resumable streams, and server-sent events such as `notifications/tools/list_changed`.
Locate them with `rg -n "Mcp-Session-Id|sessionIdGenerator|mcp-session-id|Last-Event-ID|EventStore"`.

## Security Best Practices 1-11

### BP 1. Confused deputy

Applies to: MCP proxy servers that use a static client ID with a third-party
authorization server and let MCP clients register dynamically.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Per-client consent before forwarding to the third-party authorization server | MUST | In the `/authorize` handler, find the consent lookup; confirm no path reaches the upstream redirect without it | [BP-1], [AUTH-SEC] |
| Registry of approved `client_id` values per user, checked before the upstream flow, stored securely | MUST | Key includes user and `client_id`; storage is server-side DB or server-specific cookie | [BP-1] |
| Consent page names the client, shows third-party scopes and the registered `redirect_uri` | MUST | Template values come from the registration record, not from query parameters | [BP-1] |
| Consent page has CSRF protection and anti-framing (`frame-ancestors` or `X-Frame-Options: DENY`) | MUST | Consent POST validates a token; response headers on consent route | [BP-1] |
| Consent cookies: `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax`, signed or server-side, bound to `client_id` | MUST | Inspect cookie-setting call options and value contents | [BP-1] |
| `redirect_uri` exact string match to registered value; reject changes without re-registration | MUST | Flag `startsWith`, regex, wildcard, host-only or normalized comparisons | [BP-1] |
| `state`: CSPRNG, stored only after consent, set immediately before upstream redirect, exact match at callback, reject missing or mismatched, single-use, short expiry | MUST | Trace `state` from generation to callback; confirm delete-after-use and TTL | [BP-1] |

### BP 2. Token passthrough

Applies to: every server that accepts access tokens.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Do not accept tokens not explicitly issued for this server | MUST NOT | Audience check against the canonical server URI (section 3) | [BP-2] |
| Do not forward the client's token to downstream APIs; use a separate upstream token | MUST NOT | Trace the inbound `Authorization` header; flag it or header-copying proxy middleware reaching outbound HTTP clients | [BP-2], [AUTH-SEC] |

### BP 3. SSRF during OAuth metadata discovery

Applies to: MCP clients deployed to a server (gateways, hosted agents) and authorization
servers that fetch Client ID Metadata Documents. For SSRF inside tool handlers, see
`tool-handler-vulns.md`.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Consider SSRF and mitigate when fetching OAuth-related URLs | MUST | Find fetches of `resource_metadata`, `authorization_servers`, AS endpoints, `client_id` URLs | [BP-3] |
| HTTPS only; `http://` only for loopback in development with explicit opt-out | SHOULD | Scheme check before fetch | [BP-3] |
| Block 10/8, 172.16/12, 192.168/16, 127/8, ::1, 169.254/16, fc00::/7, fe80::/10 | SHOULD | Prefer a vetted library or egress proxy over hand-written IP parsing | [BP-3] |
| Apply the same checks to each redirect hop | SHOULD | Auto-redirect disabled or per-hop validation | [BP-3] |
| Egress proxy for server-side deployments; pin DNS between check and use | SHOULD / Guidance | Deployment config; resolver reuse | [BP-3] |

### BP 4. State handle hijacking

Applies to: servers that mint handles (cart ID, workflow ID) reused across tool calls.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Servers implementing authorization verify all inbound requests | MUST | Auth runs on every request, not once per connection or handle | [BP-4] |
| Possession of a handle is never authentication | MUST NOT | Lookups by handle alone with no principal check are findings | [BP-4] |
| Handles from a CSPRNG, non-sequential; expiry reduces risk | SHOULD | Flag `Math.random`, counters, timestamps, `random.random`, `math/rand` | [BP-4] |
| Handles bound server-side to the user (`<user_id>:<handle>`, user ID from verified token) | SHOULD | Storage key and ownership check on every access | [BP-4], [TOOLS] |

### BP 5. Local MCP server compromise

Applies to: servers intended to run locally (server rows) and clients with one-click
install (client rows; review the server's install docs and deep links against them).

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Local servers use stdio, or restrict HTTP with an auth token or Unix socket / IPC | SHOULD | Transport setup; listener address; auth on local port | [BP-5] |
| One-click install shows the exact untruncated command and needs explicit approval | MUST (client) | Install snippets and deep links contain only the server launch, no chained commands | [BP-5] |
| Sandbox, least privilege, warn on `sudo`, `rm -rf`, sensitive paths | SHOULD (client) | Recommend container or OS sandbox in adoption conditions | [BP-5] |

### BP 6. OAuth authorization URL validation

Applies to: clients, and any server code that opens URLs (for example a local helper for
an upstream OAuth flow).

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Allow only `http`/`https` (`http` only for loopback); reject `javascript:`, `data:`, `file:`, `vbscript:` | MUST | Scheme allowlist before open | [BP-6] |
| Never open URLs through a shell (`cmd.exe`, `sh`, PowerShell) | MUST NOT | Flag `exec("open " + url)`, `start`, `xdg-open` via shell strings | [BP-6] |
| Sanitize and validate all URLs received from MCP servers | MUST | Strict parser, no shell metacharacters | [BP-6] |

### BP 7. stdio transport in proxy scenarios

Applies to: proxies or gateways that spawn MCP servers as child processes.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Sandbox spawned processes, restrict filesystem, log all stdio launches, extra authorization for dangerous commands | SHOULD | Spawn commands come from static admin config, never from request data; control endpoint authenticated | [BP-7] |

### BP 8. Mix-up attacks

Applies to: MCP clients. For a server that is an OAuth client of an upstream provider,
treat RFC 9207 validation as recommended practice.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Record issuer before redirect; validate `iss` per RFC 9207 §2.4 before redeeming the code; no normalization; ignore error fields on mismatch | MUST (client) | Per-request record holds issuer with PKCE verifier; simple string compare | [BP-8], [AUTH] |

### BP 9. Localhost redirect URI impersonation

Applies to: authorization servers accepting Client ID Metadata Documents.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Clearly display the redirect URI hostname during authorization | MUST (AS) | Consent template | [BP-9], [AUTH-SEC] |
| Extra warnings for localhost-only redirect URIs; attestation optional | SHOULD / MAY (AS) | Consent template branches on loopback hosts | [BP-9], [AUTH-SEC] |

### BP 10. CIMD trust policies

Applies to: authorization servers accepting Client ID Metadata Documents.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Consider CIMD security considerations, including SSRF on metadata fetch | MUST / SHOULD (AS) | Fetcher uses BP 3 controls | [AUTH-SEC] |
| Domain trust policy (allowlist, reputation, domain age); show client hostnames prominently | MAY / Guidance | Policy config | [BP-10] |

### BP 11. Scope minimization

Applies to: servers using authorization.

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Minimal initial scopes; step up through targeted `WWW-Authenticate` `scope` challenges | Guidance | `scopes_supported` lists a minimal set, not the full catalog | [BP-11], [AUTH] |
| Include `scope` in `WWW-Authenticate`; all scopes for the operation in one 403 challenge | SHOULD | 401/403 builders | [AUTH-SCOPE] |
| Do not list `offline_access` in challenges or `scopes_supported` | SHOULD NOT | Metadata and challenge values | [AUTH] |
| Account for scope hierarchies when deciding sufficiency | MUST | Scope-check helper | [AUTH] |
| No wildcard or omnibus scopes; enforce authorization server-side, not only from token claims; log elevation events | Guidance | Flag `*`, `all`, `full-access`; per-tool checks exist | [BP-11] |

## Authorization: server requirements

Authorization is optional. HTTP transports SHOULD conform; stdio transports SHOULD NOT
use it and instead read credentials from the environment ([AUTH]).

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Implement RFC 9728 Protected Resource Metadata with at least one `authorization_servers` entry | MUST | `/.well-known/oauth-protected-resource` route or equivalent | [AUTH], [AUTH-DISC] |
| Advertise metadata via `resource_metadata` in the 401 `WWW-Authenticate`, or at a well-known URI | MUST (one of) | 401 builder; well-known route | [AUTH-DISC] |
| Validate access tokens per OAuth 2.1 §5.2 before processing the request | MUST | Signature/introspection, `exp`, `iss`; no decode-only paths; runs before any handler | [AUTH], [AUTH-SEC] |
| Tokens issued for this server as audience (RFC 8707); reject tokens without it | MUST | `aud` compared to canonical server URI; flag disabled audience verification | [AUTH], [AUTH-SEC] |
| Accept only tokens valid for own resources; never accept or transit other tokens | MUST / MUST NOT | See BP 2 | [AUTH] |
| 401 for missing, invalid or expired tokens; 403 for insufficient scope; 400 for malformed | MUST | Error mapping in middleware | [AUTH] |
| 403 with `error="insufficient_scope"`, `scope`, `resource_metadata` | SHOULD | 403 builder | [AUTH-SCOPE] |
| Secure token storage (tokens cached or logged on the server are a theft path); follow OAuth 2.1 §7 | MUST | Stored tokens keyed per user, protected at rest, never logged or returned in outputs | [AUTH-SEC] |
| Access tokens never in the URI query string | MUST NOT (client) | A server that accepts tokens from query parameters invites this and leaks them to access logs; flag it | [AUTH] |

Client-side rules to keep in mind when the server also acts as a client: PKCE with
`S256`, refuse if `code_challenge_methods_supported` is absent; `resource` parameter in
authorization and token requests; `iss` validation; Bearer header on every request;
redirect URIs pre-registered, localhost or HTTPS; CIMD SHOULD, DCR deprecated (MAY);
authorization servers MUST rotate refresh tokens for public clients ([AUTH], [AUTH-SEC]).

## Transport and base protocol

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Validate `Origin` on all incoming connections; 403 if present and invalid | MUST | Middleware on the MCP endpoint; allowlist, not reflection | [SHTTP] |
| Bind local HTTP servers to 127.0.0.1, not 0.0.0.0 | SHOULD | Listen address and defaults | [SHTTP] |
| Authenticate all connections | SHOULD | No unauthenticated routes that reach handlers | [SHTTP] |
| Reject header/body mismatches (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) with 400 and `-32020`; decode Base64 sentinel before compare | MUST | Validation before routing or policy decisions | [SHTTP] |
| Do not mark secrets or PII with `x-mcp-header` | SHOULD NOT | Search schemas for `x-mcp-header` | [TOOLS] |
| stdio servers write nothing but MCP messages to stdout | MUST NOT | Flag `console.log`/`print` to stdout; logs go to stderr | [STDIO] |
| Do not rely on prior requests on a connection for context | MUST NOT | No per-connection auth or identity caches | [BASE] |
| `clientInfo` and `serverInfo` are self-reported; not used for security decisions | SHOULD NOT | Flag allowlists or trust keyed on client name | [BASE] |
| Never auto-dereference network `$ref`; bound composition-keyword validation cost | MUST NOT / SHOULD | Validator configuration | [BASE] |

## Tools, resources, MRTR and elicitation

| Requirement | Level | How to verify in code | Spec |
| --- | --- | --- | --- |
| Validate all tool inputs; access controls; rate limit invocations; sanitize outputs | MUST | Per-handler review; limiter present; see `tool-handler-vulns.md` | [TOOLS] |
| `tools/list` does not vary per-connection or as a side effect of other requests (MAY vary by authorization) | MUST NOT | Tool registration not driven by counters, time, remote content or prior calls | [TOOLS] |
| Tool names 1-128 chars, `A-Z a-z 0-9 _ - .`, unique within server | SHOULD | Registration list | [TOOLS] |
| Structured results conform to declared `outputSchema` | MUST | Output construction | [TOOLS] |
| Validate resource URIs; sanitize `file://` paths against traversal | MUST | URI parser and path containment check | [RES] |
| Access controls on sensitive resources; permissions checked before operations | SHOULD | Per-resource authorization | [RES] |
| Treat `requestState` as attacker-controlled; HMAC/AEAD when it affects authorization, resource access or business logic; reject on failure | MUST | Find encode/decode of `requestState`; flag plain base64 JSON used for decisions | [MRTR] |
| Include principal, short TTL and originating-request digest in protected `requestState`; enforce single-use server-side where required | SHOULD / MUST | Payload fields and verification | [MRTR] |
| No form-mode elicitation for passwords, API keys, tokens or payment credentials; use URL mode | MUST NOT / MUST | `elicitation/create` with `mode: "form"` requesting secrets | [ELIC] |
| Bind elicitation to client and user identity; verify the user opening a URL is the one who started it | MUST | Connect route compares authenticated subject to elicitation owner | [ELIC] |
| No credentials, PII or pre-authenticated links in elicitation URLs | MUST NOT | URL construction | [ELIC] |
| Third-party credentials never transit the client; never sent back to the client | MUST NOT | Tool outputs and errors exclude stored upstream tokens | [ELIC] |
| Do not rely on client-provided user identity without server verification | MUST NOT | Identity from token `sub`, not arguments | [ELIC] |

## Sources

All pages are protocol revision 2026-07-28 unless labeled.

- [BP-1] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#confused-deputy-problem
- [BP-2] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#token-passthrough
- [BP-3] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#server-side-request-forgery-ssrf
- [BP-4] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#state-handle-hijacking
- [BP-5] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#local-mcp-server-compromise
- [BP-6] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#oauth-authorization-url-validation
- [BP-7] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#stdio-transport-security-in-proxy-scenarios
- [BP-8] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#mix-up-attacks
- [BP-9] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#localhost-redirect-uri-impersonation
- [BP-10] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#cimd-trust-policies
- [BP-11] https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#scope-minimization
- [BP-2025] https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices#session-hijacking
- [AUTH] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- [AUTH-SCOPE] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#scope-challenge-handling
- [AUTH-DISC] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
- [AUTH-SEC] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- [SHTTP] https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- [STDIO] https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio
- [BASE] https://modelcontextprotocol.io/specification/2026-07-28/basic/index
- [TOOLS] https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- [RES] https://modelcontextprotocol.io/specification/2026-07-28/server/resources
- [MRTR] https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
- [ELIC] https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- [CHANGELOG] https://modelcontextprotocol.io/specification/2026-07-28/changelog
