# Credential rotation for agent incidents

Credentials an AI agent commonly holds or can reach, and how to revoke or rotate each one. Links
were checked on 2026-09-29; vendor UIs change, so follow the linked page when it disagrees with
the summary here.

## Contents

1. [Principles](#principles)
2. [Scope what to rotate](#scope-what-to-rotate)
3. [GitHub](#github): PATs, gh CLI, OAuth and GitHub Apps, SSH keys, deploy keys, sessions
4. [Package registries](#package-registries): npm, PyPI
5. [Cloud CLIs](#cloud-clis): AWS, Google Cloud, Azure
6. [Model provider API keys](#model-provider-api-keys): Anthropic, OpenAI
7. [Connector and OAuth grants](#connector-and-oauth-grants): Slack, Notion, Google, claude.ai connectors, MCP OAuth
8. [Secrets in .env and config files](#secrets-in-env-and-config-files): database URLs, generic API keys
9. [Browser sessions](#browser-sessions)
10. [Rotation record](#rotation-record)

## Principles

- **Do it from a clean terminal or browser**, not from inside the agent session under
  investigation. Never paste a new secret into an agent chat.
- **Revoke, then replace.** Local logout (`gh auth logout`, `az logout`) only deletes the local
  copy. It does not invalidate a token someone already copied. Revoke on the server side.
- **Order by blast radius**: publish and write rights first (package registries, repo admin, cloud
  admin, CI secrets), then read access, then sessions and cookies.
- **Update consumers before you delete, but after you revoke a leaked credential.** For a planned
  rotation the AWS pattern is: create a new key, switch consumers, deactivate the old key, delete
  it. For a leaked credential, deactivate first and accept the outage.
- **Check for use.** After revoking, review the provider's audit log from the first-seen time for
  actions taken with the old credential.
- **Remove the secret from where the agent read it.** Move it out of `.env` and config files the
  agent can read, into a secret manager or OS keychain, and deny agent reads of those paths
  (`agent-config-audit`).

## Scope what to rotate

Use the lethal-trifecta legs (see `agent-threat-model`) on the compromised context:

| Question | Where to look | Rotate if yes |
|---|---|---|
| Could it read the secret? | Files in the workspace and home the agent's tools could open (`.env`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.pypirc`, `~/.ssh/`, `~/.docker/config.json`, `~/.kube/config`), environment variables, MCP server `env` blocks, agent config files | Yes |
| Did a tool call print it? | `search-sessions` for token prefixes (`ghp_`, `github_pat_`, `npm_`, `pypi-`, `AKIA`, `sk-`, `xox`), `.env` reads, `env` or `printenv` commands | Yes, and purge the transcript after the evidence copy |
| Could it send data out? | Shell with network, web fetch, MCP tools that post or write, git push, package publish | If yes, treat everything readable as exposed |
| Could it act with the credential without reading it? | CLIs already logged in (`gh`, `aws`, `gcloud`, `az`, `npm`), SSH agent, browser tool with signed-in profile | Review audit logs for its actions; rotate if the session is long-lived |

## GitHub

**Personal access tokens (classic and fine-grained).** Settings > Developer settings > Personal
access tokens > Fine-grained tokens or Tokens (classic) > Delete. A valid token pushed to a public
repository or gist is revoked automatically. For a token that belongs to someone else, use the
credential revocation REST API.
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation
- https://docs.github.com/en/rest/credentials/revoke

**gh CLI.** `gh auth logout` removes the stored credential only locally and does not revoke the
token. Revoke the GitHub CLI OAuth app authorization (Settings > Applications > Authorized OAuth
Apps), then `gh auth login` again. gh stores the token in the system credential store, or in a
plain-text file when no store is available or `--insecure-storage` was used.
- https://cli.github.com/manual/gh_auth_logout
- https://cli.github.com/manual/gh_auth_login

**OAuth apps and GitHub Apps.** Settings > Applications > Authorized OAuth Apps or Authorized
GitHub Apps > Revoke. Only the user who authorized an app can revoke that authorization.
Organization owners can uninstall an app from the organization.
- https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps
- https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps

**SSH keys.** Settings > SSH and GPG keys; delete unknown or exposed keys. Compare fingerprints with
`ssh-add -l -E sha256`. Generate a new key pair with a passphrase, and remove the old private key
from every machine the agent could reach. Check `~/.ssh/authorized_keys` on hosts too
(see [persistence-locations.md](persistence-locations.md)).
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-ssh-keys

**Deploy keys.** Repository Settings > Deploy keys; delete the exposed key and add a new one. Deploy
keys with write access can push to the repository.
- https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys

**Sessions and audit.** Settings > Sessions > revoke unknown web sessions. Settings > Security log
(90 days) shows `oauth_access`, `oauth_authorization`, `public_key` and personal access token
events. Also rotate repository and organization Actions secrets if the agent could read them.
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/viewing-and-managing-your-sessions
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log

## Package registries

**npm.** `npm token list`, then `npm token revoke ID` (the ID or the full token), or use Access
Tokens on the website. Revocation can take up to an hour to take effect. Remove the old token from
`~/.npmrc` and CI. Review the publish history of every package the account can publish.
- https://docs.npmjs.com/revoking-access-tokens
- https://docs.npmjs.com/cli/v11/commands/npm-token

**PyPI.** Account settings > API tokens; remove the exposed token and create a new one with project
scope. PyPI revokes tokens found posted publicly and emails the owner. Review the account's
security history. Prefer Trusted Publishing from CI over long-lived tokens. The help page does not
document the removal button's exact label, so check the account UI.
- https://pypi.org/help/#apitoken
- https://pypi.org/help/#compromised-token
- https://pypi.org/help/#suspicious-activity

## Cloud CLIs

**AWS.** For IAM user access keys: `aws iam update-access-key --access-key-id ID --status Inactive
--user-name USER`, then `aws iam create-access-key`, update consumers, and `aws iam
delete-access-key`. `aws iam get-access-key-last-used` shows recent use. For role sessions the
agent could have assumed, use IAM console > Roles > Revoke sessions, which attaches the
`AWSRevokeOlderSessions` policy. Clear `~/.aws/cli/cache`. Search CloudTrail `LookupEvents` with
`AccessKeyId` for actions taken with the key.
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
- https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupAttribute.html

**Google Cloud.** `gcloud auth revoke ACCOUNT` revokes a user account token on the server. It
cannot revoke service account tokens server-side, so disable and delete the service account key
instead: `gcloud iam service-accounts keys disable KEY_ID --iam-account=SA` and then delete it.
`gcloud auth application-default revoke` revokes Application Default Credentials created by
`application-default login` and deletes the local file.
- https://docs.cloud.google.com/sdk/gcloud/reference/auth/revoke
- https://docs.cloud.google.com/sdk/gcloud/reference/auth/application-default/revoke
- https://docs.cloud.google.com/iam/docs/keys-disable-enable
- https://docs.cloud.google.com/iam/docs/keys-create-delete

**Azure.** `az logout` removes local access; server-side behavior is not documented on the
reference page, so do not rely on it. For a user identity, an admin revokes refresh tokens with
`Revoke-MgUserSignInSession` (Microsoft Graph PowerShell). Access tokens stay valid until they
expire, typically about an hour. For service principal secrets: `az ad sp credential list --id
APP_ID`, `az ad sp credential reset` or `delete --key-id`.
- https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access
- https://learn.microsoft.com/en-us/cli/azure/ad/sp/credential

## Model provider API keys

**Anthropic.** Claude Console > API keys > the key's menu > Delete API Key; create a new key and
store it in a secret manager. Review usage for the window. For a Claude Code login, run `/logout`
(or `claude auth logout`) and sign in again. Claude Code stores credentials in the macOS Keychain,
or in `~/.claude/.credentials.json` (mode 0600) on Linux, on Windows and as the macOS fallback.
Also check `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` (one-year tokens
from `claude setup-token`), and `apiKeyHelper` scripts in shell profiles and settings `env`
blocks.
- https://support.claude.com/en/articles/8384961-what-should-i-do-if-i-suspect-my-api-key-has-been-compromised
- https://code.claude.com/docs/en/authentication

**OpenAI.** Rotate the key immediately from the API keys page and review usage. Codex CLI
credentials live in `CODEX_HOME/auth.json` or the OS credential store, depending on the
credential-store setting.
- https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety

## Connector and OAuth grants

Removing a connector from an agent is not the same as revoking the grant. Do both.

**Slack.** Workspace name > Tools & settings > Manage apps > Installed Apps > the app >
Configuration > Remove App. Workspace owners may restrict who can do this. For tokens you control,
the `auth.revoke` API revokes a token.
- https://slack.com/help/articles/360003125231
- https://docs.slack.dev/reference/methods/auth.revoke

**Notion.** Settings > Connections > "•••" next to the connection > Disconnect. Enterprise
owners can also restrict page access per connection.
- https://www.notion.com/help/add-and-manage-connections-with-the-api

**Google account.** https://myaccount.google.com/linkedapps > the app > Remove access. Also check
Security > Your devices and sign out unknown sessions.
- https://support.google.com/accounts/answer/13533235
- https://support.google.com/accounts/answer/3067630

**claude.ai connectors.** Customize > Connectors > remove or disconnect. Team and Enterprise owners
use Organization settings > Connectors. Then revoke the grant at the provider (above).
- https://support.claude.com/en/articles/11175166

**MCP OAuth in Claude Code.** `claude mcp logout NAME`, or **Clear authentication** in `/mcp`,
clears the stored OAuth credential. Revoke the grant at the authorization server too.
- https://code.claude.com/docs/en/cli-reference

## Secrets in .env and config files

- Inventory what the agent could read: `.env*`, `config/*.json|yml`, `docker-compose*.yml`, MCP
  `env` blocks in `.mcp.json` and `~/.claude.json`, `~/.codex/config.toml`, CI variable files.
- **Database URLs** (`postgres://user:pass@host/db`): change the password on the server, then
  update consumers. For PostgreSQL, use `\password ROLE` in psql so the new password does not land
  in shell history or server logs as plain `ALTER ROLE ... PASSWORD` would. Review connection and
  audit logs for the window. Prefer short-lived IAM or workload identity auth where the platform
  supports it.
  - https://www.postgresql.org/docs/current/sql-alterrole.html
- **Generic third-party API keys** (Stripe, Twilio, SendGrid): use the provider's key rolling or
  delete-and-recreate. Check whether the provider offers per-key audit logs.
- **Signing keys and webhooks secrets**: rotate and redeploy consumers. Old signatures may still
  verify until you do.
- After rotation, remove secrets from files the agent can read, add deny rules for them, and
  purge transcripts that contain them once evidence is preserved.

## Browser sessions

If a browser tool (Claude in Chrome, Playwright or Puppeteer MCP, a computer-use tool) ran with a
signed-in profile, assume it could act as the user on every site open in that profile.

- Sign out everywhere on high-value sites (GitHub Sessions, Google devices, cloud consoles, email,
  Slack), and change the password where "sign out everywhere" is missing.
- Review each site's security log for the window.
- Clear the automation profile's cookies, or delete that profile. Use a separate, signed-out
  profile for agent browsing from now on.

## Rotation record

Copy into the incident report and fill in one row per credential:

| Credential (type, last 4) | Location | Reachable by | Action | Done (UTC) | Old one verified dead | Audit log reviewed |
|---|---|---|---|---|---|---|
| GitHub fine-grained PAT, ...ab12 | `~/.config/gh/hosts.yml` | Bash tool | Revoked, reissued with repo-only scope | | | |
