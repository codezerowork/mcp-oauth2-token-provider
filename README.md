# mcp-oauth2-token-provider

A generic MCP (Model Context Protocol) server that acts as an authenticated proxy between AI IDEs and remote MCP endpoints. Handles OAuth2 token generation (`client_credentials` or resource-owner `password` grant) internally and transparently injects bearer tokens into all proxied requests.

## Features

- **Transparent OAuth2 proxy** — acquires, caches, and auto-refreshes tokens
- **Dynamic tool discovery** — no hardcoded tool schemas; discovers tools from the remote MCP endpoint
- **Auto-retry on 401** — if a token expires mid-session, refreshes and retries once
- **Startup health check** — verifies remote MCP is reachable before connecting; fails fast with clear error messages
- **Client credentials or password grant** — service-to-service tokens, or user-bound tokens renewed via `refresh_token`
- **Token persistence** — caches tokens to disk at `~/.oauth2-token-provider/token-<hash>.json` (one file per token URL / client / grant / user) to survive process restarts
- **Zero configuration in code** — all settings via environment variables
- **Supports SSE and JSON responses** — handles both Streamable HTTP and plain JSON-RPC from the remote

## Installation

```bash
npm install -g github:codezerowork/mcp-oauth2-token-provider
```

Or install globally:

```bash
npx github:codezerowork/mcp-oauth2-token-provider
```

## Usage with Kiro / VS Code MCP

Add to your `.kiro/settings/mcp.json` (or equivalent):

```json
{
  "mcpServers": {
    "my-remote-server": {
      "command": "npx",
      "args": ["mcp-oauth2-token-provider"],
      "env": {
        "REMOTE_MCP_URL": "https://your-server.com/mcp",
        "OAUTH2_TOKEN_URL": "https://your-sso.com/token.oauth2",
        "OAUTH2_CLIENT_ID": "your-client-id",
        "OAUTH2_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `REMOTE_MCP_URL` | Yes | The remote MCP endpoint URL to proxy to |
| `OAUTH2_TOKEN_URL` | Yes | OAuth2 token endpoint |
| `OAUTH2_CLIENT_ID` | Yes | OAuth2 client ID |
| `OAUTH2_CLIENT_SECRET` | Yes | OAuth2 client secret |
| `OAUTH2_GRANT_TYPE` | No | `client_credentials` (default) or `password`. Inferred as `password` when `OAUTH2_USERNAME` is set |
| `OAUTH2_CLIENT_AUTH` | No | `both` (default): client_id/secret in body + Basic header if `OAUTH2_BASIC_*` set. `basic`: only a Basic header (client id:secret), nothing in the body — same as Insomnia/Postman "Send as Basic Auth header". `body`: only in the body |
| `OAUTH2_USERNAME` | Password grant | Resource-owner username |
| `OAUTH2_PASSWORD` | Password grant | Resource-owner password |
| `OAUTH2_BASIC_USERNAME` | No | Basic auth username (for dual-credential SSO) |
| `OAUTH2_BASIC_PASSWORD` | No | Basic auth password (for dual-credential SSO) |

## How It Works

```
AI IDE ←stdio→ [mcp-oauth2-token-provider] ←HTTP+Bearer→ [Remote MCP Server]
                         │
                         ├─ Acquires OAuth2 token (client_credentials or password)
                         ├─ Caches in memory + ~/.oauth2-token-provider/token-<hash>.json
                         ├─ Injects Bearer header on every request
                         ├─ Auto-refreshes on expiry (60s safety margin)
                         └─ Retries once on 401 with fresh token
```

1. On startup, verifies the remote MCP endpoint is reachable (sends MCP `initialize`)
2. If remote is unreachable, exits with error (IDE shows "Failed" status)
3. If healthy, connects to IDE via stdio and discovers tools from the remote
4. All tool calls are proxied transparently with the bearer token

## Token Caching

Tokens are cached in two layers:
- **In-memory** — fastest, lost on process restart
- **On disk** — `~/.oauth2-token-provider/token-<hash>.json`, survives restarts (for the password grant this also holds the refresh token; the user password is never written to disk)

The token is refreshed when:
- It's within 60 seconds of expiry
- A 401 response is received from the remote

## Password Grant (Resource Owner)

For user-bound tokens (e.g. an OAuth2 client registered for the resource-owner password-credentials flow), set the user's credentials:

```json
"env": {
  "REMOTE_MCP_URL": "https://your-server.com/mcp",
  "OAUTH2_TOKEN_URL": "https://your-sso.com/token.oauth2",
  "OAUTH2_CLIENT_ID": "${OAUTH2_CLIENT_ID}",
  "OAUTH2_CLIENT_SECRET": "${OAUTH2_CLIENT_SECRET}",
  "OAUTH2_GRANT_TYPE": "password",
  "OAUTH2_USERNAME": "${OAUTH2_USERNAME}",
  "OAUTH2_PASSWORD": "${OAUTH2_PASSWORD}"
}
```

The first token is requested with `grant_type=password`. Renewals use `grant_type=refresh_token`; if the refresh token is rejected, the provider falls back to the password grant. Prefer `${VAR}` references over literal credentials in `mcp.json`. Federated SSO accounts typically can't use the password grant (`invalid_grant`); use a non-federated user or a client_credentials client instead.

## Dual-Credential SSO (Optional)

Some SSO providers require both:
- A `client_id` + `client_secret` in the request body
- A Basic Auth header with service account credentials

Set `OAUTH2_BASIC_USERNAME` and `OAUTH2_BASIC_PASSWORD` to enable this pattern.

## License

MIT
