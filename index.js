/**
 * OAuth2 Token Provider MCP
 * 
 * A generic, publishable MCP server (runnable via npx) that:
 * 1. Acquires OAuth2 tokens (client_credentials or password grant) from any SSO endpoint
 * 2. Caches tokens in memory + persists to a user-writable config folder
 * 3. Proxies all tool calls to a remote MCP endpoint with the bearer token
 * 4. Dynamically discovers tools from the remote endpoint (no hardcoded schemas)
 * 5. Auto-refreshes expired tokens transparently (refresh_token grant for password flow)
 * 
 * Configuration (all via env vars):
 *   REMOTE_MCP_URL      - The remote MCP endpoint to proxy to
 *   OAUTH2_TOKEN_URL    - SSO token endpoint  
 *   OAUTH2_CLIENT_ID    - OAuth2 client ID
 *   OAUTH2_CLIENT_SECRET - OAuth2 client secret
 *   OAUTH2_GRANT_TYPE   - (optional) "client_credentials" (default) or "password".
 *                         Inferred as "password" when OAUTH2_USERNAME is set.
 *   OAUTH2_USERNAME     - (password grant) resource-owner username
 *   OAUTH2_PASSWORD     - (password grant) resource-owner password
 *   OAUTH2_BASIC_USERNAME - (optional) Basic auth username for dual-credential SSO
 *   OAUTH2_BASIC_PASSWORD - (optional) Basic auth password for dual-credential SSO
 * 
 * Token file is stored internally at: ~/.oauth2-token-provider/token-<hash>.json
 * (one file per token URL / client / grant / user combination)
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomUUID, createHash } from "crypto";

// ─── Configuration ───────────────────────────────────────────────────────

const REMOTE_MCP_URL = process.env.REMOTE_MCP_URL || "";
const OAUTH2_TOKEN_URL = process.env.OAUTH2_TOKEN_URL || "";
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID || "";
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET || "";
const OAUTH2_BASIC_USERNAME = process.env.OAUTH2_BASIC_USERNAME || "";
const OAUTH2_BASIC_PASSWORD = process.env.OAUTH2_BASIC_PASSWORD || "";

// Resource-owner (password grant) credentials
const OAUTH2_USERNAME = process.env.OAUTH2_USERNAME || "";
const OAUTH2_PASSWORD = process.env.OAUTH2_PASSWORD || "";

// Grant type: explicit OAUTH2_GRANT_TYPE wins; otherwise infer "password" when a
// resource-owner username is supplied, else default to "client_credentials".
const SUPPORTED_GRANT_TYPES = ["client_credentials", "password"];
const OAUTH2_GRANT_TYPE = (process.env.OAUTH2_GRANT_TYPE || (OAUTH2_USERNAME ? "password" : "client_credentials"))
  .trim()
  .toLowerCase();

// Where the client credentials go on the token request:
//   "both"  (default, legacy) - client_id/client_secret in the body, plus a Basic header
//                               when OAUTH2_BASIC_USERNAME/PASSWORD are set
//   "basic" - ONLY an Authorization: Basic header (client id:secret); nothing in the body.
//             Matches Insomnia/Postman "Send as Basic Auth header". Some servers
//             (e.g. PingFederate) reject requests that use more than one client-auth method.
//   "body"  - ONLY client_id/client_secret in the body; no Basic header.
const SUPPORTED_CLIENT_AUTH = ["both", "basic", "body"];
const OAUTH2_CLIENT_AUTH = (process.env.OAUTH2_CLIENT_AUTH || "both").trim().toLowerCase();

// Token persistence — internal to this provider, hardcoded writable user folder.
// The file name is keyed by the credential identity so that multiple configured
// servers (different SSO URLs / clients / users / grants) never share or
// overwrite each other's cached token.
const TOKEN_DIR = join(homedir(), ".oauth2-token-provider");
const CACHE_KEY = createHash("sha256")
  .update([OAUTH2_TOKEN_URL, OAUTH2_CLIENT_ID, OAUTH2_GRANT_TYPE, OAUTH2_USERNAME].join("\n"))
  .digest("hex")
  .slice(0, 16);
const TOKEN_FILE = join(TOKEN_DIR, `token-${CACHE_KEY}.json`);

function log(message) {
  process.stderr.write(`[mcp-oauth2-token-provider] ${message}\n`);
}

// ─── Token Persistence ───────────────────────────────────────────────────

/** Reads the persisted token state (access token may be expired; refresh token may still be usable). */
function readPersistedState() {
  try {
    if (!existsSync(TOKEN_FILE)) return null;
    return JSON.parse(readFileSync(TOKEN_FILE, "utf-8"));
  } catch {
    return null;
  }
}

function persistState(state) {
  try {
    if (!existsSync(TOKEN_DIR)) {
      mkdirSync(TOKEN_DIR, { recursive: true, mode: 0o700 });
    }
    writeFileSync(TOKEN_FILE, JSON.stringify({
      access_token: state.accessToken,
      expires_at: state.expiresAt,
      refresh_token: state.refreshToken || undefined,
      grant_type: OAUTH2_GRANT_TYPE,
      token_url: OAUTH2_TOKEN_URL,
      generated_at: new Date().toISOString(),
    }, null, 2), { encoding: "utf-8", mode: 0o600 });
  } catch (e) {
    log(`Warning: Could not persist token: ${e.message}`);
  }
}

// ─── OAuth2 Token Acquisition ────────────────────────────────────────────

let cachedToken = null;
let tokenExpiresAt = 0;
let cachedRefreshToken = null;
let pendingTokenRequest = null;

function isFresh(expiresAt) {
  return Date.now() < expiresAt - 60000;
}

function validateGrantConfig() {
  if (!SUPPORTED_GRANT_TYPES.includes(OAUTH2_GRANT_TYPE)) {
    throw new Error(`Unsupported OAUTH2_GRANT_TYPE "${OAUTH2_GRANT_TYPE}". Supported: ${SUPPORTED_GRANT_TYPES.join(", ")}`);
  }
  if (!SUPPORTED_CLIENT_AUTH.includes(OAUTH2_CLIENT_AUTH)) {
    throw new Error(`Unsupported OAUTH2_CLIENT_AUTH "${OAUTH2_CLIENT_AUTH}". Supported: ${SUPPORTED_CLIENT_AUTH.join(", ")}`);
  }
  if (!OAUTH2_TOKEN_URL) {
    throw new Error("OAUTH2_TOKEN_URL not configured");
  }
  if (OAUTH2_GRANT_TYPE === "password" && (!OAUTH2_USERNAME || !OAUTH2_PASSWORD)) {
    throw new Error("OAUTH2_GRANT_TYPE=password requires OAUTH2_USERNAME and OAUTH2_PASSWORD");
  }
}

/**
 * Builds the form body for a token request.
 * Note: the "client_id+=" key (client_id with a trailing space) is intentional —
 * it is required by some SSO providers and is preserved for backward compatibility.
 */
function buildTokenRequestBody(grantType, extraParams) {
  const params = [`grant_type=${encodeURIComponent(grantType)}`];
  for (const [key, value] of Object.entries(extraParams)) {
    params.push(`${key}=${encodeURIComponent(value)}`);
  }
  if (OAUTH2_CLIENT_AUTH !== "basic") {
    params.push(`client_id+=${encodeURIComponent(OAUTH2_CLIENT_ID)}`);
    params.push(`client_secret=${encodeURIComponent(OAUTH2_CLIENT_SECRET)}`);
  }
  return params.join("&");
}

function basicAuthHeader() {
  if (OAUTH2_CLIENT_AUTH === "body") return null;
  // Explicit BASIC_* values win; in "basic" mode fall back to the client id/secret.
  let user = OAUTH2_BASIC_USERNAME;
  let pass = OAUTH2_BASIC_PASSWORD;
  if (OAUTH2_CLIENT_AUTH === "basic" && !(user && pass)) {
    user = OAUTH2_CLIENT_ID;
    pass = OAUTH2_CLIENT_SECRET;
  }
  if (!(user && pass)) return null;
  return `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;
}

async function requestToken(body) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
  };

  const basic = basicAuthHeader();
  if (basic) headers["Authorization"] = basic;

  const response = await fetch(OAUTH2_TOKEN_URL, { method: "POST", headers, body });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OAuth2 token request failed (${response.status}): ${errorText}`);
  }

  const data = await response.json();
  if (!data.access_token) {
    throw new Error("OAuth2 token response did not contain an access_token");
  }

  const expiresInSeconds = Number(data.expires_in) > 0 ? Number(data.expires_in) : 3600;
  return {
    accessToken: data.access_token,
    expiresAt: Date.now() + expiresInSeconds * 1000,
    // Some providers rotate refresh tokens; keep the previous one if none is returned.
    refreshToken: data.refresh_token || null,
  };
}

/** Requests a brand-new token using the configured primary grant. */
async function requestPrimaryGrant() {
  if (OAUTH2_GRANT_TYPE === "password") {
    return requestToken(buildTokenRequestBody("password", {
      username: OAUTH2_USERNAME,
      password: OAUTH2_PASSWORD,
    }));
  }
  return requestToken(buildTokenRequestBody("client_credentials", {}));
}

async function fetchNewToken() {
  validateGrantConfig();

  let state = null;

  // Prefer the refresh_token grant (password flow only) to avoid resending user credentials.
  if (OAUTH2_GRANT_TYPE === "password" && cachedRefreshToken) {
    try {
      state = await requestToken(buildTokenRequestBody("refresh_token", { refresh_token: cachedRefreshToken }));
      if (!state.refreshToken) state.refreshToken = cachedRefreshToken;
    } catch (e) {
      log(`Refresh token rejected, falling back to password grant: ${e.message}`);
      cachedRefreshToken = null;
    }
  }

  if (!state) {
    state = await requestPrimaryGrant();
  }

  cachedToken = state.accessToken;
  tokenExpiresAt = state.expiresAt;
  cachedRefreshToken = OAUTH2_GRANT_TYPE === "password" ? state.refreshToken : null;

  persistState({ accessToken: cachedToken, expiresAt: tokenExpiresAt, refreshToken: cachedRefreshToken });
  return cachedToken;
}

async function acquireToken(forceRefresh = false) {
  // 1. In-memory cache
  if (!forceRefresh && cachedToken && isFresh(tokenExpiresAt)) {
    return cachedToken;
  }

  // 2. Persisted file (also restores a refresh token across restarts)
  if (!cachedToken && !cachedRefreshToken) {
    const persisted = readPersistedState();
    if (persisted && persisted.grant_type === OAUTH2_GRANT_TYPE) {
      if (OAUTH2_GRANT_TYPE === "password" && persisted.refresh_token) {
        cachedRefreshToken = persisted.refresh_token;
      }
      if (!forceRefresh && persisted.access_token && persisted.expires_at && isFresh(persisted.expires_at)) {
        cachedToken = persisted.access_token;
        tokenExpiresAt = persisted.expires_at;
        return cachedToken;
      }
    }
  }

  // 3. Fresh token from SSO — de-duplicate concurrent refreshes
  if (!pendingTokenRequest) {
    pendingTokenRequest = fetchNewToken().finally(() => {
      pendingTokenRequest = null;
    });
  }
  return pendingTokenRequest;
}

// ─── Remote MCP Proxy ────────────────────────────────────────────────────

async function callRemoteMcp(method, params) {
  const requestBody = JSON.stringify({
    jsonrpc: "2.0",
    id: randomUUID(),
    method,
    params: params || {},
  });

  const makeRequest = async (token) => fetch(REMOTE_MCP_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: requestBody,
  });

  let token = await acquireToken();
  let response = await makeRequest(token);

  // Retry once on 401 with forced refresh
  if (response.status === 401) {
    token = await acquireToken(true);
    response = await makeRequest(token);
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Remote MCP request failed (${response.status}): ${errorText}`);
  }

  // Handle SSE and plain JSON
  const contentType = response.headers.get("content-type") || "";
  let rpcResponse;

  if (contentType.includes("text/event-stream")) {
    const sseText = await response.text();
    const dataLines = sseText.split("\n")
      .filter(line => line.startsWith("data: "))
      .map(line => line.slice(6));
    const jsonStr = dataLines.join("");
    if (!jsonStr) throw new Error("Empty SSE response from remote MCP endpoint");
    rpcResponse = JSON.parse(jsonStr);
  } else {
    rpcResponse = await response.json();
  }

  if (rpcResponse.error) {
    throw new Error(`Remote MCP error (${rpcResponse.error.code}): ${rpcResponse.error.message}`);
  }

  return rpcResponse.result;
}

// ─── Tool Discovery ──────────────────────────────────────────────────────
// Only remote tools are exposed — token management is purely internal.

// Remote tools are discovered lazily and cached
let cachedRemoteTools = null;

async function getRemoteTools() {
  if (cachedRemoteTools) return cachedRemoteTools;
  try {
    const result = await callRemoteMcp("tools/list", {});
    cachedRemoteTools = result.tools || [];
  } catch (e) {
    // Remote unreachable — return empty, will retry next time
    process.stderr.write(`[mcp-oauth2-token-provider] Remote tools/list unavailable: ${e.message}. Will retry.\n`);
    return [];
  }
  return cachedRemoteTools;
}

// ─── MCP Server ──────────────────────────────────────────────────────────

const server = new Server(
  { name: "mcp-oauth2-token-provider", version: "2.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  const remoteTools = await getRemoteTools();
  return { tools: remoteTools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  // All tools are proxied to remote — token management is internal
  try {
    return await callRemoteMcp("tools/call", { name, arguments: args || {} });
  } catch (error) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// ─── Startup Health Check (BLOCKING) ─────────────────────────────────────
// Verify remote MCP endpoint is reachable BEFORE connecting to Kiro.
// If the remote is down, exit with error so Kiro shows "Failed" status.

async function checkRemoteHealth() {
  if (!REMOTE_MCP_URL) {
    console.log(`[mcp-oauth2-token-provider] FATAL: REMOTE_MCP_URL not configured. Exiting.`);
    process.stderr.write(`[mcp-oauth2-token-provider] FATAL: REMOTE_MCP_URL not configured. Exiting.\n`);
    process.exit(1);
  }

  console.log(`[mcp-oauth2-token-provider] Checking remote MCP at ${REMOTE_MCP_URL}...`);
  process.stderr.write(`[mcp-oauth2-token-provider] Checking remote MCP at ${REMOTE_MCP_URL}...\n`);

  try {
    const token = await acquireToken();
    console.log(`[mcp-oauth2-token-provider] Token acquired, sending initialize to remote...`);

    const response = await fetch(REMOTE_MCP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "health-check",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "mcp-oauth2-token-provider", version: "2.0.0" },
        },
      }),
    });

    if (!response.ok) {
      const errMsg = `Remote returned HTTP ${response.status}`;
      console.log(`[mcp-oauth2-token-provider] ERROR: ${errMsg}`);
      throw new Error(errMsg);
    }

    // Parse response to confirm it's a valid MCP server
    const contentType = response.headers.get("content-type") || "";
    let body;
    if (contentType.includes("text/event-stream")) {
      const sseText = await response.text();
      const dataLines = sseText.split("\n").filter(l => l.startsWith("data: ")).map(l => l.slice(6));
      body = JSON.parse(dataLines.join(""));
    } else {
      body = await response.json();
    }

    if (body.result && body.result.serverInfo) {
      console.log(`[mcp-oauth2-token-provider] Remote MCP connected: ${body.result.serverInfo.name} v${body.result.serverInfo.version}`);
      process.stderr.write(`[mcp-oauth2-token-provider] Remote MCP connected: ${body.result.serverInfo.name} v${body.result.serverInfo.version}\n`);
    } else if (body.error) {
      console.log(`[mcp-oauth2-token-provider] ERROR: Remote MCP error: ${body.error.message}`);
      throw new Error(`Remote MCP error: ${body.error.message}`);
    }
  } catch (e) {
    console.log(`[mcp-oauth2-token-provider] FATAL: Cannot reach remote MCP at ${REMOTE_MCP_URL}: ${e.message}`);
    process.stderr.write(`[mcp-oauth2-token-provider] FATAL: Cannot reach remote MCP at ${REMOTE_MCP_URL}: ${e.message}\n`);
    process.exit(1);
  }
}

// ─── Start ───────────────────────────────────────────────────────────────
// Health check FIRST — if remote is down, process exits and Kiro shows "Failed".

await checkRemoteHealth();

const transport = new StdioServerTransport();
await server.connect(transport);
