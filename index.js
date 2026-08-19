/**
 * OAuth2 Token Provider MCP
 * 
 * A generic, publishable MCP server (runnable via npx) that:
 * 1. Acquires OAuth2 client_credentials tokens from any SSO endpoint
 * 2. Caches tokens in memory + persists to a user-writable config folder
 * 3. Proxies all tool calls to a remote MCP endpoint with the bearer token
 * 4. Dynamically discovers tools from the remote endpoint (no hardcoded schemas)
 * 5. Auto-refreshes expired tokens transparently
 * 
 * Configuration (all via env vars):
 *   REMOTE_MCP_URL      - The remote MCP endpoint to proxy to
 *   OAUTH2_TOKEN_URL    - SSO token endpoint  
 *   OAUTH2_CLIENT_ID    - OAuth2 client ID
 *   OAUTH2_CLIENT_SECRET - OAuth2 client secret
 *   OAUTH2_BASIC_USERNAME - (optional) Basic auth username for dual-credential SSO
 *   OAUTH2_BASIC_PASSWORD - (optional) Basic auth password for dual-credential SSO
 * 
 * Token file is stored internally at: ~/.oauth2-token-provider/token.json
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
import { randomUUID } from "crypto";

// ─── Configuration ───────────────────────────────────────────────────────

const REMOTE_MCP_URL = process.env.REMOTE_MCP_URL || "";
const OAUTH2_TOKEN_URL = process.env.OAUTH2_TOKEN_URL || "";
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID || "";
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET || "";
const OAUTH2_BASIC_USERNAME = process.env.OAUTH2_BASIC_USERNAME || "";
const OAUTH2_BASIC_PASSWORD = process.env.OAUTH2_BASIC_PASSWORD || "";

// Token persistence — internal to this provider, hardcoded writable user folder
const TOKEN_DIR = join(homedir(), ".oauth2-token-provider");
const TOKEN_FILE = join(TOKEN_DIR, "token.json");

// ─── Token Persistence ───────────────────────────────────────────────────

function readPersistedToken() {
  try {
    if (!existsSync(TOKEN_FILE)) return null;
    const data = JSON.parse(readFileSync(TOKEN_FILE, "utf-8"));
    if (data.access_token && data.expires_at && Date.now() < data.expires_at - 60000) {
      return data;
    }
    return null;
  } catch {
    return null;
  }
}

function persistToken(accessToken, expiresAt) {
  try {
    if (!existsSync(TOKEN_DIR)) {
      mkdirSync(TOKEN_DIR, { recursive: true });
    }
    writeFileSync(TOKEN_FILE, JSON.stringify({
      access_token: accessToken,
      expires_at: expiresAt,
      token_url: OAUTH2_TOKEN_URL,
      generated_at: new Date().toISOString(),
    }, null, 2), "utf-8");
  } catch (e) {
    process.stderr.write(`[oauth2-token-provider] Warning: Could not persist token: ${e.message}\n`);
  }
}

// ─── OAuth2 Token Acquisition ────────────────────────────────────────────

let cachedToken = null;
let tokenExpiresAt = 0;

async function acquireToken(forceRefresh = false) {
  // 1. In-memory cache
  if (!forceRefresh && cachedToken && Date.now() < tokenExpiresAt - 60000) {
    return cachedToken;
  }

  // 2. Persisted file
  if (!forceRefresh) {
    const persisted = readPersistedToken();
    if (persisted) {
      cachedToken = persisted.access_token;
      tokenExpiresAt = persisted.expires_at;
      return cachedToken;
    }
  }

  // 3. Fresh token from SSO
  const encodedClientId = encodeURIComponent(OAUTH2_CLIENT_ID);
  const encodedClientSecret = encodeURIComponent(OAUTH2_CLIENT_SECRET);
  const body = `grant_type=client_credentials&client_id+=${encodedClientId}&client_secret=${encodedClientSecret}`;

  const headers = { "Content-Type": "application/x-www-form-urlencoded" };

  if (OAUTH2_BASIC_USERNAME && OAUTH2_BASIC_PASSWORD) {
    const credentials = Buffer.from(`${OAUTH2_BASIC_USERNAME}:${OAUTH2_BASIC_PASSWORD}`).toString("base64");
    headers["Authorization"] = `Basic ${credentials}`;
  }

  const response = await fetch(OAUTH2_TOKEN_URL, { method: "POST", headers, body });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OAuth2 token request failed (${response.status}): ${errorText}`);
  }

  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiresAt = Date.now() + (data.expires_in * 1000);

  persistToken(cachedToken, tokenExpiresAt);
  return cachedToken;
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
