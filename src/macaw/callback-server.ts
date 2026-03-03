/**
 * MACAW Callback Server
 *
 * HTTP server that receives tool execution callbacks from the Python sidecar.
 * When MACAW approves a tool invocation, it calls back here to actually execute.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";
import type { ToolExecutionHandler } from "./types.js";

const log = createSubsystemLogger("macaw-callback");

const HMAC_SECRET = process.env.MACAW_HMAC_SECRET || "secure-openclaw-dev-secret";
const CALLBACK_PORT = parseInt(process.env.MACAW_CALLBACK_PORT || "18799", 10);

// Registry of tool execution handlers
const executionHandlers = new Map<string, ToolExecutionHandler>();

let server: Server | null = null;
let callbackIdCounter = 0;

/**
 * Register a tool's execution handler.
 * Called during startup to wire up actual tool implementations.
 */
export function registerExecutionHandler(
  toolName: string,
  handler: ToolExecutionHandler,
): void {
  executionHandlers.set(toolName, handler);
  log.debug(`Registered execution handler: ${toolName}`);
}

/**
 * Get all registered tool names.
 */
export function getRegisteredToolNames(): string[] {
  return Array.from(executionHandlers.keys());
}

/**
 * Verify HMAC signature on callback request.
 */
function verifyHmacSignature(body: string, signature: string | undefined): boolean {
  if (!signature) {
    log.warn("Missing HMAC signature on callback");
    return false;
  }

  const expectedSignature = createHmac("sha256", HMAC_SECRET)
    .update(body)
    .digest("hex");

  try {
    const sigBuffer = Buffer.from(signature, "hex");
    const expectedBuffer = Buffer.from(expectedSignature, "hex");

    if (sigBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

/**
 * Read request body as string.
 */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

/**
 * Send JSON response.
 */
function sendJson(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

/**
 * Handle incoming callback request.
 */
async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Only accept POST
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  // Parse URL to extract tool name
  const match = req.url?.match(/^\/execute\/([a-zA-Z0-9_-]+)$/);
  if (!match) {
    sendJson(res, 404, { error: "Invalid endpoint" });
    return;
  }

  const toolName = match[1];
  const handler = executionHandlers.get(toolName);

  if (!handler) {
    log.warn(`No handler registered for tool: ${toolName}`);
    sendJson(res, 404, { error: `Tool not found: ${toolName}` });
    return;
  }

  // Read and verify body
  const body = await readBody(req);
  const signature = req.headers["x-macaw-signature"] as string | undefined;

  // Verify HMAC - ALWAYS enforce (prevents MACAW bypass)
  if (!verifyHmacSignature(body, signature)) {
    log.error(`HMAC verification failed for tool: ${toolName} - rejecting`);
    sendJson(res, 403, { error: "Invalid signature" });
    return;
  }

  // Parse params
  let params: Record<string, unknown>;
  try {
    params = JSON.parse(body) as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { error: "Invalid JSON body" });
    return;
  }

  // Generate callback ID for correlation
  const callbackId = `cb-${Date.now()}-${++callbackIdCounter}`;

  log.debug(`Executing tool ${toolName} (${callbackId})`);

  try {
    const result = await handler(callbackId, params);
    sendJson(res, 200, { ok: true, result });
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    log.error(`Tool execution failed: ${toolName} (${callbackId}): ${errMsg}`);
    sendJson(res, 500, { ok: false, error: errMsg });
  }
}

/**
 * Start the callback server.
 * Returns the server instance.
 */
export function startCallbackServer(port: number = CALLBACK_PORT): Server {
  if (server) {
    log.warn("Callback server already running");
    return server;
  }

  server = createServer((req, res) => {
    handleRequest(req, res).catch((err) => {
      log.error(`Callback handler error: ${String(err)}`);
      sendJson(res, 500, { error: "Internal server error" });
    });
  });

  server.listen(port, "127.0.0.1", () => {
    log.info(`MACAW callback server listening on 127.0.0.1:${port}`);
  });

  return server;
}

/**
 * Stop the callback server.
 */
export function stopCallbackServer(): Promise<void> {
  return new Promise((resolve) => {
    if (!server) {
      resolve();
      return;
    }

    server.close(() => {
      server = null;
      log.info("MACAW callback server stopped");
      resolve();
    });
  });
}

/**
 * Check if callback server is running.
 */
export function isCallbackServerRunning(): boolean {
  return server !== null && server.listening;
}
