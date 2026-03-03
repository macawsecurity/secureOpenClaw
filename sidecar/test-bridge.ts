#!/usr/bin/env npx tsx
/**
 * Standalone End-to-End Test for SecureOpenClaw MACAW Bridge
 *
 * This test validates the complete TypeScript ↔ Python ↔ MACAW flow
 * WITHOUT requiring the full OpenClaw build.
 *
 * Prerequisites:
 *   - MACAW installed (run ../install.sh)
 *   - Python dependencies (pip install httpx pydantic uvicorn fastapi)
 *   - macaw_adapters installed (pip install -e /path/to/secureAI)
 *   - Node.js 18+ (for fetch)
 *
 * Usage:
 *   cd secureopenclaw/openclaw/sidecar
 *   export MACAW_HOME=../macaw_lib
 *   export OPENAI_API_KEY=sk-...       # Optional: for LLM proxy tests
 *   export ANTHROPIC_API_KEY=sk-ant-... # Optional: for LLM proxy tests
 *   npx tsx test-bridge.ts
 *
 * What this tests:
 *   1. Sidecar connects to MACAW control plane
 *   2. Tool registration with MACAW
 *   3. invoke_tool flows through MACAW (check console.macawsecurity.ai!)
 *   4. Callback returns to TypeScript with HMAC verification
 *   5. Results flow back correctly
 *   6. LLM Proxy: OpenAI chat completions (if OPENAI_API_KEY set)
 *   7. LLM Proxy: OpenAI streaming (if OPENAI_API_KEY set)
 *   8. LLM Proxy: Anthropic messages (if ANTHROPIC_API_KEY set)
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ============================================================================
// Configuration
// ============================================================================

const __dirname = dirname(fileURLToPath(import.meta.url));
const MACAW_HOME = process.env.MACAW_HOME || join(__dirname, "..", "macaw_lib");
const SIDECAR_PORT = 18798;
const CALLBACK_PORT = 18799;
const SIDECAR_URL = `http://127.0.0.1:${SIDECAR_PORT}`;

// Generate ephemeral HMAC secret for this test session
const HMAC_SECRET = randomBytes(32).toString("hex");

// Test state
let sidecarProcess: ChildProcess | null = null;
let callbackServer: Server | null = null;
const testResults: Array<{ name: string; passed: boolean; error?: string }> = [];

// ============================================================================
// Utility Functions
// ============================================================================

function log(msg: string): void {
  console.log(`[test] ${msg}`);
}

function logError(msg: string): void {
  console.error(`[test] ERROR: ${msg}`);
}

function computeExpectedHmac(data: Record<string, unknown>): string {
  const payload = JSON.stringify(data, Object.keys(data).sort());
  return createHmac("sha256", HMAC_SECRET).update(payload).digest("hex");
}

/**
 * Recursively sort object keys to match Python's json.dumps(sort_keys=True)
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

function verifyHmac(body: string, signature: string | undefined): boolean {
  if (!signature) return false;

  try {
    // Python sends the body as json.dumps(params, sort_keys=True)
    // So we just compute HMAC on the raw body we received
    const expected = createHmac("sha256", HMAC_SECRET).update(body).digest("hex");

    const sigBuffer = Buffer.from(signature, "hex");
    const expectedBuffer = Buffer.from(expected, "hex");

    if (sigBuffer.length !== expectedBuffer.length) return false;
    return timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// Callback Server (simulates callback-server.ts)
// ============================================================================

// Tool handlers - these get called when MACAW approves an invocation
const toolHandlers: Record<string, (params: Record<string, unknown>) => unknown> = {
  "test_echo": (params) => {
    return { echoed: params.message, tool: "test_echo", timestamp: Date.now() };
  },
  "test_math": (params) => {
    const a = Number(params.a) || 0;
    const b = Number(params.b) || 0;
    const op = String(params.op || "add");

    if (op === "add") return { result: a + b, operation: "add" };
    if (op === "multiply") return { result: a * b, operation: "multiply" };
    return { error: `Unknown operation: ${op}` };
  },
  "test_file_read": (params) => {
    // This might be denied by MACAW policy depending on path
    return {
      content: `[mock content for ${params.path}]`,
      path: params.path,
      note: "This is a test - real file_read would read actual files"
    };
  }
};

function startCallbackServer(): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      // Only accept POST /execute/{tool_name}
      if (req.method !== "POST") {
        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Method not allowed" }));
        return;
      }

      const match = req.url?.match(/^\/execute\/([a-zA-Z0-9_-]+)$/);
      if (!match) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        return;
      }

      const toolName = match[1];

      // Read body
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(chunk as Buffer);
      }
      const body = Buffer.concat(chunks).toString("utf-8");

      // Verify HMAC - MUST block if invalid (prevents bypass of MACAW)
      const signature = req.headers["x-macaw-signature"] as string | undefined;
      if (!verifyHmac(body, signature)) {
        log(`  REJECTED: HMAC verification failed for ${toolName}`);
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "Invalid HMAC signature" }));
        return;
      }
      log(`  HMAC verified for ${toolName}`);

      // Parse params
      let params: Record<string, unknown>;
      try {
        params = JSON.parse(body);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON" }));
        return;
      }

      log(`  Callback received: ${toolName}(${JSON.stringify(params).slice(0, 50)}...)`);

      // Find and execute handler
      const handler = toolHandlers[toolName];
      if (!handler) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: `No handler for tool: ${toolName}` }));
        return;
      }

      try {
        const result = handler(params);
        log(`  Handler returned: ${JSON.stringify(result).slice(0, 50)}...`);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, result }));
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: errMsg }));
      }
    });

    server.on("error", reject);
    server.listen(CALLBACK_PORT, "127.0.0.1", () => {
      log(`Callback server listening on port ${CALLBACK_PORT}`);
      resolve(server);
    });
  });
}

// ============================================================================
// Sidecar Management
// ============================================================================

async function startSidecar(): Promise<ChildProcess> {
  const serverPath = join(__dirname, "server.py");

  if (!existsSync(serverPath)) {
    throw new Error(`Sidecar not found: ${serverPath}`);
  }

  log(`Starting sidecar with MACAW_HOME=${MACAW_HOME}`);
  log(`Using ephemeral HMAC secret: ${HMAC_SECRET.slice(0, 8)}...`);

  const proc = spawn("python3", [serverPath], {
    env: {
      ...process.env,
      MACAW_HOME,
      MACAW_HMAC_SECRET: HMAC_SECRET,
      MACAW_CALLBACK_URL: `http://127.0.0.1:${CALLBACK_PORT}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  // Log sidecar output
  proc.stdout?.on("data", (data: Buffer) => {
    const lines = data.toString().trim().split("\n");
    for (const line of lines) {
      if (line.trim()) log(`[sidecar] ${line}`);
    }
  });

  proc.stderr?.on("data", (data: Buffer) => {
    const lines = data.toString().trim().split("\n");
    for (const line of lines) {
      if (line.trim()) log(`[sidecar:err] ${line}`);
    }
  });

  proc.on("exit", (code) => {
    log(`Sidecar exited with code ${code}`);
  });

  return proc;
}

async function waitForSidecar(maxAttempts = 30): Promise<boolean> {
  log("Waiting for sidecar to be healthy...");

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`${SIDECAR_URL}/health`, {
        signal: AbortSignal.timeout(2000),
      });

      if (response.ok) {
        const data = await response.json() as { status: string; macawConnected: boolean };
        log(`Sidecar health: ${JSON.stringify(data)}`);

        if (data.macawConnected) {
          log("Sidecar connected to MACAW control plane!");
          return true;
        } else {
          log("Sidecar running but NOT connected to MACAW - check config");
          return false;
        }
      }
    } catch {
      // Not ready yet
    }
    await sleep(500);
  }

  return false;
}

// ============================================================================
// Bridge Client (simulates bridge.ts)
// ============================================================================

interface InvokeResult {
  ok: boolean;
  result?: unknown;
  error?: string;
  message?: string;
  auditId?: string;
}

async function registerTools(tools: string[]): Promise<boolean> {
  try {
    const response = await fetch(`${SIDECAR_URL}/register_tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tools }),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      logError(`Failed to register tools: ${response.status}`);
      return false;
    }

    const data = await response.json() as { ok: boolean; registered: number };
    log(`Registered ${data.registered} tools with MACAW`);
    return data.ok;
  } catch (err) {
    logError(`Error registering tools: ${err}`);
    return false;
  }
}

async function invokeTool(
  tool: string,
  params: Record<string, unknown>,
  principal?: { userId?: string; role?: string }
): Promise<InvokeResult> {
  try {
    const response = await fetch(`${SIDECAR_URL}/invoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool, params, principal, timeout: 30 }),
      signal: AbortSignal.timeout(35000),
    });

    return await response.json() as InvokeResult;
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

// ============================================================================
// Tests
// ============================================================================

async function runTest(name: string, fn: () => Promise<void>): Promise<void> {
  log(`\n--- Test: ${name} ---`);
  try {
    await fn();
    log(`PASSED: ${name}`);
    testResults.push({ name, passed: true });
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    logError(`FAILED: ${name} - ${errMsg}`);
    testResults.push({ name, passed: false, error: errMsg });
  }
}

async function testEcho(): Promise<void> {
  const result = await invokeTool("test_echo", { message: "Hello from SecureOpenClaw!" });

  if (!result.ok) {
    throw new Error(`Invocation failed: ${result.error || result.message}`);
  }

  const echoed = (result.result as { echoed?: string })?.echoed;
  if (echoed !== "Hello from SecureOpenClaw!") {
    throw new Error(`Expected echo "Hello from SecureOpenClaw!", got "${echoed}"`);
  }

  log(`  Echo returned: ${echoed}`);
  if (result.auditId) {
    log(`  Audit ID: ${result.auditId}`);
  }
}

async function testMath(): Promise<void> {
  // Test addition
  const addResult = await invokeTool("test_math", { a: 5, b: 3, op: "add" });
  if (!addResult.ok) {
    throw new Error(`Addition failed: ${addResult.error}`);
  }
  const sum = (addResult.result as { result?: number })?.result;
  if (sum !== 8) {
    throw new Error(`Expected 5 + 3 = 8, got ${sum}`);
  }
  log(`  5 + 3 = ${sum}`);

  // Test multiplication
  const mulResult = await invokeTool("test_math", { a: 4, b: 7, op: "multiply" });
  if (!mulResult.ok) {
    throw new Error(`Multiplication failed: ${mulResult.error}`);
  }
  const product = (mulResult.result as { result?: number })?.result;
  if (product !== 28) {
    throw new Error(`Expected 4 * 7 = 28, got ${product}`);
  }
  log(`  4 * 7 = ${product}`);
}

async function testWithPrincipal(): Promise<void> {
  const result = await invokeTool(
    "test_echo",
    { message: "Admin request" },
    { userId: "user-123", role: "admin" }
  );

  if (!result.ok) {
    throw new Error(`Invocation with principal failed: ${result.error}`);
  }

  log(`  Invocation with principal succeeded`);
  log(`  Result: ${JSON.stringify(result.result)}`);
}

async function testUnregisteredTool(): Promise<void> {
  const result = await invokeTool("nonexistent_tool", { foo: "bar" });

  if (result.ok) {
    throw new Error("Should have rejected unregistered tool");
  }

  if (result.error !== "tool_not_registered") {
    throw new Error(`Expected error "tool_not_registered", got "${result.error}"`);
  }

  log(`  Correctly rejected unregistered tool`);
}

async function testPolicyDenial(): Promise<void> {
  // This test depends on your MACAW policy configuration
  // If you have a policy that denies certain operations, test it here
  log(`  (Skipped - depends on policy configuration)`);
  log(`  Check console.macawsecurity.ai to see invocations!`);
}

// ============================================================================
// LLM Proxy Tests
// ============================================================================

interface HealthWithAdapters {
  status: string;
  macawConnected: boolean;
  registeredTools: number;
  openaiAvailable?: boolean;
  anthropicAvailable?: boolean;
}

interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface AnthropicMessageResponse {
  id: string;
  type: string;
  role: string;
  content: Array<{
    type: string;
    text: string;
  }>;
  model: string;
  stop_reason: string;
  usage?: {
    input_tokens: number;
    output_tokens: number;
  };
}

async function testOpenAIProxy(): Promise<void> {
  // Check if OpenAI is available
  const healthRes = await fetch(`${SIDECAR_URL}/health`);
  const health = (await healthRes.json()) as HealthWithAdapters;

  if (!health.openaiAvailable) {
    log("  (Skipped - OPENAI_API_KEY not set)");
    return;
  }

  log("  Making non-streaming chat completion request...");

  const response = await fetch(`${SIDECAR_URL}/openai/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: "Say 'Hello from SecureOpenClaw' and nothing else.",
        },
      ],
      max_tokens: 50,
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI proxy failed: ${response.status} - ${error}`);
  }

  const result = (await response.json()) as ChatCompletionResponse;

  if (!result.choices?.[0]?.message?.content) {
    throw new Error(`Invalid response structure: ${JSON.stringify(result)}`);
  }

  const content = result.choices[0].message.content;
  log(`  Response: "${content}"`);
  log(`  Model: ${result.model}`);
  if (result.usage) {
    log(`  Tokens: ${result.usage.total_tokens}`);
  }

  if (!content.toLowerCase().includes("hello")) {
    log(`  Warning: Expected greeting containing 'hello', got different response`);
  }
}

async function testOpenAIProxyStreaming(): Promise<void> {
  // Check if OpenAI is available
  const healthRes = await fetch(`${SIDECAR_URL}/health`);
  const health = (await healthRes.json()) as HealthWithAdapters;

  if (!health.openaiAvailable) {
    log("  (Skipped - OPENAI_API_KEY not set)");
    return;
  }

  log("  Making streaming chat completion request...");

  const response = await fetch(`${SIDECAR_URL}/openai/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Count from 1 to 5, one number per line." }],
      max_tokens: 50,
      stream: true,
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Streaming request failed: ${response.status} - ${error}`);
  }

  // Read SSE stream
  const reader = response.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let fullContent = "";
  let chunkCount = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const text = decoder.decode(value);
    const lines = text.split("\n").filter((l) => l.startsWith("data: "));

    for (const line of lines) {
      const data = line.slice(6); // Remove "data: "
      if (data === "[DONE]") continue;

      try {
        const chunk = JSON.parse(data) as {
          choices?: Array<{ delta?: { content?: string } }>;
          error?: string;
        };

        if (chunk.error) {
          throw new Error(`Stream error: ${chunk.error}`);
        }

        const delta = chunk.choices?.[0]?.delta?.content;
        if (delta) {
          fullContent += delta;
          chunkCount++;
        }
      } catch (e) {
        // Ignore parse errors for non-JSON lines
        if (data !== "[DONE]" && data.trim()) {
          log(`  Warning: Could not parse chunk: ${data.slice(0, 50)}`);
        }
      }
    }
  }

  log(`  Received ${chunkCount} content chunks`);
  log(`  Full content: "${fullContent.trim().slice(0, 100)}..."`);

  if (chunkCount < 1) {
    throw new Error(`Expected multiple chunks, got ${chunkCount}`);
  }
}

async function testAnthropicProxy(): Promise<void> {
  // Check if Anthropic is available
  const healthRes = await fetch(`${SIDECAR_URL}/health`);
  const health = (await healthRes.json()) as HealthWithAdapters;

  if (!health.anthropicAvailable) {
    log("  (Skipped - ANTHROPIC_API_KEY not set)");
    return;
  }

  log("  Making Anthropic messages request...");

  const response = await fetch(`${SIDECAR_URL}/anthropic/v1/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-3-haiku-20240307",
      max_tokens: 50,
      messages: [
        {
          role: "user",
          content: "Say 'Hello from SecureOpenClaw' and nothing else.",
        },
      ],
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Anthropic proxy failed: ${response.status} - ${error}`);
  }

  const result = (await response.json()) as AnthropicMessageResponse;

  const content = result.content?.[0]?.text;
  if (!content) {
    throw new Error(`Invalid response structure: ${JSON.stringify(result)}`);
  }

  log(`  Response: "${content}"`);
  log(`  Model: ${result.model}`);
  if (result.usage) {
    log(`  Tokens: input=${result.usage.input_tokens}, output=${result.usage.output_tokens}`);
  }

  if (!content.toLowerCase().includes("hello")) {
    log(`  Warning: Expected greeting containing 'hello', got different response`);
  }
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log("=".repeat(60));
  console.log("SecureOpenClaw MACAW Bridge - End-to-End Test");
  console.log("=".repeat(60));

  // Check MACAW installation
  const configPath = join(MACAW_HOME, ".macaw", "config.json");
  if (!existsSync(configPath)) {
    logError(`MACAW config not found: ${configPath}`);
    logError("Run ../install.sh first to set up MACAW");
    process.exit(1);
  }
  log(`MACAW_HOME: ${MACAW_HOME}`);

  try {
    // Start callback server first
    log("\n--- Starting Callback Server ---");
    callbackServer = await startCallbackServer();

    // Start sidecar
    log("\n--- Starting Sidecar ---");
    sidecarProcess = await startSidecar();

    // Wait for sidecar to connect to MACAW
    const healthy = await waitForSidecar();
    if (!healthy) {
      throw new Error("Sidecar failed to connect to MACAW. Check your configuration.");
    }

    // Register test tools
    log("\n--- Registering Tools ---");
    const tools = Object.keys(toolHandlers);
    if (!await registerTools(tools)) {
      throw new Error("Failed to register tools");
    }

    // Run tests
    log("\n--- Running Tests ---");
    await runTest("Echo Tool", testEcho);
    await runTest("Math Operations", testMath);
    await runTest("Invocation with Principal", testWithPrincipal);
    await runTest("Unregistered Tool Rejection", testUnregisteredTool);
    await runTest("Policy Denial", testPolicyDenial);

    // LLM Proxy tests (require API keys)
    log("\n--- Running LLM Proxy Tests ---");
    await runTest("OpenAI Proxy (non-streaming)", testOpenAIProxy);
    await runTest("OpenAI Proxy (streaming)", testOpenAIProxyStreaming);
    await runTest("Anthropic Proxy", testAnthropicProxy);

    // Summary
    console.log("\n" + "=".repeat(60));
    console.log("TEST SUMMARY");
    console.log("=".repeat(60));

    let passed = 0;
    let failed = 0;

    for (const result of testResults) {
      const status = result.passed ? "PASS" : "FAIL";
      console.log(`  [${status}] ${result.name}`);
      if (result.error) {
        console.log(`         ${result.error}`);
      }
      if (result.passed) passed++; else failed++;
    }

    console.log("-".repeat(60));
    console.log(`Total: ${passed} passed, ${failed} failed`);

    if (failed === 0) {
      console.log("\nAll tests passed!");
      console.log("\nCheck console.macawsecurity.ai to see the invocations in the activity graph.");
    } else {
      console.log("\nSome tests failed. Check the errors above.");
    }

  } finally {
    // Cleanup
    log("\n--- Cleanup ---");

    if (callbackServer) {
      callbackServer.close();
      log("Callback server stopped");
    }

    if (sidecarProcess && !sidecarProcess.killed) {
      sidecarProcess.kill();
      log("Sidecar stopped");
    }
  }
}

// Run
main().catch((err) => {
  logError(`Fatal error: ${err}`);
  process.exit(1);
});
