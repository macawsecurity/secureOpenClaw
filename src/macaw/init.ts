/**
 * MACAW Initialization
 *
 * Initializes the MACAW integration for SecureOpenClaw.
 * Call this at startup before any tool invocations.
 */

import { createSubsystemLogger } from "../logging/subsystem.js";
import { checkSidecarHealth, registerTools } from "./bridge.js";
import {
  getRegisteredToolNames,
  registerExecutionHandler,
  startCallbackServer,
  stopCallbackServer,
} from "./callback-server.js";
import type { ToolExecutionHandler } from "./types.js";

const log = createSubsystemLogger("macaw-init");

let initialized = false;

export interface MacawInitOptions {
  /** Port for callback server (default: 18799) */
  callbackPort?: number;
  /** Tool definitions to register */
  tools?: Array<{
    name: string;
    execute: ToolExecutionHandler;
  }>;
  /** Skip sidecar health check (for testing) */
  skipHealthCheck?: boolean;
}

/**
 * Initialize MACAW integration.
 *
 * This:
 * 1. Starts the callback server
 * 2. Registers tool execution handlers
 * 3. Registers tools with the MACAW sidecar
 */
export async function initializeMacaw(options: MacawInitOptions = {}): Promise<boolean> {
  if (initialized) {
    log.warn("MACAW already initialized");
    return true;
  }

  const { callbackPort = 18799, tools = [], skipHealthCheck = false } = options;

  try {
    // Step 1: Start callback server
    log.info("Starting MACAW callback server...");
    startCallbackServer(callbackPort);

    // Step 2: Register execution handlers for each tool
    for (const tool of tools) {
      registerExecutionHandler(tool.name, tool.execute);
    }

    // Step 3: Check sidecar health
    if (!skipHealthCheck) {
      const health = await checkSidecarHealth();
      if (health.status === "unavailable") {
        log.warn("MACAW sidecar not available - tools will fail closed");
      } else {
        log.info(`MACAW sidecar status: ${health.status}`);
      }
    }

    // Step 4: Register tools with sidecar
    const toolNames = getRegisteredToolNames();
    if (toolNames.length > 0) {
      const result = await registerTools(toolNames);
      if (result.ok) {
        log.info(`Registered ${result.registered} tools with MACAW`);
      } else {
        log.warn("Failed to register tools with MACAW sidecar");
      }
    }

    initialized = true;
    log.info("MACAW initialization complete");
    return true;
  } catch (err) {
    log.error(`MACAW initialization failed: ${String(err)}`);
    return false;
  }
}

/**
 * Shutdown MACAW integration.
 */
export async function shutdownMacaw(): Promise<void> {
  if (!initialized) {
    return;
  }

  await stopCallbackServer();
  initialized = false;
  log.info("MACAW shutdown complete");
}

/**
 * Check if MACAW is initialized.
 */
export function isMacawInitialized(): boolean {
  return initialized;
}

/**
 * Register additional tools after initialization.
 */
export async function registerAdditionalTools(
  tools: Array<{ name: string; execute: ToolExecutionHandler }>,
): Promise<boolean> {
  if (!initialized) {
    log.warn("Cannot register tools: MACAW not initialized");
    return false;
  }

  for (const tool of tools) {
    registerExecutionHandler(tool.name, tool.execute);
  }

  const toolNames = tools.map((t) => t.name);
  const result = await registerTools(toolNames);
  return result.ok;
}
