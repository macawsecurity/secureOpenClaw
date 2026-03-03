/**
 * MACAW Tool Wrapper
 *
 * Wraps OpenClaw tools with MACAW policy enforcement.
 * Each tool invocation goes through the MACAW sidecar.
 */

import type { AgentTool, AgentToolResult } from "@mariozechner/pi-agent-core";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { extractPrincipal, invokeTool, isSidecarAvailable } from "./bridge.js";
import { registerExecutionHandler } from "./callback-server.js";
import type { MacawPrincipal } from "./types.js";

const log = createSubsystemLogger("macaw-wrapper");

// Track wrapped tools to avoid double-wrapping
const wrappedTools = new WeakSet<AgentTool>();

// Global principal context (set per-request)
let currentPrincipal: MacawPrincipal | undefined;

// Global skill context (set per-request for Path 2 LLM-mediated skills)
let currentSkill: string | undefined;

/**
 * Set the current principal context for tool invocations.
 * Call this before running the agent loop.
 */
export function setCurrentPrincipal(principal: MacawPrincipal | undefined): void {
  currentPrincipal = principal;
}

/**
 * Get the current principal context.
 */
export function getCurrentPrincipal(): MacawPrincipal | undefined {
  return currentPrincipal;
}

/**
 * Clear the current principal context.
 */
export function clearCurrentPrincipal(): void {
  currentPrincipal = undefined;
}

/**
 * Set the current skill context for tool invocations.
 * Call this when processing LLM-mediated skills (Path 2).
 * All tool calls during the turn will include this skill context.
 */
export function setCurrentSkill(skillName: string | undefined): void {
  currentSkill = skillName;
}

/**
 * Get the current skill context.
 */
export function getCurrentSkill(): string | undefined {
  return currentSkill;
}

/**
 * Clear the current skill context.
 */
export function clearCurrentSkill(): void {
  currentSkill = undefined;
}

/**
 * Create a MACAW-wrapped version of a tool.
 * The wrapped tool routes through MACAW for policy enforcement.
 */
export function wrapToolWithMacaw<T extends AgentTool>(
  tool: T,
  principalContext?: {
    senderId?: string | null;
    senderName?: string | null;
    senderIsOwner?: boolean;
    messageChannel?: string;
    groupId?: string | null;
    sessionKey?: string;
  },
): T {
  // Don't double-wrap
  if (wrappedTools.has(tool)) {
    return tool;
  }

  // Extract principal from context if provided
  const staticPrincipal = principalContext ? extractPrincipal(principalContext) : undefined;

  // Register the original tool's execute function as the callback handler
  registerExecutionHandler(tool.name, async (toolCallId: string, params: Record<string, unknown>) => {
    // Execute the original tool
    return tool.execute(toolCallId, params, undefined, undefined);
  });

  // Create wrapped execute function
  const originalExecute = tool.execute.bind(tool);

  const wrappedExecute = async (
    toolCallId: string,
    params: unknown,
    signal?: AbortSignal,
    onUpdate?: unknown,
  ): Promise<AgentToolResult<unknown>> => {
    // Get principal - prefer static context, fall back to global
    const principal = staticPrincipal ?? currentPrincipal;

    // If sidecar is unavailable, we have a decision to make
    // SECURITY: Default to fail-closed
    if (!isSidecarAvailable()) {
      log.warn(`MACAW sidecar unavailable - failing closed for ${tool.name}`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "error",
              tool: tool.name,
              error: "MACAW sidecar unavailable - security policy enforcement required",
            }),
          },
        ],
        details: {
          status: "error",
          tool: tool.name,
          error: "macaw_unavailable",
        },
      };
    }

    // Invoke through MACAW (include skill context if set)
    const macawResult = await invokeTool({
      tool: tool.name,
      params: params as Record<string, unknown>,
      principal,
      skillName: currentSkill,
    });

    if (!macawResult.ok) {
      // Policy denied or execution failed
      const errorMsg = macawResult.message ?? macawResult.error ?? "Unknown error";
      log.warn(`MACAW denied ${tool.name}: ${errorMsg}`);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "error",
              tool: tool.name,
              error: errorMsg,
              policyDenied: macawResult.error === "policy_denied",
            }),
          },
        ],
        details: {
          status: "error",
          tool: tool.name,
          error: errorMsg,
          policyDenied: macawResult.error === "policy_denied",
        },
      };
    }

    // Success - return the result
    const result = macawResult.result;

    // Normalize result format
    if (result && typeof result === "object") {
      const record = result as Record<string, unknown>;
      if (Array.isArray(record.content)) {
        return result as AgentToolResult<unknown>;
      }
      return {
        content: [
          {
            type: "text",
            text: typeof result === "string" ? result : JSON.stringify(result),
          },
        ],
        details: result,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: typeof result === "string" ? result : JSON.stringify(result ?? { status: "ok" }),
        },
      ],
      details: result ?? { status: "ok" },
    };
  };

  // Create wrapped tool
  const wrappedTool = {
    ...tool,
    execute: wrappedExecute,
  } as T;

  wrappedTools.add(wrappedTool);
  return wrappedTool;
}

/**
 * Wrap multiple tools with MACAW.
 */
export function wrapToolsWithMacaw<T extends AgentTool>(
  tools: T[],
  principalContext?: {
    senderId?: string | null;
    senderName?: string | null;
    senderIsOwner?: boolean;
    messageChannel?: string;
    groupId?: string | null;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
  },
): T[] {
  return tools.map((tool) => wrapToolWithMacaw(tool, principalContext));
}

/**
 * Check if a tool is MACAW-wrapped.
 */
export function isToolMacawWrapped(tool: AgentTool): boolean {
  return wrappedTools.has(tool);
}
