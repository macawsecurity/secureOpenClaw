/**
 * MACAW Bridge
 *
 * TypeScript client for communicating with the MACAW Python sidecar.
 * All tool invocations flow through this bridge for policy enforcement.
 */

import { createSubsystemLogger } from "../logging/subsystem.js";
import type {
  MacawAuditEvent,
  MacawHealthResult,
  MacawInvokeRequest,
  MacawInvokeResult,
  MacawPrincipal,
  MacawRegisterToolsRequest,
  MacawRegisterToolsResult,
} from "./types.js";

const log = createSubsystemLogger("macaw-bridge");

const SIDECAR_URL = process.env.MACAW_SIDECAR_URL || "http://127.0.0.1:18798";
const DEFAULT_TIMEOUT_MS = 30000;

let sidecarAvailable = false;
let lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL_MS = 30000;

/**
 * Check if MACAW sidecar is available.
 */
export async function checkSidecarHealth(): Promise<MacawHealthResult> {
  try {
    const response = await fetch(`${SIDECAR_URL}/health`, {
      method: "GET",
      signal: AbortSignal.timeout(5000),
    });
    if (response.ok) {
      const result = (await response.json()) as MacawHealthResult;
      sidecarAvailable = true;
      lastHealthCheck = Date.now();
      return result;
    }
    sidecarAvailable = false;
    return { status: "unhealthy", macawConnected: false, registeredTools: 0 };
  } catch (err) {
    sidecarAvailable = false;
    log.warn(`MACAW sidecar health check failed: ${String(err)}`);
    return { status: "unavailable", macawConnected: false, registeredTools: 0 };
  }
}

/**
 * Check if sidecar is available (cached).
 */
export function isSidecarAvailable(): boolean {
  if (Date.now() - lastHealthCheck > HEALTH_CHECK_INTERVAL_MS) {
    // Trigger async health check but return cached value
    checkSidecarHealth().catch(() => {});
  }
  return sidecarAvailable;
}

/**
 * Register tools with MACAW sidecar.
 * Called at startup to inform MACAW of available tools.
 */
export async function registerTools(
  tools: string[],
): Promise<MacawRegisterToolsResult> {
  const request: MacawRegisterToolsRequest = { tools };

  try {
    const response = await fetch(`${SIDECAR_URL}/register_tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      const text = await response.text();
      log.error(`Failed to register tools: ${response.status} ${text}`);
      return { ok: false, registered: 0 };
    }

    const result = (await response.json()) as MacawRegisterToolsResult;
    log.info(`Registered ${result.registered} tools with MACAW`);
    sidecarAvailable = true;
    return result;
  } catch (err) {
    log.error(`Failed to register tools: ${String(err)}`);
    return { ok: false, registered: 0 };
  }
}

/**
 * Invoke a tool through MACAW for policy enforcement.
 * This is the main entry point for all tool executions.
 */
export async function invokeTool(params: {
  tool: string;
  params: Record<string, unknown>;
  principal?: MacawPrincipal;
  timeout?: number;
  skillName?: string;
}): Promise<MacawInvokeResult> {
  const request: MacawInvokeRequest = {
    tool: params.tool,
    params: params.params,
    principal: params.principal,
    timeout: params.timeout ?? DEFAULT_TIMEOUT_MS,
    skillName: params.skillName,
  };

  try {
    const response = await fetch(`${SIDECAR_URL}/invoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(request.timeout! + 5000), // Extra buffer
    });

    if (!response.ok) {
      const text = await response.text();
      log.error(`MACAW invoke failed: ${response.status} ${text}`);
      return {
        ok: false,
        error: "sidecar_error",
        message: `Sidecar returned ${response.status}`,
      };
    }

    const result = (await response.json()) as MacawInvokeResult;

    if (!result.ok) {
      log.warn(
        `MACAW policy denied: ${params.tool} - ${result.message ?? result.error}`,
      );
    }

    return result;
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    log.error(`MACAW invoke error: ${errMsg}`);

    // If sidecar is unavailable, we need to decide on fail-open vs fail-closed
    // SECURITY: Default to fail-closed
    return {
      ok: false,
      error: "sidecar_unavailable",
      message: `MACAW sidecar unavailable: ${errMsg}`,
    };
  }
}

/**
 * Log an audit event to MACAW via MACAWClient.log_event().
 *
 * Use for:
 * - Operations that don't go through invoke_tool (e.g., browser eval)
 * - Custom application events
 * - Signed compliance events (set signed: true)
 *
 * @see API_REFERENCE.md for MACAWClient.log_event() parameters
 */
export async function logAuditEvent(event: MacawAuditEvent): Promise<boolean> {
  try {
    const response = await fetch(`${SIDECAR_URL}/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(5000),
    });

    return response.ok;
  } catch (err) {
    log.warn(`Failed to log audit event: ${String(err)}`);
    return false;
  }
}

/**
 * Extract principal context from OpenClaw runtime params.
 */
export function extractPrincipal(params: {
  senderId?: string | null;
  senderName?: string | null;
  senderIsOwner?: boolean;
  messageChannel?: string;
  groupId?: string | null;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
}): MacawPrincipal {
  return {
    userId: params.senderId ?? undefined,
    userName: params.senderName ?? undefined,
    role: params.senderIsOwner ? "owner" : "user",
    channel: params.messageChannel ?? undefined,
    groupId: params.groupId ?? undefined,
    sessionKey: params.sessionKey ?? undefined,
    sessionId: params.sessionId ?? undefined,
    runId: params.runId ?? undefined,
  };
}
