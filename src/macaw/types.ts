/**
 * MACAW Bridge Types
 *
 * Type definitions for SecureOpenClaw MACAW integration.
 */

export interface MacawPrincipal {
  userId?: string;
  userName?: string;
  role?: string;
  channel?: string;
  groupId?: string;
  sessionKey?: string;
  /** Ephemeral session UUID - regenerated on /new and /reset */
  sessionId?: string;
  /** Stable run identifier for this agent invocation */
  runId?: string;
}

export interface MacawInvokeRequest {
  tool: string;
  params: Record<string, unknown>;
  principal?: MacawPrincipal;
  timeout?: number;
  skillName?: string;
}

export interface MacawInvokeResult {
  ok: boolean;
  result?: unknown;
  error?: string;
  message?: string;
  policyMatched?: string;
  auditId?: string;
}

export interface MacawRegisterToolsRequest {
  tools: string[];
}

export interface MacawRegisterToolsResult {
  ok: boolean;
  registered: number;
}

export interface MacawHealthResult {
  status: string;
  macawConnected: boolean;
  registeredTools: number;
}

/**
 * Audit event matching MACAWClient.log_event() API.
 */
export interface MacawAuditEvent {
  /** Event type identifier (required) */
  event_type: string;
  /** Event source. Default: agent ID */
  source?: string;
  /** Action performed */
  action?: string;
  /** Target resource */
  target?: string;
  /** Outcome: "success", "failure", or "denied" */
  outcome?: "success" | "failure" | "denied";
  /** Cryptographically sign the event for tamper-proof audit */
  signed?: boolean;
  /** Event category */
  category?: string;
  /** Additional event data */
  metadata?: Record<string, unknown>;
  /** Principal context for authorization tracking */
  principal?: MacawPrincipal;
}

export type ToolExecutionHandler = (
  toolCallId: string,
  params: Record<string, unknown>,
) => Promise<unknown>;
