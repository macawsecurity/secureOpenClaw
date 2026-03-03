/**
 * MACAW Integration for SecureOpenClaw
 *
 * This module provides policy enforcement for all tool executions
 * through the MACAW Trust Layer.
 */

// Core bridge functions
export {
  checkSidecarHealth,
  extractPrincipal,
  invokeTool,
  isSidecarAvailable,
  logAuditEvent,
  registerTools,
} from "./bridge.js";

// Callback server
export {
  getRegisteredToolNames,
  isCallbackServerRunning,
  registerExecutionHandler,
  startCallbackServer,
  stopCallbackServer,
} from "./callback-server.js";

// Initialization
export {
  initializeMacaw,
  isMacawInitialized,
  registerAdditionalTools,
  shutdownMacaw,
  type MacawInitOptions,
} from "./init.js";

// Tool wrapper
export {
  clearCurrentPrincipal,
  getCurrentPrincipal,
  isToolMacawWrapped,
  setCurrentPrincipal,
  wrapToolsWithMacaw,
  wrapToolWithMacaw,
} from "./tool-wrapper.js";

// Types
export type {
  MacawAuditEvent,
  MacawHealthResult,
  MacawInvokeRequest,
  MacawInvokeResult,
  MacawPrincipal,
  MacawRegisterToolsRequest,
  MacawRegisterToolsResult,
  ToolExecutionHandler,
} from "./types.js";
