import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { loadDotEnv } from "../infra/dotenv.js";
import { normalizeEnv } from "../infra/env.js";
import { formatUncaughtError } from "../infra/errors.js";
import { isMainModule } from "../infra/is-main.js";
import { ensureOpenClawCliOnPath } from "../infra/path-env.js";
import { assertSupportedRuntime } from "../infra/runtime-guard.js";
import { installUnhandledRejectionHandler } from "../infra/unhandled-rejections.js";
import { enableConsoleCapture } from "../logging.js";
import { getCommandPathWithRootOptions, getPrimaryCommand, hasHelpOrVersion } from "./argv.js";
import { applyCliProfileEnv, parseCliProfileArgs } from "./profile.js";
import { tryRouteCli } from "./route.js";
import { normalizeWindowsArgv } from "./windows-argv.js";

// MACAW: Resolve project root directory (where macaw_lib should be)
function getProjectRoot(): string {
  if (process.env.MACAW_HOME) {
    return dirname(process.env.MACAW_HOME);
  }
  const currentFile = fileURLToPath(import.meta.url);
  // Go up from src/cli/run-main.ts to project root
  return dirname(dirname(dirname(currentFile)));
}

// MACAW: Check if MACAW is installed
function isMacawInstalled(): { installed: boolean; macawLibDir: string; configPath: string } {
  const projectRoot = getProjectRoot();
  const macawLibDir = join(projectRoot, "macaw_lib");
  const configPath = join(macawLibDir, ".macaw", "config.json");
  return {
    installed: existsSync(configPath),
    macawLibDir,
    configPath,
  };
}

// MACAW: Start the sidecar process
async function startSidecar(macawLibDir: string): Promise<ChildProcess | null> {
  const projectRoot = getProjectRoot();
  const sidecarPath = join(projectRoot, "sidecar", "server.py");

  if (!existsSync(sidecarPath)) {
    return null;
  }

  // Generate ephemeral HMAC secret for sidecar ↔ callback communication
  // This is never written to disk, only passed via environment
  const hmacSecret = randomBytes(32).toString("hex");
  process.env.MACAW_HMAC_SECRET = hmacSecret;

  const sidecar = spawn("python3", [sidecarPath], {
    env: {
      ...process.env,
      MACAW_HOME: macawLibDir,
      MACAW_HMAC_SECRET: hmacSecret,
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: false,
  });

  // Give sidecar time to start
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Check if it's running
  if (sidecar.exitCode !== null) {
    return null;
  }

  return sidecar;
}

// MACAW: Wait for sidecar to be healthy
async function waitForSidecarHealth(maxAttempts = 10): Promise<boolean> {
  const sidecarUrl = process.env.MACAW_SIDECAR_URL || "http://127.0.0.1:18798";

  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`${sidecarUrl}/health`, {
        signal: AbortSignal.timeout(2000),
      });
      if (response.ok) {
        return true;
      }
    } catch {
      // Sidecar not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

// MACAW: Initialize with automatic sidecar management
async function initializeMacawWithSidecar(): Promise<{
  ready: boolean;
  sidecarProcess?: ChildProcess;
  error?: string;
}> {
  // Check if MACAW is installed
  const { installed, macawLibDir } = isMacawInstalled();
  if (!installed) {
    return {
      ready: false,
      error:
        "\n[SecureOpenClaw] MACAW Trust Layer not installed.\n\n" +
        "Run the install script first:\n" +
        "  ./install.sh\n\n" +
        "This will guide you through setting up MACAW.\n",
    };
  }

  // Set MACAW_HOME for client library
  process.env.MACAW_HOME = macawLibDir;

  // Start sidecar
  const sidecarProcess = await startSidecar(macawLibDir);
  if (!sidecarProcess) {
    return {
      ready: false,
      error:
        "\n[SecureOpenClaw] Failed to start MACAW sidecar.\n\n" +
        "Check that Python 3 is installed and sidecar/server.py exists.\n",
    };
  }

  // Wait for sidecar to be healthy
  const healthy = await waitForSidecarHealth();
  if (!healthy) {
    sidecarProcess.kill();
    return {
      ready: false,
      error:
        "\n[SecureOpenClaw] MACAW sidecar failed health check.\n\n" +
        "Check sidecar logs for errors.\n",
    };
  }

  // Initialize MACAW bridge
  const { initializeMacaw } = await import("../macaw/init.js");
  const macawReady = await initializeMacaw({ skipHealthCheck: true });

  if (!macawReady) {
    sidecarProcess.kill();
    return {
      ready: false,
      error:
        "\n[SecureOpenClaw] MACAW initialization failed.\n\n" +
        "Please check your configuration and try again.\n",
    };
  }

  return {
    ready: true,
    sidecarProcess,
  };
}

export function rewriteUpdateFlagArgv(argv: string[]): string[] {
  const index = argv.indexOf("--update");
  if (index === -1) {
    return argv;
  }

  const next = [...argv];
  next.splice(index, 1, "update");
  return next;
}

export function shouldRegisterPrimarySubcommand(argv: string[]): boolean {
  return !hasHelpOrVersion(argv);
}

export function shouldSkipPluginCommandRegistration(params: {
  argv: string[];
  primary: string | null;
  hasBuiltinPrimary: boolean;
}): boolean {
  if (params.hasBuiltinPrimary) {
    return true;
  }
  if (!params.primary) {
    return hasHelpOrVersion(params.argv);
  }
  return false;
}

export function shouldEnsureCliPath(argv: string[]): boolean {
  if (hasHelpOrVersion(argv)) {
    return false;
  }
  const [primary, secondary] = getCommandPathWithRootOptions(argv, 2);
  if (!primary) {
    return true;
  }
  if (primary === "status" || primary === "health" || primary === "sessions") {
    return false;
  }
  if (primary === "config" && (secondary === "get" || secondary === "unset")) {
    return false;
  }
  if (primary === "models" && (secondary === "list" || secondary === "status")) {
    return false;
  }
  return true;
}

export async function runCli(argv: string[] = process.argv) {
  let normalizedArgv = normalizeWindowsArgv(argv);
  const parsedProfile = parseCliProfileArgs(normalizedArgv);
  if (!parsedProfile.ok) {
    throw new Error(parsedProfile.error);
  }
  if (parsedProfile.profile) {
    applyCliProfileEnv({ profile: parsedProfile.profile });
  }
  normalizedArgv = parsedProfile.argv;

  loadDotEnv({ quiet: true });
  normalizeEnv();
  if (shouldEnsureCliPath(normalizedArgv)) {
    ensureOpenClawCliOnPath();
  }

  // Enforce the minimum supported runtime before doing any work.
  assertSupportedRuntime();

  if (await tryRouteCli(normalizedArgv)) {
    return;
  }

  // Capture all console output into structured logs while keeping stdout/stderr behavior.
  enableConsoleCapture();

  // MACAW: Initialize trust layer - REQUIRED for SecureOpenClaw
  const macawResult = await initializeMacawWithSidecar();
  if (!macawResult.ready) {
    console.error(macawResult.error);
    process.exit(1);
  }

  // Ensure sidecar is stopped on exit
  if (macawResult.sidecarProcess) {
    const cleanup = () => {
      if (macawResult.sidecarProcess && !macawResult.sidecarProcess.killed) {
        macawResult.sidecarProcess.kill();
      }
    };
    process.on("exit", cleanup);
    process.on("SIGINT", () => {
      cleanup();
      process.exit(0);
    });
    process.on("SIGTERM", () => {
      cleanup();
      process.exit(0);
    });
  }

  const { buildProgram } = await import("./program.js");
  const program = buildProgram();

  // Global error handlers to prevent silent crashes from unhandled rejections/exceptions.
  // These log the error and exit gracefully instead of crashing without trace.
  installUnhandledRejectionHandler();

  process.on("uncaughtException", (error) => {
    console.error("[openclaw] Uncaught exception:", formatUncaughtError(error));
    process.exit(1);
  });

  const parseArgv = rewriteUpdateFlagArgv(normalizedArgv);
  // Register the primary command (builtin or subcli) so help and command parsing
  // are correct even with lazy command registration.
  const primary = getPrimaryCommand(parseArgv);
  if (primary) {
    const { getProgramContext } = await import("./program/program-context.js");
    const ctx = getProgramContext(program);
    if (ctx) {
      const { registerCoreCliByName } = await import("./program/command-registry.js");
      await registerCoreCliByName(program, ctx, primary, parseArgv);
    }
    const { registerSubCliByName } = await import("./program/register.subclis.js");
    await registerSubCliByName(program, primary);
  }

  const hasBuiltinPrimary =
    primary !== null && program.commands.some((command) => command.name() === primary);
  const shouldSkipPluginRegistration = shouldSkipPluginCommandRegistration({
    argv: parseArgv,
    primary,
    hasBuiltinPrimary,
  });
  if (!shouldSkipPluginRegistration) {
    // Register plugin CLI commands before parsing
    const { registerPluginCliCommands } = await import("../plugins/cli.js");
    const { loadConfig } = await import("../config/config.js");
    registerPluginCliCommands(program, loadConfig());
  }

  await program.parseAsync(parseArgv);
}

export function isCliMainModule(): boolean {
  return isMainModule({ currentFile: fileURLToPath(import.meta.url) });
}
