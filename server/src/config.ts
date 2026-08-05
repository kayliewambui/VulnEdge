import { readFileSync } from "node:fs"
import { resolve } from "node:path"

/**
 * Central configuration, resolved once from the environment.
 *
 * A tiny hand-rolled `.env` loader keeps the dependency surface small — we
 * don't want a supply-chain-heavy config library in a security tool.
 */
function loadDotEnv() {
  try {
    const raw = readFileSync(resolve(process.cwd(), ".env"), "utf8")
    for (const line of raw.split("\n")) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      const eq = trimmed.indexOf("=")
      if (eq === -1) continue
      const key = trimmed.slice(0, eq).trim()
      let value = trimmed.slice(eq + 1).trim()
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1)
      }
      if (process.env[key] === undefined) process.env[key] = value
    }
  } catch {
    // No .env file — rely on the ambient environment.
  }
}

loadDotEnv()

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name]
  if (v === undefined) return fallback
  return v === "1" || v.toLowerCase() === "true" || v.toLowerCase() === "yes"
}

function int(name: string, fallback: number): number {
  const v = process.env[name]
  if (v === undefined) return fallback
  const n = Number(v)
  return Number.isFinite(n) ? n : fallback
}

function list(name: string): string[] {
  const v = process.env[name]
  if (!v) return []
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

export type ToolProviderKind = "simulation" | "mcp"

export const config = {
  port: int("PORT", 8787),
  corsOrigins: list("CORS_ORIGINS").length
    ? list("CORS_ORIGINS")
    : ["http://localhost:5173", "http://localhost:5174"],

  bridgeToken: process.env.BRIDGE_TOKEN?.trim() || null,

  // Safety — see .env.example. Both gates plus per-engagement authorization are
  // required before any real exploitation could run.
  safeMode: bool("SAFE_MODE", true),
  allowActiveExploit: bool("ALLOW_ACTIVE_EXPLOIT", false),

  scopeAllowlist: list("SCOPE_ALLOWLIST"),
  blockPrivateRanges: bool("BLOCK_PRIVATE_RANGES", true),

  toolProvider: (process.env.TOOL_PROVIDER?.trim() ||
    "simulation") as ToolProviderKind,
  mcpConfigPath: process.env.MCP_CONFIG_PATH?.trim() || "./mcp.servers.json",

  anthropicApiKey: process.env.ANTHROPIC_API_KEY?.trim() || null,
  llmModel: process.env.LLM_MODEL?.trim() || "claude-opus-5",
  // The SDK also picks up an `ant auth login` profile, so "LLM enabled" is not
  // strictly gated on the env var; the analyzer probes at call time.
  llmConfigured:
    Boolean(process.env.ANTHROPIC_API_KEY?.trim()) ||
    Boolean(process.env.ANTHROPIC_AUTH_TOKEN?.trim()),

  rateLimitPerMin: int("RATE_LIMIT_PER_MIN", 60),
} as const

/** True when real (non-simulated) execution could ever be attempted. */
export function activeExecutionPermitted(): boolean {
  return (
    !config.safeMode &&
    config.allowActiveExploit &&
    config.toolProvider === "mcp"
  )
}
