import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { config } from "./config"

/**
 * MCP request timeout shared by all tool invocations. Defaults to the maximum
 * value a Node timer accepts (~24.8 days) so long scans are effectively never
 * cut off. `resetTimeoutOnProgress` additionally refreshes the deadline every
 * time a server streams a progress notification.
 */
const MAX_TIMER_MS = 2_147_483_647
const MCP_TOOL_TIMEOUT_MS = Math.min(
  config.mcpRequestTimeoutMs > 0 ? config.mcpRequestTimeoutMs : MAX_TIMER_MS,
  MAX_TIMER_MS
)

/**
 * MCP client manager.
 *
 * Connects to MCP servers over stdio using @modelcontextprotocol/sdk and
 * exposes a thin `callTool` surface the providers use. The SDK is imported
 * dynamically so the bridge still boots (in simulation mode) even if the SDK
 * or the configured servers are absent — a security tool shouldn't crash-loop
 * because an optional scanner isn't installed.
 */

export interface McpServerSpec {
  /** Logical name, e.g. "nmap", referenced by PTES stages. */
  name: string
  command: string
  args: string[]
  env?: Record<string, string>
  /** Which PTES capability this server provides. */
  capability: "recon" | "vuln" | "exploit" | "reporting" | "intel"
}

export interface McpToolResult {
  ok: boolean
  /** Flattened text content from the tool result. */
  text: string
  raw?: unknown
  error?: string
}

interface LoadedServer {
  spec: McpServerSpec
  // Loosely typed: the SDK client shape is resolved at runtime.
  client: any
  tools: string[]
}

export class McpManager {
  private servers = new Map<string, LoadedServer>()
  private available = false

  /** Read the server registry from disk. Missing file → empty registry. */
  static readRegistry(): McpServerSpec[] {
    try {
      const path = resolve(process.cwd(), config.mcpConfigPath)
      const parsed = JSON.parse(readFileSync(path, "utf8"))
      const servers = parsed?.servers
      if (!Array.isArray(servers)) return []
      return servers.filter(
        (s: any) => s && typeof s.name === "string" && typeof s.command === "string"
      )
    } catch {
      return []
    }
  }

  isAvailable(): boolean {
    return this.available
  }

  listServers(): McpServerSpec[] {
    return [...this.servers.values()].map((s) => s.spec)
  }

  /** Tool names discovered on a connected server (empty if not connected). */
  serverTools(serverName: string): string[] {
    return this.servers.get(serverName)?.tools ?? []
  }

  /** Connect to every registered server. Best-effort; logs and continues. */
  async connectAll(onLog?: (msg: string) => void): Promise<void> {
    const registry = McpManager.readRegistry()
    if (registry.length === 0) {
      onLog?.("No MCP servers registered.")
      return
    }

    let ClientCtor: any
    let StdioTransport: any
    try {
      const clientMod = await import("@modelcontextprotocol/sdk/client/index.js")
      const stdioMod = await import("@modelcontextprotocol/sdk/client/stdio.js")
      ClientCtor = clientMod.Client
      StdioTransport = stdioMod.StdioClientTransport
    } catch {
      onLog?.(
        "@modelcontextprotocol/sdk not installed — MCP servers unavailable."
      )
      return
    }

    for (const spec of registry) {
      try {
        const transport = new StdioTransport({
          command: spec.command,
          args: spec.args ?? [],
          // Skip empty strings so a blank SHODAN_API_KEY in mcp.servers.json
          // cannot wipe a real key from .env / the process environment.
          env: mergeSpawnEnv(spec.env),
        })
        const client = new ClientCtor(
          { name: "vulnedge-bridge", version: "1.0.0" },
          { capabilities: {} }
        )
        await client.connect(transport)
        const toolList = await client.listTools()
        const toolNames: string[] = (toolList?.tools ?? []).map((t: any) => t.name)
        this.servers.set(spec.name, { spec, client, tools: toolNames })
        this.available = true
        const keyNote =
          spec.name === "shodan"
            ? resolveShodanApiKey()
              ? ", API key set"
              : ", API key missing"
            : ""
        onLog?.(`Connected MCP server "${spec.name}" (${toolNames.length} tools${keyNote}).`)
      } catch (err) {
        onLog?.(
          `Failed to connect MCP server "${spec.name}": ${err instanceof Error ? err.message : String(err)}`
        )
      }
    }
  }

  /**
   * Invoke a tool on a named server with structured arguments. The arguments
   * object is passed to the MCP server as JSON — we never build a shell string.
   */
  async callTool(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>
  ): Promise<McpToolResult> {
    const server = this.servers.get(serverName)
    if (!server) {
      return { ok: false, text: "", error: `MCP server "${serverName}" not connected.` }
    }
    try {
      const result = await server.client.callTool(
        { name: toolName, arguments: args },
        undefined,
        { timeout: MCP_TOOL_TIMEOUT_MS, resetTimeoutOnProgress: true }
      )
      const text = (result?.content ?? [])
        .filter((c: any) => c?.type === "text")
        .map((c: any) => c.text)
        .join("\n")
      return { ok: !result?.isError, text, raw: result }
    } catch (err) {
      return {
        ok: false,
        text: "",
        error: err instanceof Error ? err.message : String(err),
      }
    }
  }

  async closeAll(): Promise<void> {
    for (const { client } of this.servers.values()) {
      try {
        await client.close?.()
      } catch {
        /* ignore */
      }
    }
    this.servers.clear()
    this.available = false
  }
}

/** Merge process env with per-server overrides, ignoring blank values. */
export function mergeSpawnEnv(
  specEnv?: Record<string, string>
): Record<string, string> {
  const merged: Record<string, string> = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) merged[key] = value
  }
  for (const [key, value] of Object.entries(specEnv ?? {})) {
    if (value?.trim()) merged[key] = value
  }
  return merged
}

/**
 * Read the Shodan key at call time (not just at MCP spawn). Operators often
 * edit mcp.servers.json after the bridge has already forked the child.
 */
export function resolveShodanApiKey(): string {
  const fromEnv = process.env.SHODAN_API_KEY?.trim()
  if (fromEnv) return fromEnv
  const spec = McpManager.readRegistry().find((s) => s.name === "shodan")
  return spec?.env?.SHODAN_API_KEY?.trim() || ""
}

export const mcp = new McpManager()
