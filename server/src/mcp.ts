import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { config } from "./config"

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

  /** Connect to every registered server. Best-effort; logs and continues. */
  async connectAll(onLog?: (msg: string) => void): Promise<void> {
    const registry = McpManager.readRegistry()
    if (registry.length === 0) {
      onLog?.("No MCP servers registered — falling back to simulation.")
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
        "@modelcontextprotocol/sdk not installed — install it to use real MCP servers. Using simulation."
      )
      return
    }

    for (const spec of registry) {
      try {
        const transport = new StdioTransport({
          command: spec.command,
          args: spec.args ?? [],
          env: { ...process.env, ...(spec.env ?? {}) },
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
        onLog?.(`Connected MCP server "${spec.name}" (${toolNames.length} tools).`)
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
      const result = await server.client.callTool({ name: toolName, arguments: args })
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

export const mcp = new McpManager()
