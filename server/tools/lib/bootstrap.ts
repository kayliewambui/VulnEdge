import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"

/** Create an MCP server instance — register tools before calling connect(). */
export function createMcpServer(name: string, version = "1.0.0"): McpServer {
  return new McpServer({ name, version }, { capabilities: { tools: {} } })
}

export async function connectStdio(server: McpServer): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
}

export function textResult(payload: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload) }],
  }
}

export function errorResult(message: string) {
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  }
}
