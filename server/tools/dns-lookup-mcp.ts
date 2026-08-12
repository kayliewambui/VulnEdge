#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for DNS lookups via `host`.
 * Exposes `scan` for subdomain / record enumeration.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const HOST = binaryPath("HOST_BINARY", "/usr/bin/host")

async function main() {
  const server = createMcpServer("dns-lookup-mcp")

  server.registerTool(
    "scan",
    {
      description: "DNS record lookup for a domain.",
      inputSchema: {
        target: z.string().describe("Domain to look up"),
        intensity: z.string().optional(),
      },
    },
    async ({ target }) => {
      const host = target.replace(/^https?:\/\//, "").split(/[/:]/)[0]
      if (!host || /^\d/.test(host)) {
        return errorResult("DNS lookup requires a domain name.")
      }

      const result = await execFile(HOST, ["-a", host], 30_000)
      return textResult({
        source: "dns-lookup",
        target: host,
        dnsOutput: [result.stdout, result.stderr].filter(Boolean).join("\n"),
        exitCode: result.code,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
