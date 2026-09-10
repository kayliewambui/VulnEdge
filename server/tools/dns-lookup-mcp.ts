#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for DNS lookups via `host`.
 * Exposes `scan` for subdomain / record enumeration.
 *
 * Uses ordinary `host` queries (A/AAAA/MX/NS/TXT), not `host -a`. ANY queries
 * against some NAT64/stub resolvers time out even when A/AAAA succeed.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const HOST = binaryPath("HOST_BINARY", "/usr/bin/host")

async function lookupRecords(host: string): Promise<{ output: string; code: number }> {
  const chunks: string[] = []
  let code = 0
  for (const args of [[host], ["-t", "MX", host], ["-t", "NS", host], ["-t", "TXT", host]]) {
    const result = await execFile(HOST, args, 15_000)
    chunks.push([result.stdout, result.stderr].filter(Boolean).join("\n"))
    if (result.code !== 0) code = result.code
  }
  return { output: chunks.filter(Boolean).join("\n"), code }
}

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

      const result = await lookupRecords(host)
      return textResult({
        source: "dns-lookup",
        target: host,
        dnsOutput: result.output,
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
