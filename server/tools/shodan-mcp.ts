#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for Shodan threat intelligence.
 * Requires SHODAN_API_KEY; returns structured stub when absent.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, textResult } from "./lib/bootstrap.js"
import { execFile } from "./lib/exec.js"

async function main() {
  const server = createMcpServer("shodan-mcp")
  const apiKey = process.env.SHODAN_API_KEY?.trim()

  server.registerTool(
    "lookup",
    {
      description: "Query Shodan for host intelligence.",
      inputSchema: { target: z.string() },
    },
    async ({ target }) => {
      const host = target.replace(/^https?:\/\//, "").split(/[/:]/)[0]

      if (!apiKey) {
        return textResult({
          source: "shodan",
          target: host,
          configured: false,
          message: "SHODAN_API_KEY not set — intel will use deterministic fallback.",
        })
      }

      const cli = await execFile("shodan", ["host", host, "--format", "json"], 30_000)
      if (cli.code === 0 && cli.stdout.trim()) {
        try {
          return textResult({
            source: "shodan",
            target: host,
            configured: true,
            data: JSON.parse(cli.stdout),
          })
        } catch {
          return textResult({
            source: "shodan",
            target: host,
            configured: true,
            raw: cli.stdout,
          })
        }
      }

      // Fallback: Shodan REST API
      try {
        const res = await fetch(`https://api.shodan.io/shodan/host/${host}?key=${apiKey}`, {
          signal: AbortSignal.timeout(15_000),
        })
        if (res.ok) {
          return textResult({
            source: "shodan",
            target: host,
            configured: true,
            data: await res.json(),
          })
        }
      } catch {
        /* fall through */
      }

      return textResult({
        source: "shodan",
        target: host,
        configured: true,
        message: "Shodan lookup returned no data.",
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
