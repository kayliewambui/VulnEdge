#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for nuclei template scanning.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const NUCLEI = binaryPath("NUCLEI_BINARY", "/usr/bin/nuclei")

async function main() {
  const server = createMcpServer("nuclei-mcp")

  server.registerTool(
    "scan",
    {
      description: "Run nuclei templates against a target.",
      inputSchema: {
        target: z.string().describe("URL or host to scan"),
        services: z
          .array(
            z.object({
              port: z.number(),
              service: z.string().optional(),
              version: z.string().optional(),
            })
          )
          .optional(),
        severity: z.array(z.string()).optional(),
      },
    },
    async ({ target, severity }) => {
      const url = target.startsWith("http") ? target : `http://${target}`
      const args = ["-silent", "-jsonl", "-u", url]

      if (severity?.length) {
        args.push("-severity", severity.join(","))
      } else {
        args.push("-severity", "critical,high,medium,low")
      }

      const result = await execFile(NUCLEI, args, 600_000)
      const lines = [result.stdout, result.stderr]
        .filter(Boolean)
        .join("\n")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)

      return textResult({
        source: "nuclei",
        target: url,
        jsonl: lines,
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
