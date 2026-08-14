#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for nuclei template scanning.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const NUCLEI = binaryPath("NUCLEI_BINARY", "/usr/bin/nuclei")
const DEFAULT_SEVERITY = "critical,high,medium,low"
const DEFAULT_TAGS = "cves,vulnerabilities,misconfigurations,exposures"

function normalizeUrl(target: string): string {
  return target.startsWith("http") ? target : `http://${target}`
}

async function main() {
  const server = createMcpServer("nuclei-mcp")

  server.registerTool(
    "scan",
    {
      description: "Run nuclei templates against a target.",
      inputSchema: {
        target: z.string().optional().describe("Primary URL or host to scan"),
        targets: z
          .array(z.string())
          .optional()
          .describe("Explicit endpoint URLs (scheme + host + port)"),
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
        tags: z.array(z.string()).optional(),
      },
    },
    async ({ target, targets, severity, tags }) => {
      const urls = [
        ...new Set(
          (targets?.length ? targets : target ? [target] : []).map(normalizeUrl)
        ),
      ]

      if (urls.length === 0) {
        return errorResult("No scan targets provided.")
      }

      const severityArg = severity?.length ? severity.join(",") : DEFAULT_SEVERITY
      const tagsArg = tags?.length ? tags.join(",") : DEFAULT_TAGS
      const allLines: string[] = []
      const exitCodes: number[] = []

      for (const url of urls) {
        const args = [
          "-silent",
          "-jsonl",
          "-u",
          url,
          "-severity",
          severityArg,
          "-tags",
          tagsArg,
        ]

        const result = await execFile(NUCLEI, args, 600_000)
        exitCodes.push(result.code)
        const lines = [result.stdout, result.stderr]
          .filter(Boolean)
          .join("\n")
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
        allLines.push(...lines)
      }

      return textResult({
        source: "nuclei",
        targets: urls,
        jsonl: allLines,
        exitCode: Math.max(...exitCodes),
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
