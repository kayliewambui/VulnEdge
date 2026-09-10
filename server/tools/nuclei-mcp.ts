#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for nuclei template scanning.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const NUCLEI = binaryPath("NUCLEI_BINARY", "/usr/bin/nuclei")
// Include info/unknown so exposed panels, TLS/cert issues and missing-header
// findings surface on hardened targets. No default tag filter: nuclei tags are
// singular/product-specific, so the old plural defaults matched almost nothing.
const DEFAULT_SEVERITY = "critical,high,medium,low,info,unknown"

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
      const tagsArg = tags?.length ? tags.join(",") : ""
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
        ]
        // Only constrain by tags when explicitly requested; otherwise run the
        // full severity-selected template set.
        if (tagsArg) {
          args.push("-tags", tagsArg)
        }

        const result = await execFile(NUCLEI, args, 600_000)
        exitCodes.push(result.code)
        // Keep JSONL findings only — nuclei -silent still writes INF lines to
        // stderr, and mixing them in made parseNuclei skip the whole payload
        // when a non-JSON prefix appeared first.
        const jsonLines = result.stdout
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.startsWith("{"))
        allLines.push(...jsonLines)
      }

      return textResult({
        source: "nuclei",
        targets: urls,
        jsonl: allLines,
        findingCount: allLines.length,
        exitCode: Math.max(...exitCodes, 0),
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
