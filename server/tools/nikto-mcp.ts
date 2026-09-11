#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for the Nikto web server scanner.
 *
 * Exposes `scan` — the tool McpProvider invokes for any extra vuln-capability
 * server. Nikto writes its machine-readable report to a file (its JSON writer
 * appends the format extension and refuses to stream to stdout), so we scan
 * into a private temp dir and read the report back.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const NIKTO = binaryPath("NIKTO_BINARY", "/usr/bin/nikto")
// Empty = run every plugin. Operators can narrow via NIKTO_TUNING (e.g. "b" for
// software identification / headers only) without editing code.
const DEFAULT_TUNING = process.env.NIKTO_TUNING?.trim() ?? ""

interface NiktoHostReport {
  host?: string
  ip?: string
  port?: string
  server_banner?: string | null
  vulnerabilities?: Array<{
    id?: string
    method?: string
    url?: string
    msg?: string
    references?: string
  }>
}

function normalizeUrl(target: string): string {
  return /^https?:\/\//i.test(target) ? target : `http://${target}`
}

/** Read the JSON report Nikto dropped in the temp dir, tolerating its naming. */
function readReport(dir: string): NiktoHostReport[] {
  let files: string[]
  try {
    files = readdirSync(dir)
  } catch {
    return []
  }
  for (const name of files) {
    try {
      const raw = readFileSync(join(dir, name), "utf8").trim()
      if (!raw) continue
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) return parsed as NiktoHostReport[]
    } catch {
      /* not the JSON report — keep looking */
    }
  }
  return []
}

async function scanOne(url: string, tuning: string): Promise<NiktoHostReport[]> {
  const dir = mkdtempSync(join(tmpdir(), "nikto-"))
  // Nikto infers the report format from the output file extension and writes
  // into an otherwise-empty dir, so readReport() can pick it up regardless of
  // the exact name Nikto chooses.
  const out = join(dir, "report.json")
  try {
    // `-ask no` suppresses the interactive "submit to CIRT" prompt that would
    // otherwise block a headless run forever. No timeout is imposed here — a
    // full Nikto pass is slow by design and must not be cut short.
    const args = ["-h", url, "-ask", "no", "-o", out]
    if (tuning) args.push("-Tuning", tuning)
    await execFile(NIKTO, args)
    return readReport(dir)
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }
}

async function main() {
  const server = createMcpServer("nikto-mcp")

  server.registerTool(
    "scan",
    {
      description: "Run Nikto web server checks against a target.",
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
        tuning: z.string().optional().describe("Nikto -Tuning selector"),
      },
    },
    async ({ target, targets, tuning }) => {
      const urls = [
        ...new Set(
          (targets?.length ? targets : target ? [target] : []).map(normalizeUrl)
        ),
      ]
      if (urls.length === 0) return errorResult("No scan targets provided.")

      const tuningArg = tuning?.trim() || DEFAULT_TUNING
      const items: NiktoHostReport[] = []
      for (const url of urls) {
        try {
          items.push(...(await scanOne(url, tuningArg)))
        } catch (err) {
          items.push({
            host: url,
            vulnerabilities: [
              { msg: `Nikto failed: ${err instanceof Error ? err.message : String(err)}` },
            ],
          })
        }
      }

      const findingCount = items.reduce(
        (n, host) => n + (host.vulnerabilities?.length ?? 0),
        0
      )
      return textResult({
        source: "nikto",
        targets: urls,
        items,
        findingCount,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
