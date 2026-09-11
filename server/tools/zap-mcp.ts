#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for OWASP ZAP (the Checkmarx-stewarded DAST scanner).
 *
 * Runs the ZAP baseline scan, which spiders the target and reports passive
 * findings as a JSON report. Two execution modes:
 *
 *   - native: set ZAP_BINARY to a `zap-baseline.py` on PATH.
 *   - docker (default): run the official image, mounting a temp working dir so
 *     ZAP can drop its report where we can read it back.
 *
 * No wall-clock timeout is imposed on the scan itself; ZAP_SPIDER_MINUTES only
 * bounds the spider phase (a depth control, not a kill switch).
 */
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { execFile } from "./lib/exec.js"

const ZAP_BINARY = process.env.ZAP_BINARY?.trim() || ""
const ZAP_DOCKER_IMAGE =
  process.env.ZAP_DOCKER_IMAGE?.trim() || "ghcr.io/zaproxy/zaproxy:stable"
const DOCKER = process.env.DOCKER_BINARY?.trim() || "docker"
const SPIDER_MINUTES = process.env.ZAP_SPIDER_MINUTES?.trim() || "5"
const REPORT_NAME = "zap-report.json"

interface ZapAlert {
  pluginid?: string
  alertRef?: string
  alert?: string
  name?: string
  riskcode?: string
  confidence?: string
  riskdesc?: string
  desc?: string
  solution?: string
  reference?: string
  cweid?: string
  wascid?: string
  instances?: Array<{ uri?: string; method?: string; param?: string; evidence?: string }>
}

interface ZapSite {
  "@name"?: string
  "@host"?: string
  "@port"?: string
  alerts?: ZapAlert[]
}

function normalizeUrl(target: string): string {
  return /^https?:\/\//i.test(target) ? target : `http://${target}`
}

function readReport(dir: string): ZapSite[] {
  try {
    const raw = readFileSync(join(dir, REPORT_NAME), "utf8").trim()
    if (!raw) return []
    const parsed = JSON.parse(raw) as { site?: ZapSite[] }
    return Array.isArray(parsed.site) ? parsed.site : []
  } catch {
    return []
  }
}

async function scanOne(url: string, minutes: string): Promise<{ sites: ZapSite[]; code: number }> {
  const dir = mkdtempSync(join(tmpdir(), "zap-"))
  try {
    // ZAP's container runs as a non-root user; make the mounted working dir
    // group/other-writable so it can drop the report.
    chmodSync(dir, 0o777)

    let command: string
    let args: string[]
    if (ZAP_BINARY) {
      command = ZAP_BINARY
      args = ["-t", url, "-J", join(dir, REPORT_NAME), "-I", "-m", minutes]
    } else {
      command = DOCKER
      args = [
        "run",
        "--rm",
        "-v",
        `${dir}:/zap/wrk/:rw`,
        ZAP_DOCKER_IMAGE,
        "zap-baseline.py",
        "-t",
        url,
        "-J",
        REPORT_NAME,
        "-I",
        "-m",
        minutes,
      ]
    }

    // No timeout — baseline scans of large sites routinely run many minutes.
    // `-I` keeps ZAP's exit code at 0 even when it reports warnings, but we
    // read the report regardless of exit status.
    const result = await execFile(command, args)
    return { sites: readReport(dir), code: result.code }
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }
}

async function main() {
  const server = createMcpServer("zap-mcp")

  server.registerTool(
    "scan",
    {
      description: "Run an OWASP ZAP baseline (DAST) scan against a target.",
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
        spiderMinutes: z.string().optional().describe("Bound on the spider phase"),
      },
    },
    async ({ target, targets, spiderMinutes }) => {
      const urls = [
        ...new Set(
          (targets?.length ? targets : target ? [target] : []).map(normalizeUrl)
        ),
      ]
      if (urls.length === 0) return errorResult("No scan targets provided.")

      const minutes = spiderMinutes?.trim() || SPIDER_MINUTES
      const sites: ZapSite[] = []
      let exitCode = 0
      for (const url of urls) {
        try {
          const { sites: got, code } = await scanOne(url, minutes)
          sites.push(...got)
          if (code) exitCode = code
        } catch (err) {
          return errorResult(
            `ZAP scan failed for ${url}: ${err instanceof Error ? err.message : String(err)}`
          )
        }
      }

      const alertCount = sites.reduce((n, site) => n + (site.alerts?.length ?? 0), 0)
      return textResult({
        source: "zap",
        targets: urls,
        mode: ZAP_BINARY ? "native" : "docker",
        site: sites,
        alertCount,
        exitCode,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
