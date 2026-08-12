#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for nmap + host DNS lookups.
 * Exposes `scan` — the tool McpProvider invokes for recon.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, errorResult, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const NMAP = binaryPath("NMAP_BINARY", "/usr/bin/nmap")
const HOST = binaryPath("HOST_BINARY", "/usr/bin/host")

function nmapArgs(target: string, intensity: string): string[] {
  const base = ["-sV", "-oX", "-", target]
  switch (intensity) {
    case "stealth":
      return ["-T2", "-F", ...base.slice(0, -1), target]
    case "aggressive":
      return ["-T4", "-A", "--top-ports", "2000", ...base.slice(0, -1), target]
    default:
      return ["-T4", "--top-ports", "1000", ...base]
  }
}

async function main() {
  const server = createMcpServer("nmap-mcp")

  server.registerTool(
    "scan",
    {
      description: "Port and service scan with optional DNS enumeration.",
      inputSchema: {
        target: z.string().describe("Host, IP, or URL to scan"),
        intensity: z
          .enum(["stealth", "balanced", "aggressive"])
          .optional()
          .describe("Scan timing / depth"),
      },
    },
    async ({ target, intensity }) => {
      const host = target.replace(/^https?:\/\//, "").split(/[/:]/)[0]
      if (!host) return errorResult("Invalid target.")

      const nmap = await execFile(NMAP, nmapArgs(host, intensity ?? "balanced"), 300_000)
      let dnsOutput = ""
      if (!/^\d/.test(host)) {
        const dns = await execFile(HOST, ["-a", host], 30_000)
        dnsOutput = [dns.stdout, dns.stderr].filter(Boolean).join("\n")
      }

      return textResult({
        source: "nmap",
        target: host,
        intensity: intensity ?? "balanced",
        nmapXml: nmap.stdout,
        nmapStderr: nmap.stderr,
        nmapExitCode: nmap.code,
        dnsOutput,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
