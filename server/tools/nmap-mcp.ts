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

/**
 * `-Pn` skips ICMP host discovery (NLBs often drop ping).
 * `--system-dns` uses getaddrinfo — `host -a` / nmap's own resolver time out
 * on NAT64 setups that only answer through the system stub.
 * `-4` prefers IPv4; NAT64 AAAA answers make SYN scans look empty.
 */
function nmapArgs(target: string, intensity: string): string[] {
  const common = ["-Pn", "--system-dns", "-4", "-sV", "-oX", "-"]
  switch (intensity) {
    case "stealth":
      return ["-T2", "-F", ...common, target]
    case "aggressive":
      return ["-T4", "-A", "--top-ports", "2000", ...common, target]
    default:
      return ["-T4", "--top-ports", "1000", ...common, target]
  }
}

async function lookupRecords(host: string): Promise<string> {
  const chunks: string[] = []
  for (const args of [[host], ["-t", "MX", host], ["-t", "NS", host], ["-t", "TXT", host]]) {
    const dns = await execFile(HOST, args)
    chunks.push([dns.stdout, dns.stderr].filter(Boolean).join("\n"))
  }
  return chunks.filter(Boolean).join("\n")
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

      const nmap = await execFile(NMAP, nmapArgs(host, intensity ?? "balanced"))
      let dnsOutput = ""
      if (!/^\d/.test(host)) {
        dnsOutput = await lookupRecords(host)
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
