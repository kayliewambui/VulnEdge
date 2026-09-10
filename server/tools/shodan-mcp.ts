#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for Shodan threat intelligence.
 * Requires SHODAN_API_KEY (env, or `apiKey` tool argument).
 */
import { z } from "zod"

import { connectStdio, createMcpServer, textResult } from "./lib/bootstrap.js"
import { execFile } from "./lib/exec.js"

function isIp(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":")
}

function resolveKey(arg?: string): string {
  return arg?.trim() || process.env.SHODAN_API_KEY?.trim() || ""
}

async function resolveToIps(host: string, apiKey: string): Promise<string[]> {
  if (isIp(host)) return [host]
  try {
    const url = `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(host)}&key=${encodeURIComponent(apiKey)}`
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) })
    if (!res.ok) return []
    const data = (await res.json()) as Record<string, string | null>
    const ip = data[host] ?? data[host.toLowerCase()]
    return ip ? [ip] : []
  } catch {
    return []
  }
}

async function fetchHost(ip: string, apiKey: string): Promise<unknown | null> {
  try {
    const res = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`,
      { signal: AbortSignal.timeout(15_000) }
    )
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

async function main() {
  const server = createMcpServer("shodan-mcp")

  server.registerTool(
    "lookup",
    {
      description: "Query Shodan for host intelligence.",
      inputSchema: {
        target: z.string(),
        apiKey: z.string().optional().describe("Shodan API key; falls back to SHODAN_API_KEY"),
      },
    },
    async ({ target, apiKey: apiKeyArg }) => {
      const host = target.replace(/^https?:\/\//, "").split(/[/:]/)[0]
      const apiKey = resolveKey(apiKeyArg)
      if (apiKey) process.env.SHODAN_API_KEY = apiKey

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

      const ips = await resolveToIps(host, apiKey)
      for (const ip of ips) {
        const data = await fetchHost(ip, apiKey)
        if (data) {
          return textResult({
            source: "shodan",
            target: host,
            resolvedIp: ip,
            configured: true,
            data,
          })
        }
      }

      return textResult({
        source: "shodan",
        target: host,
        configured: true,
        message: ips.length
          ? `Shodan has no host record for ${ips.join(", ")}.`
          : `Shodan could not resolve ${host} to an IP.`,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
