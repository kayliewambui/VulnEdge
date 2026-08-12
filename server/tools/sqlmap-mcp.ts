#!/usr/bin/env -S npx tsx
/**
 * MCP wrapper for sqlmap. Respects SQLMAP_SAFE_MODE — plans only by default.
 */
import { z } from "zod"

import { connectStdio, createMcpServer, textResult } from "./lib/bootstrap.js"
import { binaryPath, execFile } from "./lib/exec.js"

const SQLMAP = binaryPath("SQLMAP_BINARY", "/usr/bin/sqlmap")
const SAFE_MODE = process.env.SQLMAP_SAFE_MODE !== "false"

async function main() {
  const server = createMcpServer("sqlmap-mcp")

  server.registerTool(
    "scan",
    {
      description: "SQL injection assessment (safe mode returns a plan only).",
      inputSchema: {
        target: z.string().describe("URL with injectable parameter"),
        parameter: z.string().optional(),
      },
    },
    async ({ target, parameter }) => {
      if (SAFE_MODE) {
        return textResult({
          source: "sqlmap",
          safeMode: true,
          target,
          parameter: parameter ?? "auto-detect",
          plan: `sqlmap -u "${target}" --batch --level=1 --risk=1${parameter ? ` -p ${parameter}` : ""}`,
          executed: false,
        })
      }

      const url = target.startsWith("http") ? target : `http://${target}`
      const args = ["-u", url, "--batch", "--random-agent", "--level=1", "--risk=1"]
      if (parameter) args.push("-p", parameter)

      const result = await execFile(SQLMAP, args, 600_000)
      return textResult({
        source: "sqlmap",
        safeMode: false,
        target: url,
        stdout: result.stdout.slice(0, 50_000),
        stderr: result.stderr.slice(0, 10_000),
        exitCode: result.code,
        executed: true,
      })
    }
  )

  server.registerTool(
    "plan",
    {
      description: "Return a non-destructive sqlmap command plan.",
      inputSchema: { target: z.string() },
    },
    async ({ target }) => {
      const url = target.startsWith("http") ? target : `http://${target}`
      return textResult({
        source: "sqlmap",
        plan: `sqlmap -u "${url}" --batch --level=1 --risk=1`,
      })
    }
  )

  await connectStdio(server)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
