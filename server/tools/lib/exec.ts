import { execFile as nodeExecFile } from "node:child_process"
import { promisify } from "node:util"

const execFileAsync = promisify(nodeExecFile)

export interface ExecResult {
  stdout: string
  stderr: string
  code: number
}

/**
 * Run a binary with argv — never invokes a shell.
 *
 * `timeoutMs` defaults to 0, which Node interprets as "no timeout": long
 * security scans (nmap, nuclei, nikto, ZAP, sqlmap) are never killed mid-run,
 * so the bridge stops surfacing "scan time limit" errors. The scanner exits on
 * its own terms; we just don't impose an external deadline.
 */
export async function execFile(
  command: string,
  args: string[],
  timeoutMs = 0
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
      encoding: "utf8",
    })
    return {
      stdout: typeof stdout === "string" ? stdout : String(stdout ?? ""),
      stderr: typeof stderr === "string" ? stderr : String(stderr ?? ""),
      code: 0,
    }
  } catch (err: any) {
    return {
      stdout: typeof err?.stdout === "string" ? err.stdout : String(err?.stdout ?? ""),
      stderr: typeof err?.stderr === "string" ? err.stderr : String(err?.stderr ?? ""),
      code: typeof err?.code === "number" ? err.code : 1,
    }
  }
}

export function binaryPath(envKey: string, fallback: string): string {
  const fromEnv = process.env[envKey]?.trim()
  return fromEnv || fallback
}
