import { execFile as nodeExecFile } from "node:child_process"
import { promisify } from "node:util"

const execFileAsync = promisify(nodeExecFile)

export interface ExecResult {
  stdout: string
  stderr: string
  code: number
}

/** Run a binary with argv — never invokes a shell. Default timeout: 10 minutes. */
export async function execFile(
  command: string,
  args: string[],
  timeoutMs = 600_000
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
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
