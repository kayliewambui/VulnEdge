import type { NextFunction, Request, Response } from "express"

import { config } from "./config"
import { isCidr, isDomain, isIPv4, isIPv6, validateTarget } from "../../src/lib/vapt/validation"
import type { RulesOfEngagement } from "./types"

/* ════════════════════════════════════════════════════════════════════════
 * 1. INPUT SANITIZATION
 *
 * Every operator-supplied string that could reach a tool invocation passes
 * through here first. The rule: structured parameters only, never a shell.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Characters that have no business appearing in a hostname, IP, CIDR, or URL
 * target and are the building blocks of command injection. We reject the whole
 * request rather than trying to escape — escaping is where injection bugs live.
 */
const SHELL_METACHARACTERS = /[;&|`$(){}<>\\!*?~\n\r\t"']/

export interface SanitizedTarget {
  ok: boolean
  normalized: string
  kind: string | null
  reason?: string
}

export function sanitizeTarget(raw: unknown): SanitizedTarget {
  if (typeof raw !== "string") {
    return { ok: false, normalized: "", kind: null, reason: "Target must be a string." }
  }

  const value = raw.trim()

  if (value.length === 0 || value.length > 253) {
    return { ok: false, normalized: value, kind: null, reason: "Target length out of range." }
  }

  if (SHELL_METACHARACTERS.test(value)) {
    return {
      ok: false,
      normalized: value,
      kind: null,
      reason: "Target contains characters that are not permitted in a scan target.",
    }
  }

  // Reuse the vetted classifier from the shared engine. It also rejects
  // whitespace and malformed inputs.
  const v = validateTarget(value)
  if (!v.valid) {
    return { ok: false, normalized: value, kind: null, reason: v.error }
  }

  return { ok: true, normalized: v.normalized, kind: v.kind }
}

/** Sanitize an arbitrary short free-text field (authorization ref, labels). */
export function sanitizeText(raw: unknown, maxLen = 200): string {
  if (typeof raw !== "string") return ""
  return raw.replace(/[\x00-\x1f\x7f]/g, "").trim().slice(0, maxLen)
}

/* ════════════════════════════════════════════════════════════════════════
 * 2. SCOPE GUARD
 *
 * A target must fall inside the declared engagement scope (RoE scope +
 * server SCOPE_ALLOWLIST). This is the control that stops the platform being
 * pointed at arbitrary third parties.
 * ════════════════════════════════════════════════════════════════════════ */

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0
}

function ipv4InCidr(ip: string, cidr: string): boolean {
  const [range, bitsRaw] = cidr.split("/")
  const bits = Number(bitsRaw)
  if (!isIPv4(range)) return false
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask)
}

function isPrivateOrReserved(target: string): boolean {
  // URLs: check the host.
  let host = target
  try {
    if (/^https?:\/\//i.test(target)) host = new URL(target).hostname
  } catch {
    /* fall through with raw */
  }
  host = host.replace(/^\[|\]$/g, "")

  if (isIPv4(host)) {
    const [a, b] = host.split(".").map(Number)
    if (a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 127) return true
    if (a === 169 && b === 254) return true // link-local + AWS metadata 169.254.169.254
    if (a === 0 || a >= 224) return true
    return false
  }
  if (isIPv6(host)) {
    const l = host.toLowerCase()
    return l === "::1" || l === "::" || l.startsWith("fe80") || /^f[cd]/.test(l)
  }
  // Common internal names.
  return host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")
}

/** Does `target` match a single scope entry (host, domain, IP, or CIDR)? */
function matchesScopeEntry(target: string, entry: string): boolean {
  const e = entry.trim().toLowerCase()
  if (!e) return false

  let host = target.toLowerCase()
  try {
    if (/^https?:\/\//i.test(target)) host = new URL(target).hostname.toLowerCase()
  } catch {
    /* keep raw */
  }
  host = host.replace(/^\[|\]$/g, "")

  // CIDR
  if (isCidr(e) && isIPv4(host)) return ipv4InCidr(host, e)

  // Leading-dot domain wildcard: ".example.com" matches example.com + *.example.com
  if (e.startsWith(".")) {
    const base = e.slice(1)
    return host === base || host.endsWith("." + base)
  }

  // Bare domain also matches its subdomains (defense-friendly default).
  if (isDomain(e)) return host === e || host.endsWith("." + e)

  return host === e
}

export interface ScopeVerdict {
  allowed: boolean
  reason: string
}

export function checkScope(target: string, roe: RulesOfEngagement): ScopeVerdict {
  if (config.blockPrivateRanges && isPrivateOrReserved(target)) {
    return {
      allowed: false,
      reason:
        "Target is a private, loopback, link-local, or reserved address. Set BLOCK_PRIVATE_RANGES=false only for an authorized internal lab.",
    }
  }

  const scope = [...config.scopeAllowlist, ...roe.scope].map((s) => s.trim()).filter(Boolean)

  if (scope.length === 0) {
    return {
      allowed: false,
      reason:
        "No engagement scope declared. Add the target to the Rules of Engagement scope (or the server SCOPE_ALLOWLIST) before scanning.",
    }
  }

  const matched = scope.some((entry) => matchesScopeEntry(target, entry))
  return matched
    ? { allowed: true, reason: "In declared scope." }
    : {
        allowed: false,
        reason: `Target is not covered by the declared scope (${scope.join(", ")}).`,
      }
}

/* ════════════════════════════════════════════════════════════════════════
 * 3. COMMAND GUARD
 *
 * The exploitation stage may have the LLM *propose* commands. Nothing the
 * model emits is trusted. Every proposal is validated against an allow-list of
 * known tools with typed, bounded argument schemas — and in safe mode, nothing
 * runs regardless. This is the direct implementation of "prevent the AI from
 * being used for unauthorized command injection on the host."
 * ════════════════════════════════════════════════════════════════════════ */

/** Allow-listed executables. A proposed command must start with one of these. */
const COMMAND_ALLOWLIST = new Set([
  "nmap",
  "nuclei",
  "sqlmap",
  "whatweb",
  "httpx",
  "dnsx",
  "subfinder",
  "testssl.sh",
  "curl", // read-only checks only; validated below
])

/** Argument tokens that are always forbidden regardless of tool. */
const FORBIDDEN_ARG_PATTERNS: RegExp[] = [
  SHELL_METACHARACTERS,
  /\.\.\//, // path traversal
  /^-o/, // no output-to-file redirection via tool flags
  /--script=.*(exploit|dos|brute|vuln\.unsafe)/i, // no destructive nmap scripts
  /-X\s*(POST|PUT|DELETE|PATCH)/i, // curl: read-only methods only
  /--data|--upload-file|-T\b|-d\b/i, // curl: no writes/uploads
  /--risk\s*[2-9]/i, // sqlmap: elevated risk
  /--level\s*[2-9]/i,
  /--os-shell|--os-cmd|--file-write|--file-dest/i,
  /-tags.*(dos|intrusive|fuzz|rce|sqli|xss|lfi|rfi|ssrf|takeover|default-login)/i,
]

/** Tools and flag profiles safe for non-destructive PoC verification in SAFE_MODE. */
const VERIFICATION_SAFE_BINS = new Set(["httpx", "curl", "whatweb", "nmap", "nuclei", "testssl.sh"])

function isVerificationSafe(bin: string, tokens: string[]): boolean {
  if (!VERIFICATION_SAFE_BINS.has(bin)) return false
  if (bin === "sqlmap") return false

  if (bin === "curl") {
    const method = tokens.find((t) => /^-X/i.test(t))
    if (method && !/-X\s*(GET|HEAD)/i.test(method)) return false
  }

  if (bin === "nmap") {
    if (tokens.some((t) => /--script=.*(exploit|dos|brute|vuln)/i.test(t))) return false
  }

  if (bin === "nuclei") {
    if (tokens.some((t) => /-tags.*(dos|intrusive|fuzz|rce|sqli|xss|default-login)/i.test(t)))
      return false
  }

  return true
}

export interface CommandVerdict {
  verdict: "allowed" | "allowed-verification" | "blocked-safe-mode" | "blocked-policy"
  reason: string
}

/**
 * Validate a proposed command string. Returns whether it *could* run under an
 * active engagement — but callers still gate execution on SAFE_MODE.
 */
export function guardCommand(command: string, safeMode: boolean): CommandVerdict {
  const trimmed = command.trim()

  if (!trimmed) {
    return { verdict: "blocked-policy", reason: "Empty command." }
  }

  // Tokenize on whitespace only — because metacharacters (which would allow
  // shell word-splitting tricks) are rejected outright below, this is safe.
  const tokens = trimmed.split(/\s+/)
  const bin = tokens[0].split("/").pop() ?? tokens[0]

  if (!COMMAND_ALLOWLIST.has(bin)) {
    return {
      verdict: "blocked-policy",
      reason: `Executable "${bin}" is not on the allow-list. Permitted: ${[...COMMAND_ALLOWLIST].join(", ")}.`,
    }
  }

  for (const arg of tokens.slice(1)) {
    for (const pattern of FORBIDDEN_ARG_PATTERNS) {
      if (pattern.test(arg)) {
        return {
          verdict: "blocked-policy",
          reason: `Argument "${arg}" matches a forbidden pattern (${pattern}).`,
        }
      }
    }
  }

  if (safeMode) {
    if (isVerificationSafe(bin, tokens)) {
      return {
        verdict: "allowed-verification",
        reason: "Read-only verification command permitted under SAFE_MODE.",
      }
    }
    return {
      verdict: "blocked-safe-mode",
      reason: "SAFE_MODE is on — only non-destructive verification commands may run.",
    }
  }

  return { verdict: "allowed", reason: "Passed allow-list and argument policy." }
}

/**
 * Split an allow-listed command string into argv for use with `execFile`
 * (NEVER `exec`/a shell). Returns null if the command would not pass the guard.
 */
export function toArgv(command: string, safeMode: boolean): string[] | null {
  const verdict = guardCommand(command, safeMode).verdict
  if (verdict !== "allowed" && verdict !== "allowed-verification") return null
  return command.trim().split(/\s+/)
}

/** Execute a verification-safe command via execFile (never a shell). */
export async function runVerification(command: string): Promise<{
  ok: boolean
  output: string
  error?: string
}> {
  const argv = toArgv(command, true)
  if (!argv) {
    return { ok: false, output: "", error: "Command failed guard policy." }
  }

  const { execFile: execFileAsync } = await import("node:child_process")
  const { promisify } = await import("node:util")
  const run = promisify(execFileAsync)

  try {
    const { stdout, stderr } = await run(argv[0], argv.slice(1), {
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8",
    })
    const output = [stdout, stderr].filter(Boolean).join("\n").slice(0, 8_000)
    return { ok: true, output }
  } catch (err: any) {
    const output = [err?.stdout, err?.stderr].filter(Boolean).join("\n").slice(0, 8_000)
    return {
      ok: false,
      output,
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

/* ════════════════════════════════════════════════════════════════════════
 * 4. AUTH + RATE LIMITING MIDDLEWARE
 * ════════════════════════════════════════════════════════════════════════ */

const rateBuckets = new Map<string, { count: number; resetAt: number }>()

export function rateLimit(req: Request, res: Response, next: NextFunction) {
  const key = req.ip ?? "unknown"
  const now = Date.now()
  const bucket = rateBuckets.get(key)

  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + 60_000 })
    return next()
  }

  bucket.count += 1
  if (bucket.count > config.rateLimitPerMin) {
    res.setHeader("Retry-After", Math.ceil((bucket.resetAt - now) / 1000))
    return res.status(429).json({ error: "Rate limit exceeded." })
  }
  next()
}

function isLoopback(req: Request): boolean {
  const ip = req.ip ?? ""
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1"
}

/**
 * Bearer-token auth. When no token is configured the bridge only serves
 * loopback clients — so a misconfigured deployment can't be reached remotely
 * without a credential.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!config.bridgeToken) {
    if (isLoopback(req)) return next()
    return res.status(401).json({
      error:
        "No BRIDGE_TOKEN configured; remote access is refused. Set BRIDGE_TOKEN or connect from localhost.",
    })
  }

  const header = req.header("authorization") ?? ""
  // EventSource (SSE) cannot set headers, so accept a query token for GET only.
  const queryToken =
    req.method === "GET" && typeof req.query.token === "string" ? req.query.token : ""
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : queryToken.trim()

  // Constant-time-ish comparison.
  if (token.length !== config.bridgeToken.length || token !== config.bridgeToken) {
    return res.status(401).json({ error: "Invalid or missing bearer token." })
  }
  next()
}
