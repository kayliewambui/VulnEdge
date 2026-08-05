import type { TargetKind, TargetValidation } from "./types"

const IPV4_GROUP = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/
const HEX_GROUP = /^[0-9a-f]{1,4}$/i
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
const TLD = /^[a-z]{2,63}$/i

/** Strict dotted-quad check — rejects leading zeros and out-of-range octets. */
export function isIPv4(value: string): boolean {
  const parts = value.split(".")
  if (parts.length !== 4) return false
  return parts.every(
    (p) => IPV4_GROUP.test(p) && (p === "0" || !p.startsWith("0"))
  )
}

/**
 * RFC 4291 address check. Handles `::` compression (at most once), embedded
 * IPv4 suffixes (`::ffff:192.0.2.1`) and scope identifiers (`fe80::1%eth0`).
 */
export function isIPv6(value: string): boolean {
  let addr = value

  // Strip the zone index — it does not participate in the address itself.
  const zoneAt = addr.indexOf("%")
  if (zoneAt !== -1) {
    if (zoneAt === 0 || zoneAt === addr.length - 1) return false
    addr = addr.slice(0, zoneAt)
  }

  if (addr.length === 0) return false
  // `::` may appear at most once.
  if (addr.split("::").length > 2) return false
  if (addr.includes(":::")) return false

  const compressed = addr.includes("::")
  const [headRaw, tailRaw = ""] = compressed ? addr.split("::") : [addr, ""]

  const head = headRaw === "" ? [] : headRaw.split(":")
  const tail = tailRaw === "" ? [] : tailRaw.split(":")

  if (!compressed && (head.includes("") || head.length === 0)) return false
  if (head.includes("") || tail.includes("")) return false

  const all = [...head, ...tail]
  let groupCount = all.length

  // A trailing dotted-quad occupies two 16-bit groups.
  const last = all[all.length - 1]
  if (last !== undefined && last.includes(".")) {
    if (!isIPv4(last)) return false
    groupCount += 1
    all.pop()
  }

  if (!all.every((g) => HEX_GROUP.test(g))) return false

  return compressed ? groupCount <= 7 : groupCount === 8
}

/** Hostname check per RFC 1123, requiring a registrable alphabetic TLD. */
export function isDomain(value: string): boolean {
  if (value.length > 253) return false
  if (value.endsWith(".")) value = value.slice(0, -1)

  const labels = value.split(".")
  if (labels.length < 2) return false
  if (!labels.every((l) => DOMAIN_LABEL.test(l))) return false
  if (!TLD.test(labels[labels.length - 1])) return false
  // A bare dotted-quad is an IP, not a domain.
  if (isIPv4(value)) return false

  return true
}

/** IPv4 or IPv6 network in CIDR notation. */
export function isCidr(value: string): boolean {
  const slash = value.lastIndexOf("/")
  if (slash === -1) return false

  const addr = value.slice(0, slash)
  const prefixRaw = value.slice(slash + 1)
  if (!/^\d{1,3}$/.test(prefixRaw)) return false

  const prefix = Number(prefixRaw)
  if (isIPv4(addr)) return prefix >= 0 && prefix <= 32
  if (isIPv6(addr)) return prefix >= 0 && prefix <= 128
  return false
}

function isPrivateIPv4(value: string): boolean {
  const [a, b] = value.split(".").map(Number)
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  return false
}

function ipv4Advisory(value: string): string | undefined {
  const [a, b] = value.split(".").map(Number)
  if (a === 127) return "Loopback address — the scan will target this host."
  if (a === 0) return "0.0.0.0/8 is a reserved 'this network' range."
  if (a === 169 && b === 254) return "Link-local (APIPA) address."
  if (a >= 224 && a <= 239) return "Multicast address — not a scannable host."
  if (a >= 240) return "240.0.0.0/4 is reserved for future use."
  if (isPrivateIPv4(value))
    return "RFC 1918 private address — reachable only from inside the network."
  return undefined
}

function ipv6Advisory(value: string): string | undefined {
  const lower = value.toLowerCase()
  if (lower === "::1") return "IPv6 loopback address."
  if (lower === "::") return "Unspecified address — not a scannable host."
  if (lower.startsWith("fe80")) return "IPv6 link-local address."
  if (/^f[cd]/.test(lower))
    return "Unique local address (fc00::/7) — internal scope only."
  if (lower.startsWith("ff")) return "IPv6 multicast address."
  return undefined
}

/**
 * Classify and normalise an operator-supplied target.
 *
 * Accepts a bare IPv4/IPv6 address, a CIDR block, a domain name, or a full
 * URL. Returns a hard `error` when the value cannot be scanned at all, or a
 * soft `warning` when the target is scannable but noteworthy.
 */
export function validateTarget(input: string): TargetValidation {
  const raw = input.trim()

  if (!raw) {
    return {
      valid: false,
      kind: null,
      normalized: "",
      error: "Target is required.",
    }
  }

  if (/\s/.test(raw)) {
    return {
      valid: false,
      kind: null,
      normalized: raw,
      error: "Target cannot contain whitespace.",
    }
  }

  // --- URL -------------------------------------------------------------
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    let parsed: URL
    try {
      parsed = new URL(raw)
    } catch {
      return {
        valid: false,
        kind: null,
        normalized: raw,
        error: "Malformed URL.",
      }
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        valid: false,
        kind: null,
        normalized: raw,
        error: `Unsupported scheme "${parsed.protocol.replace(":", "")}" — use http or https.`,
      }
    }

    // Bracketed IPv6 literals arrive as "[::1]".
    const host = parsed.hostname.replace(/^\[|\]$/g, "")
    const hostValid = isIPv4(host) || isIPv6(host) || isDomain(host)

    if (!hostValid) {
      return {
        valid: false,
        kind: null,
        normalized: raw,
        error: "URL host is not a valid IP address or domain.",
      }
    }

    return {
      valid: true,
      kind: "url",
      normalized: parsed.origin + (parsed.pathname === "/" ? "" : parsed.pathname),
      warning:
        parsed.protocol === "http:"
          ? "Target uses cleartext HTTP — traffic is unencrypted."
          : isIPv4(host)
            ? ipv4Advisory(host)
            : isIPv6(host)
              ? ipv6Advisory(host)
              : undefined,
    }
  }

  // --- CIDR ------------------------------------------------------------
  if (raw.includes("/")) {
    if (isCidr(raw)) {
      const [addr, prefix] = raw.split("/")
      const wide = isIPv4(addr) && Number(prefix) < 24
      return {
        valid: true,
        kind: "cidr",
        normalized: raw.toLowerCase(),
        warning: wide
          ? `Wide network range (/${prefix}) — expect a long assessment.`
          : isIPv4(addr)
            ? ipv4Advisory(addr)
            : ipv6Advisory(addr),
      }
    }
    return {
      valid: false,
      kind: null,
      normalized: raw,
      error: "Invalid CIDR notation. Expected e.g. 10.0.0.0/24.",
    }
  }

  // --- Bare IPv6 (possibly bracketed) ----------------------------------
  const unbracketed = raw.replace(/^\[|\]$/g, "")
  if (unbracketed.includes(":") && isIPv6(unbracketed)) {
    return {
      valid: true,
      kind: "ipv6",
      normalized: unbracketed.toLowerCase(),
      warning: ipv6Advisory(unbracketed),
    }
  }

  // --- Bare IPv4 --------------------------------------------------------
  if (isIPv4(raw)) {
    return {
      valid: true,
      kind: "ipv4",
      normalized: raw,
      warning: ipv4Advisory(raw),
    }
  }

  // --- Domain -----------------------------------------------------------
  if (isDomain(raw)) {
    return {
      valid: true,
      kind: "domain",
      normalized: raw.toLowerCase().replace(/\.$/, ""),
      warning: raw.split(".").length > 4 ? "Deeply nested subdomain." : undefined,
    }
  }

  // --- Give a targeted reason where we can ------------------------------
  if (/^\d+(\.\d+){0,3}$/.test(raw)) {
    return {
      valid: false,
      kind: null,
      normalized: raw,
      error: "Incomplete or out-of-range IPv4 address.",
    }
  }

  if (raw.includes(":")) {
    return {
      valid: false,
      kind: null,
      normalized: raw,
      error: "Invalid IPv6 address.",
    }
  }

  if (!raw.includes(".")) {
    return {
      valid: false,
      kind: null,
      normalized: raw,
      error: "Enter a fully-qualified domain (e.g. target.example.com).",
    }
  }

  return {
    valid: false,
    kind: null,
    normalized: raw,
    error: "Unrecognised target. Provide an IPv4, IPv6, CIDR, domain, or URL.",
  }
}

/** Human label for a target class, used in the UI and report header. */
export function describeTargetKind(kind: TargetKind | null): string {
  switch (kind) {
    case "ipv4":
      return "IPv4 Host"
    case "ipv6":
      return "IPv6 Host"
    case "cidr":
      return "Network Range"
    case "domain":
      return "Domain"
    case "url":
      return "Web Application"
    default:
      return "Unknown"
  }
}
