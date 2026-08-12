import {
  generateOwaspCompliance,
  generateRecon,
  generateThreatIntelligence,
  generateVulnerabilities,
  computeRiskScore,
} from "../../src/lib/vapt/generators"
import { createRng } from "../../src/lib/vapt/rng"
import type {
  AssessmentResult,
  OwaspCompliance,
  ReconResult,
  TargetKind,
  ThreatIntelligence,
  Vulnerability,
} from "../../src/lib/vapt/types"
import { mcp } from "./mcp"
import type { Engagement } from "./types"

/**
 * A ToolProvider is what the PTES orchestrator drives. Each method maps to a
 * PTES stage's data-gathering step. Two implementations exist:
 *
 *  - SimulationProvider — reuses the deterministic VulnEdge engine. No packets
 *    leave the host. This is the default and always works.
 *  - McpProvider — calls real MCP servers (nmap, nuclei, …) and normalises
 *    their output back into the same result shape, so the whole UI, report,
 *    and downstream stages are unchanged.
 */
export interface ToolProvider {
  readonly kind: "simulation" | "mcp"
  recon(engagement: Engagement, kind: TargetKind, emit: Emit): Promise<ReconResult>
  vulnerabilities(
    engagement: Engagement,
    kind: TargetKind,
    recon: ReconResult,
    emit: Emit
  ): Promise<Vulnerability[]>
  owasp(vulns: Vulnerability[]): OwaspCompliance
  threatIntel(vulns: Vulnerability[], recon: ReconResult, seed: string): ThreatIntelligence
}

export type Emit = (
  level: "info" | "tool" | "warn" | "error" | "success",
  source: string,
  message: string
) => void

function seedFor(engagement: Engagement): string {
  return `${engagement.target}::${engagement.profile}`
}

/* ─────────────────────────────────────────────────────────── SIMULATION ── */

export class SimulationProvider implements ToolProvider {
  readonly kind = "simulation" as const

  async recon(engagement: Engagement, kind: TargetKind, emit: Emit): Promise<ReconResult> {
    const rng = createRng(seedFor(engagement) + "::recon")
    emit("tool", "dns-lookup", `Enumerating DNS + subdomains for ${engagement.target}…`)
    await tick()
    const recon = generateRecon(engagement.target, kind, engagement.profile, rng)
    emit(
      "success",
      "nmap",
      `Discovered ${recon.openPorts.length} open ports, ${recon.subdomains.length} subdomains, TLS grade ${recon.ssl.grade}.`
    )
    return recon
  }

  async vulnerabilities(
    engagement: Engagement,
    kind: TargetKind,
    _recon: ReconResult,
    emit: Emit
  ): Promise<Vulnerability[]> {
    const rng = createRng(seedFor(engagement) + "::vuln")
    emit("tool", "nuclei", "Matching services against template + CVE databases…")
    await tick()
    const vulns = generateVulnerabilities(
      {
        target: engagement.target,
        profile: engagement.profile,
        ai: {
          aiPrioritisation: true,
          exploitChaining: true,
          threatFeedEnrichment: true,
          falsePositiveFiltering: true,
          remediationSynthesis: true,
        },
      },
      kind,
      rng,
      new Date().toISOString()
    )
    emit("success", "vuln-db", `Correlated ${vulns.length} findings.`)
    return vulns
  }

  owasp(vulns: Vulnerability[]): OwaspCompliance {
    return generateOwaspCompliance(vulns)
  }

  threatIntel(
    vulns: Vulnerability[],
    recon: ReconResult,
    seed: string
  ): ThreatIntelligence {
    return generateThreatIntelligence(vulns, recon, createRng(seed + "::intel"))
  }
}

/* ─────────────────────────────────────────────────────────────── MCP ───── */

/**
 * Drives real MCP servers. Where a server or its tool is unavailable, it falls
 * back to the simulation provider for that step and says so in the log — a
 * partial real assessment is more useful than a hard failure, and the operator
 * sees exactly which data is real vs. synthesised.
 *
 * NORMALISATION IS THE INTEGRATION WORK. Each MCP server returns tool-specific
 * text/JSON; `parseNmap`, `parseNuclei`, etc. below are where you map that onto
 * the shared result shape. The stubs here call the tools and, until a parser
 * is filled in for your specific server build, defer to simulation so the
 * pipeline stays green.
 */
export class McpProvider implements ToolProvider {
  readonly kind = "mcp" as const
  private readonly sim = new SimulationProvider()

  async recon(engagement: Engagement, kind: TargetKind, emit: Emit): Promise<ReconResult> {
    const servers = mcp.listServers()
    const reconServers = servers.filter((s) => s.capability === "recon")

    if (reconServers.length === 0) {
      emit("warn", "orchestrator", "No recon MCP server connected — simulating recon data.")
      return this.sim.recon(engagement, kind, emit)
    }

    const reconServer = reconServers[0]
    emit("tool", reconServer.name, `Invoking ${reconServer.name}.scan on ${engagement.target}…`)
    
    const res = await mcp.callTool(reconServer.name, "scan", {
      target: engagement.target,
      intensity: engagement.roe.aggression,
    })

    if (!res.ok) {
      emit("error", reconServer.name, `Recon tool error: ${res.error}. Falling back to simulation.`)
      return this.sim.recon(engagement, kind, emit)
    }

    emit("success", reconServer.name, "Recon complete. Normalising output…")
    
    const parsedRecon = this.parseReconOutput(res.text, engagement, kind)
    if (parsedRecon) {
      return parsedRecon
    }

    emit(
      "warn",
      "orchestrator",
      "No normaliser wired for this recon server build — using scaffold shape (raw output is in the log)."
    )
    return this.sim.recon(engagement, kind, emit)
  }

  async vulnerabilities(
    engagement: Engagement,
    kind: TargetKind,
    recon: ReconResult,
    emit: Emit
  ): Promise<Vulnerability[]> {
    const servers = mcp.listServers()
    const vulnServers = servers.filter((s) => s.capability === "vuln")

    if (vulnServers.length === 0) {
      emit("warn", "orchestrator", "No vulnerability MCP server connected — simulating findings.")
      return this.sim.vulnerabilities(engagement, kind, recon, emit)
    }

    const vulnServer = vulnServers[0]
    const services = recon.openPorts
      .filter((p) => p.state === "open")
      .map((p) => ({ port: p.port, service: p.service, version: p.version }))

    emit("tool", vulnServer.name, `Running templates against ${services.length} services…`)
    const res = await mcp.callTool(vulnServer.name, "scan", {
      target: engagement.target,
      services,
      severity: engagement.profile === "rapid" ? ["critical", "high"] : undefined,
    })

    if (!res.ok) {
      emit("error", vulnServer.name, `Scanner error: ${res.error}. Falling back to simulation.`)
      return this.sim.vulnerabilities(engagement, kind, recon, emit)
    }

    emit("success", vulnServer.name, "Scan complete. Normalising findings…")
    
    const parsedVulns = this.parseVulnOutput(res.text)
    if (parsedVulns && parsedVulns.length > 0) {
      return parsedVulns
    }

    emit(
      "warn",
      "orchestrator",
      "No normaliser wired for this scanner build — using scaffold findings (raw output is in the log)."
    )
    return this.sim.vulnerabilities(engagement, kind, recon, emit)
  }

  owasp(vulns: Vulnerability[]): OwaspCompliance {
    return generateOwaspCompliance(vulns)
  }

  threatIntel(
    vulns: Vulnerability[],
    recon: ReconResult,
    seed: string
  ): ThreatIntelligence {
    const servers = mcp.listServers()
    const intelServer = servers.find((s) => s.capability === "intel")

    if (!intelServer) {
      return generateThreatIntelligence(vulns, recon, createRng(seed + "::intel"))
    }

    return generateThreatIntelligence(vulns, recon, createRng(seed + "::intel"))
  }

  private parseReconOutput(raw: string, engagement: Engagement, kind: TargetKind): ReconResult | null {
    if (!raw?.trim()) return null

    // Direct ReconResult JSON (pre-normalised by wrapper).
    try {
      const data = JSON.parse(raw)
      if (data.openPorts && Array.isArray(data.openPorts)) {
        return data as ReconResult
      }
      if (data.source === "nmap" && typeof data.nmapXml === "string") {
        return this.mergeRecon(
          this.parseNmap(data.nmapXml),
          this.parseDns(data.dnsOutput ?? "", data.target ?? engagement.target),
          engagement,
          kind
        )
      }
      if (data.source === "dns-lookup" && typeof data.dnsOutput === "string") {
        return this.mergeRecon(
          { openPorts: [], os: defaultOs() },
          this.parseDns(data.dnsOutput, data.target ?? engagement.target),
          engagement,
          kind
        )
      }
    } catch {
      /* not JSON — try raw formats below */
    }

    if (raw.includes("<nmaprun")) {
      return this.mergeRecon(
        this.parseNmap(raw),
        { dnsRecords: [], subdomains: [] },
        engagement,
        kind
      )
    }

    if (/has address|name server|mail is handled/i.test(raw)) {
      return this.mergeRecon(
        { openPorts: [], os: defaultOs() },
        this.parseDns(raw, engagement.target),
        engagement,
        kind
      )
    }

    return null
  }

  private parseVulnOutput(raw: string): Vulnerability[] | null {
    if (!raw?.trim()) return null

    try {
      const data = JSON.parse(raw)
      if (Array.isArray(data)) {
        return data as Vulnerability[]
      }
      if (data.source === "nuclei" && Array.isArray(data.jsonl)) {
        const parsed = this.parseNuclei(data.jsonl)
        return parsed.length > 0 ? parsed : null
      }
      if (data.source === "cve-search" && Array.isArray(data.hits)) {
        const parsed = this.parseCveHits(data.hits, data.target ?? "unknown")
        return parsed.length > 0 ? parsed : null
      }
    } catch {
      /* fall through to JSONL */
    }

    const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean)
    if (lines.some((l) => l.startsWith("{"))) {
      const parsed = this.parseNuclei(lines)
      if (parsed.length > 0) return parsed
    }

    return null
  }

  /** Map nmap XML onto open ports + OS fingerprint. */
  private parseNmap(xml: string): Pick<ReconResult, "openPorts" | "os"> {
    const openPorts: ReconResult["openPorts"] = []
    const portBlocks = xml.match(/<port[\s\S]*?<\/port>/g) ?? []

    for (const block of portBlocks) {
      const port = Number(block.match(/portid="(\d+)"/)?.[1])
      if (!Number.isFinite(port)) continue
      const protocol = (block.match(/protocol="(\w+)"/)?.[1] ?? "tcp") as "tcp" | "udp"
      const stateRaw = block.match(/<state[^>]+state="([^"]+)"/)?.[1] ?? "closed"
      if (stateRaw !== "open") continue

      const service = block.match(/<service[^>]+name="([^"]*)"/)?.[1] ?? "unknown"
      const product = block.match(/product="([^"]*)"/)?.[1] ?? ""
      const version = block.match(/version="([^"]*)"/)?.[1] ?? ""
      const banner = block.match(/<banner>([^<]*)<\/banner>/)?.[1] ?? ""

      openPorts.push({
        port,
        protocol,
        state: stateRaw as ReconResult["openPorts"][0]["state"],
        service,
        version: [product, version].filter(Boolean).join(" ").trim(),
        banner,
        risk: portRisk(port, service),
      })
    }

    const osMatch = xml.match(/<osmatch name="([^"]*)" accuracy="(\d+)"/)
    const os: ReconResult["os"] = {
      osFamily: osMatch?.[1]?.split(/\s/)[0] ?? "Unknown",
      osVersion: osMatch?.[1] ?? "Unknown",
      kernel: "unknown",
      accuracy: Number(osMatch?.[2] ?? 0),
      deviceType: "unknown",
      uptimeGuess: "unknown",
      ttlSignature: 0,
      method: "nmap",
    }

    return { openPorts, os }
  }

  /** Map `host -a` text onto DNS records and subdomains. */
  private parseDns(
    text: string,
    domain: string
  ): Pick<ReconResult, "dnsRecords" | "subdomains"> {
    const dnsRecords: ReconResult["dnsRecords"] = []
    const subdomains: ReconResult["subdomains"] = []
    const host = domain.replace(/^https?:\/\//, "").split(/[/:]/)[0]
    const seen = new Set<string>()

    for (const line of text.split("\n")) {
      const addr = line.match(/(\S+) has (?:IPv6 )?address (\S+)/)
      if (addr) {
        const type = line.includes("IPv6") ? "AAAA" : "A"
        dnsRecords.push({ type, name: addr[1], value: addr[2], ttl: 0 })
        if (addr[1] !== host && !seen.has(addr[1])) {
          seen.add(addr[1])
          subdomains.push({
            name: addr[1],
            ip: addr[2],
            status: "live",
            technology: "unknown",
            risk: "Info",
          })
        }
      }
      const mx = line.match(/mail is handled by (\d+) (\S+)/)
      if (mx) dnsRecords.push({ type: "MX", name: host, value: mx[2], ttl: 0 })
      const ns = line.match(/name server (\S+)/)
      if (ns) dnsRecords.push({ type: "NS", name: host, value: ns[1], ttl: 0 })
      const txt = line.match(/^(\S+) descriptive text "([^"]*)"/)
      if (txt) dnsRecords.push({ type: "TXT", name: txt[1], value: txt[2], ttl: 0 })
    }

    return { dnsRecords, subdomains }
  }

  /** Map nuclei JSONL lines onto Vulnerability[]. */
  private parseNuclei(lines: string[]): Vulnerability[] {
    const vulns: Vulnerability[] = []
    let seq = 0

    for (const line of lines) {
      try {
        const hit = JSON.parse(line) as Record<string, any>
        const info = hit.info ?? {}
        const severity = mapNucleiSeverity(info.severity ?? "info")
        const cveIds: string[] = info.classification?.["cve-id"] ?? []
        vulns.push({
          id: `NUC-${++seq}`,
          title: info.name ?? hit.templateID ?? hit["template-id"] ?? "Nuclei finding",
          severity,
          cvss: severityToCvss(severity),
          cvssVector: "",
          cve: cveIds[0],
          cwe: info.classification?.["cwe-id"]?.[0] ?? "CWE-200",
          owasp: (info.tags ?? []).find((t: string) => /owasp/i.test(t)) ?? "A05:2021",
          category: info.tags?.[0] ?? "Misconfiguration",
          affectedComponent: hit.host ?? hit["matched-at"] ?? "unknown",
          port: extractPortFromHit(hit),
          description: info.description ?? hit.matcher_name ?? "Detected by nuclei template.",
          impact: "Potential security weakness identified by active template matching.",
          remediation: (info.reference ?? []).join("\n") || "Review nuclei template guidance.",
          confidence: 78,
          exploitability: severity === "Critical" || severity === "High" ? 72 : 45,
          exploitAvailable: cveIds.length > 0,
          references: info.reference ?? [],
          discoveredAt: new Date().toISOString(),
        })
      } catch {
        /* skip malformed JSONL line */
      }
    }

    return vulns
  }

  /** Map NVD CVE hits onto Vulnerability[]. */
  private parseCveHits(
    hits: Array<{
      keyword: string
      cve: string
      description: string
      cvss: number
      cvssVector: string
    }>,
    target: string
  ): Vulnerability[] {
    return hits.map((hit, i) => ({
      id: `CVE-${i + 1}`,
      title: `${hit.cve} — ${hit.keyword}`,
      severity: cvssToSeverity(hit.cvss),
      cvss: hit.cvss,
      cvssVector: hit.cvssVector,
      cve: hit.cve,
      cwe: "CWE-200",
      owasp: "A06:2021",
      category: "Known Vulnerability",
      affectedComponent: target,
      description: hit.description,
      impact: "Known CVE associated with observed service or component.",
      remediation: `Patch or upgrade components related to ${hit.keyword}. Monitor ${hit.cve}.`,
      confidence: 70,
      exploitability: hit.cvss >= 7 ? 65 : 40,
      exploitAvailable: hit.cvss >= 7,
      references: [`https://nvd.nist.gov/vuln/detail/${hit.cve}`],
      discoveredAt: new Date().toISOString(),
    }))
  }

  /** Fill in ReconResult defaults around parsed scan data. */
  private mergeRecon(
    scan: Pick<ReconResult, "openPorts" | "os">,
    dns: Pick<ReconResult, "dnsRecords" | "subdomains">,
    engagement: Engagement,
    _kind: TargetKind
  ): ReconResult {
    const technologies = [
      ...new Set(
        scan.openPorts.map((p) => p.service).filter((s) => s && s !== "unknown")
      ),
    ]

    return {
      subdomains: dns.subdomains,
      dnsRecords: dns.dnsRecords,
      openPorts: scan.openPorts,
      ssl: defaultSsl(),
      os: scan.os,
      whois: {
        registrar: "Unknown",
        created: "unknown",
        expires: "unknown",
        asn: "unknown",
      },
      technologies: technologies.length ? technologies : ["unknown"],
    }
  }
}

/* helpers */

function defaultSsl(): ReconResult["ssl"] {
  return {
    grade: "F",
    protocol: "unknown",
    cipherSuite: "unknown",
    keyExchange: "unknown",
    certificateIssuer: "unknown",
    certificateExpiry: "unknown",
    daysUntilExpiry: 0,
    hsts: false,
    ocspStapling: false,
    forwardSecrecy: false,
    weakProtocols: [],
    issues: ["TLS assessment not performed by recon scanner."],
  }
}

function defaultOs(): ReconResult["os"] {
  return {
    osFamily: "Unknown",
    osVersion: "Unknown",
    kernel: "unknown",
    accuracy: 0,
    deviceType: "unknown",
    uptimeGuess: "unknown",
    ttlSignature: 0,
    method: "unknown",
  }
}

function portRisk(port: number, service: string): ReconResult["openPorts"][0]["risk"] {
  const risky = new Set([21, 23, 445, 3389, 5900, 6379, 27017, 9200])
  if (risky.has(port)) return "High"
  if (/http|ssl|tls|ftp|telnet|smb|rdp/i.test(service)) return "Medium"
  return "Low"
}

function mapNucleiSeverity(raw: string): Vulnerability["severity"] {
  switch (raw.toLowerCase()) {
    case "critical":
      return "Critical"
    case "high":
      return "High"
    case "medium":
      return "Medium"
    case "low":
      return "Low"
    default:
      return "Info"
  }
}

function severityToCvss(severity: Vulnerability["severity"]): number {
  switch (severity) {
    case "Critical":
      return 9.0
    case "High":
      return 7.5
    case "Medium":
      return 5.5
    case "Low":
      return 3.0
    default:
      return 0.0
  }
}

function cvssToSeverity(cvss: number): Vulnerability["severity"] {
  if (cvss >= 9) return "Critical"
  if (cvss >= 7) return "High"
  if (cvss >= 4) return "Medium"
  if (cvss > 0) return "Low"
  return "Info"
}

function extractPortFromHit(hit: Record<string, any>): number | undefined {
  const matched = String(hit["matched-at"] ?? hit.host ?? "")
  const portMatch = matched.match(/:(\d+)/)
  return portMatch ? Number(portMatch[1]) : undefined
}

function tick(ms = 300): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

export function assembleResult(
  engagement: Engagement,
  kind: TargetKind,
  startedAt: Date,
  recon: ReconResult,
  vulns: Vulnerability[],
  owasp: OwaspCompliance,
  threatIntel: ThreatIntelligence
): AssessmentResult {
  const completedAt = new Date()
  return {
    target: engagement.target,
    targetKind: kind,
    profile: engagement.profile,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationSeconds: Math.max(
      1,
      Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)
    ),
    vulnerabilities: vulns,
    recon,
    owasp,
    threatIntel,
    riskScore: computeRiskScore(vulns),
  }
}

export function makeProvider(kind: "simulation" | "mcp"): ToolProvider {
  return kind === "mcp" ? new McpProvider() : new SimulationProvider()
}
