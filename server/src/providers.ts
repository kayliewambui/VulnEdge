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
    const reconServer = servers.find((s) => s.capability === "recon")

    if (!reconServer) {
      emit("warn", "orchestrator", "No recon MCP server connected — simulating recon data.")
      return this.sim.recon(engagement, kind, emit)
    }

    emit("tool", reconServer.name, `Invoking ${reconServer.name}.scan on ${engagement.target}…`)
    const res = await mcp.callTool(reconServer.name, "scan", {
      target: engagement.target,
      // The aggression profile shapes scan intensity; the server decides how.
      intensity: engagement.roe.aggression,
    })

    if (!res.ok) {
      emit("error", reconServer.name, `Recon tool error: ${res.error}. Falling back to simulation.`)
      return this.sim.recon(engagement, kind, emit)
    }

    emit("success", reconServer.name, "Recon complete. Normalising output…")
    // TODO(integration): parse `res.text` / `res.raw` into ReconResult here.
    // Until a parser exists for your server build, synthesise a scaffold so the
    // report renders. The raw tool output is preserved in the log stream.
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
    const vulnServer = servers.find((s) => s.capability === "vuln")

    if (!vulnServer) {
      emit("warn", "orchestrator", "No vulnerability MCP server connected — simulating findings.")
      return this.sim.vulnerabilities(engagement, kind, recon, emit)
    }

    // Feed discovered services to the scanner as structured params — never a
    // constructed command line.
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
    // TODO(integration): parse nuclei/cve-search JSON into Vulnerability[] here.
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
    return generateThreatIntelligence(vulns, recon, createRng(seed + "::intel"))
  }
}

/* helpers */

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
