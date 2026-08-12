import { config } from "./config"
import type { ExploitPlanItem, Engagement } from "./types"
import type {
  OwaspCompliance,
  ReconResult,
  ThreatIntelligence,
  Vulnerability,
} from "../../src/lib/vapt/types"
import { computeRiskScore } from "../../src/lib/vapt/generators"
import { guardCommand } from "./security"

/**
 * LLM analysis via local Ollama (OpenAI-compatible API).
 *
 * Drives executive summaries, OWASP/CWE enrichment, remediation synthesis,
 * threat-intel profiling, and non-destructive PoC planning. When Ollama is
 * unreachable the bridge returns empty structured metrics — never synthetic
 * placeholder text.
 */

const ALLOWED_TOOLS = ["nmap", "nuclei", "sqlmap", "httpx", "curl", "whatweb"]

let ollamaReachable = false

export function isOllamaReachable(): boolean {
  return ollamaReachable
}

/** Probe Ollama on boot and before health checks. */
export async function probeOllama(onLog?: (msg: string) => void): Promise<boolean> {
  const base = config.llmBaseUrl.replace(/\/v1\/?$/, "")
  try {
    const res = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(5_000) })
    ollamaReachable = res.ok
    if (!ollamaReachable) {
      onLog?.(`Ollama unreachable at ${config.llmBaseUrl} — LLM analysis will return empty metrics.`)
    }
  } catch {
    ollamaReachable = false
    onLog?.(
      `Ollama connection failed (${config.llmBaseUrl}) — LLM analysis will return empty metrics.`
    )
  }
  return ollamaReachable
}

export function llmHealthLabel(): string {
  if (!ollamaReachable) return `ollama (${config.llmModel}, unreachable)`
  return `ollama (${config.llmModel})`
}

interface ChatMessage {
  role: "system" | "user" | "assistant"
  content: string
}

async function ollamaChat(
  messages: ChatMessage[],
  onLog?: (msg: string) => void
): Promise<string | null> {
  if (!ollamaReachable) {
    await probeOllama(onLog)
    if (!ollamaReachable) return null
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (config.llmApiKey) headers.Authorization = `Bearer ${config.llmApiKey}`

  try {
    const res = await fetch(`${config.llmBaseUrl}/chat/completions`, {
      method: "POST",
      headers,
      signal: AbortSignal.timeout(120_000),
      body: JSON.stringify({
        model: config.llmModel,
        messages,
        stream: false,
        temperature: 0.2,
      }),
    })

    if (!res.ok) {
      ollamaReachable = false
      onLog?.(`Ollama request failed (${res.status}) — marking LLM unreachable.`)
      return null
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>
    }
    return data.choices?.[0]?.message?.content?.trim() ?? null
  } catch (err) {
    ollamaReachable = false
    onLog?.(
      `Ollama chat error: ${err instanceof Error ? err.message : String(err)}`
    )
    return null
  }
}

function parseJsonBlock<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T
  } catch {
    const match = text.match(/\{[\s\S]*\}|\[[\s\S]*\]/)
    if (!match) return null
    try {
      return JSON.parse(match[0]) as T
    } catch {
      return null
    }
  }
}

/* ── Empty structures (no synthetic placeholders) ─────────────────────── */

export function emptyOwasp(): OwaspCompliance {
  return {
    categories: [],
    compliancePercentage: 0,
    passed: 0,
    failed: 0,
    warnings: 0,
    overallRisk: "Info",
  }
}

export function emptyThreatIntel(): ThreatIntelligence {
  return {
    threatLevel: "Low",
    threatScore: 0,
    summary: "",
    attackVectors: [],
    industryThreats: [],
    recommendations: [],
    exposureScore: 0,
    darkWebMentions: 0,
  }
}

/* ── Finding enrichment (OWASP / CWE / remediation) ───────────────────── */

export async function enrichFindings(
  vulns: Vulnerability[],
  onLog?: (msg: string) => void
): Promise<Vulnerability[]> {
  if (vulns.length === 0) return []

  const payload = vulns.slice(0, 20).map((v) => ({
    id: v.id,
    title: v.title,
    severity: v.severity,
    category: v.category,
    cwe: v.cwe,
    owasp: v.owasp,
    description: v.description.slice(0, 300),
  }))

  const raw = await ollamaChat(
    [
      {
        role: "system",
        content:
          "You are a security analyst. Return JSON only: { \"findings\": [{ \"id\", \"cwe\", \"owasp\", \"remediation\", \"impact\" }] }. Map each finding to OWASP Top 10 2021 and a specific CWE. Remediation must be actionable.",
      },
      { role: "user", content: JSON.stringify(payload) },
    ],
    onLog
  )

  if (!raw) return vulns

  const parsed = parseJsonBlock<{ findings?: Array<Record<string, string>> }>(raw)
  if (!parsed?.findings) return vulns

  const byId = new Map(parsed.findings.map((f) => [f.id, f]))
  return vulns.map((v) => {
    const hit = byId.get(v.id)
    if (!hit) return v
    return {
      ...v,
      cwe: hit.cwe || v.cwe,
      owasp: hit.owasp || v.owasp,
      remediation: hit.remediation || v.remediation,
      impact: hit.impact || v.impact,
    }
  })
}

/* ── OWASP compliance analysis ────────────────────────────────────────── */

export async function analyzeOwasp(
  vulns: Vulnerability[],
  onLog?: (msg: string) => void
): Promise<OwaspCompliance> {
  if (vulns.length === 0) return emptyOwasp()

  const raw = await ollamaChat(
    [
      {
        role: "system",
        content:
          'Return JSON matching OwaspCompliance: { categories: [{ id, name, description, status, findings, riskScore, recommendation }], compliancePercentage, passed, failed, warnings, overallRisk }. Use OWASP Top 10 2021 categories A01-A10.',
      },
      {
        role: "user",
        content: JSON.stringify(
          vulns.map((v) => ({
            id: v.id,
            title: v.title,
            severity: v.severity,
            owasp: v.owasp,
            cwe: v.cwe,
          }))
        ),
      },
    ],
    onLog
  )

  if (!raw) return emptyOwasp()
  const parsed = parseJsonBlock<OwaspCompliance>(raw)
  return parsed?.categories ? parsed : emptyOwasp()
}

/* ── Threat intelligence + executive summary ──────────────────────────── */

export async function analyzeThreatIntel(
  vulns: Vulnerability[],
  recon: ReconResult,
  target: string,
  onLog?: (msg: string) => void
): Promise<ThreatIntelligence> {
  const raw = await ollamaChat(
    [
      {
        role: "system",
        content:
          'Return JSON matching ThreatIntelligence: { threatLevel, threatScore, summary, attackVectors: [{ name, likelihood, impact, description, mitigation, mitreId }], industryThreats: [{ actor, motivation, sophistication, targetedSectors, ttps, activity }], recommendations, exposureScore, darkWebMentions }. Summary is the executive narrative. No placeholder text.',
      },
      {
        role: "user",
        content: JSON.stringify({
          target,
          openPorts: recon.openPorts.length,
          services: recon.openPorts.map((p) => p.service),
          findings: vulns.slice(0, 15).map((v) => ({
            title: v.title,
            severity: v.severity,
            cwe: v.cwe,
          })),
        }),
      },
    ],
    onLog
  )

  if (!raw) return emptyThreatIntel()
  const parsed = parseJsonBlock<ThreatIntelligence>(raw)
  if (!parsed?.summary && !parsed?.attackVectors?.length) return emptyThreatIntel()
  return {
    ...emptyThreatIntel(),
    ...parsed,
    attackVectors: parsed.attackVectors ?? [],
    industryThreats: parsed.industryThreats ?? [],
    recommendations: parsed.recommendations ?? [],
  }
}

/* ── Risk scoring via LLM (falls back to deterministic on empty) ──────── */

export function scoreRisk(vulns: Vulnerability[]): number {
  if (vulns.length === 0) return 0
  return computeRiskScore(vulns)
}

/* ── Exploitation plan (non-destructive PoC verification) ────────────── */

function safeHost(target: string): string {
  try {
    if (/^https?:\/\//i.test(target)) return new URL(target).hostname
  } catch {
    /* fall through */
  }
  return target.replace(/[^a-zA-Z0-9.:-]/g, "")
}

function deterministicPlan(engagement: Engagement, vulns: Vulnerability[]): ExploitPlanItem[] {
  const target = engagement.target
  const top = vulns
    .filter((v) => v.severity === "Critical" || v.severity === "High")
    .slice(0, 8)

  return top.map((v) => {
    const command = commandFor(v, target)
    const guard = guardCommand(command, engagement.safeMode)
    return {
      vulnerabilityId: v.id,
      title: v.title,
      technique: v.category,
      mitreId: undefined,
      proposedCommand: command,
      rationale: `Validate ${v.title} (${v.cwe}) non-destructively before any manual exploitation.`,
      executed: false,
      verified: false,
      guardVerdict: guard.verdict,
      guardReason: guard.reason,
      source: "deterministic" as const,
    }
  })
}

function commandFor(v: Vulnerability, target: string): string {
  const host = safeHost(target)
  switch (v.category) {
    case "Injection":
      return `httpx -u https://${host}${v.affectedComponent} -status-code -title`
    case "Cryptographic Failure":
      return `curl -sI https://${host}`
    case "Vulnerable Component":
      return `nuclei -u https://${host} -tags cve -severity critical,high`
    case "Misconfiguration":
    case "Information Disclosure":
      return `httpx -u https://${host} -title -tech-detect -status-code`
    default:
      return `nuclei -u https://${host} -severity medium,high -tags exposure,tech`
  }
}

async function ollamaPlan(
  engagement: Engagement,
  vulns: Vulnerability[],
  onLog?: (msg: string) => void
): Promise<ExploitPlanItem[] | null> {
  const findings = vulns
    .filter((v) => v.severity === "Critical" || v.severity === "High")
    .slice(0, 10)
    .map((v) => ({
      id: v.id,
      title: v.title,
      category: v.category,
      cwe: v.cwe,
      cve: v.cve,
      component: v.affectedComponent,
      port: v.port,
    }))

  if (findings.length === 0) return []

  const raw = await ollamaChat(
    [
      {
        role: "system",
        content: [
          "You are a penetration-testing planning assistant under strict rules of engagement.",
          "Produce NON-DESTRUCTIVE proof-of-concept verification commands only.",
          `Allowed executables: ${ALLOWED_TOOLS.join(", ")}.`,
          "No destructive actions, no shell metacharacters, no pipes or chaining.",
          'Return JSON: { "items": [{ "vulnerabilityId", "technique", "mitreId", "proposedCommand", "rationale" }] }',
        ].join(" "),
      },
      {
        role: "user",
        content: `Target: ${engagement.target}\nAuthorization: ${engagement.roe.authorizationRef}\nFindings:\n${JSON.stringify(findings, null, 2)}`,
      },
    ],
    onLog
  )

  if (!raw) return null

  const parsed = parseJsonBlock<{ items?: Array<Record<string, string>> }>(raw)
  const items = parsed?.items ?? []
  if (!items.length) return null

  return items.map((item) => {
    const title =
      vulns.find((v) => v.id === item.vulnerabilityId)?.title ?? item.vulnerabilityId
    const guard = guardCommand(String(item.proposedCommand ?? ""), engagement.safeMode)
    return {
      vulnerabilityId: String(item.vulnerabilityId ?? ""),
      title,
      technique: String(item.technique ?? ""),
      mitreId: item.mitreId ? String(item.mitreId) : undefined,
      proposedCommand: String(item.proposedCommand ?? ""),
      rationale: String(item.rationale ?? ""),
      executed: false,
      verified: false,
      guardVerdict: guard.verdict,
      guardReason: guard.reason,
      source: "llm" as const,
    }
  })
}

/**
 * Produce the exploitation plan. Ollama is primary; deterministic templates
 * are the last-resort fallback when the model is unreachable.
 */
export async function buildExploitPlan(
  engagement: Engagement,
  vulns: Vulnerability[],
  onLog?: (msg: string) => void
): Promise<{ items: ExploitPlanItem[]; usedLlm: boolean }> {
  const llm = await ollamaPlan(engagement, vulns, onLog)
  if (llm && llm.length > 0) return { items: llm, usedLlm: true }
  return { items: deterministicPlan(engagement, vulns), usedLlm: false }
}
