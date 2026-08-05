import { config } from "./config"
import type { ExploitPlanItem, Engagement } from "./types"
import type { Vulnerability } from "../../src/lib/vapt/types"
import { guardCommand } from "./security"

/**
 * Exploitation-stage analysis.
 *
 * The PTES exploitation stage never blindly runs anything. It produces a *plan*
 * of proof-of-concept commands, each validated by the CommandGuard. Two
 * analysers exist:
 *
 *  - Claude analyser (when ANTHROPIC_API_KEY / an `ant` profile is present):
 *    reasons over the confirmed findings and proposes PoC commands. Its output
 *    is treated as fully untrusted — every proposed command is re-validated by
 *    the guard, and in safe mode nothing is executed.
 *
 *  - Deterministic analyser (default): maps finding categories to canned,
 *    known-safe PoC command templates. No network, no model.
 *
 * The model is asked for structured output and is explicitly constrained to the
 * allow-listed tools; the guard is the actual enforcement boundary.
 */

const ALLOWED_TOOLS = ["nmap", "nuclei", "sqlmap", "httpx", "curl", "whatweb"]

const PLAN_SCHEMA = {
  type: "object" as const,
  additionalProperties: false,
  properties: {
    items: {
      type: "array" as const,
      items: {
        type: "object" as const,
        additionalProperties: false,
        properties: {
          vulnerabilityId: { type: "string" as const },
          technique: { type: "string" as const },
          mitreId: { type: "string" as const },
          proposedCommand: { type: "string" as const },
          rationale: { type: "string" as const },
        },
        required: ["vulnerabilityId", "technique", "proposedCommand", "rationale"],
      },
    },
  },
  required: ["items"],
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
      return `sqlmap -u https://${host}${v.affectedComponent} --batch --level 1 --risk 1`
    case "Cryptographic Failure":
      return `testssl.sh --quiet ${host}`
    case "Vulnerable Component":
      return `nuclei -u https://${host} -tags cve -severity critical,high`
    case "Misconfiguration":
    case "Information Disclosure":
      return `httpx -u https://${host} -title -tech-detect -status-code`
    default:
      return `nuclei -u https://${host} -id ${v.cwe.toLowerCase().replace(/[^a-z0-9]/g, "-")}`
  }
}

function safeHost(target: string): string {
  try {
    if (/^https?:\/\//i.test(target)) return new URL(target).hostname
  } catch {
    /* fall through */
  }
  // Strip anything not a hostname/IP character as a last-ditch guard.
  return target.replace(/[^a-zA-Z0-9.:-]/g, "")
}

async function claudePlan(
  engagement: Engagement,
  vulns: Vulnerability[]
): Promise<ExploitPlanItem[] | null> {
  let Anthropic: any
  try {
    ;({ default: Anthropic } = await import("@anthropic-ai/sdk"))
  } catch {
    return null
  }

  const client = new Anthropic() // resolves ANTHROPIC_API_KEY or an `ant` profile

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

  const system = [
    "You are a penetration-testing planning assistant operating under strict rules of engagement.",
    "Produce a NON-DESTRUCTIVE proof-of-concept validation plan for the confirmed findings.",
    `You may ONLY propose commands whose executable is one of: ${ALLOWED_TOOLS.join(", ")}.`,
    "Never propose destructive actions (no DoS, no data modification, no brute force, no write/upload).",
    "Never include shell metacharacters, pipes, redirection, or command chaining.",
    "Each command must be a single tool invocation with flags only.",
    "This is authorized testing; the operator's authorization reference is: " +
      engagement.roe.authorizationRef,
  ].join(" ")

  try {
    const resp = await client.messages.create({
      model: config.llmModel,
      max_tokens: 4096,
      // Adaptive thinking + structured output per current API guidance.
      thinking: { type: "adaptive" },
      output_config: { format: { type: "json_schema", schema: PLAN_SCHEMA } },
      system,
      messages: [
        {
          role: "user",
          content: `Target: ${engagement.target}\nAggression: ${engagement.roe.aggression}\nConfirmed findings:\n${JSON.stringify(findings, null, 2)}\n\nReturn the validation plan.`,
        },
      ],
    })

    // The cyber classifier may decline — handle before reading content.
    if (resp.stop_reason === "refusal") {
      return null
    }

    const jsonBlock = resp.content.find((b: any) => b.type === "text")
    if (!jsonBlock) return null
    const parsed = JSON.parse(jsonBlock.text)
    const items: any[] = Array.isArray(parsed?.items) ? parsed.items : []

    return items.map((item) => {
      const title = vulns.find((v) => v.id === item.vulnerabilityId)?.title ?? item.vulnerabilityId
      const guard = guardCommand(String(item.proposedCommand ?? ""), engagement.safeMode)
      return {
        vulnerabilityId: String(item.vulnerabilityId ?? ""),
        title,
        technique: String(item.technique ?? ""),
        mitreId: item.mitreId ? String(item.mitreId) : undefined,
        proposedCommand: String(item.proposedCommand ?? ""),
        rationale: String(item.rationale ?? ""),
        executed: false,
        guardVerdict: guard.verdict,
        guardReason: guard.reason,
        source: "llm" as const,
      }
    })
  } catch {
    return null
  }
}

/**
 * Produce the exploitation plan. Tries Claude when configured, always falls
 * back to the deterministic analyser, and guarantees every item carries a
 * guard verdict.
 */
export async function buildExploitPlan(
  engagement: Engagement,
  vulns: Vulnerability[]
): Promise<{ items: ExploitPlanItem[]; usedLlm: boolean }> {
  if (config.llmConfigured) {
    const llm = await claudePlan(engagement, vulns)
    if (llm && llm.length > 0) return { items: llm, usedLlm: true }
  }
  return { items: deterministicPlan(engagement, vulns), usedLlm: false }
}
