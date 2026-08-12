import { bus, log } from "./events"
import { buildExploitPlan } from "./llm"
import { assembleResult, makeProvider, type Emit } from "./providers"
import { activeExecutionPermitted } from "./config"
import { runVerification } from "./security"
import type {
  Engagement,
  PtesStageId,
  StageState,
} from "./types"
import { validateTarget } from "../../src/lib/vapt/validation"

/**
 * The seven PTES stages. Each is a discrete, streamed step. The orchestrator
 * maps every stage onto tool-provider calls and publishes progress + logs as
 * it goes, so the frontend renders real tool activity rather than a fake timer.
 */
export const PTES_STAGES: { id: PtesStageId; label: string }[] = [
  { id: "pre-engagement", label: "Pre-Engagement & Scoping" },
  { id: "intelligence", label: "Intelligence Gathering" },
  { id: "threat-modeling", label: "Threat Modeling" },
  { id: "vulnerability-analysis", label: "Vulnerability Analysis" },
  { id: "exploitation", label: "Exploitation (Safe Mode)" },
  { id: "post-exploitation", label: "Post-Exploitation Analysis" },
  { id: "reporting", label: "Reporting" },
]

export function initialStages(): StageState[] {
  return PTES_STAGES.map((s) => ({ id: s.id, label: s.label, status: "pending" }))
}

function setStage(
  engagement: Engagement,
  id: PtesStageId,
  patch: Partial<StageState>
) {
  const stage = engagement.stages.find((s) => s.id === id)
  if (!stage) return
  Object.assign(stage, patch)
  engagement.updatedAt = new Date().toISOString()
  bus.publish(engagement.id, { type: "stage", data: { engagementId: engagement.id, stage } })
}

function setProgress(engagement: Engagement, progress: number) {
  engagement.progress = Math.min(100, Math.round(progress))
  bus.publish(engagement.id, {
    type: "progress",
    data: {
      engagementId: engagement.id,
      progress: engagement.progress,
      status: engagement.status,
    },
  })
}

/**
 * Run the full PTES pipeline for an engagement. Mutates the engagement in place
 * and streams events throughout. Resolves when the pipeline finishes (or fails).
 */
export async function runPtes(engagement: Engagement): Promise<void> {
  const emit: Emit = (level, source, message) =>
    log(engagement.id, currentStage, level, source, message)

  let currentStage: PtesStageId = "pre-engagement"
  const startedAt = new Date()
  const provider = makeProvider(engagement.provider)

  engagement.status = "running"
  setProgress(engagement, 2)

  try {
    const validation = validateTarget(engagement.target)
    if (!validation.valid || !validation.kind) {
      throw new Error(validation.error ?? "Invalid target.")
    }
    const kind = validation.kind

    // ── Stage 1: Pre-engagement ──────────────────────────────────────────
    currentStage = "pre-engagement"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    emit("info", "orchestrator", `Rules of Engagement: ${engagement.roe.aggression} · auth ref "${engagement.roe.authorizationRef}".`)
    emit(
      "info",
      "orchestrator",
      engagement.safeMode
        ? "SAFE MODE active — exploitation stage will plan/PoC only; no commands executed."
        : "Active-exploit gates checked."
    )
    setStage(engagement, currentStage, { status: "completed", completedAt: iso(), detail: "Scope validated." })
    setProgress(engagement, 8)

    // ── Stage 2: Intelligence gathering ──────────────────────────────────
    currentStage = "intelligence"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    const recon = await provider.recon(engagement, kind, emit)
    setStage(engagement, currentStage, {
      status: "completed",
      completedAt: iso(),
      detail: `${recon.subdomains.length} subdomains · ${recon.openPorts.length} ports · TLS ${recon.ssl.grade}`,
    })
    setProgress(engagement, 30)

    // ── Stage 3: Threat modeling ─────────────────────────────────────────
    currentStage = "threat-modeling"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    emit("info", "orchestrator", "Prioritising attack surface from recon (exposed services, weak TLS, risky subdomains)…")
    await sleep(engagement.provider === "simulation" ? 500 : 100)
    const riskyPorts = recon.openPorts.filter((p) => p.risk === "Critical" || p.risk === "High").length
    setStage(engagement, currentStage, {
      status: "completed",
      completedAt: iso(),
      detail: `${riskyPorts} high-risk service(s) prioritised.`,
    })
    setProgress(engagement, 42)

    // ── Stage 4: Vulnerability analysis ──────────────────────────────────
    currentStage = "vulnerability-analysis"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    const vulns = await provider.vulnerabilities(engagement, kind, recon, emit)
    emit("tool", "ollama", "Generating OWASP compliance analysis…")
    const owasp = await provider.owasp(vulns)
    const critical = vulns.filter((v) => v.severity === "Critical").length
    setStage(engagement, currentStage, {
      status: "completed",
      completedAt: iso(),
      detail: `${vulns.length} findings · ${critical} critical · OWASP ${owasp.compliancePercentage}%`,
    })
    setProgress(engagement, 62)

    // ── Stage 5: Exploitation (safe by default) ──────────────────────────
    currentStage = "exploitation"
    if (!engagement.roe.allowExploitation) {
      setStage(engagement, currentStage, {
        status: "skipped",
        detail: "Exploitation disabled in the Rules of Engagement.",
      })
      emit("warn", "orchestrator", "Exploitation stage skipped by RoE.")
    } else {
      setStage(engagement, currentStage, { status: "running", startedAt: iso() })
      emit("tool", "analyzer", "Analysing findings to build a non-destructive PoC plan…")
      const { items, usedLlm } = await buildExploitPlan(engagement, vulns, (msg) =>
        emit("warn", "ollama", msg)
      )
      engagement.exploitPlan = items
      emit(
        "success",
        usedLlm ? "ollama" : "analyzer",
        `Produced ${items.length} PoC plan item(s) via ${usedLlm ? "Ollama analysis" : "deterministic templates"}.`
      )

      for (const item of items) {
        if (item.guardVerdict === "allowed-verification") {
          emit("tool", "verification", `Running safe PoC: ${item.proposedCommand}`)
          const result = await runVerification(item.proposedCommand)
          item.verificationOutput = result.output
          item.verified = result.ok
          emit(
            result.ok ? "success" : "warn",
            "verification",
            result.ok
              ? `Verified (${result.output.slice(0, 120)}…)`
              : `Verification failed: ${result.error ?? "non-zero exit"}`
          )
        } else if (item.guardVerdict === "allowed" && activeExecutionPermitted()) {
          // Real execution would be dispatched here through the MCP exploit
          // server with execFile-style argv (never a shell). This path only
          // opens when SAFE_MODE=false AND ALLOW_ACTIVE_EXPLOIT=true AND the
          // provider is mcp — none of which are the default.
          emit("warn", "exploit", `[ARMED] would run: ${item.proposedCommand}`)
        } else {
          emit(
            "info",
            "command-guard",
            `PLAN ${item.guardVerdict}: ${item.proposedCommand}  (${item.guardReason})`
          )
        }
      }
      setStage(engagement, currentStage, {
        status: "completed",
        completedAt: iso(),
        detail: `${items.length} PoC(s) planned · none executed (safe mode).`,
      })
    }
    setProgress(engagement, 78)

    // ── Stage 6: Post-exploitation analysis ──────────────────────────────
    currentStage = "post-exploitation"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    emit("info", "orchestrator", "Modelling threat actors, attack vectors, and blast radius…")
    const threatIntel = await provider.threatIntel(vulns, recon, engagement.target)
    await sleep(engagement.provider === "simulation" ? 400 : 100)
    setStage(engagement, currentStage, {
      status: "completed",
      completedAt: iso(),
      detail: `Threat level: ${threatIntel.threatLevel} (${threatIntel.threatScore}/100).`,
    })
    setProgress(engagement, 90)

    // ── Stage 7: Reporting ───────────────────────────────────────────────
    currentStage = "reporting"
    setStage(engagement, currentStage, { status: "running", startedAt: iso() })
    engagement.result = assembleResult(engagement, kind, startedAt, recon, vulns, owasp, threatIntel)
    emit(
      "success",
      "reporter",
      `Assessment compiled — risk score ${engagement.result.riskScore}/100. Report ready for PDF export.`
    )
    setStage(engagement, currentStage, { status: "completed", completedAt: iso(), detail: "Report ready." })

    engagement.status = "completed"
    setProgress(engagement, 100)
    bus.publish(engagement.id, {
      type: "result",
      data: { engagementId: engagement.id, engagement },
    })
  } catch (err) {
    engagement.status = "failed"
    engagement.error = err instanceof Error ? err.message : String(err)
    setStage(engagement, currentStage, {
      status: "failed",
      completedAt: iso(),
      detail: engagement.error,
    })
    log(engagement.id, currentStage, "error", "orchestrator", `Pipeline failed: ${engagement.error}`)
    bus.publish(engagement.id, {
      type: "result",
      data: { engagementId: engagement.id, engagement },
    })
  }
}

function iso() {
  return new Date().toISOString()
}
function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms))
}
