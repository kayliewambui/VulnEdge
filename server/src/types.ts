import type { AssessmentResult } from "../../src/lib/vapt/types"

export type { AssessmentResult }

/** Rules of Engagement — the pre-engagement contract. */
export type Aggression = "stealth" | "balanced" | "aggressive"

export interface RulesOfEngagement {
  aggression: Aggression
  /** Operator's authorization reference (ticket, contract id, "lab", …). */
  authorizationRef: string
  /** Extra in-scope targets declared for this engagement (hosts/IPs/CIDRs). */
  scope: string[]
  /** If false, the exploitation stage is skipped entirely. */
  allowExploitation: boolean
}

export type PtesStageId =
  | "pre-engagement"
  | "intelligence"
  | "threat-modeling"
  | "vulnerability-analysis"
  | "exploitation"
  | "post-exploitation"
  | "reporting"

export type StageStatus =
  | "pending"
  | "running"
  | "completed"
  | "skipped"
  | "failed"

export interface StageState {
  id: PtesStageId
  label: string
  status: StageStatus
  startedAt?: string
  completedAt?: string
  detail?: string
}

export type EngagementStatus =
  | "created"
  | "running"
  | "completed"
  | "aborted"
  | "failed"

export interface Engagement {
  id: string
  target: string
  profile: "rapid" | "comprehensive" | "pentest"
  roe: RulesOfEngagement
  status: EngagementStatus
  provider: "simulation" | "mcp"
  safeMode: boolean
  createdAt: string
  updatedAt: string
  progress: number
  stages: StageState[]
  result: AssessmentResult | null
  /** PoC/plan artifacts from the exploitation stage (never executed in safe mode). */
  exploitPlan: ExploitPlanItem[]
  error?: string
}

export interface ExploitPlanItem {
  vulnerabilityId: string
  title: string
  technique: string
  /** MITRE ATT&CK id where applicable. */
  mitreId?: string
  /** The proposed command/PoC — a plan, gated by the CommandGuard. */
  proposedCommand: string
  rationale: string
  executed: boolean
  /** True when a safe verification command completed under SAFE_MODE. */
  verified: boolean
  /** Truncated stdout/stderr from verification execution. */
  verificationOutput?: string
  guardVerdict: "allowed" | "allowed-verification" | "blocked-safe-mode" | "blocked-policy"
  guardReason: string
  source: "llm" | "deterministic"
}

/** Structured log line streamed to the frontend over SSE. */
export interface LogEvent {
  engagementId: string
  ts: string
  stage: PtesStageId | "system"
  level: "info" | "tool" | "warn" | "error" | "success"
  /** Originating tool/server, e.g. "nmap-mcp" or "orchestrator". */
  source: string
  message: string
}

export type ServerEvent =
  | { type: "log"; data: LogEvent }
  | { type: "stage"; data: { engagementId: string; stage: StageState } }
  | {
      type: "progress"
      data: { engagementId: string; progress: number; status: EngagementStatus }
    }
  | { type: "result"; data: { engagementId: string; engagement: Engagement } }
  | { type: "heartbeat"; data: { ts: string } }
