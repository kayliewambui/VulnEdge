import type { AssessmentResult } from "@/lib/vapt/types"

/**
 * Frontend mirror of the bridge's wire types. Kept as a small standalone copy
 * (rather than importing across the package boundary) so the frontend builds
 * without the backend present — the two are wired by HTTP, not by imports.
 */

export type Aggression = "stealth" | "balanced" | "aggressive"

export interface RulesOfEngagement {
  aggression: Aggression
  authorizationRef: string
  scope: string[]
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

export interface ExploitPlanItem {
  vulnerabilityId: string
  title: string
  technique: string
  mitreId?: string
  proposedCommand: string
  rationale: string
  executed: boolean
  verified?: boolean
  verificationOutput?: string
  guardVerdict: "allowed" | "allowed-verification" | "blocked-safe-mode" | "blocked-policy"
  guardReason: string
  source: "llm" | "deterministic"
}

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
  exploitPlan: ExploitPlanItem[]
  error?: string
}

export interface BridgeHealth {
  ok: boolean
  service: string
  version: string
  safeMode: boolean
  activeExploitPermitted: boolean
  provider: "simulation" | "mcp"
  mcpAvailable: boolean
  mcpServers: { name: string; capability: string }[]
  llm: string
  authRequired: boolean
}

export interface LogEvent {
  engagementId: string
  ts: string
  stage: PtesStageId | "system"
  level: "info" | "tool" | "warn" | "error" | "success"
  source: string
  message: string
}

/** Client-side connection config, persisted in localStorage via Settings. */
export interface BridgeSettings {
  baseUrl: string
  token: string
  /** API keys the operator wants forwarded to MCP servers (never logged). */
  shodanApiKey: string
  hunterApiKey: string
}

export const DEFAULT_SETTINGS: BridgeSettings = {
  baseUrl: "http://localhost:8787",
  token: "",
  shodanApiKey: "",
  hunterApiKey: "",
}
