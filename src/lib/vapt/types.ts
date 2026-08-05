/**
 * Core domain types for the VulnEdge assessment engine.
 *
 * NOTE: this build simulates an assessment run locally. No packets leave the
 * browser. Findings are synthesised deterministically from the target string
 * so the same target always produces the same report.
 */

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info"

export type TargetKind = "ipv4" | "ipv6" | "domain" | "url" | "cidr"

export type ScanProfile = "rapid" | "comprehensive" | "pentest"

export type ScanStatus =
  | "idle"
  | "running"
  | "paused"
  | "completed"
  | "aborted"

export interface TargetValidation {
  valid: boolean
  kind: TargetKind | null
  normalized: string
  /** Hard failure — blocks the scan. */
  error?: string
  /** Non-blocking advisory (e.g. loopback, RFC1918, reserved range). */
  warning?: string
}

export interface AiConfig {
  /** Rank findings by exploitability using the correlation model. */
  aiPrioritisation: boolean
  /** Attempt to chain findings into multi-step attack paths. */
  exploitChaining: boolean
  /** Cross-reference findings against live threat feeds. */
  threatFeedEnrichment: boolean
  /** Suppress findings the model scores as probable false positives. */
  falsePositiveFiltering: boolean
  /** Generate remediation code snippets alongside each finding. */
  remediationSynthesis: boolean
}

export interface ScanConfig {
  target: string
  profile: ScanProfile
  ai: AiConfig
  /** Operator-supplied authorisation reference for the engagement. */
  authorizationRef?: string
}

export interface ScanPhase {
  id: string
  label: string
  detail: string
  /** Fraction of total scan duration this phase occupies. */
  weight: number
}

export interface Evidence {
  request?: string
  response?: string
  note?: string
}

export interface Vulnerability {
  id: string
  title: string
  severity: Severity
  cvss: number
  cvssVector: string
  cve?: string
  cwe: string
  owasp: string
  category: string
  affectedComponent: string
  port?: number
  description: string
  impact: string
  remediation: string
  /** 0–100. How sure the engine is this is not a false positive. */
  confidence: number
  /** 0–100. Model-scored likelihood of practical exploitation. */
  exploitability: number
  exploitAvailable: boolean
  references: string[]
  evidence?: Evidence
  /** Set after a retest run. */
  retestStatus?: "unverified" | "still-present" | "remediated"
  discoveredAt: string
}

export interface Subdomain {
  name: string
  ip: string
  status: "live" | "inactive"
  technology: string
  risk: Severity
}

export interface DnsRecord {
  type: "A" | "AAAA" | "MX" | "NS" | "TXT" | "CNAME" | "SOA" | "CAA"
  name: string
  value: string
  ttl: number
}

export interface OpenPort {
  port: number
  protocol: "tcp" | "udp"
  state: "open" | "filtered" | "open|filtered"
  service: string
  version: string
  banner: string
  risk: Severity
}

export interface SslAssessment {
  grade: "A+" | "A" | "B" | "C" | "D" | "F"
  protocol: string
  cipherSuite: string
  keyExchange: string
  certificateIssuer: string
  certificateExpiry: string
  daysUntilExpiry: number
  hsts: boolean
  ocspStapling: boolean
  forwardSecrecy: boolean
  weakProtocols: string[]
  issues: string[]
}

export interface OsFingerprint {
  osFamily: string
  osVersion: string
  kernel: string
  accuracy: number
  deviceType: string
  uptimeGuess: string
  ttlSignature: number
  method: string
}

export interface ReconResult {
  subdomains: Subdomain[]
  dnsRecords: DnsRecord[]
  openPorts: OpenPort[]
  ssl: SslAssessment
  os: OsFingerprint
  whois: { registrar: string; created: string; expires: string; asn: string }
  technologies: string[]
}

export interface OwaspCategory {
  id: string
  name: string
  description: string
  status: "pass" | "fail" | "warning" | "not-applicable"
  findings: number
  riskScore: number
  recommendation: string
}

export interface OwaspCompliance {
  categories: OwaspCategory[]
  compliancePercentage: number
  passed: number
  failed: number
  warnings: number
  overallRisk: Severity
}

export interface AttackVector {
  name: string
  likelihood: "Very High" | "High" | "Medium" | "Low"
  impact: Severity
  description: string
  mitigation: string
  mitreId: string
}

export interface IndustryThreat {
  actor: string
  motivation: string
  sophistication: "Low" | "Medium" | "High" | "Advanced"
  targetedSectors: string[]
  ttps: string[]
  activity: string
}

export interface ThreatIntelligence {
  threatLevel: "Critical" | "Elevated" | "Guarded" | "Low"
  threatScore: number
  summary: string
  attackVectors: AttackVector[]
  industryThreats: IndustryThreat[]
  recommendations: string[]
  exposureScore: number
  darkWebMentions: number
}

export interface AssessmentResult {
  target: string
  targetKind: TargetKind
  profile: ScanProfile
  startedAt: string
  completedAt: string
  durationSeconds: number
  vulnerabilities: Vulnerability[]
  recon: ReconResult
  owasp: OwaspCompliance
  threatIntel: ThreatIntelligence
  riskScore: number
}

export const SEVERITY_ORDER: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
]

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 10,
  High: 6,
  Medium: 3,
  Low: 1,
  Info: 0,
}
