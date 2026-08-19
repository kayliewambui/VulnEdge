import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  Activity,
  AlertTriangle,
  Binary,
  Brain,
  CheckCircle2,
  Cpu,
  Crosshair,
  Database,
  Fingerprint,
  Globe,
  HardDrive,
  Lock,
  Network,
  Radar,
  Radio,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Swords,
  Terminal,
  Wifi,
  XCircle,
  Zap,
} from "lucide-react"

import { cn } from "@/lib/utils"
import {
  generateAssessment,
  phasesFor,
  PROFILE_META,
  retestAssessment,
} from "@/lib/vapt/generators"
import { downloadReport } from "@/lib/vapt/report"
import type {
  AiConfig,
  AssessmentResult,
  OwaspCategory,
  ScanConfig,
  ScanProfile,
  ScanStatus,
  Severity,
} from "@/lib/vapt/types"
import { ENGAGEMENT_SCOPE } from "@/lib/vapt/scope"
import { describeTargetKind, validateTarget } from "@/lib/vapt/validation"
import { loadSettings, saveSettings } from "@/lib/api/client"
import type { Aggression, BridgeSettings } from "@/lib/api/types"
import {
  useBridgeHealth,
  useEngagementStream,
  useStartEngagement,
} from "@/lib/api/useEngagement"
import TargetSpecificationPanel from "@/components/home/dashboard/TargetSpecificationPanel"
import VulnerabilityDashboard from "@/components/home/dashboard/VulnerabilityDashboard"
import { LiveConsole } from "@/components/home/dashboard/LiveConsole"
import { SettingsModal } from "@/components/home/settings/SettingsModal"
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Progress,
  ScrollArea,
  Separator,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  useToast,
} from "@/components/home/ui"

/* --------------------------------------------------------------- defaults */

const DEFAULT_AI: AiConfig = {
  aiPrioritisation: true,
  exploitChaining: true,
  threatFeedEnrichment: true,
  falsePositiveFiltering: true,
  remediationSynthesis: true,
}

/** Wall-clock duration of the simulated run, per profile. */
const SIMULATED_DURATION_MS: Record<ScanProfile, number> = {
  rapid: 6_000,
  comprehensive: 10_500,
  pentest: 14_000,
}

const TICK_MS = 90

const THREAT_TICKER =
  "CVE-2021-44228 Log4Shell — actively exploited · CVE-2024-3094 xz backdoor — supply chain · Ransomware affiliates targeting exposed RDP · CISA KEV catalogue updated · Credential stuffing volume up across SSO portals · CVE-2023-44487 HTTP/2 Rapid Reset — mitigate at the edge · "

/* ------------------------------------------------------------- severity UI */

const SEVERITY_TEXT: Record<Severity, string> = {
  Critical: "text-red-400",
  High: "text-orange-400",
  Medium: "text-yellow-400",
  Low: "text-blue-400",
  Info: "text-slate-400",
}

const SEVERITY_CHIP: Record<Severity, string> = {
  Critical: "border-red-500/40 bg-red-500/15 text-red-300",
  High: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  Medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-300",
  Low: "border-blue-500/40 bg-blue-500/15 text-blue-300",
  Info: "border-slate-500/40 bg-slate-500/15 text-slate-300",
}

/* ------------------------------------------------------------------ header */

function SystemStatusPopover({ status }: { status: ScanStatus }) {
  const services = [
    { name: "Scan Orchestrator", state: "operational", latency: "12ms" },
    { name: "CVE Correlation DB", state: "operational", latency: "34ms" },
    { name: "Threat Feed Ingest", state: "operational", latency: "88ms" },
    { name: "AI Inference Engine", state: "operational", latency: "146ms" },
    { name: "Report Renderer", state: "operational", latency: "9ms" },
  ]

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="tactical" size="sm" className="gap-2">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          <span className="hidden sm:inline">System Status</span>
        </Button>
      </PopoverTrigger>

      <PopoverContent align="end" className="w-72 glass-strong">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold">Platform Health</p>
            <Badge variant="success" className="font-mono text-[10px]">
              ALL SYSTEMS GO
            </Badge>
          </div>

          <Separator className="bg-slate-800" />

          <ul className="space-y-2">
            {services.map((service) => (
              <li
                key={service.name}
                className="flex items-center justify-between text-xs"
              >
                <span className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  {service.name}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {service.latency}
                </span>
              </li>
            ))}
          </ul>

          <Separator className="bg-slate-800" />

          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Scan engine</span>
            <span
              className={cn(
                "font-mono uppercase",
                status === "running" ? "text-primary" : "text-muted-foreground"
              )}
            >
              {status}
            </span>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}

function SecurityProfileMenu({
  profile,
  onChange,
  disabled,
}: {
  profile: ScanProfile
  onChange: (p: ScanProfile) => void
  disabled: boolean
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="tactical" size="sm" className="gap-2" disabled={disabled}>
          <ShieldCheck className="h-4 w-4" />
          <span className="hidden sm:inline">Security Profile</span>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-72 glass-strong">
        <DropdownMenuLabel>Assessment Profile</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {(["rapid", "comprehensive", "pentest"] as ScanProfile[]).map((key) => (
          <DropdownMenuItem
            key={key}
            onSelect={() => onChange(key)}
            className="flex-col items-start gap-0.5 py-2"
          >
            <span className="flex w-full items-center justify-between">
              <span className="font-medium">{PROFILE_META[key].label}</span>
              {profile === key && <CheckCircle2 className="h-3.5 w-3.5 text-primary" />}
            </span>
            <span className="text-[11px] text-muted-foreground">
              {PROFILE_META[key].blurb}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function AiEngineHoverCard({ ai }: { ai: AiConfig }) {
  const active = Object.values(ai).filter(Boolean).length
  const total = Object.keys(ai).length

  return (
    <HoverCard>
      <HoverCardTrigger asChild>
        <Button variant="tactical" size="sm" className="gap-2">
          <Brain className="h-4 w-4 animate-pulse" />
          <span className="hidden sm:inline">AI Engine</span>
          <Badge variant="success" className="font-mono text-[9px]">
            {active}/{total}
          </Badge>
        </Button>
      </HoverCardTrigger>

      <HoverCardContent align="end" className="w-80 glass-strong">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-primary" />
            <p className="text-sm font-semibold">Correlation Engine</p>
          </div>

          <p className="text-xs leading-relaxed text-muted-foreground">
            Findings are scored for practical exploitability, filtered for
            probable false positives, and chained into attack paths before they
            reach the dashboard.
          </p>

          <Separator className="bg-slate-800" />

          <ul className="space-y-1.5 text-xs">
            {(
              [
                ["Exploitability prioritisation", ai.aiPrioritisation],
                ["Attack path chaining", ai.exploitChaining],
                ["Threat feed enrichment", ai.threatFeedEnrichment],
                ["False positive suppression", ai.falsePositiveFiltering],
                ["Remediation synthesis", ai.remediationSynthesis],
              ] as Array<[string, boolean]>
            ).map(([label, enabled]) => (
              <li key={label} className="flex items-center justify-between">
                <span className={enabled ? "" : "text-muted-foreground"}>
                  {label}
                </span>
                {enabled ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-primary" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-slate-600" />
                )}
              </li>
            ))}
          </ul>
        </div>
      </HoverCardContent>
    </HoverCard>
  )
}

function Header({
  status,
  profile,
  ai,
  onProfileChange,
  liveMode,
  bridgeOnline,
  onOpenSettings,
}: {
  status: ScanStatus
  profile: ScanProfile
  ai: AiConfig
  onProfileChange: (p: ScanProfile) => void
  liveMode: boolean
  bridgeOnline: boolean
  onOpenSettings: () => void
}) {
  return (
    <header className="relative overflow-hidden border-b border-slate-800/80">
      {/* Radial glow field */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "radial-gradient(600px circle at 15% 0%, hsl(160 84% 39% / 0.22), transparent 60%), radial-gradient(700px circle at 85% 20%, hsl(258 90% 66% / 0.18), transparent 60%)",
        }}
      />
      <div className="pointer-events-none absolute inset-0 scan-grid opacity-30" />
      {status === "running" && <div className="scan-beam animate-scan-beam" />}

      <div className="container relative flex flex-wrap items-center justify-between gap-4 py-5">
        <div className="flex items-center gap-3">
          <div className="relative flex h-11 w-11 items-center justify-center rounded-lg border border-primary/40 bg-gradient-to-br from-emerald-500/20 to-emerald-900/20">
            <Shield
              className={cn(
                "h-6 w-6 text-primary",
                status === "running" ? "animate-pulse" : "animate-float"
              )}
            />
            {status === "running" && (
              <span className="pulse-ring absolute inset-0 rounded-lg" />
            )}
          </div>

          <div>
            <h1 className="flex items-baseline gap-2 text-2xl font-extrabold tracking-tight">
              <span className="gradient-text">VulnEdge</span>
              <span className="hidden font-mono text-[10px] font-normal uppercase tracking-[0.2em] text-muted-foreground sm:inline">
                v1.0
              </span>
            </h1>
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              AI-Powered Vulnerability Assessment &amp; Penetration Testing
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Badge
            variant={liveMode ? (bridgeOnline ? "success" : "destructive") : "outline"}
            className="gap-1 font-mono text-[10px] uppercase"
          >
            {liveMode ? (
              bridgeOnline ? (
                <Wifi className="h-3 w-3" />
              ) : (
                <XCircle className="h-3 w-3" />
              )
            ) : (
              <Cpu className="h-3 w-3" />
            )}
            {liveMode ? (bridgeOnline ? "Live bridge" : "Bridge offline") : "Simulation"}
          </Badge>
          <SystemStatusPopover status={status} />
          <SecurityProfileMenu
            profile={profile}
            onChange={onProfileChange}
            disabled={status === "running"}
          />
          <AiEngineHoverCard ai={ai} />
          <Button variant="tactical" size="icon" onClick={onOpenSettings} title="Settings">
            <Settings className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  )
}

/* ------------------------------------------------------- recon tab panels */

function ReconTab({ result }: { result: AssessmentResult | null }) {
  if (!result) {
    return (
      <PlaceholderPanel
        icon={Radar}
        title="No reconnaissance data"
        body="Run an assessment to enumerate subdomains, DNS records, open ports, TLS posture and OS fingerprint."
      />
    )
  }

  const { recon } = result
  const liveSubdomains = recon.subdomains.filter((s) => s.status === "live")
  const openPorts = recon.openPorts.filter((p) => p.state === "open")

  return (
    <div className="space-y-4">
      {/* Summary strip */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <MiniStat
          icon={Globe}
          label="Subdomains"
          value={`${liveSubdomains.length}/${recon.subdomains.length}`}
          hint="Live of total discovered"
        />
        <MiniStat
          icon={Network}
          label="Open ports"
          value={String(openPorts.length)}
          hint="Confirmed listening services"
        />
        <MiniStat
          icon={Lock}
          label="TLS grade"
          value={recon.ssl.grade}
          tone={
            recon.ssl.grade.startsWith("A")
              ? "primary"
              : recon.ssl.grade === "B"
                ? "warn"
                : "danger"
          }
        />
        <MiniStat
          icon={Fingerprint}
          label="OS confidence"
          value={`${recon.os.accuracy}%`}
          hint={recon.os.osVersion}
        />
      </div>

      {/* WHOIS / infrastructure */}
      <Card className="glass-panel border-slate-800">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Database className="h-4 w-4 text-primary" />
            Registration &amp; Infrastructure
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <InfoCell label="Registrar" value={recon.whois.registrar} />
          <InfoCell label="Registered" value={recon.whois.created} />
          <InfoCell label="Expires" value={recon.whois.expires} />
          <InfoCell label="ASN" value={recon.whois.asn} />
          <div className="sm:col-span-2 lg:col-span-4">
            <p className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
              Detected technologies
            </p>
            <div className="flex flex-wrap gap-1.5">
              {recon.technologies.map((tech) => (
                <Badge key={tech} variant="outline" className="font-mono text-[10px]">
                  {tech}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Subdomains */}
      <Card className="glass-panel border-slate-800">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Globe className="h-4 w-4 text-primary" />
            Subdomain Discovery
          </CardTitle>
          <CardDescription className="text-xs">
            Enumerated via certificate transparency logs and passive DNS.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="max-h-[340px]">
            <Table>
              <TableHeader>
                <TableRow className="border-slate-800 hover:bg-transparent">
                  <TableHead className="text-[10px] uppercase">Subdomain</TableHead>
                  <TableHead className="text-[10px] uppercase">Address</TableHead>
                  <TableHead className="text-[10px] uppercase">State</TableHead>
                  <TableHead className="text-[10px] uppercase">Technology</TableHead>
                  <TableHead className="text-right text-[10px] uppercase">
                    Risk
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recon.subdomains.map((sub) => (
                  <TableRow key={sub.name} className="border-slate-800/60">
                    <TableCell className="py-2 font-mono text-xs">
                      {sub.name}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-xs text-muted-foreground">
                      {sub.ip}
                    </TableCell>
                    <TableCell className="py-2">
                      <span
                        className={cn(
                          "flex items-center gap-1.5 font-mono text-[10px] uppercase",
                          sub.status === "live"
                            ? "text-emerald-400"
                            : "text-slate-600"
                        )}
                      >
                        <span
                          className={cn(
                            "h-1.5 w-1.5 rounded-full",
                            sub.status === "live"
                              ? "bg-emerald-500"
                              : "bg-slate-600"
                          )}
                        />
                        {sub.status}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground">
                      {sub.technology}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <Badge
                        className={cn(
                          "font-mono text-[10px]",
                          SEVERITY_CHIP[sub.risk]
                        )}
                      >
                        {sub.risk}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* DNS */}
        <Card className="glass-panel border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Radio className="h-4 w-4 text-primary" />
              DNS Records
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[300px]">
              <ul className="space-y-1.5">
                {recon.dnsRecords.map((record, i) => (
                  <li
                    key={`${record.type}-${record.name}-${i}`}
                    className="rounded-md border border-slate-800 bg-slate-900/40 p-2"
                  >
                    <div className="flex items-center gap-2">
                      <Badge
                        variant="outline"
                        className="w-14 justify-center font-mono text-[10px]"
                      >
                        {record.type}
                      </Badge>
                      <span className="truncate font-mono text-[11px] text-slate-300">
                        {record.name}
                      </span>
                      <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground">
                        TTL {record.ttl}
                      </span>
                    </div>
                    <p className="mt-1 break-all pl-16 font-mono text-[10px] text-muted-foreground">
                      {record.value}
                    </p>
                  </li>
                ))}
              </ul>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Ports */}
        <Card className="glass-panel border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Server className="h-4 w-4 text-primary" />
              Open Ports &amp; Service Banners
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[300px]">
              <ul className="space-y-1.5">
                {recon.openPorts.map((port) => (
                  <li
                    key={`${port.port}-${port.protocol}`}
                    className={cn(
                      "rounded-md border bg-slate-900/40 p-2",
                      port.risk === "Critical" || port.risk === "High"
                        ? "border-red-500/25"
                        : "border-slate-800"
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-16 font-mono text-xs font-bold text-primary">
                        {port.port}/{port.protocol}
                      </span>
                      <span className="font-mono text-[11px] text-slate-300">
                        {port.service}
                      </span>
                      <Badge
                        variant="outline"
                        className="ml-auto font-mono text-[9px] uppercase"
                      >
                        {port.state}
                      </Badge>
                      <Badge
                        className={cn(
                          "font-mono text-[9px]",
                          SEVERITY_CHIP[port.risk]
                        )}
                      >
                        {port.risk}
                      </Badge>
                    </div>
                    <p className="mt-1 truncate pl-16 font-mono text-[10px] text-muted-foreground">
                      {port.banner}
                    </p>
                  </li>
                ))}
              </ul>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* TLS */}
        <Card className="glass-panel border-slate-800">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Lock className="h-4 w-4 text-primary" />
                SSL / TLS Assessment
              </CardTitle>
              <div
                className={cn(
                  "flex h-10 w-10 items-center justify-center rounded-lg border font-mono text-lg font-bold",
                  recon.ssl.grade.startsWith("A")
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    : recon.ssl.grade === "B"
                      ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
                      : "border-red-500/40 bg-red-500/10 text-red-400"
                )}
              >
                {recon.ssl.grade}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2">
              <InfoCell label="Protocol" value={recon.ssl.protocol} />
              <InfoCell label="Cipher suite" value={recon.ssl.cipherSuite} />
              <InfoCell label="Key exchange" value={recon.ssl.keyExchange} />
              <InfoCell label="Issuer" value={recon.ssl.certificateIssuer} />
              <InfoCell
                label="Expiry"
                value={`${recon.ssl.certificateExpiry} (${recon.ssl.daysUntilExpiry}d)`}
                tone={recon.ssl.daysUntilExpiry < 30 ? "danger" : undefined}
              />
              <InfoCell
                label="Weak protocols"
                value={
                  recon.ssl.weakProtocols.length
                    ? recon.ssl.weakProtocols.join(", ")
                    : "None"
                }
                tone={recon.ssl.weakProtocols.length ? "danger" : undefined}
              />
            </div>

            <div className="flex flex-wrap gap-2">
              <FeatureChip label="HSTS" enabled={recon.ssl.hsts} />
              <FeatureChip label="OCSP stapling" enabled={recon.ssl.ocspStapling} />
              <FeatureChip
                label="Forward secrecy"
                enabled={recon.ssl.forwardSecrecy}
              />
            </div>

            <Separator className="bg-slate-800" />

            <ul className="space-y-1">
              {recon.ssl.issues.map((issue) => (
                <li
                  key={issue}
                  className="flex items-start gap-1.5 text-[11px] text-muted-foreground"
                >
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-yellow-500" />
                  {issue}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        {/* OS fingerprint */}
        <Card className="glass-panel border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <HardDrive className="h-4 w-4 text-primary" />
              OS Fingerprinting
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/40 p-3">
              <Binary className="h-8 w-8 shrink-0 text-primary/70" />
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">
                  {recon.os.osVersion}
                </p>
                <p className="font-mono text-[11px] text-muted-foreground">
                  {recon.os.osFamily} · {recon.os.kernel}
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">Detection accuracy</span>
                <span className="font-mono text-primary">
                  {recon.os.accuracy}%
                </span>
              </div>
              <Progress
                value={recon.os.accuracy}
                className="h-1.5 bg-slate-800"
                indicatorClassName="bg-primary"
              />
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <InfoCell label="Device type" value={recon.os.deviceType} />
              <InfoCell label="Uptime estimate" value={recon.os.uptimeGuess} />
              <InfoCell
                label="TTL signature"
                value={String(recon.os.ttlSignature)}
              />
              <InfoCell label="Method" value={recon.os.method} />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

/* -------------------------------------------------------- OWASP tab panel */

function OwaspStatusIcon({ status }: { status: OwaspCategory["status"] }) {
  if (status === "pass")
    return <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
  if (status === "fail")
    return <XCircle className="h-4 w-4 shrink-0 text-red-400" />
  if (status === "warning")
    return <AlertTriangle className="h-4 w-4 shrink-0 text-yellow-400" />
  return <Activity className="h-4 w-4 shrink-0 text-slate-500" />
}

function OwaspTab({ result }: { result: AssessmentResult | null }) {
  if (!result) {
    return (
      <PlaceholderPanel
        icon={ShieldCheck}
        title="No compliance data"
        body="Run an assessment to evaluate the target against all ten OWASP Top 10 2021 categories."
      />
    )
  }

  const { owasp } = result

  return (
    <div className="space-y-4">
      {/* Score header */}
      <Card className="glass-panel relative overflow-hidden border-primary/20">
        <div className="pointer-events-none absolute inset-0 scan-grid opacity-25" />
        <CardContent className="relative grid gap-6 py-6 lg:grid-cols-[auto_1fr]">
          {/* Radial score */}
          <div className="flex items-center justify-center">
            <div className="relative flex h-32 w-32 items-center justify-center">
              <svg className="absolute inset-0 -rotate-90" viewBox="0 0 120 120">
                <circle
                  cx="60"
                  cy="60"
                  r="52"
                  fill="none"
                  stroke="hsl(217 33% 20%)"
                  strokeWidth="10"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="52"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={`${(owasp.compliancePercentage / 100) * 326.7} 326.7`}
                  className={cn(
                    "transition-all duration-1000",
                    owasp.compliancePercentage >= 80
                      ? "text-emerald-500"
                      : owasp.compliancePercentage >= 50
                        ? "text-yellow-500"
                        : "text-red-500"
                  )}
                />
              </svg>
              <div className="text-center">
                <p className="font-mono text-3xl font-bold tabular-nums">
                  {owasp.compliancePercentage}%
                </p>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  Compliant
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h3 className="text-base font-semibold">OWASP Top 10 — 2021</h3>
              <p className="text-xs text-muted-foreground">
                {owasp.passed} passed · {owasp.warnings} warning
                {owasp.warnings === 1 ? "" : "s"} · {owasp.failed} failed. Overall
                control risk rated{" "}
                <span className={SEVERITY_TEXT[owasp.overallRisk]}>
                  {owasp.overallRisk}
                </span>
                .
              </p>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <MiniStat
                icon={CheckCircle2}
                label="Passed"
                value={String(owasp.passed)}
                tone="primary"
              />
              <MiniStat
                icon={AlertTriangle}
                label="Warnings"
                value={String(owasp.warnings)}
                tone="warn"
              />
              <MiniStat
                icon={XCircle}
                label="Failed"
                value={String(owasp.failed)}
                tone="danger"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-[11px] text-muted-foreground">
                <span>Control coverage</span>
                <span className="font-mono">
                  {owasp.passed + owasp.warnings}/10 categories clear or partial
                </span>
              </div>
              <Progress
                value={owasp.compliancePercentage}
                className="h-2 bg-slate-800"
                indicatorClassName={cn(
                  owasp.compliancePercentage >= 80
                    ? "bg-emerald-500"
                    : owasp.compliancePercentage >= 50
                      ? "bg-yellow-500"
                      : "bg-red-500"
                )}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Categories */}
      <div className="grid gap-3 md:grid-cols-2">
        {owasp.categories.map((category) => (
          <Card
            key={category.id}
            className={cn(
              "glass-panel transition-all hover:-translate-y-0.5",
              category.status === "fail"
                ? "border-red-500/30"
                : category.status === "warning"
                  ? "border-yellow-500/30"
                  : "border-slate-800"
            )}
          >
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <OwaspStatusIcon status={category.status} />
                  <span className="font-mono text-primary">{category.id}</span>
                  <span>{category.name}</span>
                </CardTitle>
                <Badge
                  variant="outline"
                  className={cn(
                    "shrink-0 font-mono text-[10px] uppercase",
                    category.status === "fail" && "border-red-500/40 text-red-300",
                    category.status === "warning" &&
                      "border-yellow-500/40 text-yellow-300",
                    category.status === "pass" &&
                      "border-emerald-500/40 text-emerald-300"
                  )}
                >
                  {category.status}
                </Badge>
              </div>
            </CardHeader>

            <CardContent className="space-y-2.5">
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                {category.description}
              </p>

              <div className="space-y-1">
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>
                    {category.findings} finding
                    {category.findings === 1 ? "" : "s"}
                  </span>
                  <span className="font-mono">Risk {category.riskScore}/100</span>
                </div>
                <div className="h-1 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-700",
                      category.riskScore >= 60
                        ? "bg-red-500"
                        : category.riskScore >= 25
                          ? "bg-yellow-500"
                          : "bg-emerald-500"
                    )}
                    style={{ width: `${Math.max(category.riskScore, 2)}%` }}
                  />
                </div>
              </div>

              <div className="rounded-md border border-slate-800 bg-slate-900/40 p-2">
                <p className="mb-1 text-[9px] uppercase tracking-wider text-muted-foreground">
                  Recommendation
                </p>
                <p className="text-[11px] leading-relaxed text-slate-300">
                  {category.recommendation}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

/* ------------------------------------------------- threat intel tab panel */

function ThreatTab({ result }: { result: AssessmentResult | null }) {
  if (!result) {
    return (
      <PlaceholderPanel
        icon={Swords}
        title="No threat intelligence"
        body="Run an assessment to map attack vectors, relevant threat actors and strategic recommendations for this target."
      />
    )
  }

  const { threatIntel } = result

  const levelStyle = {
    Critical: "border-red-500/40 bg-red-500/10 text-red-300",
    Elevated: "border-orange-500/40 bg-orange-500/10 text-orange-300",
    Guarded: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
    Low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  }[threatIntel.threatLevel]

  return (
    <div className="space-y-4">
      {/* Threat level banner */}
      <Card className={cn("glass-panel relative overflow-hidden", levelStyle)}>
        <div className="pointer-events-none absolute inset-0 scan-grid opacity-20" />
        <CardContent className="relative flex flex-wrap items-center gap-6 py-6">
          <div className="flex items-center gap-4">
            <div className="relative flex h-16 w-16 items-center justify-center rounded-full border-2 border-current">
              <Siren className="h-7 w-7 animate-pulse" />
              {threatIntel.threatLevel === "Critical" && (
                <span className="pulse-ring absolute inset-0 rounded-full" />
              )}
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-[0.2em] opacity-80">
                Threat Level
              </p>
              <p className="text-3xl font-extrabold tracking-tight">
                {threatIntel.threatLevel.toUpperCase()}
              </p>
            </div>
          </div>

          <Separator
            orientation="vertical"
            className="hidden h-16 bg-slate-700/60 lg:block"
          />

          <div className="grid flex-1 grid-cols-2 gap-3 sm:grid-cols-3">
            <ScoreRing label="Threat score" value={threatIntel.threatScore} />
            <ScoreRing label="Exposure" value={threatIntel.exposureScore} />
            <div className="flex flex-col justify-center">
              <p className="font-mono text-2xl font-bold tabular-nums">
                {threatIntel.darkWebMentions}
              </p>
              <p className="text-[10px] uppercase tracking-wider opacity-70">
                Dark web mentions
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="glass-panel border-slate-800">
        <CardContent className="py-4">
          <p className="text-sm leading-relaxed text-slate-300">
            {threatIntel.summary}
          </p>
        </CardContent>
      </Card>

      {/* Attack vectors */}
      <Card className="glass-panel border-slate-800">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Crosshair className="h-4 w-4 text-primary" />
            Attack Vectors
          </CardTitle>
          <CardDescription className="text-xs">
            Mapped to MITRE ATT&amp;CK techniques, ordered by relevance to the
            findings.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2">
          {threatIntel.attackVectors.map((vector) => (
            <div
              key={vector.name}
              className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 transition-all hover:-translate-y-0.5 hover:border-slate-700"
            >
              <div className="flex items-start justify-between gap-2">
                <h4 className="text-xs font-semibold leading-snug">
                  {vector.name}
                </h4>
                <Badge variant="outline" className="shrink-0 font-mono text-[9px]">
                  {vector.mitreId}
                </Badge>
              </div>

              <div className="mt-2 flex flex-wrap gap-1.5">
                <Badge
                  variant="outline"
                  className="font-mono text-[9px] uppercase"
                >
                  Likelihood: {vector.likelihood}
                </Badge>
                <Badge
                  className={cn(
                    "font-mono text-[9px] uppercase",
                    SEVERITY_CHIP[vector.impact]
                  )}
                >
                  Impact: {vector.impact}
                </Badge>
              </div>

              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                {vector.description}
              </p>

              <div className="mt-2 rounded border border-slate-800 bg-slate-950/50 p-2">
                <p className="text-[9px] uppercase tracking-wider text-muted-foreground">
                  Mitigation
                </p>
                <p className="mt-0.5 text-[11px] text-slate-300">
                  {vector.mitigation}
                </p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Industry threats */}
      <Card className="glass-panel border-slate-800">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Swords className="h-4 w-4 text-primary" />
            Relevant Threat Actors
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {threatIntel.industryThreats.map((threat) => (
            <div
              key={threat.actor}
              className="rounded-lg border border-slate-800 bg-slate-900/40 p-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <h4 className="text-sm font-semibold">{threat.actor}</h4>
                <Badge
                  variant="outline"
                  className={cn(
                    "font-mono text-[9px] uppercase",
                    threat.sophistication === "Advanced" &&
                      "border-red-500/40 text-red-300",
                    threat.sophistication === "High" &&
                      "border-orange-500/40 text-orange-300"
                  )}
                >
                  {threat.sophistication}
                </Badge>
              </div>

              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                <InfoCell label="Motivation" value={threat.motivation} />
                <InfoCell label="Current activity" value={threat.activity} />
              </div>

              <div className="mt-2">
                <p className="mb-1 text-[9px] uppercase tracking-wider text-muted-foreground">
                  Targeted sectors
                </p>
                <div className="flex flex-wrap gap-1">
                  {threat.targetedSectors.map((sector) => (
                    <Badge
                      key={sector}
                      variant="secondary"
                      className="text-[9px] font-normal"
                    >
                      {sector}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="mt-2">
                <p className="mb-1 text-[9px] uppercase tracking-wider text-muted-foreground">
                  Observed tradecraft
                </p>
                <ul className="space-y-0.5">
                  {threat.ttps.map((ttp) => (
                    <li
                      key={ttp}
                      className="flex items-start gap-1.5 text-[11px] text-muted-foreground"
                    >
                      <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary/60" />
                      {ttp}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Recommendations */}
      <Card className="glass-panel border-primary/20">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldAlert className="h-4 w-4 text-primary" />
            Strategic Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="space-y-2">
            {threatIntel.recommendations.map((rec, i) => (
              <li
                key={rec}
                className="flex items-start gap-3 rounded-md border border-slate-800 bg-slate-900/40 p-2.5"
              >
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded border border-primary/40 bg-primary/10 font-mono text-[10px] text-primary">
                  {i + 1}
                </span>
                <span className="text-xs leading-relaxed text-slate-300">
                  {rec}
                </span>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------------------------------- shared fragments */

function PlaceholderPanel({
  icon: Icon,
  title,
  body,
}: {
  icon: typeof Radar
  title: string
  body: string
}) {
  return (
    <Card className="glass-panel border-slate-800">
      <CardContent className="flex flex-col items-center justify-center gap-3 py-20 text-center">
        <Icon className="h-10 w-10 animate-float text-slate-700" />
        <p className="text-sm font-medium text-slate-300">{title}</p>
        <p className="max-w-md text-xs text-muted-foreground">{body}</p>
      </CardContent>
    </Card>
  )
}

function MiniStat({
  icon: Icon,
  label,
  value,
  hint,
  tone = "neutral",
}: {
  icon: typeof Globe
  label: string
  value: string
  hint?: string
  tone?: "neutral" | "primary" | "warn" | "danger"
}) {
  const toneClass = {
    neutral: "border-slate-800 text-slate-300",
    primary: "border-emerald-500/30 text-emerald-400",
    warn: "border-yellow-500/30 text-yellow-400",
    danger: "border-red-500/30 text-red-400",
  }[tone]

  const tile = (
    <div className={cn("glass rounded-lg border p-3", toneClass)}>
      <div className="flex items-center justify-between">
        <Icon className="h-4 w-4 opacity-80" />
        <span className="font-mono text-xl font-bold tabular-nums">{value}</span>
      </div>
      <p className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
    </div>
  )

  if (!hint) return tile

  return (
    <Tooltip>
      <TooltipTrigger asChild>{tile}</TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  )
}

function InfoCell({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone?: "danger"
}) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-900/40 px-2.5 py-1.5">
      <p className="text-[9px] uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p
        className={cn(
          "break-words font-mono text-[11px]",
          tone === "danger" ? "text-red-400" : "text-slate-300"
        )}
      >
        {value}
      </p>
    </div>
  )
}

function FeatureChip({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <span
      className={cn(
        "flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px]",
        enabled
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
          : "border-red-500/40 bg-red-500/10 text-red-300"
      )}
    >
      {enabled ? (
        <CheckCircle2 className="h-3 w-3" />
      ) : (
        <XCircle className="h-3 w-3" />
      )}
      {label}
    </span>
  )
}

function ScoreRing({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col justify-center">
      <p className="font-mono text-2xl font-bold tabular-nums">{value}</p>
      <p className="text-[10px] uppercase tracking-wider opacity-70">{label}</p>
      <div className="mt-1 h-1 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-current transition-all duration-1000"
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  )
}

/* -------------------------------------------------------------- component */

export default function Home() {
  const { toast } = useToast()

  // --- configuration -----------------------------------------------------
  const [target, setTarget] = useState("")
  const [profile, setProfile] = useState<ScanProfile>("comprehensive")
  const [ai, setAi] = useState<AiConfig>(DEFAULT_AI)
  const [authorized, setAuthorized] = useState(false)

  // --- run state ---------------------------------------------------------
  const [status, setStatus] = useState<ScanStatus>("idle")
  const [progress, setProgress] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [result, setResult] = useState<AssessmentResult | null>(null)
  const [isRetesting, setIsRetesting] = useState(false)
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [tab, setTab] = useState("findings")

  // --- Rules of Engagement (pre-engagement) ------------------------------
  const [aggression, setAggression] = useState<Aggression>("balanced")
  const [authorizationRef, setAuthorizationRef] = useState("")
  const [allowExploitation, setAllowExploitation] = useState(true)

  // --- Backend bridge (live mode) ----------------------------------------
  const [settings, setSettings] = useState<BridgeSettings>(() => loadSettings())
  const [liveMode, setLiveMode] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [liveEngagementId, setLiveEngagementId] = useState<string | null>(null)

  const health = useBridgeHealth(settings, liveMode)
  const bridgeOnline = liveMode && health.isSuccess && Boolean(health.data?.ok)
  const startEngagement = useStartEngagement(settings)
  const live = useEngagementStream(liveMode ? liveEngagementId : null, settings)

  const timerRef = useRef<number | null>(null)
  const startedAtRef = useRef<Date | null>(null)

  const aiEnabled = useMemo(() => Object.values(ai).some(Boolean), [ai])
  const phases = useMemo(() => phasesFor(profile, aiEnabled), [profile, aiEnabled])

  const activePhaseIndex = useMemo(() => {
    let cumulative = 0
    for (let i = 0; i < phases.length; i++) {
      cumulative += phases[i].weight * 100
      if (progress <= cumulative) return i
    }
    return phases.length - 1
  }, [phases, progress])

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  // Never leave an interval running behind an unmounted component.
  useEffect(() => clearTimer, [clearTimer])

  // In live mode, project the streamed engagement onto the canonical UI state
  // (result/status/progress) so every downstream tab, retest, and the PDF
  // report keep working with zero changes.
  useEffect(() => {
    if (!liveMode || !liveEngagementId) return
    if (live.status) {
      const map: Record<string, ScanStatus> = {
        created: "running",
        running: "running",
        completed: "completed",
        aborted: "aborted",
        failed: "aborted",
      }
      setStatus(map[live.status] ?? "idle")
    }
    setProgress(live.progress)
    if (live.engagement?.result) setResult(live.engagement.result)
  }, [liveMode, liveEngagementId, live.status, live.progress, live.engagement])

  // Surface completion / failure as a toast, once.
  const notifiedRef = useRef<string | null>(null)
  useEffect(() => {
    if (!liveMode || !live.engagement) return
    const e = live.engagement
    if (
      (e.status === "completed" || e.status === "failed") &&
      notifiedRef.current !== e.id + e.status
    ) {
      notifiedRef.current = e.id + e.status
      if (e.status === "completed" && e.result) {
        const critical = e.result.vulnerabilities.filter(
          (v) => v.severity === "Critical"
        ).length
        toast({
          variant: critical > 0 ? "destructive" : "success",
          title: "Engagement complete",
          description: `${e.result.vulnerabilities.length} findings · ${critical} critical · risk ${e.result.riskScore}/100`,
        })
      } else if (e.status === "failed") {
        toast({
          variant: "destructive",
          title: "Engagement failed",
          description: e.error ?? "The bridge reported a pipeline error.",
        })
      }
    }
  }, [liveMode, live.engagement, toast])

  const handleSaveSettings = useCallback((next: BridgeSettings) => {
    setSettings(next)
    saveSettings(next)
  }, [])

  const startLiveEngagement = useCallback(
    (normalizedTarget: string, kind: string) => {
      // Auto-include the target host in scope so the common single-target case
      // isn't blocked by the bridge's scope guard; the operator can widen it.
      let host = normalizedTarget
      try {
        if (/^https?:\/\//i.test(normalizedTarget)) host = new URL(normalizedTarget).hostname
      } catch {
        /* keep raw */
      }
      const scope = Array.from(
        new Set([...ENGAGEMENT_SCOPE, normalizedTarget, host])
      )

      setStatus("running")
      setProgress(0)
      setResult(null)
      setTab("findings")
      live.reset()

      startEngagement.mutate(
        {
          target: normalizedTarget,
          profile,
          aggression,
          authorizationRef: authorizationRef.trim() || "unspecified",
          scope,
          allowExploitation,
        },
        {
          onSuccess: (engagement) => {
            setLiveEngagementId(engagement.id)
            toast({
              title: "Engagement dispatched",
              description: `${PROFILE_META[profile].label} · ${kind} · bridge id ${engagement.id.slice(0, 8)}`,
            })
          },
          onError: (err) => {
            setStatus("aborted")
            toast({
              variant: "destructive",
              title: "Bridge rejected the engagement",
              description: err instanceof Error ? err.message : "Unknown error.",
            })
          },
        }
      )
    },
    [aggression, allowExploitation, authorizationRef, live, profile, startEngagement, toast]
  )

  const handleStart = useCallback(() => {
    const validation = validateTarget(target)

    if (!validation.valid) {
      toast({
        variant: "destructive",
        title: "Invalid target",
        description: validation.error ?? "Provide a valid IP, CIDR, domain or URL.",
      })
      return
    }

    if (!authorized) {
      toast({
        variant: "warning",
        title: "Authorisation required",
        description:
          "Confirm you are authorised to assess this target before starting.",
      })
      return
    }

    // ── Live backend path ────────────────────────────────────────────────
    if (liveMode) {
      if (!bridgeOnline) {
        toast({
          variant: "destructive",
          title: "Bridge offline",
          description: "Cannot reach the backend. Check Settings → bridge connection.",
        })
        return
      }
      startLiveEngagement(validation.normalized, describeTargetKind(validation.kind))
      return
    }

    clearTimer()

    const startedAt = new Date()
    startedAtRef.current = startedAt

    setStatus("running")
    setProgress(0)
    setElapsed(0)
    setResult(null)
    setTab("findings")

    const duration = SIMULATED_DURATION_MS[profile]
    const config: ScanConfig = {
      target: validation.normalized,
      profile,
      ai,
    }

    toast({
      title: "Assessment initiated",
      description: `${PROFILE_META[profile].label} against ${validation.normalized}`,
    })

    timerRef.current = window.setInterval(() => {
      const runningFor = Date.now() - startedAt.getTime()
      const pct = Math.min(100, (runningFor / duration) * 100)

      setProgress(pct)
      setElapsed(Math.floor(runningFor / 1000))

      if (pct >= 100) {
        clearTimer()

        const completedAt = new Date()
        const assessment = generateAssessment(
          config,
          validation.kind!,
          startedAt,
          completedAt
        )

        setResult(assessment)
        setStatus("completed")

        const critical = assessment.vulnerabilities.filter(
          (v) => v.severity === "Critical"
        ).length

        toast({
          variant: critical > 0 ? "destructive" : "success",
          title: "Assessment complete",
          description: `${assessment.vulnerabilities.length} findings · ${critical} critical · risk score ${assessment.riskScore}/100`,
        })
      }
    }, TICK_MS)
  }, [ai, authorized, clearTimer, profile, target, toast])

  const handleAbort = useCallback(() => {
    clearTimer()
    setStatus("aborted")
    setProgress(0)
    setElapsed(0)

    if (liveMode) {
      // Detach from the server-side engagement. It continues on the bridge but
      // the console stops following it.
      setLiveEngagementId(null)
      live.reset()
      toast({
        variant: "warning",
        title: "Detached from engagement",
        description: "Stopped following the bridge engagement (it may still be running server-side).",
      })
      return
    }

    toast({
      variant: "warning",
      title: "Assessment aborted",
      description: "The scan was stopped before completion. No results recorded.",
    })
  }, [clearTimer, live, liveMode, toast])

  const handleRetest = useCallback(() => {
    if (!result) return

    setIsRetesting(true)

    // Give the UI a beat so the spinner is visible for a real interaction.
    window.setTimeout(() => {
      const retested = retestAssessment(result)
      setResult(retested)
      setIsRetesting(false)

      const fixed = retested.vulnerabilities.filter(
        (v) => v.retestStatus === "remediated"
      ).length
      const open = retested.vulnerabilities.length - fixed

      toast({
        variant: open === 0 ? "success" : "default",
        title: "Retest complete",
        description: `${fixed} remediated · ${open} still present · risk score now ${retested.riskScore}/100`,
      })
    }, 1400)
  }, [result, toast])

  const handleGenerateReport = useCallback(async () => {
    if (!result) return

    setIsGeneratingReport(true)

    try {
      // jspdf is code-split — the first report pays a short load, then it is cached.
      const filename = await downloadReport(result)
      toast({
        variant: "success",
        title: "Report generated",
        description: filename,
      })
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Report generation failed",
        description:
          error instanceof Error
            ? error.message
            : "Unexpected error building the PDF.",
      })
    } finally {
      setIsGeneratingReport(false)
    }
  }, [result, toast])

  const validation = useMemo(() => validateTarget(target), [target])

  return (
    <div className="min-h-screen bg-background">
      <Header
        status={status}
        profile={profile}
        ai={ai}
        onProfileChange={setProfile}
        liveMode={liveMode}
        bridgeOnline={bridgeOnline}
        onOpenSettings={() => setSettingsOpen(true)}
      />

      <SettingsModal
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        settings={settings}
        onSave={handleSaveSettings}
        liveMode={liveMode}
        onLiveModeChange={setLiveMode}
      />

      {/* ------------------------------------------------------ ticker ---- */}
      <div className="border-b border-slate-800/60 bg-slate-950/40">
        <div className="container flex items-center gap-3 py-1.5">
          <Badge variant="outline" className="shrink-0 gap-1 font-mono text-[9px]">
            <Wifi className="h-2.5 w-2.5 text-primary" />
            LIVE
          </Badge>
          {/* Two copies so the -50% translation loops seamlessly. */}
          <div className="no-scrollbar flex overflow-hidden">
            <div className="flex shrink-0 animate-marquee">
              <span className="whitespace-nowrap font-mono text-[10px] text-muted-foreground">
                {THREAT_TICKER}
              </span>
              <span
                aria-hidden
                className="whitespace-nowrap font-mono text-[10px] text-muted-foreground"
              >
                {THREAT_TICKER}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------- layout ---- */}
      <main className="container py-6">
        <div className="grid gap-6 lg:grid-cols-[400px_1fr]">
          {/* Left column — configuration */}
          <div className="space-y-4 lg:sticky lg:top-6 lg:self-start">
            <TargetSpecificationPanel
              target={target}
              onTargetChange={setTarget}
              profile={profile}
              onProfileChange={setProfile}
              ai={ai}
              onAiChange={setAi}
              authorized={authorized}
              onAuthorizedChange={setAuthorized}
              status={status}
              onStart={handleStart}
              onAbort={handleAbort}
              liveMode={liveMode}
              aggression={aggression}
              onAggressionChange={setAggression}
              authorizationRef={authorizationRef}
              onAuthorizationRefChange={setAuthorizationRef}
              allowExploitation={allowExploitation}
              onAllowExploitationChange={setAllowExploitation}
            />

            {/* Engagement summary */}
            {validation.valid && (
              <Card className="glass-panel border-slate-800">
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                    <Terminal className="h-3.5 w-3.5" />
                    Engagement
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-1.5 font-mono text-[11px]">
                  <Row label="target" value={validation.normalized} />
                  <Row label="class" value={describeTargetKind(validation.kind)} />
                  <Row label="profile" value={PROFILE_META[profile].label} />
                  <Row
                    label="ai_modules"
                    value={`${Object.values(ai).filter(Boolean).length}/5 enabled`}
                  />
                  <Row label="phases" value={String(phases.length)} />
                  <Row
                    label="status"
                    value={status}
                    valueClass={
                      status === "running"
                        ? "text-primary"
                        : status === "completed"
                          ? "text-emerald-400"
                          : status === "aborted"
                            ? "text-red-400"
                            : "text-muted-foreground"
                    }
                  />
                </CardContent>
              </Card>
            )}

            {/* Legal notice */}
            <Card className="border-yellow-600/30 bg-yellow-500/5">
              <CardContent className="flex gap-2.5 py-3">
                <ShieldAlert className="h-4 w-4 shrink-0 text-yellow-500" />
                <p className="text-[11px] leading-relaxed text-yellow-200/80">
                  {liveMode
                    ? "Live mode drives the backend bridge (PTES/MCP). The bridge enforces scope allow-listing, per-engagement authorization, and safe-mode — but you remain responsible: only run against systems you own or have written permission to test."
                    : "Simulation mode runs entirely in the browser — no packets are sent to any target. Switch to live mode in Settings to drive the backend bridge against authorized targets."}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Right column — results */}
          <div className="min-w-0">
            <Tabs value={tab} onValueChange={setTab} className="space-y-4">
              <TabsList className="grid w-full grid-cols-4 bg-slate-900/60">
                <TabsTrigger value="findings" className="gap-1.5 text-xs">
                  <Zap className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Findings</span>
                  {result && (
                    <Badge
                      variant="secondary"
                      className="ml-1 h-4 px-1.5 text-[9px]"
                    >
                      {result.vulnerabilities.length}
                    </Badge>
                  )}
                </TabsTrigger>

                <TabsTrigger value="recon" className="gap-1.5 text-xs">
                  <Radar className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Recon</span>
                </TabsTrigger>

                <TabsTrigger value="owasp" className="gap-1.5 text-xs">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">OWASP</span>
                  {result && (
                    <Badge
                      variant="secondary"
                      className="ml-1 h-4 px-1.5 text-[9px]"
                    >
                      {result.owasp.compliancePercentage}%
                    </Badge>
                  )}
                </TabsTrigger>

                <TabsTrigger value="threat" className="gap-1.5 text-xs">
                  <Swords className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Threats</span>
                </TabsTrigger>
              </TabsList>

              <TabsContent value="findings" className="mt-0 space-y-4">
                {/* Live mode streams real PTES tool output; simulation mode
                    uses the local phase timer inside the dashboard. */}
                {liveMode && (status === "running" || live.logs.length > 0) && (
                  <LiveConsole
                    engagement={live.engagement}
                    logs={live.logs}
                    connected={live.connected}
                    progress={progress}
                    running={status === "running"}
                  />
                )}
                <VulnerabilityDashboard
                  status={liveMode ? (result ? "completed" : "idle") : status}
                  progress={progress}
                  phases={phases}
                  activePhaseIndex={activePhaseIndex}
                  elapsed={elapsed}
                  target={target}
                  result={result}
                  isRetesting={isRetesting}
                  isGeneratingReport={isGeneratingReport}
                  onRetest={handleRetest}
                  onGenerateReport={handleGenerateReport}
                />
              </TabsContent>

              <TabsContent value="recon" className="mt-0">
                <ReconTab result={result} />
              </TabsContent>

              <TabsContent value="owasp" className="mt-0">
                <OwaspTab result={result} />
              </TabsContent>

              <TabsContent value="threat" className="mt-0">
                <ThreatTab result={result} />
              </TabsContent>
            </Tabs>
          </div>
        </div>
      </main>

      <footer className="border-t border-slate-800/60 py-6">
        <div className="container flex flex-wrap items-center justify-between gap-3 text-[11px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5 text-primary" />
            VulnEdge — AI-Powered VAPT Platform
          </span>
          <span className="font-mono">
            PTES · OWASP WSTG · NIST SP 800-115 aligned
          </span>
        </div>
      </footer>
    </div>
  )
}

function Row({
  label,
  value,
  valueClass,
}: {
  label: string
  value: string
  valueClass?: string
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className={cn("truncate text-right text-slate-300", valueClass)}>
        {value}
      </span>
    </div>
  )
}
