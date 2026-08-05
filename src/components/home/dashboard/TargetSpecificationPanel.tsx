import { useMemo } from "react"
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  Crosshair,
  Gauge,
  Layers,
  Link2,
  Loader2,
  Radar,
  ShieldAlert,
  Sparkles,
  Square,
  Target,
  Zap,
} from "lucide-react"

import { EyeOff, Skull, Wind } from "lucide-react"

import { cn } from "@/lib/utils"
import { PROFILE_META } from "@/lib/vapt/generators"
import type { AiConfig, ScanProfile, ScanStatus } from "@/lib/vapt/types"
import type { Aggression } from "@/lib/api/types"
import {
  describeTargetKind,
  validateTarget,
} from "@/lib/vapt/validation"
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  Switch,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/home/ui"

const AGGRESSION_OPTIONS: Array<{
  value: Aggression
  label: string
  hint: string
  icon: typeof Wind
}> = [
  {
    value: "stealth",
    label: "Stealth",
    hint: "Low-and-slow. Passive recon, throttled probes, timing evasion.",
    icon: EyeOff,
  },
  {
    value: "balanced",
    label: "Balanced",
    hint: "Standard-rate active scanning. The usual engagement default.",
    icon: Wind,
  },
  {
    value: "aggressive",
    label: "Aggressive",
    hint: "Full-rate, deep enumeration. Noisy — only where disruption is acceptable.",
    icon: Skull,
  },
]

const AI_OPTIONS: Array<{
  key: keyof AiConfig
  label: string
  hint: string
  icon: typeof Brain
}> = [
  {
    key: "aiPrioritisation",
    label: "Exploitability prioritisation",
    hint: "Rank findings by how practically exploitable they are, not by raw CVSS alone.",
    icon: Gauge,
  },
  {
    key: "exploitChaining",
    label: "Attack path chaining",
    hint: "Model how individual findings combine into a multi-step compromise.",
    icon: Layers,
  },
  {
    key: "threatFeedEnrichment",
    label: "Threat feed enrichment",
    hint: "Cross-reference findings against active exploitation and actor tracking data.",
    icon: Radar,
  },
  {
    key: "falsePositiveFiltering",
    label: "False positive suppression",
    hint: "Drop low-impact findings the model scores as probable noise.",
    icon: CheckCircle2,
  },
  {
    key: "remediationSynthesis",
    label: "Remediation synthesis",
    hint: "Generate specific, actionable fix guidance for each finding.",
    icon: Sparkles,
  },
]

const PROFILE_ORDER: ScanProfile[] = ["rapid", "comprehensive", "pentest"]

const EXAMPLE_TARGETS = [
  "scanme.nmap.org",
  "192.168.1.10",
  "https://demo.testfire.net",
  "2001:db8::1",
  "10.0.0.0/24",
]

export interface TargetSpecificationPanelProps {
  target: string
  onTargetChange: (value: string) => void
  profile: ScanProfile
  onProfileChange: (value: ScanProfile) => void
  ai: AiConfig
  onAiChange: (value: AiConfig) => void
  authorized: boolean
  onAuthorizedChange: (value: boolean) => void
  status: ScanStatus
  onStart: () => void
  onAbort: () => void
  // ── Rules of Engagement (pre-engagement) ──
  liveMode: boolean
  aggression: Aggression
  onAggressionChange: (value: Aggression) => void
  authorizationRef: string
  onAuthorizationRefChange: (value: string) => void
  allowExploitation: boolean
  onAllowExploitationChange: (value: boolean) => void
}

export function TargetSpecificationPanel({
  target,
  onTargetChange,
  profile,
  onProfileChange,
  ai,
  onAiChange,
  authorized,
  onAuthorizedChange,
  status,
  onStart,
  onAbort,
  liveMode,
  aggression,
  onAggressionChange,
  authorizationRef,
  onAuthorizationRefChange,
  allowExploitation,
  onAllowExploitationChange,
}: TargetSpecificationPanelProps) {
  const validation = useMemo(() => validateTarget(target), [target])
  const touched = target.trim().length > 0
  const running = status === "running"
  // In live mode the bridge requires an authorization reference too.
  const roeReady = !liveMode || authorizationRef.trim().length > 0
  const canStart = validation.valid && authorized && roeReady && !running

  const activeAiCount = Object.values(ai).filter(Boolean).length

  return (
    <Card className="glass-panel relative overflow-hidden border-primary/20">
      {running && <div className="scan-beam animate-scan-beam" />}

      <div className="pointer-events-none absolute inset-0 scan-grid opacity-40" />

      <CardHeader className="relative">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-lg">
              <span className="relative flex h-8 w-8 items-center justify-center rounded-md border border-primary/40 bg-primary/10">
                <Crosshair className="h-4 w-4 text-primary" />
                {running && (
                  <span className="pulse-ring absolute inset-0 rounded-md" />
                )}
              </span>
              Target Specification
            </CardTitle>
            <CardDescription>
              Define the asset, assessment depth and AI engine configuration.
            </CardDescription>
          </div>

          <Badge
            variant={running ? "success" : "outline"}
            className="shrink-0 font-mono text-[10px] uppercase tracking-wider"
          >
            {running ? "Engaged" : "Standby"}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="relative space-y-6">
        {/* ---------------------------------------------------- target ---- */}
        <div className="space-y-2">
          <Label htmlFor="target" className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
            <Target className="h-3.5 w-3.5" />
            Target — IP, CIDR, domain or URL
          </Label>

          <div className="relative">
            <Input
              id="target"
              value={target}
              disabled={running}
              placeholder="target.example.com  ·  192.0.2.10  ·  https://app.example.com"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => onTargetChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && canStart) onStart()
              }}
              className={cn(
                "h-12 border-slate-700/70 bg-slate-950/60 pr-28 font-mono text-sm transition-colors",
                touched && validation.valid && "border-primary/60",
                touched && !validation.valid && "border-destructive/60"
              )}
            />

            {touched && (
              <div className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center gap-2">
                {validation.valid ? (
                  <>
                    <Badge
                      variant="success"
                      className="font-mono text-[10px] uppercase"
                    >
                      {describeTargetKind(validation.kind)}
                    </Badge>
                    <CheckCircle2 className="h-4 w-4 text-primary" />
                  </>
                ) : (
                  <AlertTriangle className="h-4 w-4 text-destructive" />
                )}
              </div>
            )}
          </div>

          {touched && validation.error && (
            <p className="flex items-center gap-1.5 font-mono text-xs text-destructive">
              <AlertTriangle className="h-3 w-3 shrink-0" />
              {validation.error}
            </p>
          )}

          {touched && validation.valid && validation.warning && (
            <p className="flex items-center gap-1.5 font-mono text-xs text-yellow-400">
              <ShieldAlert className="h-3 w-3 shrink-0" />
              {validation.warning}
            </p>
          )}

          {!touched && (
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
              <span className="text-[11px] text-muted-foreground">Try:</span>
              {EXAMPLE_TARGETS.map((example) => (
                <button
                  key={example}
                  type="button"
                  onClick={() => onTargetChange(example)}
                  className="rounded border border-slate-700/70 bg-slate-900/60 px-2 py-0.5 font-mono text-[10px] text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary"
                >
                  {example}
                </button>
              ))}
            </div>
          )}
        </div>

        <Separator className="bg-slate-800" />

        {/* --------------------------------------------------- profile ---- */}
        <div className="space-y-2">
          <Label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
            <Zap className="h-3.5 w-3.5" />
            Assessment profile
          </Label>

          <Select
            value={profile}
            disabled={running}
            onValueChange={(value) => onProfileChange(value as ScanProfile)}
          >
            <SelectTrigger className="h-11 border-slate-700/70 bg-slate-950/60">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {/*
                Radix mirrors the selected item's text into the trigger, so the
                item label stays a single line — the blurb is surfaced below.
              */}
              {PROFILE_ORDER.map((key) => (
                <SelectItem key={key} value={key} className="py-2">
                  {PROFILE_META[key].label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <p className="pt-0.5 text-[11px] leading-relaxed text-muted-foreground">
            {PROFILE_META[profile].blurb}
          </p>

          <div className="flex items-center gap-3 font-mono text-[11px] text-muted-foreground">
            <span>
              Expected findings: {PROFILE_META[profile].findings[0]}–
              {PROFILE_META[profile].findings[1]}
            </span>
            <span className="text-slate-700">|</span>
            <span>Typical duration: ~{PROFILE_META[profile].minutes} min</span>
          </div>
        </div>

        <Separator className="bg-slate-800" />

        {/* ---------------------------------------------------------- RoE -- */}
        <div className="space-y-3">
          <Label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5" />
            Rules of Engagement
          </Label>

          <div className="grid grid-cols-3 gap-2">
            {AGGRESSION_OPTIONS.map(({ value, label, hint, icon: Icon }) => (
              <Tooltip key={value}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    disabled={running}
                    onClick={() => onAggressionChange(value)}
                    className={cn(
                      "flex flex-col items-center gap-1 rounded-md border p-2 text-[11px] transition-colors",
                      aggression === value
                        ? "border-primary/50 bg-primary/10 text-primary"
                        : "border-slate-800 text-muted-foreground hover:border-slate-700",
                      running && "cursor-not-allowed opacity-60"
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[220px]">
                  {hint}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>

          <div className="space-y-1.5">
            <Label
              htmlFor="authRef"
              className="flex items-center gap-1.5 text-xs text-muted-foreground"
            >
              Authorization reference
              {liveMode && <span className="text-destructive">*</span>}
            </Label>
            <Input
              id="authRef"
              value={authorizationRef}
              disabled={running}
              placeholder="ticket-1234 · contract ref · &quot;lab&quot;"
              className="h-9 border-slate-700/70 bg-slate-950/60 font-mono text-xs"
              onChange={(e) => onAuthorizationRefChange(e.target.value)}
            />
            <p className="text-[10px] text-muted-foreground">
              Records who authorized this engagement.
              {liveMode && " Required by the bridge before any tool runs."}
            </p>
          </div>

          <label
            className={cn(
              "flex cursor-pointer items-center justify-between rounded-md border p-2.5 transition-colors",
              allowExploitation
                ? "border-primary/40 bg-primary/5"
                : "border-slate-800 bg-slate-950/40",
              running && "cursor-not-allowed opacity-60"
            )}
          >
            <span className="flex items-center gap-2 text-xs">
              <Zap className="h-3.5 w-3.5 text-primary" />
              Exploitation stage
              <span className="text-[10px] text-muted-foreground">
                (safe-mode PoC only)
              </span>
            </span>
            <Switch
              checked={allowExploitation}
              disabled={running}
              onCheckedChange={onAllowExploitationChange}
            />
          </label>
        </div>

        <Separator className="bg-slate-800" />

        {/* -------------------------------------------------------- AI ---- */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
              <Brain className="h-3.5 w-3.5" />
              AI engine configuration
            </Label>
            <Badge variant="outline" className="font-mono text-[10px]">
              {activeAiCount}/{AI_OPTIONS.length} active
            </Badge>
          </div>

          <div className="grid gap-2 sm:grid-cols-2">
            {AI_OPTIONS.map(({ key, label, hint, icon: Icon }) => (
              <Tooltip key={key}>
                <TooltipTrigger asChild>
                  <label
                    className={cn(
                      "flex cursor-pointer items-start gap-2.5 rounded-md border p-2.5 transition-colors",
                      ai[key]
                        ? "border-primary/40 bg-primary/5"
                        : "border-slate-800 bg-slate-950/40 hover:border-slate-700",
                      running && "cursor-not-allowed opacity-60"
                    )}
                  >
                    <Checkbox
                      checked={ai[key]}
                      disabled={running}
                      onCheckedChange={(checked) =>
                        onAiChange({ ...ai, [key]: checked === true })
                      }
                      className="mt-0.5"
                    />
                    <span className="flex items-center gap-1.5 text-xs leading-tight">
                      <Icon
                        className={cn(
                          "h-3.5 w-3.5 shrink-0",
                          ai[key] ? "text-primary" : "text-muted-foreground"
                        )}
                      />
                      {label}
                    </span>
                  </label>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[240px]">
                  {hint}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        </div>

        <Separator className="bg-slate-800" />

        {/* ---------------------------------------------- authorisation ---- */}
        <label
          className={cn(
            "flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors",
            authorized
              ? "border-primary/40 bg-primary/5"
              : "border-yellow-600/40 bg-yellow-500/5",
            running && "cursor-not-allowed opacity-60"
          )}
        >
          <Checkbox
            checked={authorized}
            disabled={running}
            onCheckedChange={(checked) => onAuthorizedChange(checked === true)}
            className="mt-0.5"
          />
          <span className="space-y-1 text-xs leading-relaxed">
            <span className="flex items-center gap-1.5 font-medium">
              <ShieldAlert className="h-3.5 w-3.5 text-yellow-400" />
              I am authorised to assess this target
            </span>
            <span className="block text-muted-foreground">
              Scanning systems without the owner's written permission is illegal
              in most jurisdictions. Confirm you have authorisation for this
              engagement before proceeding.
            </span>
          </span>
        </label>

        {/* ---------------------------------------------------- actions ---- */}
        <div className="flex flex-col gap-2 sm:flex-row">
          <Button
            onClick={onStart}
            disabled={!canStart}
            size="lg"
            variant="glow"
            className="flex-1"
          >
            {running ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Assessment in progress…
              </>
            ) : (
              <>
                <Radar className="h-4 w-4" />
                Initiate Assessment
              </>
            )}
          </Button>

          {running && (
            <Button onClick={onAbort} size="lg" variant="danger">
              <Square className="h-4 w-4" />
              Abort
            </Button>
          )}
        </div>

        {!running && touched && !validation.valid && (
          <p className="text-center font-mono text-[11px] text-muted-foreground">
            Enter a valid target to enable the scan.
          </p>
        )}
        {!running && validation.valid && !authorized && (
          <p className="flex items-center justify-center gap-1.5 text-center font-mono text-[11px] text-yellow-400">
            <Link2 className="h-3 w-3" />
            Confirm authorisation to enable the scan.
          </p>
        )}
        {!running && validation.valid && authorized && !roeReady && (
          <p className="flex items-center justify-center gap-1.5 text-center font-mono text-[11px] text-yellow-400">
            <ShieldAlert className="h-3 w-3" />
            Enter an authorization reference (required in live mode).
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export default TargetSpecificationPanel
