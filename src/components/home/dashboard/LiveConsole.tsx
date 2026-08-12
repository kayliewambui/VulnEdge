import { useEffect, useMemo, useRef } from "react"
import {
  BadgeCheck,
  ChevronRight,
  CircleSlash,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Wifi,
  WifiOff,
  XCircle,
  Zap,
} from "lucide-react"

import { cn } from "@/lib/utils"
import type {
  Engagement,
  LogEvent,
  StageState,
} from "@/lib/api/types"
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Progress,
  ScrollArea,
  Separator,
} from "@/components/home/ui"

const LEVEL_STYLE: Record<LogEvent["level"], { dot: string; text: string }> = {
  info: { dot: "bg-slate-500", text: "text-slate-300" },
  tool: { dot: "bg-cyan-500", text: "text-cyan-300" },
  warn: { dot: "bg-yellow-500", text: "text-yellow-300" },
  error: { dot: "bg-red-500", text: "text-red-300" },
  success: { dot: "bg-emerald-500", text: "text-emerald-300" },
}

function StageIcon({ status }: { status: StageState["status"] }) {
  switch (status) {
    case "completed":
      return <BadgeCheck className="h-3.5 w-3.5 text-emerald-400" />
    case "running":
      return <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
    case "failed":
      return <XCircle className="h-3.5 w-3.5 text-red-400" />
    case "skipped":
      return <ChevronRight className="h-3.5 w-3.5 text-slate-600" />
    default:
      return <CircleSlash className="h-3.5 w-3.5 text-slate-700" />
  }
}

export interface LiveConsoleProps {
  engagement: Engagement | null
  logs: LogEvent[]
  connected: boolean
  progress: number
  running: boolean
}

export function LiveConsole({
  engagement,
  logs,
  connected,
  progress,
  running,
}: LiveConsoleProps) {
  const logEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" })
  }, [logs.length])

  const activeStage = useMemo(
    () => engagement?.stages.find((s) => s.status === "running"),
    [engagement]
  )

  return (
    <Card className="glass-panel relative overflow-hidden border-primary/30">
      {running && <div className="scan-beam animate-scan-beam" />}
      <div className="pointer-events-none absolute inset-0 scan-grid-animated opacity-25" />

      <CardHeader className="relative pb-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Terminal className="h-4 w-4 text-primary" />
              PTES Live Operations
            </CardTitle>
            <CardDescription className="font-mono text-xs">
              {engagement
                ? `${engagement.target} · ${engagement.provider} · ${engagement.safeMode ? "safe mode" : "ACTIVE"}`
                : "Awaiting engagement…"}
            </CardDescription>
          </div>

          <Badge
            variant={connected ? "success" : "outline"}
            className="gap-1 font-mono text-[10px] uppercase"
          >
            {connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {connected ? "streaming" : "idle"}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="relative space-y-4">
        {/* Progress */}
        <div className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <span className="font-mono text-xs text-primary">
              {activeStage?.label ?? (running ? "Working…" : "Ready")}
            </span>
            <span className="font-mono text-2xl font-bold tabular-nums text-primary text-glow">
              {Math.round(progress)}%
            </span>
          </div>
          <Progress
            value={progress}
            className="h-2 bg-slate-800"
            indicatorClassName="bg-gradient-to-r from-emerald-600 via-emerald-400 to-cyan-400"
          />
        </div>

        {/* PTES stage ladder */}
        {engagement && (
          <ol className="grid gap-1 sm:grid-cols-2">
            {engagement.stages.map((stage, i) => (
              <li
                key={stage.id}
                className={cn(
                  "flex items-start gap-2 rounded-md border px-2.5 py-1.5 font-mono text-[11px] transition-colors",
                  stage.status === "running" && "border-primary/50 bg-primary/10",
                  stage.status === "completed" && "border-slate-800 bg-slate-900/40",
                  stage.status === "failed" && "border-red-500/40 bg-red-500/5",
                  stage.status === "skipped" && "border-slate-800/60",
                  stage.status === "pending" && "border-slate-800/40 text-slate-600"
                )}
              >
                <span className="mt-0.5 w-5 shrink-0 text-right opacity-50">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <StageIcon status={stage.status} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{stage.label}</span>
                  {stage.detail && (
                    <span className="block truncate text-[10px] text-muted-foreground">
                      {stage.detail}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ol>
        )}

        <Separator className="bg-slate-800" />

        {/* Streaming log */}
        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Tool output stream
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              {logs.length} lines
            </span>
          </div>
          <ScrollArea className="h-[240px] rounded-md border border-slate-800 bg-black/60">
            <div className="space-y-0.5 p-2.5">
              {logs.length === 0 ? (
                <p className="font-mono text-[11px] text-slate-600">
                  $ waiting for the pipeline to emit events…
                </p>
              ) : (
                logs.map((entry, i) => {
                  const style = LEVEL_STYLE[entry.level]
                  return (
                    <div
                      key={`${entry.ts}-${i}`}
                      className="flex items-start gap-2 font-mono text-[11px] leading-relaxed animate-slide-up-fade"
                    >
                      <span className="shrink-0 text-slate-600">
                        {new Date(entry.ts).toLocaleTimeString([], {
                          hour12: false,
                        })}
                      </span>
                      <span
                        className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", style.dot)}
                      />
                      <span className="shrink-0 text-slate-500">[{entry.source}]</span>
                      <span className={cn("min-w-0 flex-1 break-words", style.text)}>
                        {entry.message}
                      </span>
                    </div>
                  )
                })
              )}
              <div ref={logEndRef} />
            </div>
          </ScrollArea>
        </div>

        {/* Exploit plan (safe-mode PoC plan) */}
        {engagement && engagement.exploitPlan.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Zap className="h-3.5 w-3.5 text-primary" />
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Exploitation plan · {engagement.exploitPlan[0].source === "llm" ? "AI-generated" : "template"} · none executed
              </span>
            </div>
            <div className="space-y-1.5">
              {engagement.exploitPlan.map((item, i) => (
                <div
                  key={`${item.vulnerabilityId}-${i}`}
                  className="rounded-md border border-slate-800 bg-slate-900/40 p-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[11px] font-medium text-slate-200">
                      {item.title}
                    </span>
                    <GuardBadge verdict={item.guardVerdict} />
                  </div>
                  <pre className="mt-1 overflow-x-auto rounded bg-black/60 px-2 py-1 font-mono text-[10px] text-emerald-300/90">
                    $ {item.proposedCommand}
                  </pre>
                  <p className="mt-1 text-[10px] text-muted-foreground">{item.guardReason}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function GuardBadge({
  verdict,
}: {
  verdict: "allowed" | "allowed-verification" | "blocked-safe-mode" | "blocked-policy"
}) {
  if (verdict === "blocked-policy") {
    return (
      <Badge variant="destructive" className="gap-1 text-[9px] uppercase">
        <XCircle className="h-3 w-3" />
        blocked
      </Badge>
    )
  }
  if (verdict === "allowed-verification") {
    return (
      <Badge variant="success" className="gap-1 text-[9px] uppercase">
        <ShieldCheck className="h-3 w-3" />
        verify · safe
      </Badge>
    )
  }
  if (verdict === "blocked-safe-mode") {
    return (
      <Badge variant="success" className="gap-1 text-[9px] uppercase">
        <ShieldCheck className="h-3 w-3" />
        safe · planned
      </Badge>
    )
  }
  return (
    <Badge className="gap-1 border-yellow-500/40 bg-yellow-500/15 text-[9px] uppercase text-yellow-300">
      <ShieldAlert className="h-3 w-3" />
      armed
    </Badge>
  )
}
