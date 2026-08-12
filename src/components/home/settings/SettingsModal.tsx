import { useEffect, useState } from "react"
import {
  Brain,
  CheckCircle2,
  Copy,
  KeyRound,
  Loader2,
  Plug,
  Server,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { bridge } from "@/lib/api/client"
import type { BridgeHealth, BridgeSettings } from "@/lib/api/types"
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Separator,
  Switch,
} from "@/components/home/ui"

export interface SettingsModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  settings: BridgeSettings
  onSave: (settings: BridgeSettings) => void
  liveMode: boolean
  onLiveModeChange: (live: boolean) => void
}

export function SettingsModal({
  open,
  onOpenChange,
  settings,
  onSave,
  liveMode,
  onLiveModeChange,
}: SettingsModalProps) {
  const [draft, setDraft] = useState<BridgeSettings>(settings)
  const [testing, setTesting] = useState(false)
  const [health, setHealth] = useState<BridgeHealth | null>(null)
  const [testError, setTestError] = useState<string | null>(null)

  useEffect(() => {
    if (open) {
      setDraft(settings)
      setHealth(null)
      setTestError(null)
    }
  }, [open, settings])

  const testConnection = async () => {
    setTesting(true)
    setHealth(null)
    setTestError(null)
    try {
      const h = await bridge.health(draft)
      setHealth(h)
    } catch (err) {
      setTestError(err instanceof Error ? err.message : "Connection failed.")
    } finally {
      setTesting(false)
    }
  }

  const save = () => {
    onSave(draft)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="glass-strong max-h-[90vh] max-w-lg overflow-y-auto border-primary/20">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Server className="h-4 w-4 text-primary" />
            Bridge &amp; Engagement Settings
          </DialogTitle>
          <DialogDescription className="text-xs">
            Connect to the VulnEdge backend to run real MCP-orchestrated
            assessments, or stay in local simulation.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          {/* Mode toggle */}
          <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 p-3">
            <div className="space-y-0.5">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                <Plug className="h-3.5 w-3.5 text-primary" />
                Live backend mode
              </p>
              <p className="text-[11px] text-muted-foreground">
                {liveMode
                  ? "Assessments run through the backend bridge (MCP / PTES)."
                  : "Assessments run locally in the browser (simulation)."}
              </p>
            </div>
            <Switch checked={liveMode} onCheckedChange={onLiveModeChange} />
          </div>

          <Separator className="bg-slate-800" />

          {/* Connection */}
          <div className="space-y-3">
            <Label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
              <Server className="h-3.5 w-3.5" />
              Bridge connection
            </Label>

            <div className="space-y-1.5">
              <Label htmlFor="baseUrl" className="text-xs">
                Base URL
              </Label>
              <Input
                id="baseUrl"
                value={draft.baseUrl}
                placeholder="http://localhost:8787"
                className="h-9 font-mono text-xs"
                onChange={(e) => setDraft({ ...draft, baseUrl: e.target.value.trim() })}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="token" className="flex items-center gap-1.5 text-xs">
                <KeyRound className="h-3 w-3" />
                Bearer token
                <span className="text-muted-foreground">(BRIDGE_TOKEN)</span>
              </Label>
              <Input
                id="token"
                type="password"
                value={draft.token}
                placeholder="Required unless the bridge runs loopback-only"
                className="h-9 font-mono text-xs"
                onChange={(e) => setDraft({ ...draft, token: e.target.value.trim() })}
              />
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="tactical"
                size="sm"
                onClick={testConnection}
                disabled={testing}
              >
                {testing ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Plug className="h-3.5 w-3.5" />
                )}
                Test connection
              </Button>
            </div>

            {testError && (
              <p className="flex items-center gap-1.5 rounded border border-destructive/40 bg-destructive/10 p-2 font-mono text-[11px] text-destructive">
                <XCircle className="h-3.5 w-3.5 shrink-0" />
                {testError}
              </p>
            )}

            {health && <HealthReadout health={health} />}
          </div>

          <Separator className="bg-slate-800" />

          {/* Provider API keys */}
          <div className="space-y-3">
            <Label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
              <KeyRound className="h-3.5 w-3.5" />
              Intelligence provider keys
            </Label>
            <p className="text-[11px] text-muted-foreground">
              Forwarded to the recon MCP servers that need them. Stored in your
              browser only; never rendered in logs.
            </p>

            <div className="grid gap-2 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="shodan" className="text-xs">
                  Shodan API key
                </Label>
                <Input
                  id="shodan"
                  type="password"
                  value={draft.shodanApiKey}
                  className="h-9 font-mono text-xs"
                  onChange={(e) => setDraft({ ...draft, shodanApiKey: e.target.value.trim() })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="hunter" className="text-xs">
                  Hunter.io API key
                </Label>
                <Input
                  id="hunter"
                  type="password"
                  value={draft.hunterApiKey}
                  className="h-9 font-mono text-xs"
                  onChange={(e) => setDraft({ ...draft, hunterApiKey: e.target.value.trim() })}
                />
              </div>
            </div>
          </div>

          <Separator className="bg-slate-800" />

          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="glow" size="sm" onClick={save}>
              <CheckCircle2 className="h-3.5 w-3.5" />
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function HealthReadout({ health }: { health: BridgeHealth }) {
  const copyConfig = () => {
    navigator.clipboard?.writeText(JSON.stringify(health, null, 2)).catch(() => {})
  }

  return (
    <div className="space-y-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-300">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Connected · {health.service} v{health.version}
        </span>
        <button
          type="button"
          onClick={copyConfig}
          className="text-muted-foreground transition hover:text-foreground"
          title="Copy health JSON"
        >
          <Copy className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
        <HealthChip
          ok={health.safeMode}
          okLabel="SAFE MODE ON"
          badLabel="SAFE MODE OFF"
          okIcon={ShieldCheck}
          badIcon={ShieldAlert}
          invert
        />
        <HealthChip
          ok={!health.activeExploitPermitted}
          okLabel="exploit blocked"
          badLabel="EXPLOIT ARMED"
          okIcon={ShieldCheck}
          badIcon={ShieldAlert}
        />
        <Badge variant="outline" className="justify-center text-[10px]">
          provider: {health.provider}
        </Badge>
        <Badge variant="outline" className="justify-center text-[10px]">
          MCP: {health.mcpAvailable ? `${health.mcpServers.length} servers` : "none"}
        </Badge>
        <Badge
          variant="outline"
          className="col-span-2 justify-center gap-1 text-[10px]"
        >
          <Brain className="h-3 w-3" />
          analysis: {health.llm}
        </Badge>
      </div>

      {health.mcpServers.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {health.mcpServers.map((s) => (
            <Badge key={s.name} variant="success" className="text-[9px]">
              {s.name} · {s.capability}
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}

function HealthChip({
  ok,
  okLabel,
  badLabel,
  okIcon: OkIcon,
  badIcon: BadIcon,
  invert,
}: {
  ok: boolean
  okLabel: string
  badLabel: string
  okIcon: typeof ShieldCheck
  badIcon: typeof ShieldAlert
  invert?: boolean
}) {
  const good = invert ? ok : ok
  const Icon = good ? OkIcon : BadIcon
  return (
    <span
      className={cn(
        "flex items-center justify-center gap-1 rounded border px-2 py-0.5",
        good
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
          : "border-red-500/40 bg-red-500/10 text-red-300"
      )}
    >
      <Icon className="h-3 w-3" />
      {good ? okLabel : badLabel}
    </span>
  )
}
