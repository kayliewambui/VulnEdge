import { useCallback, useEffect, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { bridge, loadSettings, type StartEngagementInput } from "./client"
import type {
  BridgeSettings,
  Engagement,
  EngagementStatus,
  LogEvent,
  StageState,
} from "./types"

/** Bridge health — polled so the UI reflects backend availability live. */
export function useBridgeHealth(settings: BridgeSettings, enabled: boolean) {
  return useQuery({
    queryKey: ["bridge-health", settings.baseUrl, settings.token],
    queryFn: () => bridge.health(settings),
    enabled,
    retry: 1,
    refetchInterval: 20_000,
    staleTime: 10_000,
  })
}

/** Kick off an engagement. Returns the created engagement (status "running"). */
export function useStartEngagement(settings: BridgeSettings) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: StartEngagementInput) => bridge.start(settings, input),
    onSuccess: (engagement) => {
      qc.setQueryData(["engagement", engagement.id], engagement)
    },
  })
}

export interface LiveEngagement {
  engagement: Engagement | null
  logs: LogEvent[]
  connected: boolean
  progress: number
  status: EngagementStatus | null
}

/**
 * Subscribe to an engagement's live event stream. Merges SSE `log`, `stage`,
 * `progress`, and `result` events into a single reactive view. The engagement
 * object is progressively patched as stages complete, and the final `result`
 * event carries the full assessment.
 */
export function useEngagementStream(
  engagementId: string | null,
  settingsOverride?: BridgeSettings
): LiveEngagement & { reset: () => void } {
  const [engagement, setEngagement] = useState<Engagement | null>(null)
  const [logs, setLogs] = useState<LogEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [progress, setProgress] = useState(0)
  const [status, setStatus] = useState<EngagementStatus | null>(null)
  const sourceRef = useRef<EventSource | null>(null)

  const reset = useCallback(() => {
    sourceRef.current?.close()
    sourceRef.current = null
    setEngagement(null)
    setLogs([])
    setConnected(false)
    setProgress(0)
    setStatus(null)
  }, [])

  useEffect(() => {
    if (!engagementId) return
    const settings = settingsOverride ?? loadSettings()

    // Seed with a REST fetch so a reload mid-run recovers state, then stream.
    let cancelled = false
    bridge
      .get(settings, engagementId)
      .then((e) => {
        if (cancelled) return
        setEngagement(e)
        setProgress(e.progress)
        setStatus(e.status)
      })
      .catch(() => {
        /* stream backlog will populate it */
      })

    const es = new EventSource(bridge.streamUrl(settings, engagementId))
    sourceRef.current = es

    es.addEventListener("open", () => setConnected(true))
    es.addEventListener("error", () => setConnected(false))

    es.addEventListener("log", (ev) => {
      const data = JSON.parse((ev as MessageEvent).data) as LogEvent
      setLogs((prev) => (prev.length > 800 ? [...prev.slice(-800), data] : [...prev, data]))
    })

    es.addEventListener("stage", (ev) => {
      const data = JSON.parse((ev as MessageEvent).data) as {
        engagementId: string
        stage: StageState
      }
      setEngagement((prev) =>
        prev
          ? {
              ...prev,
              stages: prev.stages.map((s) => (s.id === data.stage.id ? data.stage : s)),
            }
          : prev
      )
    })

    es.addEventListener("progress", (ev) => {
      const data = JSON.parse((ev as MessageEvent).data) as {
        progress: number
        status: EngagementStatus
      }
      setProgress(data.progress)
      setStatus(data.status)
    })

    es.addEventListener("result", (ev) => {
      const data = JSON.parse((ev as MessageEvent).data) as { engagement: Engagement }
      setEngagement(data.engagement)
      setProgress(data.engagement.progress)
      setStatus(data.engagement.status)
      // Terminal — close the stream.
      es.close()
      setConnected(false)
    })

    return () => {
      cancelled = true
      es.close()
      sourceRef.current = null
    }
  }, [engagementId, settingsOverride])

  return { engagement, logs, connected, progress, status, reset }
}
