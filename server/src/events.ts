import { EventEmitter } from "node:events"

import type { LogEvent, PtesStageId, ServerEvent } from "./types"

/**
 * One event bus per process. Subscribers (SSE connections) filter by
 * engagement id. Kept in-memory: this is a single-node dev bridge, not a
 * clustered service — for HA you'd back this with Redis pub/sub.
 */
class EngagementBus {
  private readonly emitter = new EventEmitter()
  /** Ring buffer of recent events per engagement so a late SSE client can replay. */
  private readonly backlog = new Map<string, ServerEvent[]>()
  private readonly BACKLOG_LIMIT = 500

  constructor() {
    // Many concurrent SSE clients are expected.
    this.emitter.setMaxListeners(0)
  }

  publish(engagementId: string, event: ServerEvent) {
    if (event.type !== "heartbeat") {
      const buf = this.backlog.get(engagementId) ?? []
      buf.push(event)
      if (buf.length > this.BACKLOG_LIMIT) buf.shift()
      this.backlog.set(engagementId, buf)
    }
    this.emitter.emit(engagementId, event)
    this.emitter.emit("*", event)
  }

  subscribe(engagementId: string, listener: (event: ServerEvent) => void) {
    this.emitter.on(engagementId, listener)
    return () => this.emitter.off(engagementId, listener)
  }

  replay(engagementId: string): ServerEvent[] {
    return this.backlog.get(engagementId) ?? []
  }

  clear(engagementId: string) {
    this.backlog.delete(engagementId)
  }
}

export const bus = new EngagementBus()

/** Convenience helper for emitting a structured, timestamped log line. */
export function log(
  engagementId: string,
  stage: PtesStageId | "system",
  level: LogEvent["level"],
  source: string,
  message: string
) {
  const data: LogEvent = {
    engagementId,
    ts: new Date().toISOString(),
    stage,
    level,
    source,
    message,
  }
  bus.publish(engagementId, { type: "log", data })
  // Mirror to stdout for host-side auditing.
  const tag = `[${engagementId.slice(0, 8)}][${stage}][${level}]`
  // eslint-disable-next-line no-console
  console.log(`${tag} ${source}: ${message}`)
}
