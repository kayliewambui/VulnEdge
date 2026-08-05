import { randomUUID } from "node:crypto"

import { config } from "./config"
import { initialStages } from "./ptes"
import type { Engagement, RulesOfEngagement } from "./types"

/**
 * In-memory engagement store. A real deployment would persist these; for a dev
 * bridge, process memory plus the SSE backlog is enough. Engagements are capped
 * so a long-running server doesn't grow unbounded.
 */
class EngagementStore {
  private map = new Map<string, Engagement>()
  private order: string[] = []
  private readonly LIMIT = 100

  create(input: {
    target: string
    profile: Engagement["profile"]
    roe: RulesOfEngagement
  }): Engagement {
    const now = new Date().toISOString()
    const engagement: Engagement = {
      id: randomUUID(),
      target: input.target,
      profile: input.profile,
      roe: input.roe,
      status: "created",
      provider: config.toolProvider,
      safeMode: config.safeMode,
      createdAt: now,
      updatedAt: now,
      progress: 0,
      stages: initialStages(),
      result: null,
      exploitPlan: [],
    }
    this.map.set(engagement.id, engagement)
    this.order.push(engagement.id)
    this.evict()
    return engagement
  }

  get(id: string): Engagement | undefined {
    return this.map.get(id)
  }

  list(): Engagement[] {
    return this.order
      .map((id) => this.map.get(id))
      .filter((e): e is Engagement => Boolean(e))
      .reverse()
  }

  private evict() {
    while (this.order.length > this.LIMIT) {
      const oldest = this.order.shift()
      if (oldest) this.map.delete(oldest)
    }
  }
}

export const engagements = new EngagementStore()
