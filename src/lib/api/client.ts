import {
  DEFAULT_SETTINGS,
  type BridgeHealth,
  type BridgeSettings,
  type Engagement,
} from "./types"

const STORAGE_KEY = "vulnedge.bridge.settings"

/** Load persisted bridge settings (falls back to defaults). */
export function loadSettings(): BridgeSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...DEFAULT_SETTINGS }
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) }
  } catch {
    return { ...DEFAULT_SETTINGS }
  }
}

export function saveSettings(settings: BridgeSettings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
}

function authHeaders(settings: BridgeSettings): HeadersInit {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (settings.token) headers.Authorization = `Bearer ${settings.token}`
  return headers
}

export class BridgeError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = "BridgeError"
  }
}

async function parseError(res: Response): Promise<never> {
  let message = `${res.status} ${res.statusText}`
  try {
    const body = await res.json()
    if (body?.error) message = body.error
  } catch {
    /* keep default */
  }
  throw new BridgeError(res.status, message)
}

export interface StartEngagementInput {
  target: string
  profile: "rapid" | "comprehensive" | "pentest"
  aggression: "stealth" | "balanced" | "aggressive"
  authorizationRef: string
  scope: string[]
  allowExploitation: boolean
}

export const bridge = {
  async health(settings: BridgeSettings): Promise<BridgeHealth> {
    const res = await fetch(`${settings.baseUrl}/api/health`, {
      headers: { "Content-Type": "application/json" },
    })
    if (!res.ok) return parseError(res)
    return res.json()
  },

  async start(
    settings: BridgeSettings,
    input: StartEngagementInput
  ): Promise<Engagement> {
    const res = await fetch(`${settings.baseUrl}/api/engagements`, {
      method: "POST",
      headers: authHeaders(settings),
      body: JSON.stringify(input),
    })
    if (!res.ok) return parseError(res)
    const body = await res.json()
    return body.engagement
  },

  async get(settings: BridgeSettings, id: string): Promise<Engagement> {
    const res = await fetch(`${settings.baseUrl}/api/engagements/${id}`, {
      headers: authHeaders(settings),
    })
    if (!res.ok) return parseError(res)
    const body = await res.json()
    return body.engagement
  },

  /** Build the SSE URL, threading the token through the query for EventSource. */
  streamUrl(settings: BridgeSettings, id: string): string {
    const url = new URL(`${settings.baseUrl}/api/engagements/${id}/stream`)
    if (settings.token) url.searchParams.set("token", settings.token)
    return url.toString()
  },
}
