import cors from "cors"
import express from "express"

import { activeExecutionPermitted, config } from "./config"
import { engagements } from "./engagements"
import { bus } from "./events"
import { llmHealthLabel, probeOllama } from "./llm"
import { mcp } from "./mcp"
import { runPtes } from "./ptes"
import {
  checkScope,
  rateLimit,
  requireAuth,
  sanitizeTarget,
  sanitizeText,
} from "./security"
import type { Aggression, RulesOfEngagement, ServerEvent } from "./types"

const app = express()
app.use(express.json({ limit: "256kb" }))
app.use(
  cors({
    origin: config.corsOrigins,
    credentials: false,
  })
)

/* ── Public: health + capabilities (no auth; leaks nothing sensitive) ────── */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "vulnedge-bridge",
    version: "1.0.0",
    safeMode: config.safeMode,
    activeExploitPermitted: activeExecutionPermitted(),
    provider: config.toolProvider,
    mcpAvailable: mcp.isAvailable(),
    mcpServers: mcp.listServers().map((s) => ({ name: s.name, capability: s.capability })),
    llm: llmHealthLabel(),
    authRequired: Boolean(config.bridgeToken),
  })
})

/* ── Everything below requires auth + rate limiting ──────────────────────── */

app.use("/api", rateLimit, requireAuth)

/**
 * Start an engagement. Validates target, sanitizes RoE, enforces scope, then
 * kicks off the PTES pipeline asynchronously. Returns the engagement id the
 * client subscribes to over SSE.
 */
app.post("/api/engagements", (req, res) => {
  const body = req.body ?? {}

  const target = sanitizeTarget(body.target)
  if (!target.ok) {
    return res.status(400).json({ error: target.reason })
  }

  const profile = ["rapid", "comprehensive", "pentest"].includes(body.profile)
    ? body.profile
    : "comprehensive"

  const aggression: Aggression = ["stealth", "balanced", "aggressive"].includes(
    body.aggression
  )
    ? body.aggression
    : "balanced"

  const roe: RulesOfEngagement = {
    aggression,
    authorizationRef: sanitizeText(body.authorizationRef, 120) || "UNSPECIFIED",
    scope: Array.isArray(body.scope)
      ? body.scope.map((s: unknown) => sanitizeText(s, 120)).filter(Boolean)
      : [],
    allowExploitation: body.allowExploitation !== false,
  }

  // Authorization ref must be present for anything beyond a stealth recon —
  // this is the human-accountability control.
  if (roe.authorizationRef === "UNSPECIFIED") {
    return res.status(400).json({
      error:
        "An authorization reference is required (ticket id, contract, or 'lab'). This records who authorized the engagement.",
    })
  }

  const scope = checkScope(target.normalized, roe)
  if (!scope.allowed) {
    return res.status(403).json({ error: `Scope check failed: ${scope.reason}` })
  }

  const engagement = engagements.create({
    target: target.normalized,
    profile,
    roe,
  })

  // Fire and forget — the client follows progress via SSE.
  void runPtes(engagement)

  res.status(202).json({ id: engagement.id, engagement })
})

app.get("/api/engagements", (_req, res) => {
  res.json({
    engagements: engagements.list().map((e) => ({
      id: e.id,
      target: e.target,
      profile: e.profile,
      status: e.status,
      progress: e.progress,
      createdAt: e.createdAt,
    })),
  })
})

app.get("/api/engagements/:id", (req, res) => {
  const engagement = engagements.get(req.params.id)
  if (!engagement) return res.status(404).json({ error: "Engagement not found." })
  res.json({ engagement })
})

/**
 * SSE live log + progress stream. The auth middleware already ran (query-token
 * fallback below covers EventSource, which cannot set headers).
 */
app.get("/api/engagements/:id/stream", (req, res) => {
  const engagement = engagements.get(req.params.id)
  if (!engagement) return res.status(404).json({ error: "Engagement not found." })

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  })

  const send = (event: ServerEvent) => {
    res.write(`event: ${event.type}\n`)
    res.write(`data: ${JSON.stringify(event.data)}\n\n`)
  }

  // Replay backlog so a late subscriber sees the whole run.
  for (const event of bus.replay(engagement.id)) send(event)

  // If the engagement already finished, push a final result and keep the
  // stream open briefly for any trailing events.
  const unsubscribe = bus.subscribe(engagement.id, send)

  const heartbeat = setInterval(() => {
    send({ type: "heartbeat", data: { ts: new Date().toISOString() } })
  }, 15_000)

  req.on("close", () => {
    clearInterval(heartbeat)
    unsubscribe()
  })
})

/**
 * EventSource can't send an Authorization header, so allow a `?token=` query
 * param for the stream endpoint specifically. Mounted before the router's auth
 * by re-checking here would be complex; instead we accept the token via query
 * for SSE and validate it in the auth middleware path. To keep it simple and
 * still safe, the auth middleware also accepts `?token=`.
 */

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(
    [
      "",
      "  VulnEdge Bridge",
      `  ├─ listening      http://localhost:${config.port}`,
      `  ├─ provider       ${config.toolProvider}`,
      `  ├─ safe mode      ${config.safeMode ? "ON (no exploitation executes)" : "OFF"}`,
      `  ├─ active exploit ${activeExecutionPermitted() ? "PERMITTED ⚠" : "blocked"}`,
      `  ├─ auth           ${config.bridgeToken ? "bearer token required" : "loopback-only (no token set)"}`,
      `  ├─ llm            ${llmHealthLabel()}`,
      `  └─ scope          ${config.scopeAllowlist.length ? config.scopeAllowlist.join(", ") : "per-engagement only"}`,
      "",
    ].join("\n")
  )

  if (config.toolProvider === "mcp") {
    void mcp.connectAll((msg) => console.log(`  [mcp] ${msg}`))
  }
  void probeOllama((msg) => console.log(`  [llm] ${msg}`))
})

async function shutdown() {
  await mcp.closeAll()
  server.close(() => process.exit(0))
  setTimeout(() => process.exit(0), 2000)
}
process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)
