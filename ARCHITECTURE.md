# VulnEdge — Agentic VAPT Architecture

VulnEdge is a two-tier system: a React frontend and a Node/TypeScript **bridge**
that acts as an MCP client, orchestrating real security tooling along the
**PTES** (Penetration Testing Execution Standard) framework.

```
┌─────────────────────────────┐         ┌──────────────────────────────────────┐
│  Frontend (React + Vite)    │         │  Bridge (Node/TS · Express)          │
│                             │  HTTP   │                                      │
│  TargetSpec + RoE ──────────┼────────▶│  POST /api/engagements               │
│  TanStack Query             │         │   ├─ sanitize · scope guard · auth   │
│  SettingsModal              │◀────────┤   └─ PTES orchestrator               │
│  LiveConsole  ◀── SSE ──────┼─────────┤  GET  /api/engagements/:id/stream    │
│  VulnerabilityDashboard     │         │                                      │
│  (PDF report — unchanged)   │         │   ToolProvider                       │
└─────────────────────────────┘         │    ├─ simulation (local engine)      │
                                         │    └─ mcp ──┐                        │
                                         │             ▼                        │
                                         │      MCP client (stdio)              │
                                         └──────────────┬───────────────────────┘
                                                        │  stdio (JSON-RPC)
                        ┌───────────────┬───────────────┼───────────────┬──────────────┐
                        ▼               ▼               ▼               ▼              ▼
                     nmap-mcp       nuclei-mcp      cve-search       sqlmap-mcp   filesystem-mcp
                   (recon)         (vuln)          (vuln)          (exploit)     (reporting)
```

Two independent MCP clients can drive the same servers: **Claude Desktop**
(via `claude_desktop_config.json`) and the **bridge** (via
`server/mcp.servers.json`).

## Safe by default

The system runs end to end with **zero external tooling** in `simulation` mode,
reusing the deterministic VulnEdge engine (`src/lib/vapt`). No packets leave the
host. Real MCP servers plug in behind `TOOL_PROVIDER=mcp`.

Three independent gates guard active exploitation, and **all three plus a
per-engagement authorization reference** are required before anything could run
against a target:

| Gate | Default | Meaning |
| --- | --- | --- |
| `SAFE_MODE` | `true` | Exploitation stage **plans and PoCs only** — nothing executes. |
| `ALLOW_ACTIVE_EXPLOIT` | `false` | Second switch; off means the exploit provider refuses. |
| `TOOL_PROVIDER` | `simulation` | Must be `mcp` for any real tool to run. |
| RoE `authorizationRef` | required | Human-accountability record; requests without it are rejected. |

Even with the gates flipped, the exploitation path is a documented stub — an
operator must deliberately wire real execution. The default posture is the only
one shipped working.

## Security middleware (`server/src/security.ts`)

1. **Input sanitization** — targets are rejected if they contain shell
   metacharacters (`; & | \` $ ( ) < > …`) and must pass the vetted target
   classifier. Tool arguments are always passed structured; the bridge never
   builds a shell string.
2. **Scope guard** — every target must fall inside the declared engagement
   scope (RoE scope + `SCOPE_ALLOWLIST`). Private/loopback/link-local/metadata
   ranges are blocked unless explicitly enabled for an internal lab.
3. **Command guard** — the LLM may *propose* PoC commands; nothing it emits is
   trusted. Each proposal is validated against an allow-list of executables and
   a forbidden-argument policy, and in safe mode is planned but never executed.
   Anything that does run uses `execFile`-style argv, never a shell.
4. **Auth + rate limiting** — a bearer token (`BRIDGE_TOKEN`) is required for
   all `/api` routes; with no token set, the bridge serves loopback only.

## PTES pipeline (`server/src/ptes.ts`)

Seven streamed stages, each mapped to tool-provider calls:

1. **Pre-Engagement** — scope + authorization validation.
2. **Intelligence Gathering** — recon (DNS, subdomains, ports, TLS, OS).
3. **Threat Modeling** — prioritise attack surface from recon.
4. **Vulnerability Analysis** — templates + CVE correlation → findings + OWASP.
5. **Exploitation (Safe Mode)** — LLM/deterministic PoC plan, guard-gated.
6. **Post-Exploitation** — threat-actor + attack-vector modelling.
7. **Reporting** — assemble the `AssessmentResult` the existing PDF renders.

Progress, per-stage status, and raw tool output stream to the frontend over SSE.

## LLM analysis (`server/src/llm.ts`)

Optional. When `ANTHROPIC_API_KEY` (or an `ant auth login` profile) is present,
the exploitation stage uses **Claude (`claude-opus-5`)** with adaptive thinking
and structured output to reason over confirmed findings and propose PoC
commands. The model is constrained to allow-listed tools in its system prompt,
but the **CommandGuard is the actual enforcement boundary** — the model's output
is fully untrusted. `stop_reason: "refusal"` (the cyber classifier) is handled
by falling back to the deterministic analyzer. With no key configured, the
deterministic template analyzer runs — no network, no model.

## Running it

```bash
# Terminal 1 — bridge (simulation, safe mode)
cd server
cp .env.example .env         # optional; sensible defaults otherwise
npm install
npm run dev                  # http://localhost:8787

# Terminal 2 — frontend
npm install
npm run dev                  # http://localhost:5173
```

Then in the UI: open **Settings** (gear icon) → toggle **Live backend mode** →
set the base URL (and bearer token if configured) → **Test connection**. Enter a
target, set the Rules of Engagement (aggression, authorization reference), and
**Initiate Assessment** — the LiveConsole streams real PTES stage activity.

### Enabling real MCP servers

```bash
cd server
cp mcp.servers.json.example mcp.servers.json   # edit to your installed servers
# in .env:  TOOL_PROVIDER=mcp
npm run dev
```

The bridge connects to each server over stdio on boot and reports them at
`GET /api/health`. Where a server or its output normaliser is missing, that
stage falls back to simulation and says so in the log — a partial real
assessment beats a hard failure. The normalisers (`parseNmap`, `parseNuclei`, …
in `server/src/providers.ts`) are the integration seam: map each server's output
onto the shared result shape and the entire UI + PDF keep working unchanged.

**Only run scanners against systems you own or have written permission to test.**
