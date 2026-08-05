# VulnEdge

AI-powered Vulnerability Assessment and Penetration Testing (VAPT) console.
Dark-themed, military-grade operations aesthetic, built with React 18 +
TypeScript + Vite + Tailwind + shadcn/ui.

> **Two modes.** By default the frontend runs **simulation** mode — assessments
> execute entirely in the browser against a deterministic engine; no packets are
> sent. Findings are seeded from the target string, so a target always yields the
> same report. Switch on **live backend mode** (Settings → gear icon) to drive
> the Node/TypeScript **bridge**, which orchestrates real MCP security servers
> along the PTES framework with scope allow-listing, per-engagement
> authorization, and safe-mode exploitation. See **[ARCHITECTURE.md](ARCHITECTURE.md)**
> for the bridge, security middleware, and how to wire real scanners.

## Backend bridge (agentic / live mode)

The `server/` directory is an Express + MCP-client bridge. It maps the seven
PTES stages to MCP tool calls, streams live tool output to the UI over SSE, and
enforces a layered security model (input sanitization, scope guard, an
allow-list command guard that neutralises LLM-proposed commands, bearer auth).
It runs **safe by default** — exploitation plans and generates PoCs but executes
nothing until an operator deliberately flips three separate gates.

```bash
cd server && cp .env.example .env && npm install && npm run dev   # :8787
```

Then in the frontend: **Settings → Live backend mode → Test connection**. Full
details, the PTES pipeline, the safety gates, the optional Claude analyzer, and
the `claude_desktop_config.json` / `server/mcp.servers.json` templates are in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

Requires Node 18+.

```bash
npm install
npm run dev          # http://localhost:5173
```

| Script              | Purpose                                          |
| ------------------- | ------------------------------------------------ |
| `npm run dev`       | Vite dev server with HMR                          |
| `npm run build`     | Typecheck, then production build to `dist/`       |
| `npm run preview`   | Serve the production build                        |
| `npm run typecheck` | `tsc --noEmit`                                    |
| `npm run smoke`     | Run the engine test suite (validation, generators) |

## What it does

**Target specification** — accepts IPv4, IPv6 (including `::` compression, zone
IDs and embedded IPv4), CIDR blocks, domains and full URLs. Classification and
validation happen as you type, with advisories for loopback, RFC 1918, link-local,
multicast and reserved ranges, and for cleartext HTTP targets. An explicit
authorisation checkbox gates the scan button.

**Assessment profiles** — Rapid (4–7 findings), Comprehensive (8–13) and Full
Pentest (12–19). The profile changes which phases run, how many findings surface,
and whether exploit validation and lateral-movement mapping are included.

**AI configuration** — five independently toggleable modules that genuinely alter
the output: exploitability prioritisation reorders findings, false-positive
suppression filters low-confidence noise, attack-path chaining adjusts
exploitability scoring, and disabling everything removes the AI phase from the
scan pipeline.

**Live scan** — animated phase-by-phase progression with a percentage readout,
per-phase status, elapsed timer and an abort control.

**Findings** — severity-coded cards with CVSS v3.1 scores and vectors, real CVE
and CWE references, OWASP category mapping, confidence and exploitability meters,
request/response evidence, and expandable remediation detail. Filterable by
severity, with a remediation roadmap grouped by SLA.

**Reconnaissance** — subdomain discovery, DNS records, open ports with service
banners, SSL/TLS assessment with letter grade, and OS fingerprinting.

**OWASP compliance** — all ten 2021 categories scored pass/warning/fail with a
radial compliance percentage, per-category risk and specific recommendations.

**Threat intelligence** — threat level and score, attack vectors mapped to MITRE
ATT&CK technique IDs, relevant threat actors with observed tradecraft, and
strategic recommendations.

**Retest** — re-runs against the previous baseline, marking findings remediated
or still-present and recomputing the risk score.

**PDF report** — a 15+ page report via jsPDF: cover page, executive summary with
severity distribution, findings index, detailed findings with evidence,
reconnaissance tables, OWASP results, threat intelligence and methodology. jsPDF
is code-split, so it only loads when a report is requested.

## Project structure

```
src/
├── components/
│   ├── home/
│   │   ├── index.tsx                      # main console: header, tabs, scan orchestration
│   │   ├── dashboard/
│   │   │   ├── TargetSpecificationPanel.tsx
│   │   │   └── VulnerabilityDashboard.tsx
│   │   └── ui/index.ts                    # barrel re-exporting all shadcn primitives
│   └── ui/                                # the 40 shadcn/ui components
├── lib/
│   ├── utils.ts                           # cn()
│   └── vapt/
│       ├── types.ts                       # domain model
│       ├── validation.ts                  # IPv4/IPv6/domain/CIDR/URL validation
│       ├── rng.ts                         # seeded deterministic PRNG
│       ├── catalog.ts                     # finding templates with real CVE/CWE data
│       ├── generators.ts                  # findings, recon, OWASP, threat intel
│       ├── report.ts                      # jsPDF report builder
│       └── index.ts
├── App.tsx
├── main.tsx
└── index.css
scripts/smoke.ts                           # engine test suite
```

Two deliberate deviations from a literal reading of the original spec:

- `components/home/ui/` is a **barrel that re-exports** `components/ui/` rather
  than a second copy of all 40 components. One source of truth means
  `npx shadcn@latest add <component>` updates apply everywhere, and
  `import { Card } from "@/components/home/ui"` still works.
- Assessment logic lives in `lib/vapt/` rather than inside `home/index.tsx`. The
  component stays a view; the engine is independently testable (`npm run smoke`)
  and is what you replace when wiring in real scanners.

## Theming

Dark by default — `main.tsx` adds `dark` to `<html>` and `index.html` ships with
the class so there is no light flash on first paint. All colour goes through CSS
variables in `src/index.css` (`--background`, `--primary`, `--severity-critical`,
…), so retheming is a matter of editing that one block.

Custom utilities: `.glass` / `.glass-panel` / `.glass-strong` (backdrop blur),
`.glow-primary` / `.glow-danger`, `.gradient-text`, `.scan-grid`, `.scan-beam`,
`.pulse-ring`, `.hover-lift`, `.hover-glow`, and `.sev-*` severity chips.

Animations: `scan-beam`, `scan-sweep`, `pulse-ring`, `float`, `glow-pulse`,
`grid-drift`, `flicker`, `slide-up-fade`, `marquee`, plus the accordion pair. All
of them collapse under `prefers-reduced-motion`.

## Wiring in real scanners

This is now built — see [ARCHITECTURE.md](ARCHITECTURE.md). In short:

1. Run the bridge with `TOOL_PROVIDER=mcp` and a `server/mcp.servers.json`
   pointing at your installed MCP servers (nmap, nuclei, cve-search, …).
2. Fill in the output normalisers (`parseNmap`, `parseNuclei`, … in
   `server/src/providers.ts`) to map each server's output onto the shared
   `AssessmentResult` shape — the entire UI, all tabs, and the PDF report then
   keep working unchanged.
3. Authorisation, scope, and command safety are already enforced **server-side**
   in `server/src/security.ts` — the UI controls are prompts, not the boundary.

**Only run scanners against systems you own or have written permission to test.**
Unauthorised scanning is a criminal offence in most jurisdictions.

## Verification

Verified on this machine with Node 20.11.1:

- `tsc --noEmit` — clean
- `vite build` — succeeds, no warnings, largest eager chunk 213 kB
- `npm run smoke` — all engine checks pass
- PDF generation — 16-page valid PDF, all sections present
- Server-side render of the full app — no runtime errors
