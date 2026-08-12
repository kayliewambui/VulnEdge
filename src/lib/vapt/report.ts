import type { jsPDF } from "jspdf"

import { severityCounts } from "./generators"
import type { AssessmentResult, Severity, Vulnerability } from "./types"
import { describeTargetKind } from "./validation"

/* ------------------------------------------------------------------ theme */

const PAGE = { width: 595.28, height: 841.89 }
const MARGIN = 48
const CONTENT_WIDTH = PAGE.width - MARGIN * 2

type RGB = [number, number, number]

const COLOR: Record<string, RGB> = {
  ink: [15, 23, 42],
  body: [51, 65, 85],
  muted: [100, 116, 139],
  hairline: [203, 213, 225],
  panel: [241, 245, 249],
  primary: [5, 150, 105],
  primaryDark: [4, 108, 78],
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [202, 138, 4],
  low: [37, 99, 235],
  info: [100, 116, 139],
  white: [255, 255, 255],
}

const SEVERITY_COLOR: Record<Severity, RGB> = {
  Critical: COLOR.critical,
  High: COLOR.high,
  Medium: COLOR.medium,
  Low: COLOR.low,
  Info: COLOR.info,
}

/* ------------------------------------------------------------- doc helper */

/**
 * Thin layout wrapper over jsPDF: tracks the cursor, breaks pages
 * automatically, and paints the shared header/footer furniture.
 */
class ReportDoc {
  readonly doc: jsPDF
  y = MARGIN
  private readonly title: string
  private readonly classification: string

  /**
   * `JsPDF` is injected rather than imported at module scope — jspdf and its
   * optional rasterisation deps are ~370 kB, and nothing needs them until the
   * operator actually asks for a report.
   */
  constructor(
    JsPDF: typeof jsPDF,
    title: string,
    classification: string
  ) {
    this.doc = new JsPDF({ unit: "pt", format: "a4", compress: true })
    this.title = title
    this.classification = classification
  }

  /* -- primitives -- */

  private setFill(c: RGB) {
    this.doc.setFillColor(c[0], c[1], c[2])
  }

  private setText(c: RGB) {
    this.doc.setTextColor(c[0], c[1], c[2])
  }

  private setDraw(c: RGB) {
    this.doc.setDrawColor(c[0], c[1], c[2])
  }

  /** Break to a new page when `needed` points will not fit. */
  ensure(needed: number) {
    if (this.y + needed > PAGE.height - MARGIN - 28) {
      this.newPage()
    }
  }

  newPage() {
    this.doc.addPage()
    this.y = MARGIN
  }

  space(points: number) {
    this.y += points
  }

  /* -- text -- */

  heading(text: string) {
    this.ensure(52)
    this.space(8)
    this.doc.setFont("helvetica", "bold")
    this.doc.setFontSize(15)
    this.setText(COLOR.ink)
    this.doc.text(text, MARGIN, this.y)
    this.y += 8
    this.setDraw(COLOR.primary)
    this.doc.setLineWidth(1.6)
    this.doc.line(MARGIN, this.y, MARGIN + 46, this.y)
    this.y += 16
  }

  subheading(text: string) {
    this.ensure(30)
    this.doc.setFont("helvetica", "bold")
    this.doc.setFontSize(11)
    this.setText(COLOR.ink)
    this.doc.text(text, MARGIN, this.y)
    this.y += 15
  }

  paragraph(text: string, options: { size?: number; color?: RGB; indent?: number } = {}) {
    const size = options.size ?? 9.5
    const color = options.color ?? COLOR.body
    const indent = options.indent ?? 0

    this.doc.setFont("helvetica", "normal")
    this.doc.setFontSize(size)
    this.setText(color)

    const lines: string[] = this.doc.splitTextToSize(
      text,
      CONTENT_WIDTH - indent
    )
    const lineHeight = size * 1.45

    for (const line of lines) {
      this.ensure(lineHeight)
      this.doc.text(line, MARGIN + indent, this.y)
      this.y += lineHeight
    }
    this.y += 4
  }

  /** `Label: value` row with the label in a fixed-width gutter. */
  field(label: string, value: string, labelWidth = 132) {
    const size = 9.5
    this.doc.setFontSize(size)

    const lines: string[] = this.doc.splitTextToSize(
      value,
      CONTENT_WIDTH - labelWidth
    )
    const lineHeight = size * 1.42
    this.ensure(lineHeight * lines.length + 2)

    this.doc.setFont("helvetica", "bold")
    this.setText(COLOR.muted)
    this.doc.text(label, MARGIN, this.y)

    this.doc.setFont("helvetica", "normal")
    this.setText(COLOR.body)
    lines.forEach((line, i) => {
      this.doc.text(line, MARGIN + labelWidth, this.y + i * lineHeight)
    })

    this.y += lineHeight * lines.length + 2
  }

  bullets(items: string[]) {
    const size = 9.5
    const lineHeight = size * 1.45

    this.doc.setFontSize(size)
    for (const item of items) {
      const lines: string[] = this.doc.splitTextToSize(item, CONTENT_WIDTH - 16)
      this.ensure(lineHeight * lines.length + 3)

      this.setFill(COLOR.primary)
      this.doc.circle(MARGIN + 3.5, this.y - 3, 1.9, "F")

      this.doc.setFont("helvetica", "normal")
      this.setText(COLOR.body)
      lines.forEach((line, i) => {
        this.doc.text(line, MARGIN + 16, this.y + i * lineHeight)
      })

      this.y += lineHeight * lines.length + 3
    }
    this.y += 4
  }

  /* -- blocks -- */

  panel(lines: Array<[string, string]>) {
    const rowHeight = 16
    const height = lines.length * rowHeight + 16
    this.ensure(height + 8)

    this.setFill(COLOR.panel)
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, height, 4, 4, "F")

    let rowY = this.y + 18
    for (const [label, value] of lines) {
      this.doc.setFont("helvetica", "bold")
      this.doc.setFontSize(9)
      this.setText(COLOR.muted)
      this.doc.text(label, MARGIN + 14, rowY)

      this.doc.setFont("helvetica", "normal")
      this.setText(COLOR.ink)
      this.doc.text(value, MARGIN + 160, rowY)

      rowY += rowHeight
    }

    this.y += height + 12
  }

  /** Severity distribution strip used on the summary page. */
  severityBar(counts: Record<Severity, number>) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0)
    if (total === 0) return

    const barHeight = 16
    this.ensure(barHeight + 34)

    let x = MARGIN
    const order: Severity[] = ["Critical", "High", "Medium", "Low", "Info"]

    for (const severity of order) {
      const count = counts[severity]
      if (!count) continue
      const width = (count / total) * CONTENT_WIDTH
      this.setFill(SEVERITY_COLOR[severity])
      this.doc.rect(x, this.y, width, barHeight, "F")
      x += width
    }

    this.y += barHeight + 14

    // Legend
    let legendX = MARGIN
    this.doc.setFontSize(8)
    for (const severity of order) {
      const count = counts[severity]
      if (!count) continue
      this.setFill(SEVERITY_COLOR[severity])
      this.doc.rect(legendX, this.y - 6, 7, 7, "F")
      this.doc.setFont("helvetica", "normal")
      this.setText(COLOR.body)
      this.doc.text(`${severity} (${count})`, legendX + 11, this.y)
      legendX += this.doc.getTextWidth(`${severity} (${count})`) + 30
    }

    this.y += 18
  }

  table(headers: string[], rows: string[][], widths: number[]) {
    const headerHeight = 20
    const size = 8.2
    const lineHeight = size * 1.35

    const drawHeader = () => {
      this.setFill(COLOR.ink)
      this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, "F")
      this.doc.setFont("helvetica", "bold")
      this.doc.setFontSize(size)
      this.setText(COLOR.white)

      let x = MARGIN + 8
      headers.forEach((h, i) => {
        this.doc.text(h, x, this.y + 13)
        x += widths[i]
      })
      this.y += headerHeight
    }

    this.ensure(headerHeight + 40)
    drawHeader()

    rows.forEach((row, rowIndex) => {
      // Pre-measure so a row never straddles a page break.
      this.doc.setFont("helvetica", "normal")
      this.doc.setFontSize(size)

      const cells = row.map((cell, i) =>
        this.doc.splitTextToSize(cell, widths[i] - 12)
      )
      const rowHeight =
        Math.max(...cells.map((c) => c.length)) * lineHeight + 10

      if (this.y + rowHeight > PAGE.height - MARGIN - 28) {
        this.newPage()
        drawHeader()
      }

      if (rowIndex % 2 === 1) {
        this.setFill(COLOR.panel)
        this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, rowHeight, "F")
      }

      let x = MARGIN + 8
      cells.forEach((cellLines, i) => {
        this.setText(COLOR.body)
        cellLines.forEach((line: string, lineIndex: number) => {
          this.doc.text(line, x, this.y + 12 + lineIndex * lineHeight)
        })
        x += widths[i]
      })

      this.setDraw(COLOR.hairline)
      this.doc.setLineWidth(0.4)
      this.doc.line(MARGIN, this.y + rowHeight, PAGE.width - MARGIN, this.y + rowHeight)

      this.y += rowHeight
    })

    this.y += 12
  }

  severityChip(severity: Severity, x: number, y: number) {
    const label = severity.toUpperCase()
    this.doc.setFont("helvetica", "bold")
    this.doc.setFontSize(7.5)
    const width = this.doc.getTextWidth(label) + 14

    this.setFill(SEVERITY_COLOR[severity])
    this.doc.roundedRect(x, y - 8, width, 13, 2.5, 2.5, "F")
    this.setText(COLOR.white)
    this.doc.text(label, x + 7, y + 1)

    return width
  }

  /* -- furniture -- */

  finalise() {
    const pageCount = this.doc.getNumberOfPages()

    // Page 1 is the cover — it carries no running header.
    for (let page = 2; page <= pageCount; page++) {
      this.doc.setPage(page)

      this.doc.setFont("helvetica", "normal")
      this.doc.setFontSize(7.5)
      this.setText(COLOR.muted)
      this.doc.text(this.title, MARGIN, 30)
      this.doc.text(this.classification, PAGE.width - MARGIN, 30, {
        align: "right",
      })

      this.setDraw(COLOR.hairline)
      this.doc.setLineWidth(0.5)
      this.doc.line(MARGIN, 36, PAGE.width - MARGIN, 36)

      this.doc.line(
        MARGIN,
        PAGE.height - MARGIN + 6,
        PAGE.width - MARGIN,
        PAGE.height - MARGIN + 6
      )
      this.doc.text(
        "Generated by VulnEdge — AI-Powered VAPT Platform",
        MARGIN,
        PAGE.height - MARGIN + 20
      )
      this.doc.text(
        `Page ${page} of ${pageCount}`,
        PAGE.width - MARGIN,
        PAGE.height - MARGIN + 20,
        { align: "right" }
      )
    }
  }
}

/* ------------------------------------------------------------------ pages */

function drawCover(rd: ReportDoc, result: AssessmentResult, generatedAt: Date) {
  const d = rd.doc

  // Dark banner
  d.setFillColor(COLOR.ink[0], COLOR.ink[1], COLOR.ink[2])
  d.rect(0, 0, PAGE.width, 300, "F")

  d.setFillColor(COLOR.primary[0], COLOR.primary[1], COLOR.primary[2])
  d.rect(0, 296, PAGE.width, 4, "F")

  d.setFont("helvetica", "bold")
  d.setFontSize(34)
  d.setTextColor(255, 255, 255)
  d.text("VulnEdge", MARGIN, 116)

  d.setFont("helvetica", "normal")
  d.setFontSize(11)
  d.setTextColor(COLOR.primary[0] + 60, 220, 180)
  d.text("AI-POWERED VULNERABILITY ASSESSMENT & PENETRATION TESTING", MARGIN, 138)

  d.setFont("helvetica", "bold")
  d.setFontSize(20)
  d.setTextColor(255, 255, 255)
  d.text("Security Assessment Report", MARGIN, 196)

  d.setFont("helvetica", "normal")
  d.setFontSize(13)
  d.setTextColor(203, 213, 225)
  d.text(result.target, MARGIN, 220)

  d.setFontSize(9)
  d.setTextColor(148, 163, 184)
  d.text(
    `${describeTargetKind(result.targetKind)}  ·  ${result.profile.toUpperCase()} PROFILE`,
    MARGIN,
    240
  )

  rd.y = 344

  const counts = severityCounts(result.vulnerabilities)

  rd.panel([
    ["Target", result.target],
    ["Target class", describeTargetKind(result.targetKind)],
    ["Assessment profile", result.profile.toUpperCase()],
    ["Scan started", new Date(result.startedAt).toLocaleString()],
    ["Scan completed", new Date(result.completedAt).toLocaleString()],
    ["Duration", `${result.durationSeconds}s`],
    ["Report generated", generatedAt.toLocaleString()],
    ["Total findings", String(result.vulnerabilities.length)],
    ["Aggregate risk score", `${result.riskScore} / 100`],
    ["OWASP compliance", `${result.owasp.compliancePercentage}%`],
  ])

  rd.subheading("Findings by Severity")
  rd.severityBar(counts)

  rd.space(8)
  rd.paragraph(
    "CONFIDENTIAL — This report contains sensitive information about security weaknesses in the assessed target. Distribute only to personnel authorised to receive it, and store it in accordance with your organisation's data classification policy.",
    { size: 8.5, color: COLOR.muted }
  )

  if (result.provider !== "mcp") {
    rd.paragraph(
      "SIMULATED OUTPUT — This build of VulnEdge synthesises findings locally for demonstration and training. No packets were sent to the named target and no live testing was performed. Do not present these results as evidence of a real engagement.",
      { size: 8.5, color: COLOR.critical }
    )
  }
}

function drawExecutiveSummary(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("1. Executive Summary")

  const counts = severityCounts(result.vulnerabilities)
  const critical = counts.Critical
  const high = counts.High
  const exploitable = result.vulnerabilities.filter((v) => v.exploitAvailable).length

  const posture =
    critical > 0
      ? "requires immediate remediation"
      : high > 0
        ? "requires prioritised remediation"
        : "is broadly sound with residual hardening opportunities"

  rd.paragraph(
    `An automated vulnerability assessment and penetration test was performed against ${result.target} using the ${result.profile.toUpperCase()} profile. The assessment identified ${result.vulnerabilities.length} finding${result.vulnerabilities.length === 1 ? "" : "s"}, of which ${critical} ${critical === 1 ? "is" : "are"} rated Critical and ${high} High. The overall security posture ${posture}.`
  )

  rd.paragraph(
    `The aggregate risk score for this target is ${result.riskScore} out of 100, and the current threat level is assessed as ${result.threatIntel.threatLevel}. ${result.threatIntel.summary}`
  )

  if (exploitable > 0) {
    rd.paragraph(
      `${exploitable} of the identified findings have publicly available exploit code. These should be treated as the highest priority regardless of their raw CVSS score, since exploitation requires no original research on the attacker's part.`
    )
  }

  rd.subheading("Key Metrics")
  rd.panel([
    ["Total findings", String(result.vulnerabilities.length)],
    ["Critical / High", `${critical} / ${high}`],
    ["Medium / Low / Info", `${counts.Medium} / ${counts.Low} / ${counts.Info}`],
    ["Publicly exploitable", String(exploitable)],
    ["Aggregate risk score", `${result.riskScore} / 100`],
    ["Threat level", result.threatIntel.threatLevel],
    ["OWASP Top 10 compliance", `${result.owasp.compliancePercentage}%`],
    ["Controls failed", `${result.owasp.failed} of 10`],
    ["Live subdomains", String(result.recon.subdomains.filter((s) => s.status === "live").length)],
    ["Open ports", String(result.recon.openPorts.filter((p) => p.state === "open").length)],
    ["TLS grade", result.recon.ssl.grade],
  ])

  rd.subheading("Priority Actions")
  rd.bullets(result.threatIntel.recommendations.slice(0, 5))
}

function drawFindings(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("2. Vulnerability Findings")

  rd.paragraph(
    "Findings are ordered by remediation priority. Each entry states the weakness, its measured impact, and the specific action required to close it. CVSS values are v3.1 base scores."
  )

  // Index table first — lets a reader triage before reading detail.
  rd.subheading("2.1 Findings Index")
  rd.table(
    ["ID", "Finding", "Severity", "CVSS", "CWE"],
    result.vulnerabilities.map((v) => [
      v.id,
      v.title,
      v.severity,
      v.cvss.toFixed(1),
      v.cwe,
    ]),
    [96, 232, 60, 44, 66]
  )

  rd.subheading("2.2 Detailed Findings")

  result.vulnerabilities.forEach((v, index) => {
    drawFinding(rd, v, index + 1)
  })
}

function drawFinding(rd: ReportDoc, v: Vulnerability, ordinal: number) {
  const d = rd.doc

  rd.ensure(150)
  rd.space(10)

  // Severity accent bar down the left edge of the title block.
  const color = SEVERITY_COLOR[v.severity]
  d.setFillColor(color[0], color[1], color[2])
  d.rect(MARGIN, rd.y - 10, 3, 26, "F")

  d.setFont("helvetica", "bold")
  d.setFontSize(11)
  d.setTextColor(COLOR.ink[0], COLOR.ink[1], COLOR.ink[2])
  const titleLines: string[] = d.splitTextToSize(
    `2.2.${ordinal}  ${v.title}`,
    CONTENT_WIDTH - 12
  )
  titleLines.forEach((line, i) => {
    d.text(line, MARGIN + 12, rd.y + i * 14)
  })
  rd.y += titleLines.length * 14 + 6

  const chipWidth = rd.severityChip(v.severity, MARGIN + 12, rd.y)

  d.setFont("helvetica", "normal")
  d.setFontSize(8)
  d.setTextColor(COLOR.muted[0], COLOR.muted[1], COLOR.muted[2])
  d.text(
    `${v.id}  ·  CVSS ${v.cvss.toFixed(1)}  ·  ${v.cwe}${v.cve ? `  ·  ${v.cve}` : ""}`,
    MARGIN + 12 + chipWidth + 10,
    rd.y
  )
  rd.y += 18

  rd.field("Affected component", `${v.affectedComponent}${v.port ? ` (port ${v.port})` : ""}`)
  rd.field("OWASP category", v.owasp)
  rd.field("CVSS vector", v.cvssVector)
  rd.field("Confidence", `${v.confidence}%`)
  rd.field("Exploitability score", `${v.exploitability}/100`)
  rd.field(
    "Public exploit",
    v.exploitAvailable ? "Yes — weaponised code is publicly available" : "None identified"
  )
  if (v.retestStatus && v.retestStatus !== "unverified") {
    rd.field(
      "Retest status",
      v.retestStatus === "remediated" ? "Remediated — no longer reproducible" : "Still present"
    )
  }

  rd.space(6)
  rd.subheading("Description")
  rd.paragraph(v.description)

  rd.subheading("Impact")
  rd.paragraph(v.impact)

  if (v.evidence?.request || v.evidence?.response) {
    rd.subheading("Evidence")
    const evidence = [v.evidence.request, v.evidence.response]
      .filter(Boolean)
      .join("\n\n")

    d.setFont("courier", "normal")
    d.setFontSize(7.5)
    const lines: string[] = d.splitTextToSize(evidence, CONTENT_WIDTH - 20)
    const height = lines.length * 10 + 16

    rd.ensure(height + 6)
    d.setFillColor(COLOR.panel[0], COLOR.panel[1], COLOR.panel[2])
    d.roundedRect(MARGIN, rd.y - 8, CONTENT_WIDTH, height, 3, 3, "F")

    d.setTextColor(COLOR.ink[0], COLOR.ink[1], COLOR.ink[2])
    lines.forEach((line: string, i: number) => {
      d.text(line, MARGIN + 10, rd.y + 6 + i * 10)
    })
    rd.y += height + 8

    if (v.evidence.note) {
      rd.paragraph(v.evidence.note, { size: 8.5, color: COLOR.muted })
    }
  }

  rd.subheading("Remediation")
  rd.paragraph(v.remediation)

  if (v.references.length) {
    rd.subheading("References")
    rd.bullets(v.references)
  }

  rd.space(4)
  rd.doc.setDrawColor(COLOR.hairline[0], COLOR.hairline[1], COLOR.hairline[2])
  rd.doc.setLineWidth(0.5)
  rd.ensure(10)
  rd.doc.line(MARGIN, rd.y, PAGE.width - MARGIN, rd.y)
  rd.space(6)
}

function drawRecon(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("3. Reconnaissance")

  const { recon } = result

  rd.subheading("3.1 Registration & Infrastructure")
  rd.panel([
    ["Registrar", recon.whois.registrar],
    ["Registered", recon.whois.created],
    ["Expires", recon.whois.expires],
    ["Autonomous system", recon.whois.asn],
    ["Technologies", recon.technologies.slice(0, 4).join(", ")],
  ])

  rd.subheading("3.2 Subdomain Discovery")
  rd.table(
    ["Subdomain", "Address", "State", "Technology", "Risk"],
    recon.subdomains.map((s) => [s.name, s.ip, s.status, s.technology, s.risk]),
    [150, 92, 52, 118, 86]
  )

  rd.subheading("3.3 DNS Records")
  rd.table(
    ["Type", "Name", "Value", "TTL"],
    recon.dnsRecords.map((r) => [r.type, r.name, r.value, String(r.ttl)]),
    [46, 122, 288, 42]
  )

  rd.subheading("3.4 Open Ports & Services")
  rd.table(
    ["Port", "Proto", "State", "Service", "Version", "Risk"],
    recon.openPorts.map((p) => [
      String(p.port),
      p.protocol,
      p.state,
      p.service,
      p.version,
      p.risk,
    ]),
    [44, 44, 76, 92, 148, 94]
  )

  rd.subheading("3.5 TLS / SSL Assessment")
  rd.panel([
    ["Overall grade", recon.ssl.grade],
    ["Negotiated protocol", recon.ssl.protocol],
    ["Cipher suite", recon.ssl.cipherSuite],
    ["Key exchange", recon.ssl.keyExchange],
    ["Certificate issuer", recon.ssl.certificateIssuer],
    ["Certificate expiry", `${recon.ssl.certificateExpiry} (${recon.ssl.daysUntilExpiry} days)`],
    ["HSTS", recon.ssl.hsts ? "Enabled" : "Not enabled"],
    ["OCSP stapling", recon.ssl.ocspStapling ? "Enabled" : "Not enabled"],
    ["Forward secrecy", recon.ssl.forwardSecrecy ? "Supported" : "Not supported"],
  ])
  rd.subheading("TLS Observations")
  rd.bullets(recon.ssl.issues)

  rd.subheading("3.6 Operating System Fingerprint")
  rd.panel([
    ["OS family", recon.os.osFamily],
    ["Version", recon.os.osVersion],
    ["Kernel / build", recon.os.kernel],
    ["Device type", recon.os.deviceType],
    ["Detection accuracy", `${recon.os.accuracy}%`],
    ["TTL signature", String(recon.os.ttlSignature)],
    ["Estimated uptime", recon.os.uptimeGuess],
  ])
  rd.paragraph(`Detection method: ${recon.os.method}`, {
    size: 8.5,
    color: COLOR.muted,
  })
}

function drawOwasp(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("4. OWASP Top 10 (2021) Compliance")

  const { owasp } = result

  rd.paragraph(
    `The target was evaluated against all ten OWASP Top 10 2021 categories. ${owasp.passed} categor${owasp.passed === 1 ? "y" : "ies"} passed, ${owasp.warnings} raised warnings, and ${owasp.failed} failed. Overall compliance stands at ${owasp.compliancePercentage}%, with an aggregate control risk rated ${owasp.overallRisk}.`
  )

  rd.panel([
    ["Compliance", `${owasp.compliancePercentage}%`],
    ["Passed", `${owasp.passed} of 10`],
    ["Warnings", `${owasp.warnings} of 10`],
    ["Failed", `${owasp.failed} of 10`],
    ["Overall control risk", owasp.overallRisk],
  ])

  rd.subheading("4.1 Category Results")
  rd.table(
    ["ID", "Category", "Status", "Findings", "Risk"],
    owasp.categories.map((c) => [
      c.id,
      c.name,
      c.status.toUpperCase(),
      String(c.findings),
      `${c.riskScore}/100`,
    ]),
    [40, 246, 78, 70, 64]
  )

  rd.subheading("4.2 Recommendations by Category")
  owasp.categories
    .filter((c) => c.status !== "pass")
    .forEach((c) => {
      rd.ensure(60)
      rd.subheading(`${c.id} — ${c.name}  (${c.status.toUpperCase()})`)
      rd.paragraph(c.description, { size: 9, color: COLOR.muted })
      rd.paragraph(c.recommendation)
    })

  if (owasp.categories.every((c) => c.status === "pass")) {
    rd.paragraph(
      "No OWASP Top 10 categories require remediation. Maintain current controls and re-verify on each release."
    )
  }
}

function drawThreatIntel(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("5. Threat Intelligence")

  const { threatIntel } = result

  rd.panel([
    ["Threat level", threatIntel.threatLevel],
    ["Threat score", `${threatIntel.threatScore} / 100`],
    ["Exposure score", `${threatIntel.exposureScore} / 100`],
    ["Dark web mentions", String(threatIntel.darkWebMentions)],
  ])

  rd.paragraph(threatIntel.summary)

  rd.subheading("5.1 Attack Vectors")
  threatIntel.attackVectors.forEach((vector) => {
    rd.ensure(70)
    rd.subheading(`${vector.name}  (${vector.mitreId})`)
    rd.field("Likelihood", vector.likelihood, 92)
    rd.field("Impact", vector.impact, 92)
    rd.paragraph(vector.description)
    rd.paragraph(`Mitigation: ${vector.mitigation}`, { size: 9, color: COLOR.muted })
  })

  rd.subheading("5.2 Relevant Threat Actors")
  threatIntel.industryThreats.forEach((threat) => {
    rd.ensure(90)
    rd.subheading(threat.actor)
    rd.field("Motivation", threat.motivation, 106)
    rd.field("Sophistication", threat.sophistication, 106)
    rd.field("Targeted sectors", threat.targetedSectors.join(", "), 106)
    rd.field("Current activity", threat.activity, 106)
    rd.paragraph("Observed tradecraft:", { size: 9, color: COLOR.muted })
    rd.bullets(threat.ttps)
  })

  rd.subheading("5.3 Strategic Recommendations")
  rd.bullets(threatIntel.recommendations)
}

function drawMethodology(rd: ReportDoc, result: AssessmentResult) {
  rd.newPage()
  rd.heading("6. Methodology")

  rd.paragraph(
    "The assessment followed a structured methodology aligned to the Penetration Testing Execution Standard (PTES), the OWASP Web Security Testing Guide (WSTG) and NIST SP 800-115. The phases below were executed in sequence."
  )

  rd.table(
    ["Phase", "Activity"],
    [
      ["Authorisation", "Confirmation of engagement scope, target ownership and rules of engagement before any active probing."],
      ["Passive reconnaissance", "WHOIS and registration data, DNS enumeration, certificate transparency log review, and public source collection. No traffic to the target."],
      ["Host discovery", "ICMP echo, TCP SYN probing and ARP resolution to establish which hosts in scope are reachable."],
      ["Service enumeration", "Port scanning across the profile's range, with banner grabbing and service version identification."],
      ["Fingerprinting", "TCP/IP stack analysis and technology identification to establish the platform baseline."],
      ["Cryptographic audit", "TLS protocol and cipher suite negotiation testing, certificate chain validation and header inspection."],
      ["Vulnerability analysis", "Correlation of enumerated services and versions against CVE, CWE and vendor advisory data."],
      ["AI correlation", "Model-assisted scoring of exploitability, suppression of probable false positives, and chaining of findings into attack paths."],
      ["Exploit validation", "Where the profile permits, non-destructive confirmation of findings against the live target to eliminate false positives."],
      ["Reporting", "Consolidation of findings with severity rating, OWASP mapping, business impact and prioritised remediation."],
    ],
    [110, 366]
  )

  rd.subheading("6.1 Severity Rating")
  rd.paragraph(
    "Severity is derived from the CVSS v3.1 base score, then adjusted for exploit availability and the specific exposure of the affected component. Ratings map to CVSS bands as follows: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, Informational 0.0."
  )

  rd.subheading("6.2 Scope and Limitations")
  rd.bullets([
    `Assessment was limited to ${result.target} using the ${result.profile.toUpperCase()} profile.`,
    "Findings reflect the target state at the time of the scan; subsequent changes are not represented.",
    "An absence of findings in a category is not proof that no weakness exists — only that none was identified by the techniques applied.",
    "Denial-of-service conditions were identified by configuration analysis, not by inducing service disruption.",
    "This build synthesises results locally for demonstration. No live testing was performed against the named target.",
  ])

  rd.subheading("6.3 Retest Guidance")
  rd.paragraph(
    "Re-run the assessment once remediation is deployed. Use the retest function to compare against this baseline so that closed findings are recorded and any regression is surfaced. Critical and High findings should be retested individually as soon as each fix reaches production rather than waiting for a full cycle."
  )
}

/* ----------------------------------------------------------------- public */

export interface ReportOptions {
  classification?: string
  filename?: string
}

/** Build the report and return the jsPDF instance (unsaved). */
export async function buildReport(
  result: AssessmentResult,
  options: ReportOptions = {}
): Promise<jsPDF> {
  const { jsPDF: JsPDF } = await import("jspdf")

  const classification = options.classification ?? "CONFIDENTIAL"
  const generatedAt = new Date()

  const rd = new ReportDoc(
    JsPDF,
    `VulnEdge Security Assessment — ${result.target}`,
    classification
  )

  drawCover(rd, result, generatedAt)
  drawExecutiveSummary(rd, result)
  drawFindings(rd, result)
  drawRecon(rd, result)
  drawOwasp(rd, result)
  drawThreatIntel(rd, result)
  drawMethodology(rd, result)

  rd.finalise()

  rd.doc.setProperties({
    title: `VulnEdge Assessment — ${result.target}`,
    subject: "Vulnerability Assessment and Penetration Test Report",
    author: "VulnEdge",
    keywords: `VAPT, ${result.target}, OWASP, ${result.profile}`,
    creator: "VulnEdge AI-Powered VAPT Platform",
  })

  return rd.doc
}

export function reportFilename(result: AssessmentResult): string {
  const safeTarget = result.target.replace(/[^a-z0-9.-]/gi, "_").slice(0, 60)
  const stamp = new Date().toISOString().slice(0, 10)
  return `VulnEdge_${safeTarget}_${result.profile}_${stamp}.pdf`
}

/** Build and trigger a browser download. Resolves with the filename used. */
export async function downloadReport(
  result: AssessmentResult,
  options: ReportOptions = {}
): Promise<string> {
  const doc = await buildReport(result, options)
  const filename = options.filename ?? reportFilename(result)
  doc.save(filename)
  return filename
}
