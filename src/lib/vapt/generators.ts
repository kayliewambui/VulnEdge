import { templatesFor, type Applicability, type VulnTemplate } from "./catalog"
import { createRng, type Rng } from "./rng"
import type {
  AssessmentResult,
  AttackVector,
  DnsRecord,
  IndustryThreat,
  OpenPort,
  OsFingerprint,
  OwaspCategory,
  OwaspCompliance,
  ReconResult,
  ScanConfig,
  ScanPhase,
  ScanProfile,
  Severity,
  SslAssessment,
  Subdomain,
  TargetKind,
  ThreatIntelligence,
  Vulnerability,
} from "./types"
import { SEVERITY_WEIGHT } from "./types"

// ---------------------------------------------------------------- PROFILES

export const PROFILE_META: Record<
  ScanProfile,
  { label: string; blurb: string; findings: [number, number]; minutes: number }
> = {
  rapid: {
    label: "Rapid Assessment",
    blurb: "Surface sweep — top ports, banner grab, passive checks. ~2 min.",
    findings: [4, 7],
    minutes: 2,
  },
  comprehensive: {
    label: "Comprehensive Scan",
    blurb: "Full port range, authenticated web crawl, TLS and config audit.",
    findings: [8, 13],
    minutes: 18,
  },
  pentest: {
    label: "Full Penetration Test",
    blurb: "Comprehensive plus exploit validation and lateral-movement mapping.",
    findings: [12, 19],
    minutes: 45,
  },
}

const BASE_PHASES: ScanPhase[] = [
  {
    id: "authz",
    label: "Authorisation Check",
    detail: "Validating engagement scope and target ownership",
    weight: 0.04,
  },
  {
    id: "recon",
    label: "Passive Reconnaissance",
    detail: "WHOIS, DNS enumeration, certificate transparency logs",
    weight: 0.12,
  },
  {
    id: "discovery",
    label: "Host Discovery",
    detail: "ICMP sweep, TCP SYN probes, ARP resolution",
    weight: 0.1,
  },
  {
    id: "portscan",
    label: "Port & Service Scan",
    detail: "Enumerating listening services and grabbing banners",
    weight: 0.16,
  },
  {
    id: "fingerprint",
    label: "OS & Stack Fingerprinting",
    detail: "TCP/IP stack analysis and technology identification",
    weight: 0.1,
  },
  {
    id: "tls",
    label: "TLS / Crypto Audit",
    detail: "Protocol versions, cipher suites, certificate chain",
    weight: 0.08,
  },
  {
    id: "vulnscan",
    label: "Vulnerability Analysis",
    detail: "Correlating services against CVE and weakness databases",
    weight: 0.2,
  },
  {
    id: "ai",
    label: "AI Correlation",
    detail: "Scoring exploitability and chaining attack paths",
    weight: 0.1,
  },
  {
    id: "report",
    label: "Report Synthesis",
    detail: "Compiling findings, OWASP mapping and remediation guidance",
    weight: 0.1,
  },
]

/** Phase list for a profile. Rapid skips the deep stages. */
export function phasesFor(profile: ScanProfile, aiEnabled: boolean): ScanPhase[] {
  let phases = BASE_PHASES

  if (profile === "rapid") {
    phases = phases.filter((p) => !["tls", "fingerprint"].includes(p.id))
  }

  if (!aiEnabled) {
    phases = phases.filter((p) => p.id !== "ai")
  }

  if (profile === "pentest") {
    phases = [
      ...phases.slice(0, -1),
      {
        id: "exploit",
        label: "Exploit Validation",
        detail: "Safely confirming findings against the live target",
        weight: 0.18,
      },
      {
        id: "lateral",
        label: "Lateral Movement Mapping",
        detail: "Modelling post-compromise reachability",
        weight: 0.1,
      },
      phases[phases.length - 1],
    ]
  }

  // Renormalise so weights always sum to 1.
  const total = phases.reduce((sum, p) => sum + p.weight, 0)
  return phases.map((p) => ({ ...p, weight: p.weight / total }))
}

// ------------------------------------------------------------ APPLICABILITY

function applicabilityFor(kind: TargetKind): Applicability[] {
  switch (kind) {
    case "url":
      return ["web"]
    case "domain":
      return ["web", "network", "host"]
    case "ipv4":
    case "ipv6":
      return ["network", "host", "web"]
    case "cidr":
      return ["network", "host"]
    default:
      return ["web", "network", "host"]
  }
}

// ---------------------------------------------------------- VULNERABILITIES

/** Weighted draw without replacement, honouring each template's frequency. */
function drawTemplates(
  rng: Rng,
  pool: VulnTemplate[],
  count: number
): VulnTemplate[] {
  const remaining = [...pool]
  const drawn: VulnTemplate[] = []

  while (drawn.length < count && remaining.length > 0) {
    const totalWeight = remaining.reduce((s, t) => s + t.frequency, 0)
    let roll = rng.float(0, totalWeight)
    let index = 0

    for (let i = 0; i < remaining.length; i++) {
      roll -= remaining[i].frequency
      if (roll <= 0) {
        index = i
        break
      }
    }

    drawn.push(remaining[index])
    remaining.splice(index, 1)
  }

  return drawn
}

function severityRank(severity: Severity): number {
  return SEVERITY_WEIGHT[severity]
}

export function generateVulnerabilities(
  config: ScanConfig,
  kind: TargetKind,
  rng: Rng,
  discoveredAt: string
): Vulnerability[] {
  const pool = templatesFor(applicabilityFor(kind))
  const [min, max] = PROFILE_META[config.profile].findings
  const count = rng.int(min, max)

  const templates = drawTemplates(rng, pool, count)

  let findings: Vulnerability[] = templates.map((t, i) => {
    // Confidence is higher when an exploit was actually validated.
    const validated = config.profile === "pentest" && t.exploitAvailable
    const baseConfidence = validated ? rng.int(94, 99) : rng.int(72, 93)

    const exploitability = Math.min(
      100,
      Math.round(
        t.cvss * 8 +
          (t.exploitAvailable ? 18 : 0) +
          (config.ai.exploitChaining ? rng.int(0, 6) : 0) -
          rng.int(0, 12)
      )
    )

    return {
      id: `VE-${String(i + 1).padStart(3, "0")}-${t.key.toUpperCase().slice(0, 6)}`,
      title: t.title,
      severity: t.severity,
      cvss: t.cvss,
      cvssVector: t.cvssVector,
      cve: t.cve,
      cwe: t.cwe,
      owasp: t.owasp,
      category: t.category,
      affectedComponent: t.component,
      port: t.port,
      description: t.description,
      impact: t.impact,
      remediation: t.remediation,
      confidence: baseConfidence,
      exploitability: Math.max(5, exploitability),
      exploitAvailable: t.exploitAvailable,
      references: t.references,
      evidence: t.evidence,
      retestStatus: "unverified",
      discoveredAt,
    }
  })

  // AI false-positive filtering drops the least-confident low-impact noise.
  if (config.ai.falsePositiveFiltering) {
    findings = findings.filter(
      (f) => f.confidence >= 78 || severityRank(f.severity) >= 6
    )
  }

  // AI prioritisation reorders by practical exploitability rather than raw CVSS.
  findings.sort((a, b) => {
    if (config.ai.aiPrioritisation) {
      const scoreA = a.exploitability * 0.6 + severityRank(a.severity) * 4
      const scoreB = b.exploitability * 0.6 + severityRank(b.severity) * 4
      if (scoreB !== scoreA) return scoreB - scoreA
    }
    if (severityRank(b.severity) !== severityRank(a.severity)) {
      return severityRank(b.severity) - severityRank(a.severity)
    }
    return b.cvss - a.cvss
  })

  return findings
}

// ------------------------------------------------------------------- RECON

const TECH_STACKS = [
  "nginx 1.24.0",
  "Apache httpd 2.4.57",
  "Cloudflare",
  "React 18.2",
  "Next.js 14.1",
  "Node.js 20.11",
  "PostgreSQL 15.4",
  "Redis 7.2",
  "Kubernetes 1.28",
  "Elasticsearch 8.11",
  "WordPress 6.4",
  "Django 4.2",
  "Spring Boot 3.2",
  "HAProxy 2.8",
  "Varnish 7.4",
]

const SUBDOMAIN_PREFIXES = [
  "www",
  "api",
  "mail",
  "vpn",
  "dev",
  "staging",
  "admin",
  "portal",
  "cdn",
  "git",
  "jenkins",
  "grafana",
  "sso",
  "docs",
  "status",
  "legacy",
  "backup",
  "test",
  "internal",
  "mx1",
]

const SERVICE_TABLE: Array<{
  port: number
  service: string
  versions: string[]
  risk: Severity
}> = [
  { port: 21, service: "ftp", versions: ["vsftpd 3.0.5", "ProFTPD 1.3.8"], risk: "High" },
  { port: 22, service: "ssh", versions: ["OpenSSH 9.6p1", "OpenSSH 7.6p1"], risk: "Low" },
  { port: 23, service: "telnet", versions: ["Linux telnetd"], risk: "Critical" },
  { port: 25, service: "smtp", versions: ["Postfix smtpd", "Exim 4.97"], risk: "Medium" },
  { port: 53, service: "domain", versions: ["ISC BIND 9.18.24", "dnsmasq 2.90"], risk: "Medium" },
  { port: 80, service: "http", versions: ["nginx 1.24.0", "Apache httpd 2.4.57"], risk: "Medium" },
  { port: 110, service: "pop3", versions: ["Dovecot pop3d"], risk: "Medium" },
  { port: 143, service: "imap", versions: ["Dovecot imapd"], risk: "Low" },
  { port: 161, service: "snmp", versions: ["net-snmp 5.9.4"], risk: "High" },
  { port: 443, service: "https", versions: ["nginx 1.24.0", "Cloudflare"], risk: "Low" },
  { port: 445, service: "microsoft-ds", versions: ["Samba 4.19.4", "Windows Server 2019"], risk: "High" },
  { port: 1433, service: "ms-sql-s", versions: ["Microsoft SQL Server 2019"], risk: "High" },
  { port: 3306, service: "mysql", versions: ["MySQL 8.0.36", "MariaDB 10.11.6"], risk: "High" },
  { port: 3389, service: "ms-wbt-server", versions: ["Microsoft Terminal Services"], risk: "Critical" },
  { port: 5432, service: "postgresql", versions: ["PostgreSQL 15.4"], risk: "High" },
  { port: 6379, service: "redis", versions: ["Redis 7.2.4"], risk: "Critical" },
  { port: 8080, service: "http-proxy", versions: ["Apache Tomcat 10.1.18", "Jetty 12.0.5"], risk: "Medium" },
  { port: 8443, service: "https-alt", versions: ["Apache Tomcat 10.1.18"], risk: "Medium" },
  { port: 9200, service: "elasticsearch", versions: ["Elasticsearch 8.11.3"], risk: "High" },
  { port: 27017, service: "mongodb", versions: ["MongoDB 7.0.5"], risk: "Critical" },
]

function randomIp(rng: Rng): string {
  return [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join(".")
}

function baseDomainFor(target: string, kind: TargetKind): string {
  if (kind === "url") {
    try {
      return new URL(target).hostname
    } catch {
      return target
    }
  }
  if (kind === "domain") return target
  return `${target.replace(/[^a-z0-9]/gi, "-")}.internal`
}

function registrableDomain(host: string): string {
  const parts = host.split(".")
  return parts.length > 2 ? parts.slice(-2).join(".") : host
}

function generateSubdomains(rng: Rng, host: string, profile: ScanProfile): Subdomain[] {
  const root = registrableDomain(host)
  const count = profile === "rapid" ? rng.int(3, 6) : rng.int(7, 14)

  return rng.sample(SUBDOMAIN_PREFIXES, count).map((prefix) => {
    const live = rng.chance(0.78)
    const risky = ["admin", "legacy", "backup", "test", "dev", "staging", "internal", "jenkins"]
    const isRisky = risky.includes(prefix)

    return {
      name: `${prefix}.${root}`,
      ip: randomIp(rng),
      status: live ? "live" : "inactive",
      technology: rng.pick(TECH_STACKS),
      risk: !live
        ? "Info"
        : isRisky
          ? rng.pick<Severity>(["High", "Critical", "Medium"])
          : rng.pick<Severity>(["Low", "Info", "Medium"]),
    }
  })
}

function generateDnsRecords(rng: Rng, host: string): DnsRecord[] {
  const root = registrableDomain(host)
  const records: DnsRecord[] = [
    { type: "A", name: root, value: randomIp(rng), ttl: rng.pick([300, 600, 3600]) },
    {
      type: "AAAA",
      name: root,
      value: `2606:4700:${rng.int(16, 65535).toString(16)}::${rng.int(16, 65535).toString(16)}`,
      ttl: 300,
    },
    { type: "NS", name: root, value: `ns1.${root}`, ttl: 86400 },
    { type: "NS", name: root, value: `ns2.${root}`, ttl: 86400 },
    { type: "MX", name: root, value: `10 mx1.${root}`, ttl: 3600 },
    {
      type: "SOA",
      name: root,
      value: `ns1.${root} hostmaster.${root} 2026${rng.int(10, 12)}${rng.int(10, 28)}01 7200 3600 1209600 3600`,
      ttl: 3600,
    },
    { type: "TXT", name: root, value: "v=spf1 include:_spf.google.com ~all", ttl: 3600 },
    { type: "CNAME", name: `www.${root}`, value: root, ttl: 3600 },
  ]

  if (rng.chance(0.65)) {
    records.push({
      type: "TXT",
      name: `_dmarc.${root}`,
      value: rng.chance(0.5)
        ? "v=DMARC1; p=none; rua=mailto:dmarc@" + root
        : "v=DMARC1; p=reject; rua=mailto:dmarc@" + root,
      ttl: 3600,
    })
  }

  if (rng.chance(0.5)) {
    records.push({
      type: "CAA",
      name: root,
      value: '0 issue "letsencrypt.org"',
      ttl: 3600,
    })
  }

  return records
}

function generateOpenPorts(rng: Rng, profile: ScanProfile): OpenPort[] {
  const count = profile === "rapid" ? rng.int(3, 6) : rng.int(6, 12)

  return rng
    .sample(SERVICE_TABLE, count)
    .map((entry) => {
      const version = rng.pick(entry.versions)
      const state: OpenPort["state"] = rng.chance(0.85)
        ? "open"
        : rng.chance(0.5)
          ? "filtered"
          : "open|filtered"

      return {
        port: entry.port,
        protocol: entry.port === 161 || entry.port === 53 ? "udp" : "tcp",
        state,
        service: entry.service,
        version,
        banner: `${version} (${entry.service}) — ${rng.pick([
          "Ubuntu 22.04",
          "Debian 12",
          "RHEL 9",
          "Alpine 3.19",
          "Windows Server 2019",
        ])}`,
        risk: state === "open" ? entry.risk : "Info",
      } satisfies OpenPort
    })
    .sort((a, b) => a.port - b.port)
}

function generateSsl(rng: Rng, host: string): SslAssessment {
  const weak = rng.chance(0.45)
  const daysUntilExpiry = rng.int(-14, 340)
  const weakProtocols = weak
    ? rng.sample(["TLSv1.0", "TLSv1.1", "SSLv3"], rng.int(1, 2))
    : []

  const issues: string[] = []
  if (weakProtocols.length) {
    issues.push(`Deprecated protocols negotiable: ${weakProtocols.join(", ")}`)
  }
  if (daysUntilExpiry < 0) {
    issues.push("Certificate has expired")
  } else if (daysUntilExpiry < 30) {
    issues.push(`Certificate expires in ${daysUntilExpiry} days`)
  }

  const hsts = rng.chance(0.6)
  if (!hsts) issues.push("HSTS header not present")

  const forwardSecrecy = rng.chance(0.8)
  if (!forwardSecrecy) issues.push("Cipher suites without forward secrecy offered")

  const ocspStapling = rng.chance(0.55)
  if (!ocspStapling) issues.push("OCSP stapling not enabled")

  const grade: SslAssessment["grade"] =
    daysUntilExpiry < 0
      ? "F"
      : weakProtocols.length >= 2
        ? "D"
        : weakProtocols.length === 1
          ? "C"
          : !forwardSecrecy
            ? "B"
            : hsts && ocspStapling
              ? "A+"
              : "A"

  const expiry = new Date()
  expiry.setDate(expiry.getDate() + daysUntilExpiry)

  return {
    grade,
    protocol: weakProtocols.length ? "TLSv1.2 (TLSv1.0 also offered)" : "TLSv1.3",
    cipherSuite: rng.pick([
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
    ]),
    keyExchange: rng.pick(["X25519", "secp384r1", "ECDHE-RSA 2048-bit"]),
    certificateIssuer: rng.pick([
      "Let's Encrypt R3",
      "DigiCert TLS RSA SHA256 2020 CA1",
      "Sectigo RSA DV",
      "GlobalSign Atlas R3",
    ]),
    certificateExpiry: expiry.toISOString().slice(0, 10),
    daysUntilExpiry,
    hsts,
    ocspStapling,
    forwardSecrecy,
    weakProtocols,
    issues: issues.length ? issues : ["No TLS configuration issues identified"],
  }
}

function generateOsFingerprint(rng: Rng): OsFingerprint {
  const profiles = [
    {
      osFamily: "Linux",
      osVersion: "Ubuntu 22.04.4 LTS",
      kernel: "5.15.0-97-generic",
      ttl: 64,
      device: "General purpose server",
    },
    {
      osFamily: "Linux",
      osVersion: "Debian 12 (bookworm)",
      kernel: "6.1.0-18-amd64",
      ttl: 64,
      device: "General purpose server",
    },
    {
      osFamily: "Linux",
      osVersion: "Red Hat Enterprise Linux 9.3",
      kernel: "5.14.0-362.el9",
      ttl: 64,
      device: "General purpose server",
    },
    {
      osFamily: "Windows",
      osVersion: "Windows Server 2019 Standard",
      kernel: "NT 10.0.17763",
      ttl: 128,
      device: "Domain member server",
    },
    {
      osFamily: "Windows",
      osVersion: "Windows Server 2022 Datacenter",
      kernel: "NT 10.0.20348",
      ttl: 128,
      device: "Domain controller",
    },
    {
      osFamily: "BSD",
      osVersion: "FreeBSD 14.0-RELEASE",
      kernel: "14.0-RELEASE-p5",
      ttl: 64,
      device: "Network appliance",
    },
  ]

  const p = rng.pick(profiles)

  return {
    osFamily: p.osFamily,
    osVersion: p.osVersion,
    kernel: p.kernel,
    accuracy: rng.int(88, 99),
    deviceType: p.device,
    uptimeGuess: `${rng.int(3, 420)} days`,
    ttlSignature: p.ttl,
    method: rng.pick([
      "TCP/IP stack fingerprint (SYN/ACK window analysis)",
      "TCP ISN sequence predictability + ICMP echo signature",
      "Service banner correlation + TCP options ordering",
    ]),
  }
}

export function generateRecon(
  target: string,
  kind: TargetKind,
  profile: ScanProfile,
  rng: Rng
): ReconResult {
  const host = baseDomainFor(target, kind)
  const created = new Date()
  created.setFullYear(created.getFullYear() - rng.int(2, 18))
  const expires = new Date()
  expires.setFullYear(expires.getFullYear() + rng.int(1, 4))

  return {
    subdomains: generateSubdomains(rng, host, profile),
    dnsRecords: generateDnsRecords(rng, host),
    openPorts: generateOpenPorts(rng, profile),
    ssl: generateSsl(rng, host),
    os: generateOsFingerprint(rng),
    whois: {
      registrar: rng.pick([
        "MarkMonitor Inc.",
        "Cloudflare, Inc.",
        "GoDaddy.com, LLC",
        "Gandi SAS",
        "Amazon Registrar, Inc.",
      ]),
      created: created.toISOString().slice(0, 10),
      expires: expires.toISOString().slice(0, 10),
      asn: `AS${rng.int(1000, 65000)} ${rng.pick([
        "CLOUDFLARENET",
        "AMAZON-02",
        "GOOGLE-CLOUD",
        "DIGITALOCEAN-ASN",
        "HETZNER-AS",
      ])}`,
    },
    technologies: rng.sample(TECH_STACKS, rng.int(4, 8)),
  }
}

// ---------------------------------------------------------------- OWASP

const OWASP_2021: Array<{ id: string; name: string; description: string }> = [
  {
    id: "A01",
    name: "Broken Access Control",
    description:
      "Restrictions on authenticated users are not properly enforced, allowing access to unauthorised functionality or data.",
  },
  {
    id: "A02",
    name: "Cryptographic Failures",
    description:
      "Failures related to cryptography that lead to exposure of sensitive data in transit or at rest.",
  },
  {
    id: "A03",
    name: "Injection",
    description:
      "Untrusted data is sent to an interpreter as part of a command or query.",
  },
  {
    id: "A04",
    name: "Insecure Design",
    description:
      "Missing or ineffective control design — flaws that cannot be fixed by implementation alone.",
  },
  {
    id: "A05",
    name: "Security Misconfiguration",
    description:
      "Insecure default configuration, incomplete hardening, or verbose error handling.",
  },
  {
    id: "A06",
    name: "Vulnerable and Outdated Components",
    description:
      "Use of components with known vulnerabilities or that are no longer supported.",
  },
  {
    id: "A07",
    name: "Identification and Authentication Failures",
    description:
      "Weaknesses in confirming user identity, authentication, and session management.",
  },
  {
    id: "A08",
    name: "Software and Data Integrity Failures",
    description:
      "Code and infrastructure that does not protect against integrity violations.",
  },
  {
    id: "A09",
    name: "Security Logging and Monitoring Failures",
    description:
      "Insufficient logging, detection, monitoring and active response.",
  },
  {
    id: "A10",
    name: "Server-Side Request Forgery",
    description:
      "The application fetches a remote resource without validating the user-supplied destination URL.",
  },
]

const OWASP_RECOMMENDATIONS: Record<string, string> = {
  A01: "Deny by default, enforce ownership checks server-side on every object access, and cover access-control rules with automated regression tests.",
  A02: "Classify data, encrypt in transit with TLS 1.2+ and at rest with managed keys, and remove all legacy cipher suites and protocols.",
  A03: "Use parameterised queries and context-aware output encoding throughout; validate input against positive allow-lists at trust boundaries.",
  A04: "Introduce threat modelling into design review and codify the resulting controls as reusable, tested secure design patterns.",
  A05: "Harden by default through infrastructure-as-code, remove unused features, and continuously verify configuration drift against a baseline.",
  A06: "Maintain a live SBOM, subscribe to advisories for every dependency, and enforce an SLA for patching known-exploited vulnerabilities.",
  A07: "Enforce MFA for privileged access, screen passwords against breach corpora, and apply progressive rate limiting on all authentication paths.",
  A08: "Verify integrity of dependencies and updates with signatures, and secure the CI/CD pipeline against unauthorised modification.",
  A09: "Log security-relevant events to append-only central storage with alerting on authentication anomalies and privilege changes.",
  A10: "Validate and allow-list outbound destinations, re-resolve after DNS lookup to defeat rebinding, and block link-local and private ranges.",
}

export function generateOwaspCompliance(
  vulnerabilities: Vulnerability[]
): OwaspCompliance {
  const categories: OwaspCategory[] = OWASP_2021.map((cat) => {
    const matched = vulnerabilities.filter((v) => v.owasp.startsWith(cat.id))

    const riskScore = matched.reduce(
      (sum, v) => sum + SEVERITY_WEIGHT[v.severity],
      0
    )

    const hasSevere = matched.some(
      (v) => v.severity === "Critical" || v.severity === "High"
    )

    const status: OwaspCategory["status"] = !matched.length
      ? "pass"
      : hasSevere
        ? "fail"
        : "warning"

    return {
      id: cat.id,
      name: cat.name,
      description: cat.description,
      status,
      findings: matched.length,
      riskScore: Math.min(100, riskScore * 5),
      recommendation: matched.length
        ? OWASP_RECOMMENDATIONS[cat.id]
        : `No findings mapped to ${cat.id}. Maintain current controls and re-verify each release.`,
    }
  })

  const passed = categories.filter((c) => c.status === "pass").length
  const failed = categories.filter((c) => c.status === "fail").length
  const warnings = categories.filter((c) => c.status === "warning").length

  // A warning counts as a half pass — it is a gap, not a breach of the control.
  const compliancePercentage = Math.round(
    ((passed + warnings * 0.5) / categories.length) * 100
  )

  const overallRisk: Severity =
    failed >= 4 ? "Critical" : failed >= 2 ? "High" : failed >= 1 ? "Medium" : "Low"

  return {
    categories,
    compliancePercentage,
    passed,
    failed,
    warnings,
    overallRisk,
  }
}

// -------------------------------------------------------- THREAT INTEL

const ATTACK_VECTOR_LIBRARY: AttackVector[] = [
  {
    name: "Internet-Facing Application Exploitation",
    likelihood: "High",
    impact: "Critical",
    description:
      "Exposed web services with known-exploitable defects give an attacker an initial foothold without any credential.",
    mitigation:
      "Patch internet-facing services on a 72-hour SLA for known-exploited CVEs and front them with a tuned WAF.",
    mitreId: "T1190",
  },
  {
    name: "Valid Account Abuse via Credential Stuffing",
    likelihood: "Very High",
    impact: "High",
    description:
      "Unthrottled authentication endpoints combined with credential reuse allow attackers to log in with legitimate credentials.",
    mitigation:
      "Enforce MFA, apply per-account rate limiting, and screen passwords against known-breach corpora at set time.",
    mitreId: "T1078",
  },
  {
    name: "Supply Chain Compromise via Vulnerable Dependency",
    likelihood: "Medium",
    impact: "Critical",
    description:
      "Outdated third-party components carry publicly documented exploits that require no target-specific research.",
    mitigation:
      "Maintain an SBOM, gate builds on dependency scanning, and verify artefact signatures before deployment.",
    mitreId: "T1195.002",
  },
  {
    name: "Adversary-in-the-Middle on Weak Transport",
    likelihood: "Medium",
    impact: "High",
    description:
      "Deprecated TLS versions and cleartext services permit interception and downgrade on shared network paths.",
    mitigation:
      "Enforce TLS 1.2+ everywhere, publish HSTS with preload, and retire all cleartext administrative protocols.",
    mitreId: "T1557",
  },
  {
    name: "External Remote Services Abuse",
    likelihood: "High",
    impact: "Critical",
    description:
      "Directly exposed RDP, SSH and VPN endpoints are continuously probed by opportunistic and targeted actors alike.",
    mitigation:
      "Place remote access behind an identity-aware proxy with MFA, and restrict source addresses where feasible.",
    mitreId: "T1133",
  },
  {
    name: "Cloud Instance Metadata Harvesting",
    likelihood: "Medium",
    impact: "Critical",
    description:
      "SSRF primitives reach the instance metadata service and return short-lived IAM credentials for the host role.",
    mitigation:
      "Require IMDSv2, scope instance roles to least privilege, and block link-local egress from application workloads.",
    mitreId: "T1552.005",
  },
  {
    name: "Lateral Movement over SMB",
    likelihood: "Medium",
    impact: "High",
    description:
      "Unsigned SMB sessions permit NTLM relay, letting a foothold on one host spread across the estate.",
    mitigation:
      "Require SMB signing, disable NTLMv1, and segment the network so a single host compromise is contained.",
    mitreId: "T1021.002",
  },
  {
    name: "Data Exfiltration over Web Protocols",
    likelihood: "High",
    impact: "High",
    description:
      "Absent egress filtering and monitoring, bulk data can be staged and removed over ordinary HTTPS traffic.",
    mitigation:
      "Apply egress allow-listing from server subnets and alert on anomalous outbound volume per workload.",
    mitreId: "T1041",
  },
]

const INDUSTRY_THREAT_LIBRARY: IndustryThreat[] = [
  {
    actor: "Financially Motivated Ransomware Affiliates",
    motivation: "Extortion and double-extortion data leak",
    sophistication: "High",
    targetedSectors: ["Healthcare", "Manufacturing", "Education", "Local Government"],
    ttps: [
      "Initial access via exposed remote services",
      "Credential dumping and privilege escalation",
      "Exfiltration before encryption",
      "Backup destruction prior to detonation",
    ],
    activity: "Sustained — highest observed volume against unpatched perimeter services",
  },
  {
    actor: "Initial Access Brokers",
    motivation: "Resale of authenticated footholds",
    sophistication: "Medium",
    targetedSectors: ["All sectors — opportunistic"],
    ttps: [
      "Mass scanning for known-exploited CVEs",
      "Credential stuffing against SSO portals",
      "Web shell deployment for persistence",
    ],
    activity: "Continuous background scanning of the full IPv4 space",
  },
  {
    actor: "State-Aligned Espionage Group",
    motivation: "Long-term intelligence collection",
    sophistication: "Advanced",
    targetedSectors: ["Government", "Defence", "Technology", "Telecommunications"],
    ttps: [
      "Zero-day exploitation of edge appliances",
      "Living-off-the-land persistence",
      "Supply chain compromise of trusted vendors",
      "Anti-forensic log manipulation",
    ],
    activity: "Targeted — low volume, high dwell time",
  },
  {
    actor: "Hacktivist Collectives",
    motivation: "Ideological disruption and publicity",
    sophistication: "Low",
    targetedSectors: ["Government", "Energy", "Media", "Financial Services"],
    ttps: [
      "Volumetric and application-layer DDoS",
      "Website defacement via known CMS flaws",
      "Public leak of scraped data",
    ],
    activity: "Episodic — spikes correlate with geopolitical events",
  },
  {
    actor: "Commodity Botnet Operators",
    motivation: "Resource hijacking and proxy resale",
    sophistication: "Low",
    targetedSectors: ["All sectors — opportunistic"],
    ttps: [
      "Default credential abuse on exposed services",
      "Cryptomining payload deployment",
      "Residential proxy enrolment",
    ],
    activity: "Constant — automated, indiscriminate",
  },
]

export function generateThreatIntelligence(
  vulnerabilities: Vulnerability[],
  recon: ReconResult,
  rng: Rng
): ThreatIntelligence {
  const critical = vulnerabilities.filter((v) => v.severity === "Critical").length
  const high = vulnerabilities.filter((v) => v.severity === "High").length
  const exploitable = vulnerabilities.filter((v) => v.exploitAvailable).length

  const threatScore = Math.min(
    100,
    Math.round(
      critical * 18 +
        high * 9 +
        exploitable * 4 +
        recon.openPorts.filter((p) => p.risk === "Critical" || p.risk === "High")
          .length *
          3
    )
  )

  const threatLevel: ThreatIntelligence["threatLevel"] =
    threatScore >= 75
      ? "Critical"
      : threatScore >= 45
        ? "Elevated"
        : threatScore >= 20
          ? "Guarded"
          : "Low"

  // Surface the vectors the actual findings support, then top up.
  const relevant = new Set<string>()
  for (const v of vulnerabilities) {
    if (v.category === "SSRF") relevant.add("Cloud Instance Metadata Harvesting")
    if (v.category === "Authentication")
      relevant.add("Valid Account Abuse via Credential Stuffing")
    if (v.category === "Vulnerable Component")
      relevant.add("Supply Chain Compromise via Vulnerable Dependency")
    if (v.category === "Cryptographic Failure")
      relevant.add("Adversary-in-the-Middle on Weak Transport")
    if (v.port === 3389 || v.port === 22)
      relevant.add("External Remote Services Abuse")
    if (v.cwe === "CWE-287") relevant.add("Lateral Movement over SMB")
    if (v.severity === "Critical")
      relevant.add("Internet-Facing Application Exploitation")
  }

  const chosen = ATTACK_VECTOR_LIBRARY.filter((v) => relevant.has(v.name))
  const filler = rng
    .shuffle(ATTACK_VECTOR_LIBRARY.filter((v) => !relevant.has(v.name)))
    .slice(0, Math.max(0, 4 - chosen.length))

  const attackVectors = [...chosen, ...filler].slice(0, 6)

  const recommendations = [
    critical > 0
      ? `Remediate all ${critical} critical finding${critical === 1 ? "" : "s"} within 72 hours — each is independently sufficient for full compromise.`
      : "No critical findings outstanding. Maintain the current patch cadence.",
    "Enforce phishing-resistant MFA on every externally reachable authentication surface.",
    recon.openPorts.some((p) => [3389, 23, 445].includes(p.port))
      ? "Remove administrative protocols (RDP/Telnet/SMB) from internet exposure and place them behind an identity-aware proxy."
      : "Continue restricting administrative protocols to management networks.",
    recon.ssl.grade === "A+" || recon.ssl.grade === "A"
      ? "TLS posture is strong — keep certificate automation and monitoring in place."
      : `Remediate TLS configuration (currently grade ${recon.ssl.grade}): ${recon.ssl.issues[0]}.`,
    "Apply network segmentation so that compromise of any single host does not yield lateral reach to the data tier.",
    "Establish egress filtering and alert on anomalous outbound volume — this is the last control before exfiltration succeeds.",
    exploitable > 0
      ? `${exploitable} finding${exploitable === 1 ? " has" : "s have"} public exploit code available; prioritise these above raw CVSS ordering.`
      : "No public exploit code identified for the current findings.",
  ]

  const summary =
    threatLevel === "Critical"
      ? "The target presents an immediately exploitable external attack surface. Multiple findings require no authentication and have public exploit code, placing this asset within reach of opportunistic mass-exploitation campaigns."
      : threatLevel === "Elevated"
        ? "The target carries meaningful exposure. Individual findings are unlikely to yield compromise alone, but chaining is realistic for a moderately capable attacker."
        : threatLevel === "Guarded"
          ? "The target's external posture is reasonable. Remaining findings are primarily configuration gaps that reduce defence in depth rather than granting direct access."
          : "The target's external posture is strong. No findings support a practical unauthenticated attack path at this time."

  return {
    threatLevel,
    threatScore,
    summary,
    attackVectors,
    industryThreats: rng.sample(INDUSTRY_THREAT_LIBRARY, 3),
    recommendations,
    exposureScore: Math.min(
      100,
      recon.subdomains.filter((s) => s.status === "live").length * 6 +
        recon.openPorts.filter((p) => p.state === "open").length * 5
    ),
    darkWebMentions: rng.int(0, 24),
  }
}

// ------------------------------------------------------------- ASSESSMENT

export function computeRiskScore(vulnerabilities: Vulnerability[]): number {
  if (!vulnerabilities.length) return 0

  const weighted = vulnerabilities.reduce(
    (sum, v) => sum + SEVERITY_WEIGHT[v.severity] * (v.confidence / 100),
    0
  )

  // Logarithmic so a long tail of lows cannot outweigh a single critical.
  return Math.min(100, Math.round(Math.log2(weighted + 1) * 21))
}

export function generateAssessment(
  config: ScanConfig,
  kind: TargetKind,
  startedAt: Date,
  completedAt: Date
): AssessmentResult {
  // Seed on target + profile so a re-run of the same job is reproducible,
  // while switching profile legitimately changes what is found.
  const rng = createRng(`${config.target}::${config.profile}`)

  const vulnerabilities = generateVulnerabilities(
    config,
    kind,
    rng,
    startedAt.toISOString()
  )
  const recon = generateRecon(config.target, kind, config.profile, rng)
  const owasp = generateOwaspCompliance(vulnerabilities)
  const threatIntel = generateThreatIntelligence(vulnerabilities, recon, rng)

  return {
    target: config.target,
    targetKind: kind,
    profile: config.profile,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationSeconds: Math.max(
      1,
      Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)
    ),
    vulnerabilities,
    recon,
    owasp,
    threatIntel,
    riskScore: computeRiskScore(vulnerabilities),
  }
}

/**
 * Retest pass. Findings the team has had time to address flip to remediated;
 * the rest are re-confirmed as still present.
 */
export function retestAssessment(previous: AssessmentResult): AssessmentResult {
  const rng = createRng(`${previous.target}::retest::${previous.completedAt}`)
  const now = new Date()

  const vulnerabilities = previous.vulnerabilities.map((v) => {
    // Low-hanging configuration issues get fixed first in practice.
    const easyWin = v.severity === "Low" || v.category === "Misconfiguration"
    const remediated = rng.chance(easyWin ? 0.7 : v.severity === "Critical" ? 0.45 : 0.35)

    return {
      ...v,
      retestStatus: remediated
        ? ("remediated" as const)
        : ("still-present" as const),
      confidence: remediated ? v.confidence : Math.min(99, v.confidence + 4),
    }
  })

  const open = vulnerabilities.filter((v) => v.retestStatus !== "remediated")
  const owasp = generateOwaspCompliance(open)
  const threatIntel = generateThreatIntelligence(open, previous.recon, rng)

  return {
    ...previous,
    completedAt: now.toISOString(),
    vulnerabilities,
    owasp,
    threatIntel,
    riskScore: computeRiskScore(open),
  }
}

export function severityCounts(
  vulnerabilities: Vulnerability[]
): Record<Severity, number> {
  return vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] += 1
      return acc
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } as Record<Severity, number>
  )
}
