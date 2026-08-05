/**
 * Engine smoke test — exercises target validation and assessment generation
 * outside the browser. Run with:  npm run smoke
 */
import {
  generateAssessment,
  phasesFor,
  retestAssessment,
  severityCounts,
} from "@/lib/vapt/generators"
import type { ScanConfig } from "@/lib/vapt/types"
import { isIPv4, isIPv6, isDomain, validateTarget } from "@/lib/vapt/validation"

let failures = 0

function check(name: string, condition: boolean, detail = "") {
  if (condition) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`)
  }
}

/* -------------------------------------------------------------- validation */

console.log("\nIPv4")
for (const v of ["192.168.1.1", "8.8.8.8", "255.255.255.255", "0.0.0.0"]) {
  check(`accepts ${v}`, isIPv4(v))
}
for (const v of ["256.1.1.1", "1.2.3", "01.2.3.4", "1.2.3.4.5", "a.b.c.d", ""]) {
  check(`rejects ${v || "<empty>"}`, !isIPv4(v))
}

console.log("\nIPv6")
for (const v of [
  "::1",
  "::",
  "2001:db8::1",
  "fe80::1%eth0",
  "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "::ffff:192.0.2.1",
  "2001:db8::192.0.2.1",
]) {
  check(`accepts ${v}`, isIPv6(v))
}
for (const v of [
  "2001:db8::1::2",
  "gggg::1",
  "2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra",
  "1:2:3:4:5:6:7",
  ":::",
  "12345::1",
]) {
  check(`rejects ${v}`, !isIPv6(v))
}

console.log("\nDomain")
for (const v of ["example.com", "sub.example.co.uk", "a-b.example.org"]) {
  check(`accepts ${v}`, isDomain(v))
}
for (const v of ["localhost", "-bad.com", "bad-.com", "example", "1.2.3.4", "exa mple.com"]) {
  check(`rejects ${v}`, !isDomain(v))
}

console.log("\nTarget classification")
const cases: Array<[string, string | null]> = [
  ["10.0.0.5", "ipv4"],
  ["2001:db8::1", "ipv6"],
  ["example.com", "domain"],
  ["https://app.example.com/login", "url"],
  ["10.0.0.0/24", "cidr"],
  ["ftp://example.com", null],
  ["not a target", null],
  ["", null],
]
for (const [input, expected] of cases) {
  const v = validateTarget(input)
  check(
    `${input || "<empty>"} -> ${expected ?? "invalid"}`,
    v.kind === expected,
    `got ${v.kind ?? "invalid"} (${v.error ?? "no error"})`
  )
}

check(
  "loopback carries a warning",
  Boolean(validateTarget("127.0.0.1").warning)
)
check(
  "RFC1918 carries a warning",
  Boolean(validateTarget("192.168.1.1").warning)
)
check(
  "http URL warns about cleartext",
  Boolean(validateTarget("http://example.com").warning)
)

/* -------------------------------------------------------------- generation */

console.log("\nAssessment generation")

const config: ScanConfig = {
  target: "example.com",
  profile: "comprehensive",
  ai: {
    aiPrioritisation: true,
    exploitChaining: true,
    threatFeedEnrichment: true,
    falsePositiveFiltering: true,
    remediationSynthesis: true,
  },
}

const started = new Date("2026-08-05T10:00:00Z")
const finished = new Date("2026-08-05T10:00:12Z")

const a = generateAssessment(config, "domain", started, finished)
const b = generateAssessment(config, "domain", started, finished)

check("produces findings", a.vulnerabilities.length > 0)
check(
  "deterministic for the same target+profile",
  JSON.stringify(a.vulnerabilities.map((v) => v.title)) ===
    JSON.stringify(b.vulnerabilities.map((v) => v.title))
)

const other = generateAssessment(
  { ...config, target: "different.example.org" },
  "domain",
  started,
  finished
)
check(
  "different target yields different findings",
  JSON.stringify(a.vulnerabilities.map((v) => v.title)) !==
    JSON.stringify(other.vulnerabilities.map((v) => v.title))
)

check("finding ids are unique", new Set(a.vulnerabilities.map((v) => v.id)).size === a.vulnerabilities.length)
check("risk score in range", a.riskScore >= 0 && a.riskScore <= 100)
check(
  "cvss values are sane",
  a.vulnerabilities.every((v) => v.cvss > 0 && v.cvss <= 10)
)
check(
  "confidence values are sane",
  a.vulnerabilities.every((v) => v.confidence >= 0 && v.confidence <= 100)
)
check(
  "exploitability values are sane",
  a.vulnerabilities.every((v) => v.exploitability >= 0 && v.exploitability <= 100)
)
check(
  "every finding maps to an OWASP category",
  a.vulnerabilities.every((v) => /^A(0[1-9]|10):2021/.test(v.owasp))
)
check(
  "every finding has remediation text",
  a.vulnerabilities.every((v) => v.remediation.length > 20)
)

console.log("\nOWASP compliance")
check("ten categories", a.owasp.categories.length === 10)
check(
  "compliance percentage in range",
  a.owasp.compliancePercentage >= 0 && a.owasp.compliancePercentage <= 100
)
check(
  "status tally matches category count",
  a.owasp.passed + a.owasp.failed + a.owasp.warnings === 10
)
const mappedTotal = a.owasp.categories.reduce((s, c) => s + c.findings, 0)
check(
  "all findings are accounted for in the mapping",
  mappedTotal === a.vulnerabilities.length,
  `mapped ${mappedTotal} of ${a.vulnerabilities.length}`
)

console.log("\nRecon")
check("subdomains discovered", a.recon.subdomains.length > 0)
check("dns records present", a.recon.dnsRecords.length > 0)
check("ports discovered", a.recon.openPorts.length > 0)
check("ports are sorted", a.recon.openPorts.every((p, i, arr) => i === 0 || arr[i - 1].port <= p.port))
check("ssl grade assigned", Boolean(a.recon.ssl.grade))
check("os accuracy in range", a.recon.os.accuracy > 0 && a.recon.os.accuracy <= 100)

console.log("\nThreat intelligence")
check("attack vectors present", a.threatIntel.attackVectors.length > 0)
check("industry threats present", a.threatIntel.industryThreats.length === 3)
check("recommendations present", a.threatIntel.recommendations.length > 0)
check(
  "threat score in range",
  a.threatIntel.threatScore >= 0 && a.threatIntel.threatScore <= 100
)

console.log("\nPhases")
for (const profile of ["rapid", "comprehensive", "pentest"] as const) {
  const phases = phasesFor(profile, true)
  const sum = phases.reduce((s, p) => s + p.weight, 0)
  check(`${profile} weights normalise to 1`, Math.abs(sum - 1) < 1e-9, `sum=${sum}`)
}
check(
  "disabling AI removes the AI phase",
  !phasesFor("comprehensive", false).some((p) => p.id === "ai")
)

console.log("\nRetest")
const retested = retestAssessment(a)
check(
  "every finding gets a retest verdict",
  retested.vulnerabilities.every(
    (v) => v.retestStatus === "remediated" || v.retestStatus === "still-present"
  )
)
check(
  "finding count is preserved",
  retested.vulnerabilities.length === a.vulnerabilities.length
)
const openAfter = retested.vulnerabilities.filter(
  (v) => v.retestStatus !== "remediated"
).length
check(
  "risk score does not increase after remediation",
  retested.riskScore <= a.riskScore || openAfter === a.vulnerabilities.length
)

console.log("\nProfiles")
for (const profile of ["rapid", "comprehensive", "pentest"] as const) {
  const r = generateAssessment({ ...config, profile }, "domain", started, finished)
  const counts = severityCounts(r.vulnerabilities)
  const total = Object.values(counts).reduce((s, n) => s + n, 0)
  check(
    `${profile} produces findings (${total})`,
    total > 0 && total === r.vulnerabilities.length
  )
}

console.log(
  failures === 0
    ? "\nAll engine checks passed.\n"
    : `\n${failures} check(s) FAILED.\n`
)

process.exit(failures === 0 ? 0 : 1)
