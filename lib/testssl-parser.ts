import type { Finding, FindingSeverity } from "./findings-store";

export interface TestsslFinding {
  id: string;
  ip: string;
  port: string;
  severity: string;
  finding: string;
  cve?: string;
  cwe?: string;
}

export interface TestsslOutput {
  scanTime?: string;
  serverDefaults?: Record<string, unknown>;
  findings: TestsslFinding[];
}

const TESTSSL_FINDING_MAP: Record<string, { title: string; severity: FindingSeverity; mitre: string }> = {
  "SSLv2":                    { title: "SSLv2 Enabled",                    severity: "CRITICAL", mitre: "T1040" },
  "SSLv3":                    { title: "SSLv3 Enabled (POODLE)",           severity: "CRITICAL", mitre: "T1040" },
  "TLS1":                     { title: "TLS 1.0 Enabled",                  severity: "HIGH",     mitre: "T1040" },
  "TLS1_1":                   { title: "TLS 1.1 Enabled",                  severity: "MEDIUM",   mitre: "T1040" },
  "heartbleed":               { title: "Heartbleed (CVE-2014-0160)",       severity: "CRITICAL", mitre: "T1040" },
  "CCS":                      { title: "CCS Injection (CVE-2014-0224)",    severity: "HIGH",     mitre: "T1040" },
  "ticketbleed":              { title: "Ticketbleed (CVE-2016-9244)",      severity: "HIGH",     mitre: "T1040" },
  "ROBOT":                    { title: "ROBOT Attack",                     severity: "HIGH",     mitre: "T1040" },
  "DROWN":                    { title: "DROWN Attack (CVE-2016-0800)",     severity: "CRITICAL", mitre: "T1040" },
  "LOGJAM-common":            { title: "Logjam DH Downgrade",              severity: "HIGH",     mitre: "T1040" },
  "BEAST_CBC_TLS1":           { title: "BEAST Attack (TLS 1.0)",           severity: "MEDIUM",   mitre: "T1040" },
  "LUCKY13":                  { title: "Lucky Thirteen Attack",            severity: "MEDIUM",   mitre: "T1040" },
  "SWEET32":                  { title: "SWEET32 Attack",                   severity: "MEDIUM",   mitre: "T1040" },
  "POODLE_SSL":               { title: "POODLE (SSLv3)",                   severity: "CRITICAL", mitre: "T1040" },
  "cert_expired":             { title: "Certificate Expired",              severity: "HIGH",     mitre: "" },
  "cert_notYetValid":         { title: "Certificate Not Yet Valid",        severity: "HIGH",     mitre: "" },
  "cert_hostnameMismatch":    { title: "Hostname Mismatch",                severity: "HIGH",     mitre: "T1040" },
  "HSTS_not_offered":         { title: "HSTS Not Configured",              severity: "MEDIUM",   mitre: "" },
  "HSTS_timeout":             { title: "HSTS Max-Age Too Short",           severity: "LOW",      mitre: "" },
};

const SEVERITY_ORDER: FindingSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function mapTestsslSeverity(s: string): FindingSeverity {
  const upper = s.toUpperCase();
  return (SEVERITY_ORDER.includes(upper as FindingSeverity) ? upper : "INFO") as FindingSeverity;
}

function deriveCvssFromSeverity(s: FindingSeverity): string {
  return { CRITICAL: "9.8", HIGH: "7.5", MEDIUM: "5.0", LOW: "3.1", INFO: "0.0" }[s] ?? "0.0";
}

export function parseTestsslOutput(
  output: TestsslOutput,
  host: string,
): Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline">[] {
  return output.findings
    .filter((f) => f.severity !== "OK" && f.severity !== "INFO" && f.severity !== "DEBUG")
    .map((f) => {
      const meta = TESTSSL_FINDING_MAP[f.id] ?? {
        title: `TLS Issue: ${f.id}`,
        severity: mapTestsslSeverity(f.severity),
        mitre: "",
      };

      const finding: Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline"> = {
        title: `${meta.title} — ${host}`,
        severity: meta.severity,
        cvss: deriveCvssFromSeverity(meta.severity),
        cvssVector: "",
        category: "Cryptographic / TLS",
        status: "OPEN",
        affectedHost: host,
        description: f.finding,
        technicalDetails: `testssl.sh finding ID: ${f.id}\nCVE: ${f.cve ?? "N/A"}\nCWE: ${f.cwe ?? "N/A"}`,
        attackPath: `External → ${host} → TLS Downgrade/Attack`,
        evidence: [{ label: "testssl.sh Output", content: JSON.stringify(f, null, 2) }],
        impact: `Cryptographic weakness on ${host} enables traffic interception or decryption.`,
        remediation: [],
        compliance: [],
        mitre: meta.mitre ? [{ id: meta.mitre, name: "Network Sniffing" }] : [],
        source: "testssl",
      } as Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline">;

      return finding;
    });
}
