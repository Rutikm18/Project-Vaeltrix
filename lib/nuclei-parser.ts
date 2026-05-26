import type { Finding, FindingSeverity } from "./findings-store";

export interface NucleiMatch {
  templateId: string;
  templateName: string;
  severity: string;
  host: string;
  ip: string;
  port: string;
  matchedAt: string;
  type: string;
  extractedResults?: string[];
  curlCommand?: string;
  timestamp: string;
  cvss?: string;
  cve?: string;
  reference?: string[];
  tags: string[];
}

export interface NucleiRawLine {
  "template-id": string;
  info: {
    name: string;
    severity: string;
    tags?: string[];
    description?: string;
    reference?: string[];
    classification?: { "cvss-score"?: number; "cve-id"?: string };
  };
  host: string;
  ip?: string;
  port?: string;
  "matched-at": string;
  "extracted-results"?: string[];
  "curl-command"?: string;
  timestamp: string;
  type?: string;
}

const SEVERITY_MAP: Record<string, FindingSeverity> = {
  critical: "CRITICAL",
  high:     "HIGH",
  medium:   "MEDIUM",
  low:      "LOW",
  info:     "INFO",
};

function deriveCategory(tags: string[]): string {
  if (tags.some((t) => ["cve", "cves"].includes(t))) return "CVE";
  if (tags.some((t) => t.includes("panel") || t.includes("login"))) return "Exposed Panel";
  if (tags.some((t) => ["misconfiguration", "misconfig", "misconfigs"].includes(t))) return "Misconfiguration";
  if (tags.some((t) => t === "ssl" || t === "tls")) return "Cryptographic / TLS";
  if (tags.some((t) => ["default-login", "default-logins"].includes(t))) return "Default Credentials";
  if (tags.some((t) => t === "takeover")) return "Subdomain Takeover";
  if (tags.some((t) => t === "network")) return "Network Service";
  return "Vulnerability";
}

function deriveImpact(match: NucleiMatch): string {
  if (match.severity === "critical") return `Critical vulnerability on ${match.ip}. Immediate exploitation likely.`;
  if (match.severity === "high")     return `High-severity issue on ${match.ip}. Exploitable with low effort.`;
  return `${match.templateName} detected on ${match.matchedAt}.`;
}

function deriveRemediation(match: NucleiMatch): Finding["remediation"] {
  const steps: Finding["remediation"] = [
    {
      step: 1,
      title: "Investigate and confirm",
      description: `Review the Nuclei finding for ${match.templateId} on ${match.matchedAt}. Confirm the vulnerability is genuine.`,
      estimatedHours: 0.5,
      completed: false,
    },
    {
      step: 2,
      title: "Apply vendor patch or configuration fix",
      description: match.reference?.[0]
        ? `Refer to: ${match.reference[0]}`
        : "Apply the latest security patch or harden the service configuration.",
      estimatedHours: 2,
      completed: false,
    },
  ];
  return steps;
}

function computeRiskScore(severity: string): number {
  return { critical: 95, high: 75, medium: 50, low: 25, info: 5 }[severity] ?? 10;
}

function deriveCvss(severity: string): string {
  return { critical: "9.8", high: "7.5", medium: "5.0", low: "3.1", info: "0.0" }[severity] ?? "0.0";
}

export function parseNucleiLine(raw: NucleiRawLine): NucleiMatch {
  return {
    templateId:       raw["template-id"],
    templateName:     raw.info.name,
    severity:         raw.info.severity,
    host:             raw.host,
    ip:               raw.ip ?? raw.host.replace(/https?:\/\//, "").split(":")[0],
    port:             raw.port ?? raw["matched-at"].split(":")[2]?.split("/")[0] ?? "",
    matchedAt:        raw["matched-at"],
    type:             raw.type ?? "http",
    extractedResults: raw["extracted-results"],
    curlCommand:      raw["curl-command"],
    timestamp:        raw.timestamp,
    cvss:             raw.info.classification?.["cvss-score"]?.toString(),
    cve:              raw.info.classification?.["cve-id"],
    reference:        raw.info.reference,
    tags:             raw.info.tags ?? [],
  };
}

export function nucleiMatchToFinding(
  match: NucleiMatch,
): Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline"> {
  return {
    title:            match.templateName,
    severity:         SEVERITY_MAP[match.severity] ?? "INFO",
    cvss:             match.cvss ?? deriveCvss(match.severity),
    cvssVector:       "",
    category:         deriveCategory(match.tags),
    status:           "OPEN",
    affectedHost:     match.ip,
    description:      `${match.templateName} detected on ${match.matchedAt}`,
    technicalDetails: match.curlCommand
      ? `Template: ${match.templateId}\nMatched at: ${match.matchedAt}\n\n${match.curlCommand}`
      : `Template: ${match.templateId}\nMatched at: ${match.matchedAt}`,
    attackPath:       `External → ${match.ip}:${match.port} → ${match.templateId}`,
    evidence: [
      { label: "Nuclei Match", content: JSON.stringify(match, null, 2) },
      ...(match.curlCommand ? [{ label: "Reproduction Command", content: match.curlCommand }] : []),
      ...(match.extractedResults?.length ? [{ label: "Extracted Data", content: match.extractedResults.join("\n") }] : []),
    ],
    impact:           deriveImpact(match),
    businessImpact:   "",
    exploitability:   match.severity === "critical" ? "EASY" : "MODERATE",
    remediation:      deriveRemediation(match),
    compliance:       [],
    mitre:            [],
    riskScore:        computeRiskScore(match.severity),
    source:           "nuclei",
  } as Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline">;
}

export function countBySeverity(matches: NucleiMatch[]): Record<string, number> {
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const m of matches) {
    const key = m.severity.toLowerCase() as keyof typeof stats;
    if (key in stats) stats[key]++;
  }
  return stats;
}
