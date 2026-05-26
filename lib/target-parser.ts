/**
 * Smart target parser for offensive security scanning.
 * Accepts anything a pentester might paste: IPs, CIDRs, ranges,
 * hostnames, URLs, or raw scope documents with mixed content.
 */

export type TargetType = "ip" | "cidr" | "range" | "hostname" | "url" | "invalid";

export interface ParsedTarget {
  raw: string;
  normalized: string;
  type: TargetType;
  hostCount: number;
  isPrivate: boolean;
  isExcluded: boolean;
  validationMsg?: string;
}

export interface ParseResult {
  targets: ParsedTarget[];
  valid: ParsedTarget[];
  invalid: ParsedTarget[];
  excluded: ParsedTarget[];
  totalHosts: number;
  hasPublicIPs: boolean;
  hasBroadTargets: boolean; // any CIDR /16 or larger
}

/* ── Regex patterns ── */
const RE_IP      = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_CIDR    = /^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/;
const RE_RANGE_S = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3})$/;           // 10.0.0.1-50
const RE_RANGE_F = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/; // 10.0.0.1-10.0.0.50
const RE_HOST    = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;

const PRIVATE_RANGES = [
  { cidr: "10.0.0.0/8",      start: ip2long("10.0.0.0"),     end: ip2long("10.255.255.255")  },
  { cidr: "172.16.0.0/12",   start: ip2long("172.16.0.0"),   end: ip2long("172.31.255.255")  },
  { cidr: "192.168.0.0/16",  start: ip2long("192.168.0.0"),  end: ip2long("192.168.255.255") },
  { cidr: "169.254.0.0/16",  start: ip2long("169.254.0.0"),  end: ip2long("169.254.255.255") },
  { cidr: "127.0.0.0/8",     start: ip2long("127.0.0.0"),    end: ip2long("127.255.255.255") },
];

/* ── IP utilities ── */
export function ip2long(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isValidIp(ip: string): boolean {
  if (!RE_IP.test(ip)) return false;
  return ip.split(".").every((o) => parseInt(o, 10) <= 255);
}

function isPrivateIp(ip: string): boolean {
  const n = ip2long(ip);
  return PRIVATE_RANGES.some((r) => n >= r.start && n <= r.end);
}

function cidrHostCount(prefix: number): number {
  if (prefix >= 32) return 1;
  if (prefix <= 0)  return 0;
  return Math.pow(2, 32 - prefix) - 2; // subtract network + broadcast
}

/* ── Extract IPs embedded in freeform text ── */
export function extractTargetsFromText(text: string): string[] {
  // Match IPs/CIDRs/ranges/hostnames anywhere in a block of text
  const IP_LIKE = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2}|-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|-\d{1,3})?)/g;
  const matches = text.match(IP_LIKE) ?? [];
  // Also grab hostnames that look like internal FQDN
  const HOST_LIKE = /\b([a-zA-Z][a-zA-Z0-9\-\.]{3,63})\b/g;
  const hosts = (text.match(HOST_LIKE) ?? []).filter((h) =>
    h.includes(".") && !h.match(/^\d/) && !h.endsWith(".com") && !h.endsWith(".org"),
  );
  return [...new Set([...matches, ...hosts])];
}

/* ── Parse a single target string ── */
export function parseTarget(raw: string, exclusions: string[] = []): ParsedTarget {
  const t = raw.trim().replace(/,\s*$/, "");
  if (!t) return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Empty" };

  // Strip protocol for URL
  let input = t;
  let wasUrl = false;
  try {
    const u = new URL(t.startsWith("http") ? t : `http://${t}`);
    if (u.hostname && t.startsWith("http")) { input = u.hostname; wasUrl = true; }
  } catch { /* not a URL */ }

  // CIDR
  if (RE_CIDR.test(input)) {
    const [ipPart, prefixStr] = input.split("/");
    const prefix = parseInt(prefixStr, 10);
    if (!isValidIp(ipPart) || prefix < 0 || prefix > 32) {
      return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Invalid CIDR" };
    }
    const priv = isPrivateIp(ipPart);
    const excl = exclusions.some((e) => e === input || overlapsExclusion(input, e));
    return {
      raw, normalized: input, type: "cidr",
      hostCount: cidrHostCount(prefix),
      isPrivate: priv, isExcluded: excl,
      validationMsg: prefix <= 16 ? `Large range — ${cidrHostCount(prefix).toLocaleString()} hosts` : undefined,
    };
  }

  // Full range: 10.0.0.1-10.0.0.50
  if (RE_RANGE_F.test(input)) {
    const [start, end] = input.split("-");
    if (!isValidIp(start) || !isValidIp(end)) {
      return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Invalid range" };
    }
    const count = Math.max(0, ip2long(end) - ip2long(start) + 1);
    const excl = exclusions.some((e) => e === start);
    return { raw, normalized: input, type: "range", hostCount: count, isPrivate: isPrivateIp(start), isExcluded: excl };
  }

  // Short range: 10.0.0.1-50
  if (RE_RANGE_S.test(input)) {
    const [ipBase, endOctet] = input.split("-");
    const prefix = ipBase.split(".").slice(0, 3).join(".");
    const startOctet = parseInt(ipBase.split(".")[3], 10);
    const endOct = parseInt(endOctet, 10);
    if (!isValidIp(ipBase) || endOct > 255 || endOct < startOctet) {
      return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Invalid range" };
    }
    const normalized = `${prefix}.${startOctet}-${prefix}.${endOct}`;
    const count = endOct - startOctet + 1;
    const excl = exclusions.some((e) => e === ipBase);
    return { raw, normalized, type: "range", hostCount: count, isPrivate: isPrivateIp(ipBase), isExcluded: excl };
  }

  // Single IP
  if (RE_IP.test(input)) {
    if (!isValidIp(input)) {
      return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Octet out of range" };
    }
    const excl = exclusions.some((e) => {
      if (RE_IP.test(e))   return e === input;
      if (RE_CIDR.test(e)) return ipInCidr(input, e);
      return false;
    });
    return { raw, normalized: input, type: "ip", hostCount: 1, isPrivate: isPrivateIp(input), isExcluded: excl };
  }

  // Hostname / FQDN
  if (RE_HOST.test(input)) {
    const excl = exclusions.includes(input);
    return {
      raw, normalized: wasUrl ? t : input, type: "hostname",
      hostCount: 1, isPrivate: false, isExcluded: excl,
    };
  }

  return { raw, normalized: t, type: "invalid", hostCount: 0, isPrivate: false, isExcluded: false, validationMsg: "Unrecognized format" };
}

/* ── Check if IP is inside a CIDR ── */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, prefix] = cidr.split("/");
  const mask = ~(Math.pow(2, 32 - parseInt(prefix, 10)) - 1);
  return (ip2long(ip) & mask) === (ip2long(base) & mask);
}

/* ── Simple overlap check ── */
function overlapsExclusion(target: string, exclusion: string): boolean {
  try {
    if (RE_CIDR.test(target) && RE_CIDR.test(exclusion)) {
      const [tBase, tPrefix] = target.split("/");
      const [eBase, ePrefix] = exclusion.split("/");
      const tp = parseInt(tPrefix, 10), ep = parseInt(ePrefix, 10);
      const mask = ~(Math.pow(2, 32 - Math.min(tp, ep)) - 1);
      return (ip2long(tBase) & mask) === (ip2long(eBase) & mask);
    }
  } catch { /* ignore */ }
  return false;
}

/* ── Parse multiple targets from a text block ── */
export function parseTargets(text: string, exclusions: string[] = []): ParseResult {
  const lines = text
    .split(/[\n,;]+/)
    .map((l) => l.trim())
    .filter(Boolean);

  const targets = lines.map((l) => parseTarget(l, exclusions));

  const valid    = targets.filter((t) => t.type !== "invalid" && !t.isExcluded);
  const invalid  = targets.filter((t) => t.type === "invalid");
  const excluded = targets.filter((t) => t.isExcluded);
  const totalHosts = valid.reduce((s, t) => s + t.hostCount, 0);
  const hasPublicIPs = valid.some((t) => !t.isPrivate && t.type !== "hostname");
  const hasBroadTargets = valid.some((t) => {
    if (t.type === "cidr") {
      const prefix = parseInt(t.normalized.split("/")[1], 10);
      return prefix <= 16;
    }
    return false;
  });

  return { targets, valid, invalid, excluded, totalHosts, hasPublicIPs, hasBroadTargets };
}

/* ── Quick-add common internal ranges ── */
export const COMMON_RANGES = [
  { label: "10.x.x.x",       cidr: "10.0.0.0/8",       hosts: "16.7M" },
  { label: "172.16-31.x.x",  cidr: "172.16.0.0/12",    hosts: "1M"    },
  { label: "192.168.x.x",    cidr: "192.168.0.0/16",   hosts: "65K"   },
  { label: "192.168.1.x",    cidr: "192.168.1.0/24",   hosts: "254"   },
  { label: "10.0.0.x",       cidr: "10.0.0.0/24",      hosts: "254"   },
  { label: "10.10.10.x",     cidr: "10.10.10.0/24",    hosts: "254"   },
];

/* ── Compute API-ready target list ── */
export function toApiTargets(result: ParseResult): string[] {
  return result.valid.map((t) => t.normalized);
}
