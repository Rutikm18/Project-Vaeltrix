export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ScanProfile = 'fast' | 'standard' | 'deep';

export interface ScanOptions {
  targets: string[];
  profile: ScanProfile;
  stealth: number;
  tools: ('naabu' | 'nmap' | 'nuclei' | 'testssl')[];
  save: boolean;
  engagementId?: string;
  scanId?: string;
}

export interface DiscoveredHost {
  ip: string;
  ports: number[];
  services: { port: number; proto: string; name?: string; version?: string }[];
  os?: string;
  hostnames?: string[];
}

export interface Evidence {
  label: string;
  content: string;
  timestamp: string;
}

export interface LiveFinding {
  id: string;
  title: string;
  severity: Severity;
  cvss?: string;
  cvssVector?: string;
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  serviceVersion?: string;
  evidence: Evidence[];
  source: 'nmap' | 'nuclei' | 'testssl' | 'naabu' | 'openvas' | 'manual' | 'agent';
  cveIds?: string[];
  mitre?: { id: string; name: string }[];
  compliance?: { framework: string; refs: string[] }[];
  attackPath?: string;
  remediation?: string;
  timestamp: string;
  engagementId?: string;
  status: 'OPEN' | 'IN_REVIEW' | 'IN_REMEDIATION' | 'VERIFIED' | 'CLOSED';
  slaDeadline?: string;
  falsePositive?: boolean;
  falsePositiveReason?: string;
}

export interface ScanCallbacks {
  onStageStart:    (stage: string) => void;
  onStageComplete: (stage: string, summary: string) => void | Promise<void>;
  onHostDiscovered:(host: DiscoveredHost) => void;
  onFinding:       (finding: LiveFinding) => void;
  onProgress:      (pct: number, message: string) => void;
  onError:         (stage: string, error: string) => void;
  onComplete:      (summary: ScanSummary) => void | Promise<void>;
}

export interface ScanSummary {
  scanId: string;
  startTime: string;
  endTime: string;
  duration: number;
  hostsScanned: number;
  portsFound: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  savedCount: number;
  engagementId?: string;
}

export interface AgentJob {
  id: string;
  type: 'scan' | 'exploit' | 'verify';
  scanId: string;
  targets: string[];
  profile?: ScanProfile;
  stealth?: number;
  tools?: string[];
  scopeToken: string;
  exploitCommand?: string;
  createdAt: string;
}

export interface AgentJobResult {
  jobId: string;
  agentId: string;
  status: 'COMPLETE' | 'FAILED' | 'PARTIAL';
  findings: LiveFinding[];
  error?: string;
  duration: number;
}
