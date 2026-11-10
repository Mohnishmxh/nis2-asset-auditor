export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type ControlStatus = "PASS" | "WARN" | "FAIL";

export interface CveFinding {
  id: string;
  score: number | string;
  severity: Severity;
  cvss_version?: string;
  vector?: string;
  cwe_ids?: string[];
  published?: string;
  last_modified?: string;
  references?: string[];
  summary: string;
  description?: string;
}

export interface Asset {
  host: string;
  hostname?: string;
  port: number;
  protocol: string;
  service: string;
  product: string;
  version: string;
  cpe?: string;
  extrainfo?: string;
  banner?: string;
  encrypted: boolean;
  exposure: "loopback" | "internal-lan" | string;
  risk_score: number;
  nvd_status?: string;
  cves: CveFinding[];
}

export interface ComplianceControl {
  id: string;
  article: string;
  title: string;
  description: string;
  status: ControlStatus;
  score: number;
  max_score: number;
  evidence: string[];
}

export interface RemediationAction {
  id: string;
  title: string;
  priority: Severity;
  nis2_article: string;
  pillar_id: string;
  effort: "LOW" | "MEDIUM" | "HIGH" | string;
  affected_assets: string[];
  rationale: string;
  commands: string;
  impact_points: number;
  mitigated: boolean;
  cve_id?: string;
}

export interface ComplianceSummary {
  score: number;
  baseline_score: number;
  grade: string;
  posture: string;
  controls: ComplianceControl[];
  remediations: RemediationAction[];
  severity_counts: Record<Severity, number>;
  encrypted_count: number;
  cleartext_count: number;
  total_cves: number;
  critical_high_cves: number;
  nis2_reporting_alert: string;
}

export interface ScopeValidationResult {
  valid: boolean;
  normalized_targets: string[];
  host_count: number;
  network_classes: string[];
  reason: string;
}

export interface AuditReport {
  id: string;
  timestamp: string;
  target: string;
  ports: string;
  profile: string;
  mode: "live" | "simulation" | string;
  scenario_id?: string | null;
  scanner_engine: string;
  duration_ms: number;
  scope_summary: ScopeValidationResult;
  assets: Asset[];
  compliance: ComplianceSummary;
  mitigated_ids: string[];
}

export interface AuditSummary {
  id: string;
  created_at: string;
  target: string;
  ports: string;
  profile: string;
  mode: string;
  scanner_engine: string;
  compliance_score: number;
  grade: string;
  asset_count: number;
  cve_count: number;
  critical_count: number;
  high_count: number;
}

export interface ScanProfile {
  id: string;
  name: string;
  ports: string;
  description: string;
}

export interface SimulationScenario {
  id: string;
  name: string;
  target: string;
  ports: string;
  description: string;
  asset_count: number;
}

export interface HealthInfo {
  status: string;
  version: string;
  nmap_available: boolean;
  nvd_api_key_configured: boolean;
  frontend_built: boolean;
  storage: {
    cached_queries: number;
    stored_audits: number;
    db_path: string;
  };
}

export interface ProgressEvent {
  stage: string;
  message: string;
  progress: number;
  audit_id?: string;
  error?: string;
  done?: boolean;
}

export interface ComparisonResult {
  baseline_id: string;
  comparison_id: string;
  baseline_score: number;
  comparison_score: number;
  score_delta: number;
  new_services: string[];
  removed_services: string[];
  new_cves: string[];
  resolved_cves: string[];
}

export interface AssistantResponse {
  answer: string;
  highlights: string[];
  suggested_actions: string[];
}
