import type {
  AssistantResponse,
  AuditReport,
  AuditSummary,
  ComparisonResult,
  HealthInfo,
  ProgressEvent,
  ScanProfile,
  ScopeValidationResult,
  SimulationScenario,
} from "./types";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      // ignore non-json error body
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export async function fetchHealth(): Promise<HealthInfo> {
  return requestJson<HealthInfo>("/api/health");
}

export async function fetchProfiles(): Promise<{
  profiles: ScanProfile[];
  scenarios: SimulationScenario[];
}> {
  return requestJson("/api/profiles");
}

export async function validateScope(target: string): Promise<ScopeValidationResult> {
  return requestJson<ScopeValidationResult>("/api/validate-scope", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function startAuditJob(payload: {
  target: string;
  ports: string;
  profile: string;
  mode: "live" | "simulation";
  scenario_id?: string | null;
  max_cves?: number;
  use_cache?: boolean;
  api_key?: string | null;
}): Promise<{ job_id: string; status: string }> {
  return requestJson("/api/audits/run", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function subscribeJobStream(
  jobId: string,
  onEvent: (ev: ProgressEvent) => void,
  onError: (msg: string) => void
): () => void {
  const es = new EventSource(`/api/audits/jobs/${jobId}/stream`);
  es.onmessage = (msg) => {
    try {
      const parsed = JSON.parse(msg.data) as ProgressEvent;
      onEvent(parsed);
      if (parsed.done) {
        es.close();
      }
    } catch {
      // ignore parse hiccup
    }
  };
  es.onerror = () => {
    es.close();
    onError("Lost connection to live audit stream; checking final status...");
  };
  return () => es.close();
}

export async function fetchJobStatus(jobId: string): Promise<{
  status: string;
  progress: number;
  stage: string;
  message: string;
  audit_id?: string;
  report?: AuditReport;
  error?: string;
}> {
  return requestJson(`/api/audits/jobs/${jobId}`);
}

export async function fetchAudits(): Promise<AuditSummary[]> {
  const data = await requestJson<{ audits: AuditSummary[] }>("/api/audits");
  return data.audits;
}

export async function fetchAuditReport(auditId: string): Promise<AuditReport> {
  return requestJson<AuditReport>(`/api/audits/${auditId}`);
}

export async function deleteAudit(auditId: string): Promise<void> {
  await requestJson(`/api/audits/${auditId}`, { method: "DELETE" });
}

export async function toggleMitigation(
  auditId: string,
  actionId: string,
  mitigated: boolean
): Promise<AuditReport> {
  return requestJson<AuditReport>(`/api/audits/${auditId}/mitigations`, {
    method: "POST",
    body: JSON.stringify({ action_id: actionId, mitigated }),
  });
}

export async function compareAudits(
  baselineId: string,
  comparisonId: string
): Promise<ComparisonResult> {
  return requestJson<ComparisonResult>(
    `/api/audits/${baselineId}/compare/${comparisonId}`
  );
}

export async function askComplianceAssistant(
  auditId: string,
  question: string
): Promise<AssistantResponse> {
  return requestJson<AssistantResponse>(`/api/audits/${auditId}/ask`, {
    method: "POST",
    body: JSON.stringify({ question }),
  });
}

export async function fetchExportPreview(
  auditId: string,
  format: "md" | "json" | "csv" | "html"
): Promise<string> {
  const res = await fetch(`/api/audits/${auditId}/export?format=${format}`);
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  return res.text();
}

export function getExportDownloadUrl(
  auditId: string,
  format: "md" | "json" | "csv" | "html"
): string {
  return `/api/audits/${auditId}/export?format=${format}`;
}

export async function clearNvdCache(): Promise<{ cleared_entries: number }> {
  return requestJson("/api/cache", { method: "DELETE" });
}
