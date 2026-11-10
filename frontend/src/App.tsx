import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Database,
  Download,
  FlaskConical,
  History,
  LayoutDashboard,
  Moon,
  Server,
  Shield,
  Sun,
  Trash2,
  Wrench,
} from "lucide-react";
import {
  clearNvdCache,
  deleteAudit,
  fetchAuditReport,
  fetchAudits,
  fetchHealth,
  fetchJobStatus,
  fetchProfiles,
  startAuditJob,
  subscribeJobStream,
  toggleMitigation,
} from "./api";
import { AssetExplorer } from "./components/AssetExplorer";
import { AuditHistoryCompare } from "./components/AuditHistoryCompare";
import { AuditLaunchpad, type AuditRunOptions } from "./components/AuditLaunchpad";
import { ComplianceAssistant } from "./components/ComplianceAssistant";
import { ComplianceGauge } from "./components/ComplianceGauge";
import { Nis2Matrix } from "./components/Nis2Matrix";
import { RemediationSimulator } from "./components/RemediationSimulator";
import { ReportPreviewModal } from "./components/ReportPreviewModal";
import { TopologyMap } from "./components/TopologyMap";
import type {
  AuditReport,
  AuditSummary,
  HealthInfo,
  ProgressEvent,
  ScanProfile,
  SimulationScenario,
} from "./types";

type ActiveTab = "overview" | "assets" | "remediate" | "history";

export function App() {
  const [dark, setDark] = useState(true);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [audits, setAudits] = useState<AuditSummary[]>([]);
  const [activeReport, setActiveReport] = useState<AuditReport | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("overview");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [progressLog, setProgressLog] = useState<ProgressEvent[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [highlightedActions, setHighlightedActions] = useState<string[]>([]);
  const [assetHostFilter, setAssetHostFilter] = useState("");
  const [showExportModal, setShowExportModal] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    if (dark) {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [dark]);

  const refreshSidebarData = useCallback(async () => {
    const [h, prof, list] = await Promise.all([
      fetchHealth(),
      fetchProfiles(),
      fetchAudits(),
    ]);
    setHealth(h);
    setProfiles(prof.profiles);
    setScenarios(prof.scenarios);
    setAudits(list);
    return list;
  }, []);

  useEffect(() => {
    refreshSidebarData()
      .then((list) => {
        if (list.length > 0) {
          return fetchAuditReport(list[0].id).then((rep) => setActiveReport(rep));
        }
        return undefined;
      })
      .catch((err) => {
        setErrorMessage(err instanceof Error ? err.message : "Failed to initialize console.");
      });
  }, [refreshSidebarData]);

  const executeJob = async (payload: {
    target: string;
    ports: string;
    profile: string;
    mode: "live" | "simulation";
    scenario_id?: string | null;
    max_cves?: number;
    use_cache?: boolean;
    api_key?: string | null;
  }) => {
    setErrorMessage(null);
    setAssetHostFilter("");
    setRunning(true);
    setProgressLog([]);
    setProgress({ stage: "init", message: "Starting NIS2 audit pipeline...", progress: 5 });

    try {
      const { job_id } = await startAuditJob(payload);
      await new Promise<void>((resolve, reject) => {
        const stopStream = subscribeJobStream(
          job_id,
          async (ev) => {
            setProgress(ev);
            if (!ev.done) {
              setProgressLog((prev) => [...prev, ev]);
              return;
            }
            if (ev.error) {
              reject(new Error(ev.error));
              return;
            }
            if (ev.audit_id) {
              const rep = await fetchAuditReport(ev.audit_id);
              setActiveReport(rep);
              await refreshSidebarData();
              setActiveTab("overview");
              resolve();
            } else {
              resolve();
            }
          },
          async () => {
            // Fallback check if SSE closes early
            try {
              const status = await fetchJobStatus(job_id);
              if (status.status === "completed" && status.audit_id) {
                const rep = await fetchAuditReport(status.audit_id);
                setActiveReport(rep);
                await refreshSidebarData();
                resolve();
              } else if (status.status === "failed") {
                reject(new Error(status.error || "Audit failed."));
              } else {
                resolve();
              }
            } catch (err) {
              reject(err);
            }
          }
        );

        // Safety cleanup timer after 2 minutes
        setTimeout(() => stopStream(), 120000);
      });
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Audit failed.");
    } finally {
      setRunning(false);
    }
  };

  const handleRunLive = (
    target: string,
    ports: string,
    profile: string,
    options?: AuditRunOptions
  ) => {
    void executeJob({
      target,
      ports,
      profile,
      mode: "live",
      max_cves: options?.maxCves ?? 5,
      use_cache: options?.useCache ?? true,
      api_key: options?.apiKey ? options.apiKey : null,
    });
  };

  const handleRunSimulation = (scenarioId: string) => {
    const sc = scenarios.find((s) => s.id === scenarioId);
    void executeJob({
      target: sc?.target || "192.168.10.0/24",
      ports: sc?.ports || "22,80,443",
      profile: "custom",
      mode: "simulation",
      scenario_id: scenarioId,
    });
  };

  const handleToggleMitigation = async (actionId: string, mitigated: boolean) => {
    if (!activeReport) return;
    const updated = await toggleMitigation(activeReport.id, actionId, mitigated);
    setActiveReport(updated);
    await refreshSidebarData();
  };

  const handleSelectAudit = async (auditId: string) => {
    const rep = await fetchAuditReport(auditId);
    setActiveReport(rep);
    setActiveTab("overview");
  };

  const handleDeleteAudit = async (auditId: string) => {
    await deleteAudit(auditId);
    const remaining = await refreshSidebarData();
    if (activeReport?.id === auditId) {
      if (remaining.length > 0) {
        const nextRep = await fetchAuditReport(remaining[0].id);
        setActiveReport(nextRep);
      } else {
        setActiveReport(null);
      }
    }
  };

  const handleClearCache = async () => {
    await clearNvdCache();
    await refreshSidebarData();
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 transition-colors dark:bg-slate-950 dark:text-slate-100">
      {/* Subtle Ambient Background Gradient */}
      <div className="pointer-events-none fixed inset-x-0 top-0 h-80 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-500/12 via-emerald-500/5 to-transparent" />

      {/* Top Navigation Header */}
      <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/85 backdrop-blur-md dark:border-slate-800/80 dark:bg-slate-950/85">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-emerald-500 text-white shadow-md shadow-cyan-500/20">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-extrabold tracking-tight text-slate-900 dark:text-white sm:text-base">
                  NIS2 Asset Auditor
                </h1>
                <span className="rounded-md border border-cyan-500/35 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-600 dark:text-cyan-300">
                  EU 2022/2555
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Internal Attack Surface Discovery &amp; NIST NVD v2.0 Compliance Console
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {health && (
              <div className="hidden items-center gap-2 text-[11px] md:flex">
                <span
                  className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 font-mono ${
                    health.nmap_available
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300"
                  }`}
                >
                  <Activity className="h-3 w-3" />
                  {health.nmap_available ? "Nmap Ready" : "Socket Fallback"}
                </span>
                <button
                  type="button"
                  onClick={handleClearCache}
                  title="Click to clear cached NIST NVD responses"
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-100 px-2.5 py-1 font-mono text-slate-600 hover:border-rose-400 hover:text-rose-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
                >
                  <Database className="h-3 w-3 text-cyan-500" />
                  NVD Cache: {health.storage.cached_queries}
                  <Trash2 className="ml-0.5 h-2.5 w-2.5 opacity-60" />
                </button>
              </div>
            )}

            {activeReport && (
              <button
                type="button"
                onClick={() => setShowExportModal(true)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm transition hover:border-cyan-500 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
              >
                <Download className="h-3.5 w-3.5" />
                Export Report
              </button>
            )}

            <button
              type="button"
              onClick={() => setDark((d) => !d)}
              title="Toggle Dark / Light Mode"
              className="rounded-xl border border-slate-200 bg-slate-100 p-2 text-slate-700 transition hover:bg-slate-200 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        <AuditLaunchpad
          profiles={profiles}
          scenarios={scenarios}
          running={running}
          progress={progress}
          progressLog={progressLog}
          errorMessage={errorMessage}
          onRunLive={handleRunLive}
          onRunSimulation={handleRunSimulation}
        />

        {!activeReport ? (
          <section className="rounded-2xl border border-dashed border-slate-300 bg-white/70 p-10 text-center dark:border-slate-800 dark:bg-slate-900/50">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-cyan-500/10 text-cyan-500">
              <Shield className="h-7 w-7" />
            </div>
            <h2 className="mt-4 text-lg font-bold text-slate-900 dark:text-white">
              Ready for Your First EU NIS2 Audit
            </h2>
            <p className="mx-auto mt-1.5 max-w-xl text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Run a live guarded scan on <code className="text-cyan-500">127.0.0.1</code> or your private subnet above, or launch an instant offline simulation to inspect NIS2 Article 21(2) scoring, CVE mappings, and remediation workflows.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <button
                type="button"
                disabled={running}
                onClick={() => handleRunSimulation("mittelstand_office")}
                className="inline-flex items-center gap-2 rounded-xl bg-cyan-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500"
              >
                <FlaskConical className="h-4 w-4" />
                Launch Mittelstand Office Demo
              </button>
              <button
                type="button"
                disabled={running}
                onClick={() =>
                  handleRunLive(
                    "127.0.0.1",
                    "21,22,23,25,53,80,443,3306,5432,6379,8000,8080,8443",
                    "quick"
                  )
                }
                className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-xs font-semibold text-slate-800 hover:border-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
              >
                <Activity className="h-4 w-4 text-emerald-500" />
                Scan Localhost (127.0.0.1)
              </button>
            </div>
          </section>
        ) : (
          <>
            {/* Active Audit Context Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-xs text-slate-500 dark:text-slate-400">
              <div>
                Active Audit: <code className="font-semibold text-slate-800 dark:text-slate-200">{activeReport.target}</code>{" "}
                &bull; {activeReport.timestamp} &bull; {activeReport.duration_ms}ms ({activeReport.mode})
              </div>
              <div className="font-mono text-[11px]">ID: {activeReport.id}</div>
            </div>

            <ComplianceGauge
              report={activeReport}
              onJumpToRemediation={() => setActiveTab("remediate")}
            />

            {/* Workspace Navigation Tabs */}
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 pb-3 dark:border-slate-800">
              {(
                [
                  ["overview", "NIS2 Control Matrix", LayoutDashboard],
                  ["assets", `Assets & CVEs (${activeReport.assets.length})`, Server],
                  [
                    "remediate",
                    `Remediation Simulator (${activeReport.compliance.remediations.filter((r) => !r.mitigated).length} open)`,
                    Wrench,
                  ],
                  ["history", `History & Drift (${audits.length})`, History],
                ] as [ActiveTab, string, typeof LayoutDashboard][]
              ).map(([tabId, label, Icon]) => (
                <button
                  key={tabId}
                  type="button"
                  onClick={() => setActiveTab(tabId)}
                  className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-semibold transition ${
                    activeTab === tabId
                      ? "bg-slate-900 text-white shadow-sm dark:bg-cyan-500/15 dark:text-cyan-300 dark:ring-1 dark:ring-cyan-500/40"
                      : "bg-white text-slate-600 hover:bg-slate-100 dark:bg-slate-900/60 dark:text-slate-400 dark:hover:text-slate-200"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </button>
              ))}
            </div>

            {activeTab === "overview" && (
              <div className="space-y-5">
                <TopologyMap
                  target={activeReport.target}
                  assets={activeReport.assets}
                  onInspectHost={(host) => {
                    setAssetHostFilter(host);
                    setActiveTab("assets");
                  }}
                />
                <Nis2Matrix report={activeReport} />
              </div>
            )}
            {activeTab === "assets" && (
              <AssetExplorer
                assets={activeReport.assets}
                externalQuery={assetHostFilter}
              />
            )}
            {activeTab === "remediate" && (
              <RemediationSimulator
                report={activeReport}
                highlightedActionIds={highlightedActions}
                onToggleMitigation={handleToggleMitigation}
              />
            )}
            {activeTab === "history" && (
              <AuditHistoryCompare
                audits={audits}
                activeAuditId={activeReport.id}
                onSelectAudit={handleSelectAudit}
                onDeleteAudit={handleDeleteAudit}
              />
            )}

            <ComplianceAssistant
              auditId={activeReport.id}
              onHighlightActions={(ids) => {
                setHighlightedActions(ids);
                setActiveTab("remediate");
              }}
            />
          </>
        )}
      </main>

      {showExportModal && activeReport && (
        <ReportPreviewModal
          auditId={activeReport.id}
          onClose={() => setShowExportModal(false)}
        />
      )}
    </div>
  );
}

export default App;
