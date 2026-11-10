import { useState } from "react";
import { ArrowLeftRight, Clock, GitCompare, Trash2 } from "lucide-react";
import { compareAudits } from "../api";
import type { AuditSummary, ComparisonResult } from "../types";
import { gradeBadgeClass } from "./BadgeUtils";

interface AuditHistoryCompareProps {
  audits: AuditSummary[];
  activeAuditId: string | null;
  onSelectAudit: (id: string) => void;
  onDeleteAudit: (id: string) => void;
}

export function AuditHistoryCompare({
  audits,
  activeAuditId,
  onSelectAudit,
  onDeleteAudit,
}: AuditHistoryCompareProps) {
  const [baselineId, setBaselineId] = useState(audits[1]?.id || audits[0]?.id || "");
  const [compareId, setCompareId] = useState(audits[0]?.id || "");
  const [diff, setDiff] = useState<ComparisonResult | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);

  const handleCompare = async () => {
    if (!baselineId || !compareId) return;
    setLoadingDiff(true);
    setDiffError(null);
    try {
      const res = await compareAudits(baselineId, compareId);
      setDiff(res);
    } catch (err) {
      setDiffError(err instanceof Error ? err.message : "Failed to compare audits.");
    } finally {
      setLoadingDiff(false);
    }
  };

  // Chronological order (oldest -> newest) for trajectory sparkline
  const trendPoints = [...audits].slice(0, 12).reverse();
  const sparkCoords = trendPoints.map((pt, idx) => {
    const x = trendPoints.length === 1 ? 150 : (idx / (trendPoints.length - 1)) * 280 + 10;
    const y = 62 - (Math.min(100, Math.max(0, pt.compliance_score)) / 100) * 50;
    return { x, y, pt };
  });
  const polylinePoints = sparkCoords.map((c) => `${c.x},${c.y}`).join(" ");

  return (
    <div className="space-y-5">
      {/* Score Trajectory Sparkline & Drift Comparison */}
      {audits.length >= 2 && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white">
                <GitCompare className="h-4 w-4 text-cyan-500" />
                Posture Drift &amp; Compliance Trajectory
              </h3>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Compare any two stored audits to track newly opened ports, resolved CVEs, and NIS2 score trend.
              </p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Recent Score Trend ({trendPoints.length} runs)
              </div>
              <svg viewBox="0 0 300 72" className="h-14 w-64">
                <line x1="10" y1="12" x2="290" y2="12" strokeDasharray="3 3" className="stroke-emerald-500/35" />
                <polyline
                  fill="none"
                  stroke="#06b6d4"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={polylinePoints}
                />
                {sparkCoords.map((c) => (
                  <circle key={c.pt.id} cx={c.x} cy={c.y} r="3.5" className="fill-cyan-400 stroke-slate-950" strokeWidth="1.2">
                    <title>{`${c.pt.target}: ${c.pt.compliance_score}/100 (${c.pt.grade})`}</title>
                  </circle>
                ))}
              </svg>
            </div>
          </div>

          <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="flex-1 rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            >
              {audits.map((a) => (
                <option key={a.id} value={a.id}>
                  Baseline: {a.target} ({a.compliance_score}/100) — {a.created_at}
                </option>
              ))}
            </select>
            <ArrowLeftRight className="hidden h-4 w-4 shrink-0 text-slate-400 sm:block" />
            <select
              value={compareId}
              onChange={(e) => setCompareId(e.target.value)}
              className="flex-1 rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
            >
              {audits.map((a) => (
                <option key={a.id} value={a.id}>
                  Target: {a.target} ({a.compliance_score}/100) — {a.created_at}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={loadingDiff}
              onClick={handleCompare}
              className="rounded-xl bg-cyan-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-cyan-500 disabled:opacity-50"
            >
              {loadingDiff ? "Comparing..." : "Compare Drift"}
            </button>
          </div>

          {diffError && (
            <div className="mt-3 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-500">
              {diffError}
            </div>
          )}

          {diff && (
            <div className="mt-4 grid grid-cols-1 gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs dark:border-slate-800 dark:bg-slate-950 md:grid-cols-4">
              <div>
                <div className="text-slate-500">Score Delta</div>
                <div
                  className={`mt-1 font-mono text-xl font-bold ${
                    diff.score_delta >= 0 ? "text-emerald-500" : "text-rose-500"
                  }`}
                >
                  {diff.score_delta >= 0 ? `+${diff.score_delta}` : diff.score_delta} pts
                </div>
                <div className="text-[11px] text-slate-500">
                  {diff.baseline_score} &rarr; {diff.comparison_score}
                </div>
              </div>
              <div>
                <div className="text-slate-500">New Services</div>
                <div className="mt-1 font-mono font-semibold text-slate-900 dark:text-slate-100">
                  {diff.new_services.length ? diff.new_services.join(", ") : "None"}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Removed Services</div>
                <div className="mt-1 font-mono font-semibold text-emerald-500">
                  {diff.removed_services.length ? diff.removed_services.join(", ") : "None"}
                </div>
              </div>
              <div>
                <div className="text-slate-500">CVE Change</div>
                <div className="mt-1 space-y-0.5 font-mono text-[11px]">
                  <div className="text-rose-500">+{diff.new_cves.length} new</div>
                  <div className="text-emerald-500">-{diff.resolved_cves.length} resolved</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Audit History Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            <Clock className="h-4 w-4 text-cyan-500" />
            Stored Audit Timeline ({audits.length})
          </h3>
        </div>
        {audits.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No saved audits yet. Run a live scan or simulation above to persist audit evidence.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase text-slate-500 dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Target Scope</th>
                  <th className="px-4 py-3">Mode</th>
                  <th className="px-4 py-3">Services</th>
                  <th className="px-4 py-3">CVEs (C/H)</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {audits.map((a) => {
                  const isActive = a.id === activeAuditId;
                  return (
                    <tr
                      key={a.id}
                      className={`transition ${
                        isActive ? "bg-cyan-500/10" : "hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      }`}
                    >
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                        {a.created_at}
                      </td>
                      <td className="px-4 py-3 font-mono font-semibold text-slate-900 dark:text-white">
                        {a.target}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[10px] text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {a.mode} / {a.scanner_engine}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono">{a.asset_count}</td>
                      <td className="px-4 py-3 font-mono">
                        {a.cve_count}{" "}
                        <span className="text-[11px] text-rose-500">
                          ({a.critical_count}/{a.high_count})
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold ${gradeBadgeClass(
                            a.grade
                          )}`}
                        >
                          {a.compliance_score} ({a.grade})
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => onSelectAudit(a.id)}
                            className="rounded-lg border border-cyan-500/40 px-2.5 py-1 text-[11px] font-semibold text-cyan-600 hover:bg-cyan-500/10 dark:text-cyan-300"
                          >
                            {isActive ? "Viewing" : "Open"}
                          </button>
                          <button
                            type="button"
                            title="Delete audit"
                            onClick={() => onDeleteAudit(a.id)}
                            className="rounded-lg p-1 text-slate-400 hover:bg-rose-500/10 hover:text-rose-500"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
