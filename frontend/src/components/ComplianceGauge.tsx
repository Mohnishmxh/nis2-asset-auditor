import { AlertTriangle, Lock, LockOpen, Server, ShieldAlert, Sparkles } from "lucide-react";
import type { AuditReport } from "../types";
import { gradeBadgeClass, scoreColorHex } from "./BadgeUtils";

interface ComplianceGaugeProps {
  report: AuditReport;
  onJumpToRemediation: () => void;
}

export function ComplianceGauge({ report, onJumpToRemediation }: ComplianceGaugeProps) {
  const { compliance, assets } = report;
  const score = compliance.score;
  const baseline = compliance.baseline_score;
  const delta = Number((score - baseline).toFixed(1));
  const strokeColor = scoreColorHex(score);

  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  const sev = compliance.severity_counts;
  const critHigh = (sev.CRITICAL || 0) + (sev.HIGH || 0);

  return (
    <section className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      {/* Primary NIS2 Posture Gauge Card */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75 lg:col-span-5">
        <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
          <div className="relative flex h-36 w-36 shrink-0 items-center justify-center">
            <svg className="h-36 w-36 -rotate-90 transform" viewBox="0 0 140 140">
              <circle
                cx="70"
                cy="70"
                r={radius}
                strokeWidth="11"
                fill="none"
                className="stroke-slate-200 dark:stroke-slate-800"
              />
              <circle
                cx="70"
                cy="70"
                r={radius}
                strokeWidth="11"
                strokeLinecap="round"
                fill="none"
                stroke={strokeColor}
                strokeDasharray={circumference}
                strokeDashoffset={dashOffset}
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                {score}
              </span>
              <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                / 100 NIS2
              </span>
            </div>
          </div>

          <div className="flex-1 space-y-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded-lg border px-2.5 py-0.5 text-xs font-bold ${gradeBadgeClass(
                  compliance.grade
                )}`}
              >
                Grade {compliance.grade}
              </span>
              {delta > 0 && (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-xs font-semibold text-emerald-600 dark:text-emerald-300">
                  <Sparkles className="h-3 w-3" /> +{delta} pts simulated
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
              {compliance.posture}
            </h2>
            <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              {compliance.nis2_reporting_alert}
            </p>
            {score < 90 && (
              <button
                type="button"
                onClick={onJumpToRemediation}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-600 hover:text-cyan-500 dark:text-cyan-400 dark:hover:text-cyan-300"
              >
                Simulate Path to Grade A &rarr;
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 4 Telemetry KPI Tiles */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:col-span-7">
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Services</span>
            <Server className="h-4 w-4 text-cyan-500" />
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900 dark:text-white">
            {assets.length}
          </div>
          <p className="mt-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
            Engine: {report.scanner_engine}
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Mapped CVEs</span>
            <ShieldAlert className="h-4 w-4 text-rose-500" />
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900 dark:text-white">
            {compliance.total_cves}
          </div>
          <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            <span className="font-semibold text-rose-500">{sev.CRITICAL || 0} Crit</span> &bull;{" "}
            <span className="font-semibold text-orange-500">{sev.HIGH || 0} High</span>
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Cleartext Risk</span>
            {compliance.cleartext_count > 0 ? (
              <LockOpen className="h-4 w-4 text-amber-500" />
            ) : (
              <Lock className="h-4 w-4 text-emerald-500" />
            )}
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900 dark:text-white">
            {compliance.cleartext_count}
          </div>
          <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {compliance.encrypted_count} encrypted service(s)
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Art. 23 SLA</span>
            <AlertTriangle
              className={`h-4 w-4 ${critHigh > 0 ? "text-rose-500" : "text-emerald-500"}`}
            />
          </div>
          <div className="mt-3 text-2xl font-bold text-slate-900 dark:text-white">
            {sev.CRITICAL > 0 ? "24h" : sev.HIGH > 0 ? "72h" : "Routine"}
          </div>
          <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {critHigh > 0 ? `${critHigh} urgent issue(s)` : "No urgent CVEs"}
          </p>
        </div>
      </div>
    </section>
  );
}
