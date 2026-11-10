import { CheckCircle2, ShieldAlert, AlertCircle } from "lucide-react";
import type { AuditReport, ComplianceControl } from "../types";
import { controlBadgeClass } from "./BadgeUtils";

interface Nis2MatrixProps {
  report: AuditReport;
}

function ControlIcon({ status }: { status: ComplianceControl["status"] }) {
  if (status === "PASS") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === "WARN") return <AlertCircle className="h-4 w-4 text-amber-500" />;
  return <ShieldAlert className="h-4 w-4 text-rose-500" />;
}

export function Nis2Matrix({ report }: Nis2MatrixProps) {
  const { compliance } = report;
  const sev = compliance.severity_counts;
  const sevBars = [
    { label: "CRITICAL", count: sev.CRITICAL || 0, color: "bg-rose-500" },
    { label: "HIGH", count: sev.HIGH || 0, color: "bg-orange-500" },
    { label: "MEDIUM", count: sev.MEDIUM || 0, color: "bg-amber-400" },
    { label: "LOW", count: sev.LOW || 0, color: "bg-sky-400" },
  ];
  const maxBar = Math.max(1, ...sevBars.map((b) => b.count));

  return (
    <div className="space-y-5">
      {/* Severity & Encryption Telemetry Strip */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75 lg:col-span-7">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            CVE Severity Distribution
          </h3>
          <div className="mt-4 space-y-3">
            {sevBars.map((b) => (
              <div key={b.label} className="grid grid-cols-12 items-center gap-3">
                <span className="col-span-3 font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                  {b.label}
                </span>
                <div className="col-span-7 h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                  <div
                    className={`h-full rounded-full ${b.color} transition-all duration-500`}
                    style={{ width: `${(b.count / maxBar) * 100}%` }}
                  />
                </div>
                <span className="col-span-2 text-right font-mono text-xs font-bold text-slate-900 dark:text-slate-100">
                  {b.count}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75 lg:col-span-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Transport Encryption Posture
          </h3>
          <div className="mt-4 flex items-center gap-5">
            <div className="flex-1 space-y-2">
              <div className="flex justify-between text-xs font-medium">
                <span className="text-emerald-600 dark:text-emerald-400">Encrypted (TLS / SSH)</span>
                <span className="font-mono font-bold text-slate-900 dark:text-white">
                  {compliance.encrypted_count}
                </span>
              </div>
              <div className="h-3 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div
                  className="h-full bg-emerald-500 transition-all duration-500"
                  style={{
                    width: `${
                      report.assets.length
                        ? (compliance.encrypted_count / report.assets.length) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>
              <div className="flex justify-between pt-2 text-xs font-medium">
                <span className="text-amber-600 dark:text-amber-400">Cleartext / Unencrypted</span>
                <span className="font-mono font-bold text-slate-900 dark:text-white">
                  {compliance.cleartext_count}
                </span>
              </div>
              <div className="h-3 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div
                  className="h-full bg-amber-500 transition-all duration-500"
                  style={{
                    width: `${
                      report.assets.length
                        ? (compliance.cleartext_count / report.assets.length) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 5 NIS2 Article 21(2) Control Cards */}
      <div>
        <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          EU NIS2 Directive — Article 21(2) Control Evaluation
        </h3>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {compliance.controls.map((ctrl) => {
            const pct = ctrl.max_score > 0 ? Math.round((ctrl.score / ctrl.max_score) * 100) : 100;
            return (
              <div
                key={ctrl.id}
                className="flex flex-col justify-between rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-cyan-300">
                      {ctrl.article}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${controlBadgeClass(
                        ctrl.status
                      )}`}
                    >
                      <ControlIcon status={ctrl.status} />
                      {ctrl.status}
                    </span>
                  </div>
                  <h4 className="mt-3 text-sm font-bold text-slate-900 dark:text-white">
                    {ctrl.title}
                  </h4>
                  <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                    {ctrl.description}
                  </p>
                  <ul className="mt-3 space-y-1.5 border-t border-slate-100 pt-3 dark:border-slate-800">
                    {ctrl.evidence.slice(0, 3).map((ev, i) => (
                      <li
                        key={i}
                        className="flex items-start gap-1.5 text-[11px] text-slate-600 dark:text-slate-300"
                      >
                        <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-500" />
                        <span>{ev}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-4 pt-2">
                  <div className="flex justify-between font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    <span>Pillar Score</span>
                    <span className="font-bold text-slate-900 dark:text-slate-100">
                      {ctrl.score} / {ctrl.max_score} ({pct}%)
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        ctrl.status === "PASS"
                          ? "bg-emerald-500"
                          : ctrl.status === "WARN"
                          ? "bg-amber-500"
                          : "bg-rose-500"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
