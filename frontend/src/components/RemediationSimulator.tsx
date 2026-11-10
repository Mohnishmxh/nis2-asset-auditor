import { useState } from "react";
import { Check, CheckCircle2, Copy, Sparkles, Terminal, Wrench } from "lucide-react";
import type { AuditReport } from "../types";
import { severityBadgeClass } from "./BadgeUtils";

interface RemediationSimulatorProps {
  report: AuditReport;
  highlightedActionIds: string[];
  onToggleMitigation: (actionId: string, mitigated: boolean) => Promise<void>;
}

export function RemediationSimulator({
  report,
  highlightedActionIds,
  onToggleMitigation,
}: RemediationSimulatorProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { compliance } = report;
  const remediations = compliance.remediations;
  const mitigatedCount = remediations.filter((r) => r.mitigated).length;
  const pointsGained = Number((compliance.score - compliance.baseline_score).toFixed(1));

  const handleToggle = async (actionId: string, next: boolean) => {
    setBusyId(actionId);
    try {
      await onToggleMitigation(actionId, next);
    } finally {
      setBusyId(null);
    }
  };

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1600);
    } catch {
      // ignore clipboard restrictions
    }
  };

  return (
    <div className="space-y-4">
      {/* Simulator Banner */}
      <div className="flex flex-col justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-500/10 via-emerald-500/5 to-transparent p-5 sm:flex-row sm:items-center">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-white">
            <Sparkles className="h-4 w-4 text-cyan-500" />
            Interactive &ldquo;Path to Grade A&rdquo; Remediation Simulator
          </h3>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
            Toggle remediation items below to simulate fixes or track completed engineering patches. Your NIS2 Compliance Score recalculates live and persists to the audit log.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-4 font-mono">
          <div className="text-right">
            <div className="text-[11px] uppercase text-slate-500 dark:text-slate-400">
              Mitigated
            </div>
            <div className="text-lg font-bold text-slate-900 dark:text-white">
              {mitigatedCount} / {remediations.length}
            </div>
          </div>
          <div className="h-8 w-px bg-slate-300 dark:bg-slate-700" />
          <div className="text-right">
            <div className="text-[11px] uppercase text-slate-500 dark:text-slate-400">
              Simulated Boost
            </div>
            <div className="text-lg font-bold text-emerald-500">+{pointsGained} pts</div>
          </div>
        </div>
      </div>

      {remediations.length === 0 ? (
        <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-8 text-center">
          <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-500" />
          <h4 className="mt-2 text-sm font-bold text-slate-900 dark:text-white">
            Zero Open Remediations
          </h4>
          <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            This target meets baseline NIS2 Article 21(2) posture controls.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {remediations.map((rem) => {
            const isHighlighted = highlightedActionIds.includes(rem.id);
            return (
              <div
                key={rem.id}
                className={`rounded-2xl border p-5 transition ${
                  rem.mitigated
                    ? "border-emerald-500/35 bg-emerald-500/5 opacity-85"
                    : isHighlighted
                    ? "border-cyan-500/60 bg-cyan-500/5 ring-2 ring-cyan-500/20"
                    : "border-slate-200 bg-white dark:border-slate-800/90 dark:bg-slate-900/75"
                }`}
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded-md border px-2 py-0.5 font-mono text-[10px] font-bold ${severityBadgeClass(
                          rem.priority
                        )}`}
                      >
                        {rem.priority}
                      </span>
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-cyan-300">
                        {rem.nis2_article}
                      </span>
                      <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                        Effort: {rem.effort}
                      </span>
                      <span className="rounded-md bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-600 dark:text-emerald-300">
                        +{rem.impact_points} pts
                      </span>
                    </div>

                    <h4
                      className={`text-sm font-bold ${
                        rem.mitigated
                          ? "line-through text-slate-500 dark:text-slate-400"
                          : "text-slate-900 dark:text-white"
                      }`}
                    >
                      {rem.title}
                    </h4>
                    <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                      {rem.rationale}
                    </p>

                    <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                      <Wrench className="h-3 w-3" />
                      <span>Affected:</span>
                      {rem.affected_assets.map((a) => (
                        <code
                          key={a}
                          className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                        >
                          {a}
                        </code>
                      ))}
                    </div>
                  </div>

                  {/* Interactive Simulate Switch */}
                  <button
                    type="button"
                    disabled={busyId === rem.id}
                    onClick={() => handleToggle(rem.id, !rem.mitigated)}
                    className={`inline-flex shrink-0 items-center gap-2 rounded-xl border px-3.5 py-2 text-xs font-semibold transition ${
                      rem.mitigated
                        ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                        : "border-slate-300 bg-slate-50 text-slate-700 hover:border-cyan-500 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200"
                    }`}
                  >
                    <CheckCircle2 className="h-4 w-4" />
                    {rem.mitigated ? "Mitigated" : "Mark Resolved"}
                  </button>
                </div>

                {/* Copyable Hardening Snippet */}
                {rem.commands && (
                  <div className="mt-4 overflow-hidden rounded-xl border border-slate-200 bg-slate-950 dark:border-slate-800">
                    <div className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5 text-[11px] text-slate-400">
                      <span className="flex items-center gap-1.5 font-mono">
                        <Terminal className="h-3 w-3 text-cyan-400" />
                        Recommended Hardening Snippet
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(rem.id, rem.commands)}
                        className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-semibold text-slate-300 hover:bg-slate-800"
                      >
                        {copiedId === rem.id ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-400" /> Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" /> Copy
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="overflow-x-auto p-3 font-mono text-[11px] leading-relaxed text-slate-200">
                      {rem.commands}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
