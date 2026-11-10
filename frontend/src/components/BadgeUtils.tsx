import type { ControlStatus, Severity } from "../types";

export function severityBadgeClass(severity: Severity | string): string {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "bg-rose-500/15 text-rose-400 border-rose-500/35 ring-1 ring-rose-500/20 dark:text-rose-300";
    case "HIGH":
      return "bg-orange-500/15 text-orange-500 border-orange-500/35 dark:text-orange-300";
    case "MEDIUM":
      return "bg-amber-500/15 text-amber-600 border-amber-500/35 dark:text-amber-300";
    case "LOW":
      return "bg-sky-500/15 text-sky-600 border-sky-500/35 dark:text-sky-300";
    default:
      return "bg-slate-500/15 text-slate-500 border-slate-500/30 dark:text-slate-300";
  }
}

export function controlBadgeClass(status: ControlStatus): string {
  switch (status) {
    case "PASS":
      return "bg-emerald-500/15 text-emerald-600 border-emerald-500/35 dark:text-emerald-300";
    case "WARN":
      return "bg-amber-500/15 text-amber-600 border-amber-500/35 dark:text-amber-300";
    case "FAIL":
      return "bg-rose-500/15 text-rose-600 border-rose-500/35 dark:text-rose-300";
  }
}

export function scoreColorHex(score: number): string {
  if (score >= 90) return "#10b981";
  if (score >= 75) return "#22d3ee";
  if (score >= 60) return "#f59e0b";
  if (score >= 40) return "#f97316";
  return "#f43f5e";
}

export function gradeBadgeClass(grade: string): string {
  switch (grade) {
    case "A":
      return "bg-emerald-500/15 text-emerald-500 border-emerald-500/40";
    case "B":
      return "bg-cyan-500/15 text-cyan-500 border-cyan-500/40";
    case "C":
      return "bg-amber-500/15 text-amber-500 border-amber-500/40";
    case "D":
      return "bg-orange-500/15 text-orange-500 border-orange-500/40";
    default:
      return "bg-rose-500/15 text-rose-500 border-rose-500/40";
  }
}
