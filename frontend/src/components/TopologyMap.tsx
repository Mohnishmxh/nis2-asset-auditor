import { useMemo } from "react";
import { Globe, Lock, LockOpen, Network, Server, ShieldCheck } from "lucide-react";
import type { Asset } from "../types";

interface TopologyMapProps {
  target: string;
  assets: Asset[];
  onInspectHost: (host: string) => void;
}

export function TopologyMap({ target, assets, onInspectHost }: TopologyMapProps) {
  const hosts = useMemo(() => {
    const grouped = new Map<string, Asset[]>();
    for (const a of assets) {
      const existing = grouped.get(a.host) || [];
      existing.push(a);
      grouped.set(a.host, existing);
    }
    return Array.from(grouped.entries()).map(([host, items]) => {
      const maxRisk = Math.max(0, ...items.map((i) => i.risk_score));
      const totalCves = items.reduce((acc, i) => acc + i.cves.length, 0);
      const hostname = items.find((i) => i.hostname)?.hostname || "";
      const exposure = items[0]?.exposure || "internal-lan";
      return { host, hostname, exposure, items, maxRisk, totalCves };
    });
  }, [assets]);

  if (hosts.length === 0) return null;

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            <Network className="h-4 w-4 text-cyan-500" />
            Internal Attack Surface Topology ({hosts.length} host{hosts.length === 1 ? "" : "s"})
          </h3>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Click any host node to filter its exposed ports and CVEs in the Asset Explorer.
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-mono text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
          <ShieldCheck className="h-3.5 w-3.5" />
          Scope Guardrail: {target}
        </span>
      </div>

      {/* Central Scanner Origin + Host Grid */}
      <div className="mt-5 flex flex-col items-center">
        <div className="inline-flex items-center gap-2 rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 font-mono text-xs font-bold text-cyan-700 shadow-sm dark:text-cyan-300">
          <Globe className="h-4 w-4" />
          NIS2 Auditor Probe &rarr; RFC 1918 Boundary
        </div>
        <div className="h-5 w-px bg-gradient-to-b from-cyan-500/50 to-slate-300 dark:to-slate-700" />

        <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {hosts.map((h) => {
            const borderTone =
              h.maxRisk >= 60
                ? "border-rose-500/45 hover:border-rose-500"
                : h.maxRisk >= 30
                ? "border-amber-500/45 hover:border-amber-500"
                : "border-emerald-500/35 hover:border-emerald-500";
            const riskDot =
              h.maxRisk >= 60
                ? "bg-rose-500"
                : h.maxRisk >= 30
                ? "bg-amber-500"
                : "bg-emerald-500";

            return (
              <button
                key={h.host}
                type="button"
                onClick={() => onInspectHost(h.host)}
                className={`group flex flex-col justify-between rounded-xl border bg-slate-50/70 p-4 text-left transition hover:-translate-y-0.5 hover:shadow-md dark:bg-slate-950/70 ${borderTone}`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs font-bold text-slate-900 dark:text-white">
                      <Server className="h-3.5 w-3.5 text-cyan-500" />
                      {h.host}
                    </span>
                    <span className={`h-2.5 w-2.5 rounded-full ${riskDot}`} />
                  </div>
                  <div className="mt-0.5 truncate text-[11px] text-slate-500 dark:text-slate-400">
                    {h.hostname ? `${h.hostname} • ` : ""}
                    {h.exposure}
                  </div>

                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {h.items.map((svc) => (
                      <span
                        key={`${svc.port}-${svc.protocol}`}
                        className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold ${
                          svc.cves.some((c) => c.severity === "CRITICAL" || c.severity === "HIGH")
                            ? "border-rose-500/35 bg-rose-500/10 text-rose-600 dark:text-rose-300"
                            : svc.encrypted
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                            : "border-amber-500/35 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                        }`}
                      >
                        {svc.encrypted ? (
                          <Lock className="h-2.5 w-2.5" />
                        ) : (
                          <LockOpen className="h-2.5 w-2.5" />
                        )}
                        {svc.port}/{svc.service}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-3 flex items-center justify-between border-t border-slate-200/80 pt-2.5 font-mono text-[10px] text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  <span>Max Risk: {h.maxRisk}/100</span>
                  <span className="font-semibold text-cyan-600 group-hover:underline dark:text-cyan-400">
                    {h.totalCves} CVE(s) &rarr;
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
