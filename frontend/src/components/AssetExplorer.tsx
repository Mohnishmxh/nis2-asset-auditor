import { useEffect, useMemo, useState } from "react";
import {
  ChevronRight,
  ExternalLink,
  Lock,
  LockOpen,
  Search,
  Server,
  ShieldAlert,
  X,
} from "lucide-react";
import type { Asset } from "../types";
import { severityBadgeClass } from "./BadgeUtils";

interface AssetExplorerProps {
  assets: Asset[];
  externalQuery?: string;
}

type FilterMode = "all" | "cves" | "crit_high" | "cleartext";

export function AssetExplorer({ assets, externalQuery = "" }: AssetExplorerProps) {
  const [query, setQuery] = useState(externalQuery);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  useEffect(() => {
    setQuery(externalQuery);
  }, [externalQuery]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return assets.filter((a) => {
      if (filter === "cves" && a.cves.length === 0) return false;
      if (
        filter === "crit_high" &&
        !a.cves.some((c) => c.severity === "CRITICAL" || c.severity === "HIGH")
      ) {
        return false;
      }
      if (filter === "cleartext" && a.encrypted) return false;

      if (!q) return true;
      const hay = [
        a.host,
        a.hostname || "",
        String(a.port),
        a.service,
        a.product,
        a.version,
        ...a.cves.map((c) => `${c.id} ${c.summary}`),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [assets, query, filter]);

  return (
    <div className="space-y-4">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by host, port, product, or CVE ID (e.g. CVE-2021, Redis, 6379)..."
            className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2 pr-3 pl-9 text-xs text-slate-900 outline-none focus:border-cyan-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(
            [
              ["all", `All (${assets.length})`],
              ["crit_high", "Critical / High"],
              ["cves", "Has CVEs"],
              ["cleartext", "Cleartext Only"],
            ] as [FilterMode, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setFilter(id)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                filter === id
                  ? "bg-cyan-500/15 text-cyan-700 ring-1 ring-cyan-500/40 dark:text-cyan-300"
                  : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-400"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Asset Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
        {filtered.length === 0 ? (
          <div className="p-10 text-center text-sm text-slate-500 dark:text-slate-400">
            No discovered services match the current filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 bg-slate-50 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:border-slate-800 dark:bg-slate-950/70 dark:text-slate-400">
                <tr>
                  <th className="px-4 py-3">Host &amp; Exposure</th>
                  <th className="px-4 py-3">Port / Service</th>
                  <th className="px-4 py-3">Identified Software</th>
                  <th className="px-4 py-3">Transport</th>
                  <th className="px-4 py-3">Mapped CVEs</th>
                  <th className="px-4 py-3 text-right">Risk</th>
                  <th className="px-3 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {filtered.map((asset) => {
                  const versionLabel =
                    `${asset.product || ""} ${asset.version || ""}`.trim() || "Unidentified Banner";
                  return (
                    <tr
                      key={`${asset.host}:${asset.port}`}
                      onClick={() => setSelectedAsset(asset)}
                      className="cursor-pointer transition hover:bg-cyan-500/5"
                    >
                      <td className="px-4 py-3.5">
                        <div className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                          {asset.host}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {asset.hostname ? `${asset.hostname} • ` : ""}
                          {asset.exposure}
                        </div>
                      </td>
                      <td className="px-4 py-3.5 font-mono">
                        <span className="rounded-md bg-slate-100 px-2 py-0.5 font-semibold text-slate-800 dark:bg-slate-800 dark:text-cyan-300">
                          {asset.port}/{asset.protocol}
                        </span>
                        <span className="ml-2 text-slate-600 dark:text-slate-300">
                          {asset.service}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {versionLabel}
                        </div>
                        {asset.cpe && (
                          <div className="mt-0.5 truncate font-mono text-[10px] text-slate-400 max-w-[230px]">
                            {asset.cpe}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        {asset.encrypted ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-300">
                            <Lock className="h-3 w-3" /> Encrypted
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-amber-600 dark:text-amber-300">
                            <LockOpen className="h-3 w-3" /> Cleartext
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        {asset.cves.length > 0 ? (
                          <div className="flex flex-wrap gap-1.5">
                            {asset.cves.slice(0, 3).map((c) => (
                              <span
                                key={c.id}
                                className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${severityBadgeClass(
                                  c.severity
                                )}`}
                              >
                                {c.id} ({c.score})
                              </span>
                            ))}
                            {asset.cves.length > 3 && (
                              <span className="text-[11px] text-slate-500">
                                +{asset.cves.length - 3} more
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400">No CVEs matched</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-right font-mono font-bold">
                        <span
                          className={
                            asset.risk_score >= 60
                              ? "text-rose-500"
                              : asset.risk_score >= 30
                              ? "text-amber-500"
                              : "text-emerald-500"
                          }
                        >
                          {asset.risk_score}
                        </span>
                      </td>
                      <td className="px-3 py-3.5 text-slate-400">
                        <ChevronRight className="h-4 w-4" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-Over Inspection Drawer */}
      {selectedAsset && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-slate-950/60 backdrop-blur-sm"
          onClick={() => setSelectedAsset(null)}
        >
          <div
            className="h-full w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-6 shadow-2xl dark:border-slate-800 dark:bg-slate-900"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4 border-b border-slate-200 pb-4 dark:border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-500" />
                  <span className="font-mono text-sm font-bold text-slate-900 dark:text-white">
                    {selectedAsset.host}:{selectedAsset.port}/{selectedAsset.protocol}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  {selectedAsset.product || selectedAsset.service} {selectedAsset.version} &bull;{" "}
                  {selectedAsset.exposure} &bull; NVD: {selectedAsset.nvd_status || "ok"}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedAsset(null)}
                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-xs dark:border-slate-800 dark:bg-slate-950">
                <div>
                  <div className="text-slate-500">Asset Risk Score</div>
                  <div className="mt-0.5 font-mono text-lg font-bold text-slate-900 dark:text-white">
                    {selectedAsset.risk_score} / 100
                  </div>
                </div>
                <div>
                  <div className="text-slate-500">Transport Security</div>
                  <div className="mt-0.5 font-semibold text-slate-900 dark:text-white">
                    {selectedAsset.encrypted ? "Encrypted (TLS/SSH)" : "Cleartext (Unencrypted)"}
                  </div>
                </div>
                {selectedAsset.cpe && (
                  <div className="col-span-2">
                    <div className="text-slate-500">CPE 2.3 Identifier</div>
                    <code className="mt-0.5 block break-all text-[11px] text-cyan-600 dark:text-cyan-400">
                      {selectedAsset.cpe}
                    </code>
                  </div>
                )}
                {selectedAsset.banner && (
                  <div className="col-span-2">
                    <div className="text-slate-500">Observed Service Banner</div>
                    <pre className="mt-1 overflow-x-auto rounded-lg bg-slate-900 p-2.5 text-[11px] text-slate-200">
                      {selectedAsset.banner}
                    </pre>
                  </div>
                )}
              </div>

              <div>
                <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  <ShieldAlert className="h-3.5 w-3.5 text-rose-500" />
                  Mapped Vulnerabilities ({selectedAsset.cves.length})
                </h4>

                {selectedAsset.cves.length === 0 ? (
                  <p className="mt-3 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4 text-xs text-emerald-700 dark:text-emerald-300">
                    No matching CVEs found in NIST NVD v2.0 for this exact version signature.
                  </p>
                ) : (
                  <div className="mt-3 space-y-3">
                    {selectedAsset.cves.map((c) => (
                      <div
                        key={c.id}
                        className="rounded-xl border border-slate-200 p-4 dark:border-slate-800 dark:bg-slate-950/60"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-bold text-slate-900 dark:text-white">
                              {c.id}
                            </span>
                            <span
                              className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold ${severityBadgeClass(
                                c.severity
                              )}`}
                            >
                              {c.severity} &bull; CVSS {c.score}
                            </span>
                          </div>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyan-600 hover:underline dark:text-cyan-400"
                          >
                            NVD Advisory <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>

                        {c.vector && (
                          <div className="mt-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                            {c.vector}
                          </div>
                        )}
                        <p className="mt-2 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                          {c.description || c.summary}
                        </p>
                        {c.cwe_ids && c.cwe_ids.length > 0 && (
                          <div className="mt-2.5 flex flex-wrap gap-1.5">
                            {c.cwe_ids.map((cwe) => (
                              <span
                                key={cwe}
                                className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                              >
                                {cwe}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
