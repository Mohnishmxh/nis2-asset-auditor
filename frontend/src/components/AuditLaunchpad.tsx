import { useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  FlaskConical,
  Play,
  Radar,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { validateScope } from "../api";
import type {
  ProgressEvent,
  ScanProfile,
  ScopeValidationResult,
  SimulationScenario,
} from "../types";

export interface AuditRunOptions {
  maxCves: number;
  useCache: boolean;
  apiKey: string;
}

interface AuditLaunchpadProps {
  profiles: ScanProfile[];
  scenarios: SimulationScenario[];
  running: boolean;
  progress: ProgressEvent | null;
  progressLog: ProgressEvent[];
  errorMessage: string | null;
  onRunLive: (target: string, ports: string, profile: string, options: AuditRunOptions) => void;
  onRunSimulation: (scenarioId: string) => void;
}

const TARGET_PRESETS = ["127.0.0.1", "localhost", "192.168.1.0/24", "10.0.0.0/24"];

export function AuditLaunchpad({
  profiles,
  scenarios,
  running,
  progress,
  progressLog,
  errorMessage,
  onRunLive,
  onRunSimulation,
}: AuditLaunchpadProps) {
  const [mode, setMode] = useState<"live" | "simulation">("live");
  const [target, setTarget] = useState("127.0.0.1");
  const [selectedProfile, setSelectedProfile] = useState("quick");
  const [ports, setPorts] = useState("21,22,23,25,53,80,443,3306,5432,6379,8000,8080,8443");
  const [scopeStatus, setScopeStatus] = useState<ScopeValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxCves, setMaxCves] = useState(5);
  const [useCache, setUseCache] = useState(true);
  const [apiKey, setApiKey] = useState("");

  useEffect(() => {
    const trimmed = target.trim();
    if (!trimmed) {
      setScopeStatus({
        valid: false,
        normalized_targets: [],
        host_count: 0,
        network_classes: [],
        reason: "Enter a private IP, CIDR range, or localhost.",
      });
      return;
    }

    const timer = setTimeout(async () => {
      setValidating(true);
      try {
        const res = await validateScope(trimmed);
        setScopeStatus(res);
      } catch {
        // ignore transient network check error while typing
      } finally {
        setValidating(false);
      }
    }, 220);

    return () => clearTimeout(timer);
  }, [target]);

  const handleProfileClick = (profile: ScanProfile) => {
    setSelectedProfile(profile.id);
    setPorts(profile.ports);
  };

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-white">
            <Radar className="h-4 w-4 text-cyan-500" />
            Internal Audit Launchpad
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            Execute a guarded RFC 1918 network discovery &amp; NIST NVD v2.0 scan, or test an offline NIS2 benchmark scenario.
          </p>
        </div>

        {/* Mode Switcher */}
        <div className="inline-flex rounded-xl border border-slate-200 bg-slate-100 p-1 dark:border-slate-800 dark:bg-slate-950">
          <button
            type="button"
            onClick={() => setMode("live")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
              mode === "live"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-cyan-300"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            Live Network Scan
          </button>
          <button
            type="button"
            onClick={() => setMode("simulation")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
              mode === "simulation"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-cyan-300"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200"
            }`}
          >
            <FlaskConical className="h-3.5 w-3.5" />
            Interactive Demo Scenarios
          </button>
        </div>
      </div>

      {mode === "live" ? (
        <div className="mt-5 space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            {/* Target Input + Live RFC 1918 Guardrail */}
            <div className="lg:col-span-5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Target IP / Subnet (RFC 1918 or Loopback)
                </label>
                <div className="flex gap-1.5">
                  {TARGET_PRESETS.map((preset) => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setTarget(preset)}
                      className="rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 hover:bg-cyan-500/15 hover:text-cyan-600 dark:bg-slate-800 dark:text-slate-400 dark:hover:text-cyan-300"
                    >
                      {preset}
                    </button>
                  ))}
                </div>
              </div>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 127.0.0.1 or 192.168.10.0/24"
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-3.5 py-2.5 font-mono text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              />
              {scopeStatus && (
                <div
                  className={`mt-2 flex items-start gap-1.5 rounded-lg px-2.5 py-1.5 text-[11px] ${
                    scopeStatus.valid
                      ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                      : "bg-rose-500/10 text-rose-700 dark:text-rose-300"
                  }`}
                >
                  {scopeStatus.valid ? (
                    <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  ) : (
                    <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  )}
                  <span>
                    {validating ? "Verifying scope..." : scopeStatus.reason}
                    {scopeStatus.valid && scopeStatus.network_classes.length > 0 && (
                      <span className="ml-1 font-mono opacity-80">
                        [{scopeStatus.network_classes.join(", ")} &bull; {scopeStatus.host_count} host(s)]
                      </span>
                    )}
                  </span>
                </div>
              )}
            </div>

            {/* Ports & Profiles */}
            <div className="lg:col-span-5">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                Audit Ports / Service Profile
              </label>
              <input
                type="text"
                value={ports}
                onChange={(e) => {
                  setPorts(e.target.value);
                  setSelectedProfile("custom");
                }}
                placeholder="22,80,443,8000,8080"
                className="mt-1.5 w-full rounded-xl border border-slate-300 bg-slate-50 px-3.5 py-2.5 font-mono text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              />
              <div className="mt-2 flex flex-wrap gap-1.5">
                {profiles.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    title={p.description}
                    onClick={() => handleProfileClick(p)}
                    className={`rounded-lg border px-2.5 py-1 text-[11px] font-medium transition ${
                      selectedProfile === p.id
                        ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-700 dark:text-cyan-300"
                        : "border-slate-200 bg-slate-50 text-slate-600 hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400"
                    }`}
                  >
                    {p.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Run CTA */}
            <div className="flex flex-col justify-start lg:col-span-2 lg:pt-6">
              <button
                type="button"
                disabled={running || (scopeStatus !== null && !scopeStatus.valid)}
                onClick={() =>
                  onRunLive(target, ports, selectedProfile, { maxCves, useCache, apiKey })
                }
                className="inline-flex h-[42px] w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 px-4 text-sm font-semibold text-white shadow-md shadow-cyan-900/20 transition hover:from-cyan-500 hover:to-emerald-500 disabled:cursor-not-allowed disabled:opacity-45"
              >
                <Play className="h-4 w-4 fill-current" />
                {running ? "Scanning..." : "Run Audit"}
              </button>
              <button
                type="button"
                onClick={() => setShowAdvanced((s) => !s)}
                className="mt-2 inline-flex items-center justify-center gap-1 text-[11px] font-medium text-slate-500 hover:text-cyan-600 dark:text-slate-400 dark:hover:text-cyan-300"
              >
                <SlidersHorizontal className="h-3 w-3" />
                {showAdvanced ? "Hide Options" : "NVD & Scan Options"}
              </button>
            </div>
          </div>

          {showAdvanced && (
            <div className="grid grid-cols-1 gap-4 rounded-xl border border-slate-200 bg-slate-50 p-3.5 text-xs dark:border-slate-800 dark:bg-slate-950/70 sm:grid-cols-3">
              <div>
                <label className="font-semibold text-slate-700 dark:text-slate-300">
                  Max CVEs per Service
                </label>
                <select
                  value={maxCves}
                  onChange={(e) => setMaxCves(Number(e.target.value))}
                  className="mt-1 w-full rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                >
                  <option value={3}>3 CVEs (Fast)</option>
                  <option value={5}>5 CVEs (Balanced)</option>
                  <option value={10}>10 CVEs (Deep)</option>
                </select>
              </div>
              <div>
                <label className="font-semibold text-slate-700 dark:text-slate-300">
                  Optional NVD API Key (Session Only)
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Boosts rate limit to 50 req / 30s"
                  className="mt-1 w-full rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
                />
              </div>
              <div className="flex items-end pb-1">
                <label className="inline-flex cursor-pointer items-center gap-2 font-medium text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    checked={useCache}
                    onChange={(e) => setUseCache(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 accent-cyan-600"
                  />
                  Use Local NVD Response Cache (24h TTL)
                </label>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-3">
          {scenarios.map((sc) => (
            <div
              key={sc.id}
              className="flex flex-col justify-between rounded-xl border border-slate-200 bg-slate-50/70 p-4 transition hover:border-cyan-500/40 dark:border-slate-800 dark:bg-slate-950/60"
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-cyan-600 dark:text-cyan-400">
                    {sc.target}
                  </span>
                  <span className="rounded-md bg-slate-200/80 px-2 py-0.5 text-[10px] font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    {sc.asset_count} services
                  </span>
                </div>
                <h3 className="mt-1.5 text-sm font-bold text-slate-900 dark:text-slate-100">
                  {sc.name}
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                  {sc.description}
                </p>
              </div>
              <button
                type="button"
                disabled={running}
                onClick={() => onRunSimulation(sc.id)}
                className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-700 transition hover:bg-cyan-500/20 disabled:opacity-50 dark:text-cyan-300"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                Load &amp; Audit Scenario
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Live Progress Stream */}
      {(running || (progress && progress.progress > 0 && progress.progress < 100)) && progress && (
        <div className="mt-4 rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-3.5">
          <div className="flex items-center justify-between text-xs font-semibold text-cyan-700 dark:text-cyan-300">
            <span className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 animate-ping rounded-full bg-cyan-400" />
              {progress.message}
            </span>
            <span className="font-mono">{progress.progress}%</span>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all duration-300"
              style={{ width: `${progress.progress}%` }}
            />
          </div>
          {progressLog.length > 0 && (
            <div className="mt-2.5 max-h-24 space-y-1 overflow-y-auto font-mono text-[11px] text-slate-600 dark:text-slate-400">
              {progressLog.slice(-4).map((ev, idx) => (
                <div key={`${ev.stage}-${idx}`} className="flex items-center gap-1.5">
                  <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-500" />
                  <span>[{ev.stage}]</span>
                  <span className="truncate">{ev.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {errorMessage && (
        <div className="mt-4 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-xs font-medium text-rose-600 dark:text-rose-300">
          {errorMessage}
        </div>
      )}
    </section>
  );
}
