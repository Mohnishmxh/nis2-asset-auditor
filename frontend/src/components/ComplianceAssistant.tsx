import { useState } from "react";
import { Bot, Send, Sparkles } from "lucide-react";
import { askComplianceAssistant } from "../api";
import type { AssistantResponse } from "../types";

interface ComplianceAssistantProps {
  auditId: string;
  onHighlightActions: (actionIds: string[]) => void;
}

const QUICK_PROMPTS = [
  "What should I patch first?",
  "Show encryption violations",
  "Summarize critical CVEs",
  "Check exposed databases",
];

export function ComplianceAssistant({
  auditId,
  onHighlightActions,
}: ComplianceAssistantProps) {
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [reply, setReply] = useState<AssistantResponse | null>(null);
  const [askError, setAskError] = useState<string | null>(null);

  const submitQuery = async (qText: string) => {
    if (!qText.trim()) return;
    setLoading(true);
    setAskError(null);
    try {
      const res = await askComplianceAssistant(auditId, qText);
      setReply(res);
    } catch (err) {
      setAskError(err instanceof Error ? err.message : "Failed to query compliance analyst.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800/90 dark:bg-slate-900/75">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-cyan-500/15 text-cyan-500">
            <Bot className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Smart NIS2 Compliance Analyst
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Deterministic audit intelligence — ask about patch priority, encryption gaps, or Article 21(2) posture.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {QUICK_PROMPTS.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => {
                setQuestion(p);
                submitQuery(p);
              }}
              className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600 transition hover:border-cyan-500/50 hover:text-cyan-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300 dark:hover:text-cyan-300"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          submitQuery(question);
        }}
        className="mt-4 flex gap-2"
      >
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask anything about this audit (e.g. 'How do I reach Grade A?')"
          className="flex-1 rounded-xl border border-slate-300 bg-slate-50 px-3.5 py-2 text-xs text-slate-900 outline-none focus:border-cyan-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
        />
        <button
          type="submit"
          disabled={loading || !question.trim()}
          className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-cyan-500 disabled:opacity-50"
        >
          <Send className="h-3.5 w-3.5" />
          {loading ? "Analyzing..." : "Ask"}
        </button>
      </form>

      {askError && (
        <div className="mt-3 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-500">
          {askError}
        </div>
      )}

      {reply && (
        <div className="mt-4 rounded-xl border border-cyan-500/25 bg-cyan-500/5 p-4 text-xs">
          <div className="whitespace-pre-line leading-relaxed text-slate-800 dark:text-slate-200">
            {reply.answer}
          </div>
          {reply.highlights.length > 0 && (
            <ul className="mt-2.5 space-y-1 text-[11px] text-slate-600 dark:text-slate-300">
              {reply.highlights.map((h, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <Sparkles className="mt-0.5 h-3 w-3 shrink-0 text-cyan-500" />
                  <span>{h}</span>
                </li>
              ))}
            </ul>
          )}
          {reply.suggested_actions.length > 0 && (
            <button
              type="button"
              onClick={() => onHighlightActions(reply.suggested_actions)}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-cyan-600/15 px-3 py-1.5 text-[11px] font-semibold text-cyan-700 hover:bg-cyan-600/25 dark:text-cyan-300"
            >
              Jump to {reply.suggested_actions.length} Recommended Fix(es) &rarr;
            </button>
          )}
        </div>
      )}
    </section>
  );
}
