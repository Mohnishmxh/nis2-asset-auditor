import { useEffect, useState } from "react";
import { Download, FileText, X } from "lucide-react";
import { fetchExportPreview, getExportDownloadUrl } from "../api";

interface ReportPreviewModalProps {
  auditId: string;
  onClose: () => void;
}

type ExportFormat = "md" | "json" | "csv" | "html";

export function ReportPreviewModal({ auditId, onClose }: ReportPreviewModalProps) {
  const [format, setFormat] = useState<ExportFormat>("md");
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchExportPreview(auditId, format)
      .then((txt) => {
        if (active) setContent(txt);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [auditId, format]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-cyan-500" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Compliance Evidence Export &amp; Preview
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {(["md", "html", "json", "csv"] as ExportFormat[]).map((fmt) => (
              <button
                key={fmt}
                type="button"
                onClick={() => setFormat(fmt)}
                className={`rounded-lg px-2.5 py-1 font-mono text-xs font-semibold uppercase ${
                  format === fmt
                    ? "bg-cyan-500/15 text-cyan-600 dark:text-cyan-300"
                    : "text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
                }`}
              >
                .{fmt}
              </button>
            ))}
            <a
              href={getExportDownloadUrl(auditId, format)}
              className="ml-2 inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500"
            >
              <Download className="h-3.5 w-3.5" />
              Download .{format}
            </a>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto bg-slate-50 p-5 dark:bg-slate-950">
          {loading ? (
            <div className="py-12 text-center text-xs text-slate-500">
              Rendering {format.toUpperCase()} compliance artifact...
            </div>
          ) : format === "html" ? (
            <iframe
              title="HTML Report Preview"
              srcDoc={content}
              className="h-[60vh] w-full rounded-xl border border-slate-200 bg-white dark:border-slate-800"
            />
          ) : (
            <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200">
              {content}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
