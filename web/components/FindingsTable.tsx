import type { Finding } from "@/lib/api";

const SEVERITY_STYLE: Record<string, string> = {
  ERROR: "bg-red-950 text-red-300 border-red-800",
  WARNING: "bg-amber-950 text-amber-300 border-amber-800",
  INFO: "bg-slate-800 text-slate-300 border-slate-700",
};

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-emerald-900 bg-emerald-950/40 p-4 text-sm text-emerald-300">
        No findings.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {findings.map((f, i) => (
        <div
          key={`${f.rule_id}-${f.line}-${i}`}
          className="rounded-lg border border-slate-800 bg-slate-900 p-3"
        >
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="rounded border border-sky-800 bg-sky-950 px-1.5 py-0.5 font-mono text-sky-300">
              {f.cwe_id}
            </span>
            <span
              className={`rounded border px-1.5 py-0.5 ${
                SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.INFO
              }`}
            >
              {f.severity}
            </span>
            <span className="text-slate-500">line {f.line}</span>
          </div>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-slate-300">
            <code>{f.snippet}</code>
          </pre>
          <p className="mt-2 text-xs text-slate-400">{f.message}</p>
        </div>
      ))}
    </div>
  );
}
