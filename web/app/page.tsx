"use client";

import { useEffect, useState } from "react";
import {
  fetchExamples,
  scanCode,
  remediateStream,
  type Example,
  type Finding,
  type PipelineEvent,
} from "@/lib/api";
import { formatEvent, type LogLine } from "@/lib/formatEvent";
import CodeBlock from "@/components/CodeBlock";
import FindingsTable from "@/components/FindingsTable";
import PipelineLog from "@/components/PipelineLog";
import ExamplePicker from "@/components/ExamplePicker";

const DEFAULT_CODE = `import hashlib

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
`;

export default function Home() {
  const [examples, setExamples] = useState<Example[]>([]);
  const [code, setCode] = useState(DEFAULT_CODE);
  const [filename, setFilename] = useState("app.py");

  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [scanning, setScanning] = useState(false);

  const [logLines, setLogLines] = useState<LogLine[]>([]);
  const [finalSource, setFinalSource] = useState<string | null>(null);
  const [summary, setSummary] = useState<{ fixed: number; total: number } | null>(null);
  const [remediating, setRemediating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchExamples()
      .then(setExamples)
      .catch(() => setError("Could not reach the slm-avr API. Is the backend running?"));
  }, []);

  function loadExample(example: Example) {
    setCode(example.code);
    setFilename(example.filename);
    setFindings(null);
    setFinalSource(null);
    setSummary(null);
    setLogLines([]);
    setError(null);
  }

  async function handleScan() {
    setScanning(true);
    setError(null);
    setFindings(null);
    try {
      const result = await scanCode(code, filename);
      setFindings(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }

  async function handleRemediate() {
    setRemediating(true);
    setError(null);
    setLogLines([]);
    setFinalSource(null);
    setSummary(null);

    const onEvent = (event: PipelineEvent) => {
      if (event.type === "complete") {
        setFinalSource(event.final_source as string);
        setSummary({
          fixed: event.fixed_count as number,
          total: event.total_count as number,
        });
        return; // superseded by the file_done log line + summary/patched panels
      }
      setLogLines((prev) => [...prev, formatEvent(event)]);
    };

    try {
      await remediateStream(code, filename, undefined, onEvent);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRemediating(false);
    }
  }

  const busy = scanning || remediating;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-4">
        <h1 className="text-lg font-semibold tracking-tight">
          slm-avr <span className="text-slate-500 font-normal">/ vulnerability remediation</span>
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Retrieval-Augmented Autonomous Code Vulnerability Remediation, guided by static
          analysis and a local small language model.
        </p>
      </header>

      {error && (
        <div className="mx-6 mt-4 rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <main className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-2">
        {/* Left column: input */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <input
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                className="w-32 rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
              />
              <ExamplePicker examples={examples} onSelect={loadExample} />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleScan}
                disabled={busy}
                className="rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm font-medium hover:bg-slate-700 disabled:opacity-50"
              >
                {scanning ? "Scanning..." : "Scan"}
              </button>
              <button
                onClick={handleRemediate}
                disabled={busy}
                className="rounded-md bg-emerald-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-600 disabled:opacity-50"
              >
                {remediating ? "Remediating..." : "Remediate"}
              </button>
            </div>
          </div>

          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            className="h-96 w-full resize-none rounded-lg border border-slate-800 bg-slate-900 p-3 font-mono text-xs text-slate-200 outline-none focus:border-slate-600"
          />

          {findings !== null && (
            <div>
              <h2 className="mb-2 text-sm font-medium text-slate-400">
                Findings ({findings.length})
              </h2>
              <FindingsTable findings={findings} />
            </div>
          )}
        </section>

        {/* Right column: pipeline + result */}
        <section className="space-y-3">
          <h2 className="text-sm font-medium text-slate-400">Agent pipeline</h2>
          <PipelineLog lines={logLines} />

          {summary && (
            <div
              className={`rounded-md border px-3 py-2 text-sm ${
                summary.fixed === summary.total
                  ? "border-emerald-800 bg-emerald-950/50 text-emerald-300"
                  : "border-amber-800 bg-amber-950/50 text-amber-300"
              }`}
            >
              {summary.fixed}/{summary.total} finding(s) resolved
            </div>
          )}

          {finalSource && <CodeBlock code={finalSource} label="Patched code" highlight />}
        </section>
      </main>
    </div>
  );
}
