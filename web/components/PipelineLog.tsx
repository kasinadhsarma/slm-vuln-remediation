"use client";

import { useEffect, useRef } from "react";
import type { LogLine } from "@/lib/formatEvent";

const TONE_STYLE: Record<LogLine["tone"], string> = {
  info: "text-slate-300",
  success: "text-emerald-400",
  warning: "text-amber-400",
  error: "text-red-400",
};

export default function PipelineLog({ lines }: { lines: LogLine[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [lines.length]);

  return (
    <div className="h-80 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs">
      {lines.length === 0 && (
        <p className="text-slate-600">Pipeline events will appear here...</p>
      )}
      {lines.map((line) => (
        <div key={line.id} className={`flex gap-2 py-0.5 ${TONE_STYLE[line.tone]}`}>
          <span>{line.icon}</span>
          <span>{line.text}</span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
