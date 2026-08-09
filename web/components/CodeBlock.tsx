"use client";

import { useState } from "react";

export default function CodeBlock({
  code,
  label,
  highlight,
}: {
  code: string;
  label?: string;
  highlight?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="relative rounded-lg border border-slate-800 bg-slate-950">
      {label && (
        <div className="flex items-center justify-between border-b border-slate-800 px-3 py-1.5">
          <span className="text-xs font-medium text-slate-400">{label}</span>
          <button
            onClick={copy}
            className="text-xs text-slate-400 hover:text-slate-200 transition"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
      )}
      <pre
        className={`overflow-x-auto p-3 text-xs leading-relaxed ${
          highlight ? "text-emerald-300" : "text-slate-200"
        }`}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}
