"use client";

import type { Example } from "@/lib/api";

export default function ExamplePicker({
  examples,
  onSelect,
}: {
  examples: Example[];
  onSelect: (example: Example) => void;
}) {
  return (
    <select
      className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-200"
      defaultValue=""
      onChange={(e) => {
        const example = examples.find((ex) => ex.name === e.target.value);
        if (example) onSelect(example);
      }}
    >
      <option value="" disabled>
        Load an example...
      </option>
      {examples.map((ex) => (
        <option key={ex.name} value={ex.name}>
          {ex.cwe_id} &mdash; {ex.name}
        </option>
      ))}
    </select>
  );
}
