const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type Finding = {
  cwe_id: string;
  cwe: string;
  rule_id: string;
  message: string;
  line: number;
  end_line: number;
  severity: string;
  snippet: string;
};

export type Example = {
  name: string;
  cwe_id: string;
  description: string;
  filename: string;
  code: string;
};

export type PipelineEvent = {
  type: string;
  [key: string]: unknown;
};

export async function fetchExamples(): Promise<Example[]> {
  const res = await fetch(`${API_BASE}/api/examples`);
  if (!res.ok) throw new Error(`failed to load examples: ${res.status}`);
  const data = await res.json();
  return data.examples as Example[];
}

export async function scanCode(code: string, filename: string): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, filename }),
  });
  if (!res.ok) throw new Error(`scan failed: ${res.status}`);
  const data = await res.json();
  return data.findings as Finding[];
}

export async function remediateStream(
  code: string,
  filename: string,
  maxIterations: number | undefined,
  onEvent: (event: PipelineEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  const res = await fetch(`${API_BASE}/api/remediate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, filename, max_iterations: maxIterations }),
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`remediate request failed: ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let newlineIndex: number;
    while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (line) onEvent(JSON.parse(line) as PipelineEvent);
    }
  }

  const rest = buffer.trim();
  if (rest) onEvent(JSON.parse(rest) as PipelineEvent);
}

export { API_BASE };
