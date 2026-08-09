import type { PipelineEvent } from "./api";

export type LogLine = {
  id: string;
  icon: string;
  text: string;
  tone: "info" | "success" | "warning" | "error";
};

let counter = 0;

export function formatEvent(event: PipelineEvent): LogLine {
  const id = `evt-${counter++}`;
  const t = event.type as string;

  switch (t) {
    case "scan_complete":
      return {
        id,
        icon: "🔍",
        tone: "info",
        text: `Static analysis found ${event.findings_total as number} finding(s)`,
      };
    case "finding_start":
      return {
        id,
        icon: "▶️",
        tone: "info",
        text: `[${event.index}/${event.total}] Working on ${event.cwe_id} at line ${event.line}`,
      };
    case "slicing_complete":
      return {
        id,
        icon: "✂️",
        tone: "info",
        text: `Program slice ready: function \`${event.enclosing_name}\` (${event.included_lines} relevant line(s))`,
      };
    case "retrieval_complete": {
      const exemplars = event.exemplars as { title: string; score: number }[];
      const titles = exemplars.map((e) => e.title).join(", ") || "none";
      return {
        id,
        icon: "📚",
        tone: "info",
        text: `Retrieved ${exemplars.length} historical fix exemplar(s): ${titles}`,
      };
    }
    case "curator_complete":
      return {
        id,
        icon: "🕸️",
        tone: "info",
        text: `Curator Agent: ${event.callers} caller(s), ${event.related_definitions} related definition(s), ${event.callees} callee(s)`,
      };
    case "generation_start":
      return {
        id,
        icon: "🤖",
        tone: "info",
        text: `Patch Generator: iteration ${event.iteration}/${event.max_iterations}...`,
      };
    case "generation_complete":
      return {
        id,
        icon: "📝",
        tone: "info",
        text: `Candidate patch generated (iteration ${event.iteration})`,
      };
    case "review_result": {
      const verdict = event.verdict as string;
      const tone = verdict === "fixed" ? "success" : "warning";
      return {
        id,
        icon: verdict === "fixed" ? "✅" : "🔁",
        tone,
        text: `Patch Reviewer verdict (iteration ${event.iteration}): ${verdict}`,
      };
    }
    case "finding_resolved": {
      const verdict = event.verdict as string;
      const fixed = verdict === "fixed";
      return {
        id,
        icon: fixed ? "🎯" : "⚠️",
        tone: fixed ? "success" : "error",
        text: fixed
          ? `${event.cwe_id} resolved after ${event.iterations_used} iteration(s)`
          : `${event.cwe_id} not resolved (${verdict}) after ${event.iterations_used} iteration(s)`,
      };
    }
    case "finding_skipped_already_fixed":
      return {
        id,
        icon: "⏭️",
        tone: "success",
        text: `${event.cwe_id} already resolved as a side effect of an earlier fix`,
      };
    case "file_done":
      return {
        id,
        icon: "🏁",
        tone: (event.fixed_count === event.total_count ? "success" : "warning"),
        text: `Done: ${event.fixed_count}/${event.total_count} finding(s) fixed`,
      };
    case "error":
      return { id, icon: "❌", tone: "error", text: `Error: ${event.message}` };
    default:
      return { id, icon: "•", tone: "info", text: t };
  }
}
